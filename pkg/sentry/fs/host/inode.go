// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package host

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/secio"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// inodeOperations implements fs.InodeOperations for an fs.Inodes backed
// by a host file descriptor.
//
// +stateify savable
type inodeOperations struct {
	fsutil.InodeNotVirtual           `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`

	// fileState implements fs.CachedFileObject. It exists
	// to break a circular load dependency between inodeOperations
	// and cachingInodeOps (below).
	fileState *inodeFileState `state:"wait"`

	// cachedInodeOps implements memmap.Mappable.
	cachingInodeOps *fsutil.CachingInodeOperations

	// readdirMu protects the file offset on the host FD. This is needed
	// for readdir because getdents must use the kernel offset, so
	// concurrent readdirs must be exclusive.
	//
	// All read/write functions pass the offset directly to the kernel and
	// thus don't need a lock.
	readdirMu sync.Mutex `state:"nosave"`
}

// inodeFileState implements fs.CachedFileObject and otherwise fully
// encapsulates state that needs to be manually loaded on restore for
// this file object.
//
// This unfortunate structure exists because fs.CachingInodeOperations
// defines afterLoad and therefore cannot be lazily loaded (to break a
// circular load dependency between it and inodeOperations). Even with
// lazy loading, this approach defines the dependencies between objects
// and the expected load behavior more concretely.
//
// +stateify savable
type inodeFileState struct {
	// descriptor is the backing host FD.
	descriptor *descriptor `state:"wait"`

	// Event queue for blocking operations.
	queue waiter.Queue `state:"zerovalue"`

	// sattr is used to restore the inodeOperations.
	sattr fs.StableAttr `state:"wait"`

	// savedUAttr is only allocated during S/R. It points to the save-time
	// unstable attributes and is used to validate restore-time ones.
	//
	// Note that these unstable attributes are only used to detect cross-S/R
	// external file system metadata changes. They may differ from the
	// cached unstable attributes in cachingInodeOps, as that might differ
	// from the external file system attributes if there had been WriteOut
	// failures. S/R is transparent to Sentry and the latter will continue
	// using its cached values after restore.
	savedUAttr *fs.UnstableAttr
}

// ReadToBlocksAt implements fsutil.CachedFileObject.ReadToBlocksAt.
func (i *inodeFileState) ReadToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error) {
	// TODO(jamieliu): Using safemem.FromIOReader here is wasteful for two
	// reasons:
	//
	// - Using preadv instead of iterated preads saves on host system calls.
	//
	// - Host system calls can handle destination memory that would fault in
	// gr3 (i.e. they can accept safemem.Blocks with NeedSafecopy() == true),
	// so the buffering performed by FromIOReader is unnecessary.
	//
	// This also applies to the write path below.
	return safemem.FromIOReader{secio.NewOffsetReader(fd.NewReadWriter(i.FD()), int64(offset))}.ReadToBlocks(dsts)
}

// WriteFromBlocksAt implements fsutil.CachedFileObject.WriteFromBlocksAt.
func (i *inodeFileState) WriteFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error) {
	return safemem.FromIOWriter{secio.NewOffsetWriter(fd.NewReadWriter(i.FD()), int64(offset))}.WriteFromBlocks(srcs)
}

// SetMaskedAttributes implements fsutil.CachedFileObject.SetMaskedAttributes.
func (i *inodeFileState) SetMaskedAttributes(ctx context.Context, mask fs.AttrMask, attr fs.UnstableAttr, _ bool) error {
	if mask.Empty() {
		return nil
	}
	if mask.UID || mask.GID {
		return syserror.EPERM
	}
	if mask.Perms {
		if err := unix.Fchmod(i.FD(), uint32(attr.Perms.LinuxMode())); err != nil {
			return err
		}
	}
	if mask.Size {
		if err := unix.Ftruncate(i.FD(), attr.Size); err != nil {
			return err
		}
	}
	if mask.AccessTime || mask.ModificationTime {
		ts := fs.TimeSpec{
			ATime:     attr.AccessTime,
			ATimeOmit: !mask.AccessTime,
			MTime:     attr.ModificationTime,
			MTimeOmit: !mask.ModificationTime,
		}
		if err := setTimestamps(i.FD(), ts); err != nil {
			return err
		}
	}
	return nil
}

// Sync implements fsutil.CachedFileObject.Sync.
func (i *inodeFileState) Sync(ctx context.Context) error {
	return unix.Fsync(i.FD())
}

// FD implements fsutil.CachedFileObject.FD.
func (i *inodeFileState) FD() int {
	return i.descriptor.value
}

func (i *inodeFileState) unstableAttr(ctx context.Context) (fs.UnstableAttr, error) {
	var s unix.Stat_t
	if err := unix.Fstat(i.FD(), &s); err != nil {
		return fs.UnstableAttr{}, err
	}
	return unstableAttr(&s), nil
}

// Allocate implements fsutil.CachedFileObject.Allocate.
func (i *inodeFileState) Allocate(_ context.Context, offset, length int64) error {
	return unix.Fallocate(i.FD(), 0, offset, length)
}

// inodeOperations implements fs.InodeOperations.
var _ fs.InodeOperations = (*inodeOperations)(nil)

// newInode returns a new fs.Inode backed by the host FD.
func newInode(ctx context.Context, msrc *fs.MountSource, fd int, saveable bool) (*fs.Inode, error) {
	// Retrieve metadata.
	var s unix.Stat_t
	err := unix.Fstat(fd, &s)
	if err != nil {
		return nil, err
	}

	fileState := &inodeFileState{
		sattr: stableAttr(&s),
	}

	// Initialize the wrapped host file descriptor.
	fileState.descriptor, err = newDescriptor(fd, saveable, wouldBlock(&s), &fileState.queue)
	if err != nil {
		return nil, err
	}

	// Build the fs.InodeOperations.
	uattr := unstableAttr(&s)
	iops := &inodeOperations{
		fileState: fileState,
		cachingInodeOps: fsutil.NewCachingInodeOperations(ctx, fileState, uattr, fsutil.CachingInodeOperationsOptions{
			ForcePageCache: msrc.Flags.ForcePageCache,
		}),
	}

	// Return the fs.Inode.
	return fs.NewInode(ctx, iops, msrc, fileState.sattr), nil
}

// Mappable implements fs.InodeOperations.Mappable.
func (i *inodeOperations) Mappable(inode *fs.Inode) memmap.Mappable {
	if !canMap(inode) {
		return nil
	}
	return i.cachingInodeOps
}

// ReturnsWouldBlock returns true if this host FD can return EWOULDBLOCK for
// operations that would block.
func (i *inodeOperations) ReturnsWouldBlock() bool {
	return i.fileState.descriptor.wouldBlock
}

// Release implements fs.InodeOperations.Release.
func (i *inodeOperations) Release(context.Context) {
	i.fileState.descriptor.Release()
	i.cachingInodeOps.Release()
}

// Lookup implements fs.InodeOperations.Lookup.
func (i *inodeOperations) Lookup(ctx context.Context, dir *fs.Inode, name string) (*fs.Dirent, error) {
	return nil, syserror.ENOENT
}

// Create implements fs.InodeOperations.Create.
func (i *inodeOperations) Create(ctx context.Context, dir *fs.Inode, name string, flags fs.FileFlags, perm fs.FilePermissions) (*fs.File, error) {
	return nil, syserror.EPERM

}

// CreateDirectory implements fs.InodeOperations.CreateDirectory.
func (i *inodeOperations) CreateDirectory(ctx context.Context, dir *fs.Inode, name string, perm fs.FilePermissions) error {
	return syserror.EPERM
}

// CreateLink implements fs.InodeOperations.CreateLink.
func (i *inodeOperations) CreateLink(ctx context.Context, dir *fs.Inode, oldname string, newname string) error {
	return syserror.EPERM
}

// CreateHardLink implements fs.InodeOperations.CreateHardLink.
func (*inodeOperations) CreateHardLink(context.Context, *fs.Inode, *fs.Inode, string) error {
	return syserror.EPERM
}

// CreateFifo implements fs.InodeOperations.CreateFifo.
func (*inodeOperations) CreateFifo(context.Context, *fs.Inode, string, fs.FilePermissions) error {
	return syserror.EPERM
}

// Remove implements fs.InodeOperations.Remove.
func (i *inodeOperations) Remove(ctx context.Context, dir *fs.Inode, name string) error {
	return syserror.EPERM
}

// RemoveDirectory implements fs.InodeOperations.RemoveDirectory.
func (i *inodeOperations) RemoveDirectory(ctx context.Context, dir *fs.Inode, name string) error {
	return syserror.EPERM
}

// Rename implements fs.InodeOperations.Rename.
func (i *inodeOperations) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return syserror.EPERM
}

// Bind implements fs.InodeOperations.Bind.
func (i *inodeOperations) Bind(ctx context.Context, dir *fs.Inode, name string, data transport.BoundEndpoint, perm fs.FilePermissions) (*fs.Dirent, error) {
	return nil, syserror.EOPNOTSUPP
}

// BoundEndpoint implements fs.InodeOperations.BoundEndpoint.
func (i *inodeOperations) BoundEndpoint(inode *fs.Inode, path string) transport.BoundEndpoint {
	return nil
}

// GetFile implements fs.InodeOperations.GetFile.
func (i *inodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	if fs.IsSocket(d.Inode.StableAttr) {
		return nil, syserror.ENXIO
	}

	return newFile(ctx, d, flags, i), nil
}

// canMap returns true if this fs.Inode can be memory mapped.
func canMap(inode *fs.Inode) bool {
	// FIXME(b/38213152): Some obscure character devices can be mapped.
	return fs.IsFile(inode.StableAttr)
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (i *inodeOperations) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	// When the kernel supports mapping host FDs, we do so to take
	// advantage of the host page cache. We forego updating fs.Inodes
	// because the host manages consistency of its own inode structures.
	//
	// For fs.Inodes that can never be mapped we take advantage of
	// synchronizing metadata updates through host caches.
	//
	// So can we use host kernel metadata caches?
	if !inode.MountSource.Flags.ForcePageCache || !canMap(inode) {
		// Then just obtain the attributes.
		return i.fileState.unstableAttr(ctx)
	}
	// No, we're maintaining consistency of metadata ourselves.
	return i.cachingInodeOps.UnstableAttr(ctx, inode)
}

// Check implements fs.InodeOperations.Check.
func (i *inodeOperations) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (i *inodeOperations) SetOwner(context.Context, *fs.Inode, fs.FileOwner) error {
	return syserror.EPERM
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (i *inodeOperations) SetPermissions(ctx context.Context, inode *fs.Inode, f fs.FilePermissions) bool {
	// Can we use host kernel metadata caches?
	if !inode.MountSource.Flags.ForcePageCache || !canMap(inode) {
		// Then just change the timestamps on the FD, the host
		// will synchronize the metadata update with any host
		// inode and page cache.
		return unix.Fchmod(i.fileState.FD(), uint32(f.LinuxMode())) == nil
	}
	// Otherwise update our cached metadata.
	return i.cachingInodeOps.SetPermissions(ctx, inode, f)
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (i *inodeOperations) SetTimestamps(ctx context.Context, inode *fs.Inode, ts fs.TimeSpec) error {
	// Can we use host kernel metadata caches?
	if !inode.MountSource.Flags.ForcePageCache || !canMap(inode) {
		// Then just change the timestamps on the FD, the host
		// will synchronize the metadata update with any host
		// inode and page cache.
		return setTimestamps(i.fileState.FD(), ts)
	}
	// Otherwise update our cached metadata.
	return i.cachingInodeOps.SetTimestamps(ctx, inode, ts)
}

// Truncate implements fs.InodeOperations.Truncate.
func (i *inodeOperations) Truncate(ctx context.Context, inode *fs.Inode, size int64) error {
	// Is the file not memory-mappable?
	if !canMap(inode) {
		// Then just change the file size on the FD, the host
		// will synchronize the metadata update with any host
		// inode and page cache.
		return unix.Ftruncate(i.fileState.FD(), size)
	}
	// Otherwise we need to go through cachingInodeOps, even if the host page
	// cache is in use, to invalidate private copies of truncated pages.
	return i.cachingInodeOps.Truncate(ctx, inode, size)
}

// Allocate implements fs.InodeOperations.Allocate.
func (i *inodeOperations) Allocate(ctx context.Context, inode *fs.Inode, offset, length int64) error {
	// Is the file not memory-mappable?
	if !canMap(inode) {
		// Then just send the call to the FD, the host will synchronize the metadata
		// update with any host inode and page cache.
		return i.fileState.Allocate(ctx, offset, length)
	}
	// Otherwise we need to go through cachingInodeOps, even if the host page
	// cache is in use, to invalidate private copies of truncated pages.
	return i.cachingInodeOps.Allocate(ctx, offset, length)
}

// WriteOut implements fs.InodeOperations.WriteOut.
func (i *inodeOperations) WriteOut(ctx context.Context, inode *fs.Inode) error {
	if inode.MountSource.Flags.ReadOnly {
		return nil
	}
	// Have we been using host kernel metadata caches?
	if !inode.MountSource.Flags.ForcePageCache || !canMap(inode) {
		// Then the metadata is already up to date on the host.
		return nil
	}
	// Otherwise we need to write out cached pages and attributes
	// that are dirty.
	return i.cachingInodeOps.WriteOut(ctx, inode)
}

// Readlink implements fs.InodeOperations.Readlink.
func (i *inodeOperations) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	return readLink(i.fileState.FD())
}

// Getlink implements fs.InodeOperations.Getlink.
func (i *inodeOperations) Getlink(context.Context, *fs.Inode) (*fs.Dirent, error) {
	if !fs.IsSymlink(i.fileState.sattr) {
		return nil, syserror.ENOLINK
	}
	return nil, fs.ErrResolveViaReadlink
}

// StatFS implements fs.InodeOperations.StatFS.
func (i *inodeOperations) StatFS(context.Context) (fs.Info, error) {
	return fs.Info{}, syserror.ENOSYS
}

// AddLink implements fs.InodeOperations.AddLink.
func (i *inodeOperations) AddLink() {}

// DropLink implements fs.InodeOperations.DropLink.
func (i *inodeOperations) DropLink() {}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
func (i *inodeOperations) NotifyStatusChange(ctx context.Context) {}
