// Copyright 2018 Google LLC
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

package gofer

import (
	"errors"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fdpipe"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/host"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// inodeOperations implements fs.InodeOperations.
//
// +stateify savable
type inodeOperations struct {
	fsutil.InodeNotVirtual           `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`

	// fileState implements fs.CachedFileObject. It exists
	// to break a circular load dependency between inodeOperations
	// and cachingInodeOps (below).
	fileState *inodeFileState `state:"wait"`

	// cachingInodeOps implement memmap.Mappable for inodeOperations.
	cachingInodeOps *fsutil.CachingInodeOperations

	// readdirMu protects readdirCache and concurrent Readdirs.
	readdirMu sync.Mutex `state:"nosave"`

	// readdirCache is a cache of readdir results in the form of
	// a fs.SortedDentryMap.
	//
	// Starts out as nil, and is initialized under readdirMu lazily;
	// invalidating the cache means setting it to nil.
	readdirCache *fs.SortedDentryMap `state:"nosave"`
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
	// s is common file system state for Gofers.
	s *session `state:"wait"`

	// MultiDeviceKey consists of:
	//
	// * Device:          file system device from a specific gofer.
	// * SecondaryDevice: unique identifier of the attach point.
	// * Inode:           the inode of this resource, unique per Device.=
	//
	// These fields combined enable consistent hashing of virtual inodes
	// on goferDevice.
	key device.MultiDeviceKey `state:"nosave"`

	// file is the p9 file that contains a single unopened fid.
	file contextFile `state:"nosave"`

	// sattr caches the stable attributes.
	sattr fs.StableAttr `state:"wait"`

	// handlesMu protects the below fields.
	handlesMu sync.RWMutex `state:"nosave"`

	// Do minimal open handle caching: only for read only filesystems.
	readonly *handles `state:"nosave"`

	// Maintain readthrough handles for populating page caches.
	readthrough *handles `state:"nosave"`

	// Maintain writeback handles for syncing from page caches.
	writeback *handles `state:"nosave"`

	// writebackRW indicates whether writeback is opened read-write. If
	// it is not and a read-write handle could replace writeback (above),
	// then writeback is replaced with the read-write handle. This
	// ensures that files that were first opened write-only and then
	// later are opened read-write to be mapped can in fact be mapped.
	writebackRW bool

	// loading is acquired when the inodeFileState begins an asynchronous
	// load. It releases when the load is complete. Callers that require all
	// state to be available should call waitForLoad() to ensure that.
	loading sync.Mutex `state:".(struct{})"`

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

	// hostMappable is created when using 'cacheRemoteRevalidating' to map pages
	// directly from host.
	hostMappable *fsutil.HostMappable
}

// Release releases file handles.
func (i *inodeFileState) Release(ctx context.Context) {
	i.file.close(ctx)
	if i.readonly != nil {
		i.readonly.DecRef()
	}
	if i.readthrough != nil {
		i.readthrough.DecRef()
	}
	if i.writeback != nil {
		i.writeback.DecRef()
	}
}

// setHandlesForCachedIO installs file handles for reading and writing
// through fs.CachingInodeOperations.
func (i *inodeFileState) setHandlesForCachedIO(flags fs.FileFlags, h *handles) {
	i.handlesMu.Lock()
	defer i.handlesMu.Unlock()

	if flags.Read {
		if i.readthrough == nil {
			h.IncRef()
			i.readthrough = h
		}
	}
	if flags.Write {
		if i.writeback == nil {
			h.IncRef()
			i.writeback = h
		} else if !i.writebackRW && flags.Read {
			i.writeback.DecRef()
			h.IncRef()
			i.writeback = h
		}
		if flags.Read {
			i.writebackRW = true
		}
	}
}

// getCachedHandles returns any cached handles which would accelerate
// performance generally. These handles should only be used if the mount
// supports caching. This is distinct from fs.CachingInodeOperations
// which is used for a limited set of file types (those that can be mapped).
func (i *inodeFileState) getCachedHandles(ctx context.Context, flags fs.FileFlags, msrc *fs.MountSource) (*handles, bool) {
	i.handlesMu.Lock()
	defer i.handlesMu.Unlock()

	if flags.Read && !flags.Write && msrc.Flags.ReadOnly {
		if i.readonly != nil {
			i.readonly.IncRef()
			return i.readonly, true
		}
		h, err := newHandles(ctx, i.file, flags)
		if err != nil {
			return nil, false
		}
		i.readonly = h
		i.readonly.IncRef()
		return i.readonly, true
	}

	return nil, false
}

// ReadToBlocksAt implements fsutil.CachedFileObject.ReadToBlocksAt.
func (i *inodeFileState) ReadToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error) {
	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()
	return i.readthrough.readWriterAt(ctx, int64(offset)).ReadToBlocks(dsts)
}

// WriteFromBlocksAt implements fsutil.CachedFileObject.WriteFromBlocksAt.
func (i *inodeFileState) WriteFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error) {
	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()
	return i.writeback.readWriterAt(ctx, int64(offset)).WriteFromBlocks(srcs)
}

// SetMaskedAttributes implements fsutil.CachedFileObject.SetMaskedAttributes.
func (i *inodeFileState) SetMaskedAttributes(ctx context.Context, mask fs.AttrMask, attr fs.UnstableAttr) error {
	if i.skipSetAttr(mask) {
		return nil
	}
	as, ans := attr.AccessTime.Unix()
	ms, mns := attr.ModificationTime.Unix()
	// An update of status change time is implied by mask.AccessTime
	// or mask.ModificationTime. Updating status change time to a
	// time earlier than the system time is not possible.
	return i.file.setAttr(
		ctx,
		p9.SetAttrMask{
			Permissions:        mask.Perms,
			Size:               mask.Size,
			UID:                mask.UID,
			GID:                mask.GID,
			ATime:              mask.AccessTime,
			ATimeNotSystemTime: true,
			MTime:              mask.ModificationTime,
			MTimeNotSystemTime: true,
		}, p9.SetAttr{
			Permissions:      p9.FileMode(attr.Perms.LinuxMode()),
			UID:              p9.UID(attr.Owner.UID),
			GID:              p9.GID(attr.Owner.GID),
			Size:             uint64(attr.Size),
			ATimeSeconds:     uint64(as),
			ATimeNanoSeconds: uint64(ans),
			MTimeSeconds:     uint64(ms),
			MTimeNanoSeconds: uint64(mns),
		})
}

// skipSetAttr checks if attribute change can be skipped. It can be skipped
// when:
//   - Mask is empty
//   - Mask contains only attributes that cannot be set in the gofer
//   - Mask contains only atime and/or mtime, and host FD exists
//
// Updates to atime and mtime can be skipped because cached value will be
// "close enough" to host value, given that operation went directly to host FD.
// Skipping atime updates is particularly important to reduce the number of
// operations sent to the Gofer for readonly files.
func (i *inodeFileState) skipSetAttr(mask fs.AttrMask) bool {
	// First remove attributes that cannot be updated.
	cpy := mask
	cpy.Type = false
	cpy.DeviceID = false
	cpy.InodeID = false
	cpy.BlockSize = false
	cpy.Usage = false
	cpy.Links = false
	if cpy.Empty() {
		return true
	}

	// Then check if more than just atime and mtime is being set.
	cpy.AccessTime = false
	cpy.ModificationTime = false
	if !cpy.Empty() {
		return false
	}

	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()
	return (i.readonly != nil && i.readonly.Host != nil) ||
		(i.readthrough != nil && i.readthrough.Host != nil) ||
		(i.writeback != nil && i.writeback.Host != nil)
}

// Sync implements fsutil.CachedFileObject.Sync.
func (i *inodeFileState) Sync(ctx context.Context) error {
	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()
	if i.writeback == nil {
		return nil
	}
	return i.writeback.File.fsync(ctx)
}

// FD implements fsutil.CachedFileObject.FD.
//
// FD meets the requirements of fsutil.CachedFileObject.FD because p9.File.Open
// returns a host file descriptor to back _both_ readthrough and writeback or
// not at all (e.g. both are nil).
func (i *inodeFileState) FD() int {
	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()
	return i.fdLocked()
}

func (i *inodeFileState) fdLocked() int {
	// Assert that the file was actually opened.
	if i.writeback == nil && i.readthrough == nil {
		panic("cannot get host FD for a file that was never opened")
	}
	// If this file is mapped, then it must have been opened
	// read-write and i.writeback was upgraded to a read-write
	// handle. Prefer that to map.
	if i.writeback != nil {
		if i.writeback.Host == nil {
			return -1
		}
		return int(i.writeback.Host.FD())
	}
	// Otherwise the file may only have been opened readable
	// so far. That's the only way it can be accessed.
	if i.readthrough.Host == nil {
		return -1
	}
	return int(i.readthrough.Host.FD())
}

// waitForLoad makes sure any restore-issued loading is done.
func (i *inodeFileState) waitForLoad() {
	// This is not a no-op. The loading mutex is hold upon restore until
	// all loading actions are done.
	i.loading.Lock()
	i.loading.Unlock()
}

func (i *inodeFileState) unstableAttr(ctx context.Context) (fs.UnstableAttr, error) {
	_, valid, pattr, err := getattr(ctx, i.file)
	if err != nil {
		return fs.UnstableAttr{}, err
	}
	return unstable(ctx, valid, pattr, i.s.mounter, i.s.client), nil
}

// session extracts the gofer's session from the MountSource.
func (i *inodeOperations) session() *session {
	return i.fileState.s
}

// Release implements fs.InodeOperations.Release.
func (i *inodeOperations) Release(ctx context.Context) {
	i.cachingInodeOps.Release()

	// Releasing the fileState may make RPCs to the gofer. There is
	// no need to wait for those to return, so we can do this
	// asynchronously.
	fs.Async(func() {
		i.fileState.Release(ctx)
	})
}

// Mappable implements fs.InodeOperations.Mappable.
func (i *inodeOperations) Mappable(inode *fs.Inode) memmap.Mappable {
	if i.session().cachePolicy.useCachingInodeOps(inode) {
		return i.cachingInodeOps
	}
	// This check is necessary because it's returning an interface type.
	if i.fileState.hostMappable != nil {
		return i.fileState.hostMappable
	}
	return nil
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (i *inodeOperations) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	if i.session().cachePolicy.cacheUAttrs(inode) {
		return i.cachingInodeOps.UnstableAttr(ctx, inode)
	}
	return i.fileState.unstableAttr(ctx)
}

// Check implements fs.InodeOperations.Check.
func (i *inodeOperations) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// GetFile implements fs.InodeOperations.GetFile.
func (i *inodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	switch d.Inode.StableAttr.Type {
	case fs.Socket:
		return i.getFileSocket(ctx, d, flags)
	case fs.Pipe:
		return i.getFilePipe(ctx, d, flags)
	default:
		return i.getFileDefault(ctx, d, flags)
	}
}

func (i *inodeOperations) getFileSocket(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	f, err := i.fileState.file.connect(ctx, p9.AnonymousSocket)
	if err != nil {
		return nil, syscall.EIO
	}
	fsf, err := host.NewSocketWithDirent(ctx, d, f, flags)
	if err != nil {
		f.Close()
		return nil, err
	}
	return fsf, nil
}

func (i *inodeOperations) getFilePipe(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	// Try to open as a host pipe.
	if pipeOps, err := fdpipe.Open(ctx, i, flags); err != errNotHostFile {
		return fs.NewFile(ctx, d, flags, pipeOps), err
	}

	// If the error is due to the fact that this was never a host pipe, then back
	// this file with its dirent.
	h, err := newHandles(ctx, i.fileState.file, flags)
	if err != nil {
		return nil, err
	}
	return NewFile(ctx, d, d.BaseName(), flags, i, h), nil
}

// errNotHostFile indicates that the file is not a host file.
var errNotHostFile = errors.New("not a host file")

// NonBlockingOpen implements fdpipe.NonBlockingOpener for opening host named pipes.
func (i *inodeOperations) NonBlockingOpen(ctx context.Context, p fs.PermMask) (*fd.FD, error) {
	i.fileState.waitForLoad()

	// Get a cloned fid which we will open.
	_, newFile, err := i.fileState.file.walk(ctx, nil)
	if err != nil {
		log.Warningf("Open Walk failed: %v", err)
		return nil, err
	}
	defer newFile.close(ctx)

	flags, err := openFlagsFromPerms(p)
	if err != nil {
		log.Warningf("Open flags %s parsing failed: %v", p, err)
		return nil, err
	}
	hostFile, _, _, err := newFile.open(ctx, flags)
	// If the host file returned is nil and the error is nil,
	// then this was never a host file to begin with, and should
	// be treated like a remote file.
	if hostFile == nil && err == nil {
		return nil, errNotHostFile
	}
	return hostFile, err
}

func (i *inodeOperations) getFileDefault(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	if !i.session().cachePolicy.cacheHandles(d.Inode) {
		h, err := newHandles(ctx, i.fileState.file, flags)
		if err != nil {
			return nil, err
		}
		return NewFile(ctx, d, d.BaseName(), flags, i, h), nil
	}

	h, ok := i.fileState.getCachedHandles(ctx, flags, d.Inode.MountSource)
	if !ok {
		var err error
		h, err = newHandles(ctx, i.fileState.file, flags)
		if err != nil {
			return nil, err
		}
	}
	i.fileState.setHandlesForCachedIO(flags, h)

	return NewFile(ctx, d, d.BaseName(), flags, i, h), nil
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (i *inodeOperations) SetPermissions(ctx context.Context, inode *fs.Inode, p fs.FilePermissions) bool {
	if i.session().cachePolicy.cacheUAttrs(inode) {
		return i.cachingInodeOps.SetPermissions(ctx, inode, p)
	}

	mask := p9.SetAttrMask{Permissions: true}
	pattr := p9.SetAttr{Permissions: p9.FileMode(p.LinuxMode())}
	// Execute the chmod.
	return i.fileState.file.setAttr(ctx, mask, pattr) == nil
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (i *inodeOperations) SetOwner(ctx context.Context, inode *fs.Inode, owner fs.FileOwner) error {
	// Save the roundtrip.
	if !owner.UID.Ok() && !owner.GID.Ok() {
		return nil
	}

	if i.session().cachePolicy.cacheUAttrs(inode) {
		return i.cachingInodeOps.SetOwner(ctx, inode, owner)
	}

	var mask p9.SetAttrMask
	var attr p9.SetAttr
	if owner.UID.Ok() {
		mask.UID = true
		attr.UID = p9.UID(owner.UID)
	}
	if owner.GID.Ok() {
		mask.GID = true
		attr.GID = p9.GID(owner.GID)
	}
	return i.fileState.file.setAttr(ctx, mask, attr)
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (i *inodeOperations) SetTimestamps(ctx context.Context, inode *fs.Inode, ts fs.TimeSpec) error {
	if i.session().cachePolicy.cacheUAttrs(inode) {
		return i.cachingInodeOps.SetTimestamps(ctx, inode, ts)
	}

	return utimes(ctx, i.fileState.file, ts)
}

// Truncate implements fs.InodeOperations.Truncate.
func (i *inodeOperations) Truncate(ctx context.Context, inode *fs.Inode, length int64) error {
	// This can only be called for files anyway.
	if i.session().cachePolicy.useCachingInodeOps(inode) {
		return i.cachingInodeOps.Truncate(ctx, inode, length)
	}
	if i.session().cachePolicy == cacheRemoteRevalidating {
		return i.fileState.hostMappable.Truncate(ctx, length)
	}

	return i.fileState.file.setAttr(ctx, p9.SetAttrMask{Size: true}, p9.SetAttr{Size: uint64(length)})
}

// WriteOut implements fs.InodeOperations.WriteOut.
func (i *inodeOperations) WriteOut(ctx context.Context, inode *fs.Inode) error {
	if !i.session().cachePolicy.cacheUAttrs(inode) {
		return nil
	}

	return i.cachingInodeOps.WriteOut(ctx, inode)
}

// Readlink implements fs.InodeOperations.Readlink.
func (i *inodeOperations) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	if !fs.IsSymlink(inode.StableAttr) {
		return "", syscall.ENOLINK
	}
	return i.fileState.file.readlink(ctx)
}

// Getlink implementfs fs.InodeOperations.Getlink.
func (i *inodeOperations) Getlink(context.Context, *fs.Inode) (*fs.Dirent, error) {
	if !fs.IsSymlink(i.fileState.sattr) {
		return nil, syserror.ENOLINK
	}
	return nil, fs.ErrResolveViaReadlink
}

// StatFS makes a StatFS request.
func (i *inodeOperations) StatFS(ctx context.Context) (fs.Info, error) {
	fsstat, err := i.fileState.file.statFS(ctx)
	if err != nil {
		return fs.Info{}, err
	}

	info := fs.Info{
		// This is primarily for distinguishing a gofer file system in
		// tests. Testing is important, so instead of defining
		// something completely random, use a standard value.
		Type:        linux.V9FS_MAGIC,
		TotalBlocks: fsstat.Blocks,
		FreeBlocks:  fsstat.BlocksFree,
		TotalFiles:  fsstat.Files,
		FreeFiles:   fsstat.FilesFree,
	}

	// If blocks available is non-zero, prefer that.
	if fsstat.BlocksAvailable != 0 {
		info.FreeBlocks = fsstat.BlocksAvailable
	}

	return info, nil
}

func (i *inodeOperations) configureMMap(file *fs.File, opts *memmap.MMapOpts) error {
	if i.session().cachePolicy.useCachingInodeOps(file.Dirent.Inode) {
		return fsutil.GenericConfigureMMap(file, i.cachingInodeOps, opts)
	}
	if i.fileState.hostMappable != nil {
		return fsutil.GenericConfigureMMap(file, i.fileState.hostMappable, opts)
	}
	return syserror.ENODEV
}

func init() {
	syserror.AddErrorUnwrapper(func(err error) (syscall.Errno, bool) {
		if _, ok := err.(p9.ErrSocket); ok {
			// Treat as an I/O error.
			return syscall.EIO, true
		}
		return 0, false
	})
}

// AddLink implements InodeOperations.AddLink, but is currently a noop.
// FIXME: Remove this from InodeOperations altogether.
func (*inodeOperations) AddLink() {}

// DropLink implements InodeOperations.DropLink, but is currently a noop.
// FIXME: Remove this from InodeOperations altogether.
func (*inodeOperations) DropLink() {}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
// FIXME: Remove this from InodeOperations altogether.
func (i *inodeOperations) NotifyStatusChange(ctx context.Context) {}
