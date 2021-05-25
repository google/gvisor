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

package gofer

import (
	"errors"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fdpipe"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/host"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// inodeOperations implements fs.InodeOperations.
//
// +stateify savable
type inodeOperations struct {
	fsutil.InodeNotVirtual `state:"nosave"`

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

	// If readHandles is non-nil, it holds handles that are either read-only or
	// read/write. If writeHandles is non-nil, it holds write-only handles if
	// writeHandlesRW is false, and read/write handles if writeHandlesRW is
	// true.
	//
	// Once readHandles becomes non-nil, it can't be changed until
	// inodeFileState.Release()*, because of a defect in the
	// fsutil.CachedFileObject interface: there's no way for the caller of
	// fsutil.CachedFileObject.FD() to keep the returned FD open, so if we
	// racily replace readHandles after inodeFileState.FD() has returned
	// readHandles.Host.FD(), fsutil.CachingInodeOperations may use a closed
	// FD. writeHandles can be changed if writeHandlesRW is false, since
	// inodeFileState.FD() can't return a write-only FD, but can't be changed
	// if writeHandlesRW is true for the same reason.
	//
	// * There is one notable exception in recreateReadHandles(), where it dup's
	// the FD and invalidates the page cache.
	readHandles    *handles `state:"nosave"`
	writeHandles   *handles `state:"nosave"`
	writeHandlesRW bool     `state:"nosave"`

	// loading is acquired when the inodeFileState begins an asynchronous
	// load. It releases when the load is complete. Callers that require all
	// state to be available should call waitForLoad() to ensure that.
	loading sync.CrossGoroutineMutex `state:".(struct{})"`

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
	if i.readHandles != nil {
		i.readHandles.DecRef()
	}
	if i.writeHandles != nil {
		i.writeHandles.DecRef()
	}
}

func (i *inodeFileState) canShareHandles() bool {
	// Only share handles for regular files, since for other file types,
	// distinct handles may have special semantics even if they represent the
	// same file. Disable handle sharing for cache policy cacheNone, since this
	// is legacy behavior.
	return fs.IsFile(i.sattr) && i.s.cachePolicy != cacheNone
}

// Preconditions: i.handlesMu must be locked for writing.
func (i *inodeFileState) setSharedHandlesLocked(flags fs.FileFlags, h *handles) {
	if flags.Read && i.readHandles == nil {
		h.IncRef()
		i.readHandles = h
	}
	if flags.Write {
		if i.writeHandles == nil {
			h.IncRef()
			i.writeHandles = h
			i.writeHandlesRW = flags.Read
		} else if !i.writeHandlesRW && flags.Read {
			// Upgrade i.writeHandles.
			i.writeHandles.DecRef()
			h.IncRef()
			i.writeHandles = h
			i.writeHandlesRW = flags.Read
		}
	}
}

// getHandles returns a set of handles for a new file using i opened with the
// given flags.
func (i *inodeFileState) getHandles(ctx context.Context, flags fs.FileFlags, cache *fsutil.CachingInodeOperations) (*handles, error) {
	if !i.canShareHandles() {
		return newHandles(ctx, i.s.client, i.file, flags)
	}

	i.handlesMu.Lock()
	h, invalidate, err := i.getHandlesLocked(ctx, flags)
	i.handlesMu.Unlock()

	if invalidate {
		cache.NotifyChangeFD()
		if i.hostMappable != nil {
			i.hostMappable.NotifyChangeFD()
		}
	}

	return h, err
}

// getHandlesLocked returns a pointer to cached handles and a boolean indicating
// whether previously open read handle was recreated. Host mappings must be
// invalidated if so.
func (i *inodeFileState) getHandlesLocked(ctx context.Context, flags fs.FileFlags) (*handles, bool, error) {
	// Check if we are able to use cached handles.
	if flags.Truncate && p9.VersionSupportsOpenTruncateFlag(i.s.client.Version()) {
		// If we are truncating (and the gofer supports it), then we
		// always need a new handle. Don't return one from the cache.
	} else if flags.Write {
		if i.writeHandles != nil && (i.writeHandlesRW || !flags.Read) {
			// File is opened for writing, and we have cached write
			// handles that we can use.
			i.writeHandles.IncRef()
			return i.writeHandles, false, nil
		}
	} else if i.readHandles != nil {
		// File is opened for reading and we have cached handles.
		i.readHandles.IncRef()
		return i.readHandles, false, nil
	}

	// Get new handles and cache them for future sharing.
	h, err := newHandles(ctx, i.s.client, i.file, flags)
	if err != nil {
		return nil, false, err
	}

	// Read handles invalidation is needed if:
	//   - Mount option 'overlayfs_stale_read' is set
	//   - Read handle is open: nothing to invalidate otherwise
	//   - Write handle is not open: file was not open for write and is being open
	//     for write now (will trigger copy up in overlayfs).
	invalidate := false
	if i.s.overlayfsStaleRead && i.readHandles != nil && i.writeHandles == nil && flags.Write {
		if err := i.recreateReadHandles(ctx, h, flags); err != nil {
			return nil, false, err
		}
		invalidate = true
	}
	i.setSharedHandlesLocked(flags, h)
	return h, invalidate, nil
}

func (i *inodeFileState) recreateReadHandles(ctx context.Context, writer *handles, flags fs.FileFlags) error {
	h := writer
	if !flags.Read {
		// Writer can't be used for read, must create a new handle.
		var err error
		h, err = newHandles(ctx, i.s.client, i.file, fs.FileFlags{Read: true})
		if err != nil {
			return err
		}
		defer h.DecRef()
	}

	if i.readHandles.Host == nil {
		// If current readHandles doesn't have a host FD, it can simply be replaced.
		i.readHandles.DecRef()

		h.IncRef()
		i.readHandles = h
		return nil
	}

	if h.Host == nil {
		// Current read handle has a host FD and can't be replaced with one that
		// doesn't, because it breaks fsutil.CachedFileObject.FD() contract.
		log.Warningf("Read handle can't be invalidated, reads may return stale data")
		return nil
	}

	// Due to a defect in the fsutil.CachedFileObject interface,
	// readHandles.Host.FD() may be used outside locks, making it impossible to
	// reliably close it. To workaround it, we dup the new FD into the old one, so
	// operations on the old will see the new data. Then, make the new handle take
	// ownereship of the old FD and mark the old readHandle to not close the FD
	// when done.
	if err := unix.Dup3(h.Host.FD(), i.readHandles.Host.FD(), unix.O_CLOEXEC); err != nil {
		return err
	}

	h.Host.Close()
	h.Host = fd.New(i.readHandles.Host.FD())
	i.readHandles.isHostBorrowed = true
	i.readHandles.DecRef()

	h.IncRef()
	i.readHandles = h
	return nil
}

// ReadToBlocksAt implements fsutil.CachedFileObject.ReadToBlocksAt.
func (i *inodeFileState) ReadToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error) {
	i.handlesMu.RLock()
	n, err := i.readHandles.readWriterAt(ctx, int64(offset)).ReadToBlocks(dsts)
	i.handlesMu.RUnlock()
	return n, err
}

// WriteFromBlocksAt implements fsutil.CachedFileObject.WriteFromBlocksAt.
func (i *inodeFileState) WriteFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error) {
	i.handlesMu.RLock()
	n, err := i.writeHandles.readWriterAt(ctx, int64(offset)).WriteFromBlocks(srcs)
	i.handlesMu.RUnlock()
	return n, err
}

// SetMaskedAttributes implements fsutil.CachedFileObject.SetMaskedAttributes.
func (i *inodeFileState) SetMaskedAttributes(ctx context.Context, mask fs.AttrMask, attr fs.UnstableAttr, forceSetTimestamps bool) error {
	if i.skipSetAttr(mask, forceSetTimestamps) {
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
//   - forceSetTimestamps is false and mask contains only atime and/or mtime
//     and host FD exists
//
// Updates to atime and mtime can be skipped because cached value will be
// "close enough" to host value, given that operation went directly to host FD.
// Skipping atime updates is particularly important to reduce the number of
// operations sent to the Gofer for readonly files.
func (i *inodeFileState) skipSetAttr(mask fs.AttrMask, forceSetTimestamps bool) bool {
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

	// If forceSetTimestamps was passed, then we cannot skip.
	if forceSetTimestamps {
		return false
	}

	// Skip if we have a host FD.
	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()
	return (i.readHandles != nil && i.readHandles.Host != nil) ||
		(i.writeHandles != nil && i.writeHandles.Host != nil)
}

// Sync implements fsutil.CachedFileObject.Sync.
func (i *inodeFileState) Sync(ctx context.Context) error {
	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()
	if i.writeHandles == nil {
		return nil
	}
	return i.writeHandles.File.fsync(ctx)
}

// FD implements fsutil.CachedFileObject.FD.
func (i *inodeFileState) FD() int {
	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()
	if i.writeHandlesRW && i.writeHandles != nil && i.writeHandles.Host != nil {
		return int(i.writeHandles.Host.FD())
	}
	if i.readHandles != nil && i.readHandles.Host != nil {
		return int(i.readHandles.Host.FD())
	}
	return -1
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

func (i *inodeFileState) Allocate(ctx context.Context, offset, length int64) error {
	i.handlesMu.RLock()
	defer i.handlesMu.RUnlock()

	// No options are supported for now.
	mode := p9.AllocateMode{}
	return i.writeHandles.File.allocate(ctx, mode, uint64(offset), uint64(length))
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
	//
	// We use AsyncWithContext to avoid needing to allocate an extra
	// anonymous function on the heap. We must use background context
	// because the async work cannot happen on the task context.
	fs.AsyncWithContext(context.Background(), i.fileState.Release)
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
		if i.session().overrides != nil {
			return nil, syserror.ENXIO
		}
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
		return nil, unix.EIO
	}
	fsf, err := host.NewSocketWithDirent(ctx, d, f, flags)
	if err != nil {
		f.Close()
		return nil, err
	}
	return fsf, nil
}

func (i *inodeOperations) getFilePipe(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	// Try to open as a host pipe; if that doesn't work, handle it normally.
	pipeOps, err := fdpipe.Open(ctx, i, flags)
	if err == errNotHostFile {
		return i.getFileDefault(ctx, d, flags)
	}
	if err != nil {
		return nil, err
	}
	return fs.NewFile(ctx, d, flags, pipeOps), nil
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
	h, err := i.fileState.getHandles(ctx, flags, i.cachingInodeOps)
	if err != nil {
		return nil, err
	}
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

	uattr, err := i.fileState.unstableAttr(ctx)
	if err != nil {
		return err
	}

	if i.session().cachePolicy == cacheRemoteRevalidating {
		return i.fileState.hostMappable.Truncate(ctx, length, uattr)
	}

	mask := p9.SetAttrMask{Size: true}
	attr := p9.SetAttr{Size: uint64(length)}
	if uattr.Perms.HasSetUIDOrGID() {
		mask.Permissions = true
		uattr.Perms.DropSetUIDAndMaybeGID()
		attr.Permissions = p9.FileMode(uattr.Perms.LinuxMode())
	}

	return i.fileState.file.setAttr(ctx, mask, attr)
}

// GetXattr implements fs.InodeOperations.GetXattr.
func (i *inodeOperations) GetXattr(ctx context.Context, _ *fs.Inode, name string, size uint64) (string, error) {
	return i.fileState.file.getXattr(ctx, name, size)
}

// SetXattr implements fs.InodeOperations.SetXattr.
func (i *inodeOperations) SetXattr(ctx context.Context, _ *fs.Inode, name string, value string, flags uint32) error {
	return i.fileState.file.setXattr(ctx, name, value, flags)
}

// ListXattr implements fs.InodeOperations.ListXattr.
func (i *inodeOperations) ListXattr(ctx context.Context, _ *fs.Inode, size uint64) (map[string]struct{}, error) {
	return i.fileState.file.listXattr(ctx, size)
}

// RemoveXattr implements fs.InodeOperations.RemoveXattr.
func (i *inodeOperations) RemoveXattr(ctx context.Context, _ *fs.Inode, name string) error {
	return i.fileState.file.removeXattr(ctx, name)
}

// Allocate implements fs.InodeOperations.Allocate.
func (i *inodeOperations) Allocate(ctx context.Context, inode *fs.Inode, offset, length int64) error {
	// This can only be called for files anyway.
	if i.session().cachePolicy.useCachingInodeOps(inode) {
		return i.cachingInodeOps.Allocate(ctx, offset, length)
	}
	if i.session().cachePolicy == cacheRemoteRevalidating {
		return i.fileState.hostMappable.Allocate(ctx, offset, length)
	}

	// No options are supported for now.
	mode := p9.AllocateMode{}
	return i.fileState.file.allocate(ctx, mode, uint64(offset), uint64(length))
}

// WriteOut implements fs.InodeOperations.WriteOut.
func (i *inodeOperations) WriteOut(ctx context.Context, inode *fs.Inode) error {
	if inode.MountSource.Flags.ReadOnly || !i.session().cachePolicy.cacheUAttrs(inode) {
		return nil
	}

	return i.cachingInodeOps.WriteOut(ctx, inode)
}

// Readlink implements fs.InodeOperations.Readlink.
func (i *inodeOperations) Readlink(ctx context.Context, inode *fs.Inode) (string, error) {
	if !fs.IsSymlink(inode.StableAttr) {
		return "", unix.ENOLINK
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
	syserror.AddErrorUnwrapper(func(err error) (unix.Errno, bool) {
		if _, ok := err.(p9.ErrSocket); ok {
			// Treat as an I/O error.
			return unix.EIO, true
		}
		return 0, false
	})
}

// AddLink implements InodeOperations.AddLink, but is currently a noop.
func (*inodeOperations) AddLink() {}

// DropLink implements InodeOperations.DropLink, but is currently a noop.
func (*inodeOperations) DropLink() {}

// NotifyStatusChange implements fs.InodeOperations.NotifyStatusChange.
func (i *inodeOperations) NotifyStatusChange(ctx context.Context) {}
