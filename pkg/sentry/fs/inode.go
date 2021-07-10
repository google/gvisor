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

package fs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/fsmetric"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sync"
)

// Inode is a file system object that can be simultaneously referenced by different
// components of the VFS (Dirent, fs.File, etc).
//
// +stateify savable
type Inode struct {
	// AtomicRefCount is our reference count.
	refs.AtomicRefCount

	// InodeOperations is the file system specific behavior of the Inode.
	InodeOperations InodeOperations

	// StableAttr are stable cached attributes of the Inode.
	StableAttr StableAttr

	// LockCtx is the file lock context. It manages its own sychronization and tracks
	// regions of the Inode that have locks held.
	LockCtx LockCtx

	// Watches is the set of inotify watches for this inode.
	Watches *Watches

	// MountSource is the mount source this Inode is a part of.
	MountSource *MountSource

	// overlay is the overlay entry for this Inode.
	overlay *overlayEntry

	// appendMu is used to synchronize write operations into files which
	// have been opened with O_APPEND. Operations which change a file size
	// have to take this lock for read. Write operations to files with
	// O_APPEND have to take this lock for write.
	appendMu sync.RWMutex `state:"nosave"`
}

// LockCtx is an Inode's lock context and contains different personalities of locks; both
// Posix and BSD style locks are supported.
//
// Note that in Linux fcntl(2) and flock(2) locks are _not_ cooperative, because race and
// deadlock conditions make merging them prohibitive. We do the same and keep them oblivious
// to each other but provide a "context" as a convenient container.
//
// +stateify savable
type LockCtx struct {
	// Posix is a set of POSIX-style regional advisory locks, see fcntl(2).
	Posix lock.Locks

	// BSD is a set of BSD-style advisory file wide locks, see flock(2).
	BSD lock.Locks
}

// NewInode constructs an Inode from InodeOperations, a MountSource, and stable attributes.
//
// NewInode takes a reference on msrc.
func NewInode(ctx context.Context, iops InodeOperations, msrc *MountSource, sattr StableAttr) *Inode {
	msrc.IncRef()
	i := Inode{
		InodeOperations: iops,
		StableAttr:      sattr,
		Watches:         newWatches(),
		MountSource:     msrc,
	}
	i.EnableLeakCheck("fs.Inode")
	return &i
}

// DecRef drops a reference on the Inode.
func (i *Inode) DecRef(ctx context.Context) {
	i.DecRefWithDestructor(ctx, i.destroy)
}

// destroy releases the Inode and releases the msrc reference taken.
func (i *Inode) destroy(ctx context.Context) {
	if err := i.WriteOut(ctx); err != nil {
		// FIXME(b/65209558): Mark as warning again once noatime is
		// properly supported.
		log.Debugf("Inode %+v, failed to sync all metadata: %v", i.StableAttr, err)
	}

	// If this inode is being destroyed because it was unlinked, queue a
	// deletion event. This may not be the case for inodes being revalidated.
	if i.Watches.unlinked {
		i.Watches.Notify("", linux.IN_DELETE_SELF, 0)
	}

	// Remove references from the watch owners to the watches on this inode,
	// since the watches are about to be GCed. Note that we don't need to worry
	// about the watch pins since if there were any active pins, this inode
	// wouldn't be in the destructor.
	i.Watches.targetDestroyed()

	if i.overlay != nil {
		i.overlay.release(ctx)
	} else {
		i.InodeOperations.Release(ctx)
	}

	i.MountSource.DecRef(ctx)
}

// Mappable calls i.InodeOperations.Mappable.
func (i *Inode) Mappable() memmap.Mappable {
	if i.overlay != nil {
		// In an overlay, Mappable is always implemented by
		// the overlayEntry metadata to synchronize memory
		// access of files with copy up. But first check if
		// the Inodes involved would be mappable in the first
		// place.
		i.overlay.copyMu.RLock()
		ok := i.overlay.isMappableLocked()
		i.overlay.copyMu.RUnlock()
		if !ok {
			return nil
		}
		return i.overlay
	}
	return i.InodeOperations.Mappable(i)
}

// WriteOut calls i.InodeOperations.WriteOut with i as the Inode.
func (i *Inode) WriteOut(ctx context.Context) error {
	if i.overlay != nil {
		return overlayWriteOut(ctx, i.overlay)
	}
	return i.InodeOperations.WriteOut(ctx, i)
}

// Lookup calls i.InodeOperations.Lookup with i as the directory.
func (i *Inode) Lookup(ctx context.Context, name string) (*Dirent, error) {
	if i.overlay != nil {
		d, _, err := overlayLookup(ctx, i.overlay, i, name)
		return d, err
	}
	return i.InodeOperations.Lookup(ctx, i, name)
}

// Create calls i.InodeOperations.Create with i as the directory.
func (i *Inode) Create(ctx context.Context, d *Dirent, name string, flags FileFlags, perm FilePermissions) (*File, error) {
	if i.overlay != nil {
		return overlayCreate(ctx, i.overlay, d, name, flags, perm)
	}
	return i.InodeOperations.Create(ctx, i, name, flags, perm)
}

// CreateDirectory calls i.InodeOperations.CreateDirectory with i as the directory.
func (i *Inode) CreateDirectory(ctx context.Context, d *Dirent, name string, perm FilePermissions) error {
	if i.overlay != nil {
		return overlayCreateDirectory(ctx, i.overlay, d, name, perm)
	}
	return i.InodeOperations.CreateDirectory(ctx, i, name, perm)
}

// CreateLink calls i.InodeOperations.CreateLink with i as the directory.
func (i *Inode) CreateLink(ctx context.Context, d *Dirent, oldname string, newname string) error {
	if i.overlay != nil {
		return overlayCreateLink(ctx, i.overlay, d, oldname, newname)
	}
	return i.InodeOperations.CreateLink(ctx, i, oldname, newname)
}

// CreateHardLink calls i.InodeOperations.CreateHardLink with i as the directory.
func (i *Inode) CreateHardLink(ctx context.Context, d *Dirent, target *Dirent, name string) error {
	if i.overlay != nil {
		return overlayCreateHardLink(ctx, i.overlay, d, target, name)
	}
	return i.InodeOperations.CreateHardLink(ctx, i, target.Inode, name)
}

// CreateFifo calls i.InodeOperations.CreateFifo with i as the directory.
func (i *Inode) CreateFifo(ctx context.Context, d *Dirent, name string, perm FilePermissions) error {
	if i.overlay != nil {
		return overlayCreateFifo(ctx, i.overlay, d, name, perm)
	}
	return i.InodeOperations.CreateFifo(ctx, i, name, perm)
}

// Remove calls i.InodeOperations.Remove/RemoveDirectory with i as the directory.
func (i *Inode) Remove(ctx context.Context, d *Dirent, remove *Dirent) error {
	if i.overlay != nil {
		return overlayRemove(ctx, i.overlay, d, remove)
	}
	switch remove.Inode.StableAttr.Type {
	case Directory, SpecialDirectory:
		return i.InodeOperations.RemoveDirectory(ctx, i, remove.name)
	default:
		return i.InodeOperations.Remove(ctx, i, remove.name)
	}
}

// Rename calls i.InodeOperations.Rename with the given arguments.
func (i *Inode) Rename(ctx context.Context, oldParent *Dirent, renamed *Dirent, newParent *Dirent, newName string, replacement bool) error {
	if i.overlay != nil {
		return overlayRename(ctx, i.overlay, oldParent, renamed, newParent, newName, replacement)
	}
	return i.InodeOperations.Rename(ctx, renamed.Inode, oldParent.Inode, renamed.name, newParent.Inode, newName, replacement)
}

// Bind calls i.InodeOperations.Bind with i as the directory.
func (i *Inode) Bind(ctx context.Context, parent *Dirent, name string, data transport.BoundEndpoint, perm FilePermissions) (*Dirent, error) {
	if i.overlay != nil {
		return overlayBind(ctx, i.overlay, parent, name, data, perm)
	}
	return i.InodeOperations.Bind(ctx, i, name, data, perm)
}

// BoundEndpoint calls i.InodeOperations.BoundEndpoint with i as the Inode.
func (i *Inode) BoundEndpoint(path string) transport.BoundEndpoint {
	if i.overlay != nil {
		return overlayBoundEndpoint(i.overlay, path)
	}
	return i.InodeOperations.BoundEndpoint(i, path)
}

// GetFile calls i.InodeOperations.GetFile with the given arguments.
func (i *Inode) GetFile(ctx context.Context, d *Dirent, flags FileFlags) (*File, error) {
	if i.overlay != nil {
		return overlayGetFile(ctx, i.overlay, d, flags)
	}
	fsmetric.Opens.Increment()
	return i.InodeOperations.GetFile(ctx, d, flags)
}

// UnstableAttr calls i.InodeOperations.UnstableAttr with i as the Inode.
func (i *Inode) UnstableAttr(ctx context.Context) (UnstableAttr, error) {
	if i.overlay != nil {
		return overlayUnstableAttr(ctx, i.overlay)
	}
	return i.InodeOperations.UnstableAttr(ctx, i)
}

// GetXattr calls i.InodeOperations.GetXattr with i as the Inode.
func (i *Inode) GetXattr(ctx context.Context, name string, size uint64) (string, error) {
	if i.overlay != nil {
		return overlayGetXattr(ctx, i.overlay, name, size)
	}
	return i.InodeOperations.GetXattr(ctx, i, name, size)
}

// SetXattr calls i.InodeOperations.SetXattr with i as the Inode.
func (i *Inode) SetXattr(ctx context.Context, d *Dirent, name, value string, flags uint32) error {
	if i.overlay != nil {
		return overlaySetXattr(ctx, i.overlay, d, name, value, flags)
	}
	return i.InodeOperations.SetXattr(ctx, i, name, value, flags)
}

// ListXattr calls i.InodeOperations.ListXattr with i as the Inode.
func (i *Inode) ListXattr(ctx context.Context, size uint64) (map[string]struct{}, error) {
	if i.overlay != nil {
		return overlayListXattr(ctx, i.overlay, size)
	}
	return i.InodeOperations.ListXattr(ctx, i, size)
}

// RemoveXattr calls i.InodeOperations.RemoveXattr with i as the Inode.
func (i *Inode) RemoveXattr(ctx context.Context, d *Dirent, name string) error {
	if i.overlay != nil {
		return overlayRemoveXattr(ctx, i.overlay, d, name)
	}
	return i.InodeOperations.RemoveXattr(ctx, i, name)
}

// CheckPermission will check if the caller may access this file in the
// requested way for reading, writing, or executing.
//
// CheckPermission is like Linux's fs/namei.c:inode_permission. It
// - checks file system mount flags,
// - and utilizes InodeOperations.Check to check capabilities and modes.
func (i *Inode) CheckPermission(ctx context.Context, p PermMask) error {
	// First check the outer-most mounted filesystem.
	if p.Write && i.MountSource.Flags.ReadOnly {
		return linuxerr.EROFS
	}

	if i.overlay != nil {
		// CheckPermission requires some special handling for
		// an overlay.
		//
		// Writes will always be redirected to an upper filesystem,
		// so ignore all lower layers being read-only.
		//
		// But still honor the upper-most filesystem's mount flags;
		// we should not attempt to modify the writable layer if it
		// is mounted read-only.
		if p.Write && overlayUpperMountSource(i.MountSource).Flags.ReadOnly {
			return linuxerr.EROFS
		}
	}

	return i.check(ctx, p)
}

func (i *Inode) check(ctx context.Context, p PermMask) error {
	if i.overlay != nil {
		return overlayCheck(ctx, i.overlay, p)
	}
	if !i.InodeOperations.Check(ctx, i, p) {
		return linuxerr.EACCES
	}
	return nil
}

// SetPermissions calls i.InodeOperations.SetPermissions with i as the Inode.
func (i *Inode) SetPermissions(ctx context.Context, d *Dirent, f FilePermissions) bool {
	if i.overlay != nil {
		return overlaySetPermissions(ctx, i.overlay, d, f)
	}
	return i.InodeOperations.SetPermissions(ctx, i, f)
}

// SetOwner calls i.InodeOperations.SetOwner with i as the Inode.
func (i *Inode) SetOwner(ctx context.Context, d *Dirent, o FileOwner) error {
	if i.overlay != nil {
		return overlaySetOwner(ctx, i.overlay, d, o)
	}
	return i.InodeOperations.SetOwner(ctx, i, o)
}

// SetTimestamps calls i.InodeOperations.SetTimestamps with i as the Inode.
func (i *Inode) SetTimestamps(ctx context.Context, d *Dirent, ts TimeSpec) error {
	if i.overlay != nil {
		return overlaySetTimestamps(ctx, i.overlay, d, ts)
	}
	return i.InodeOperations.SetTimestamps(ctx, i, ts)
}

// Truncate calls i.InodeOperations.Truncate with i as the Inode.
func (i *Inode) Truncate(ctx context.Context, d *Dirent, size int64) error {
	if IsDir(i.StableAttr) {
		return linuxerr.EISDIR
	}

	if i.overlay != nil {
		return overlayTruncate(ctx, i.overlay, d, size)
	}
	i.appendMu.RLock()
	defer i.appendMu.RUnlock()
	return i.InodeOperations.Truncate(ctx, i, size)
}

// Allocate calls i.InodeOperations.Allocate with i as the Inode.
func (i *Inode) Allocate(ctx context.Context, d *Dirent, offset int64, length int64) error {
	if i.overlay != nil {
		return overlayAllocate(ctx, i.overlay, d, offset, length)
	}
	return i.InodeOperations.Allocate(ctx, i, offset, length)
}

// Readlink calls i.InodeOperations.Readlnk with i as the Inode.
func (i *Inode) Readlink(ctx context.Context) (string, error) {
	if i.overlay != nil {
		return overlayReadlink(ctx, i.overlay)
	}
	return i.InodeOperations.Readlink(ctx, i)
}

// Getlink calls i.InodeOperations.Getlink.
func (i *Inode) Getlink(ctx context.Context) (*Dirent, error) {
	if i.overlay != nil {
		return overlayGetlink(ctx, i.overlay)
	}
	return i.InodeOperations.Getlink(ctx, i)
}

// AddLink calls i.InodeOperations.AddLink.
func (i *Inode) AddLink() {
	if i.overlay != nil {
		// This interface is only used by ramfs to update metadata of
		// children. These filesystems should _never_ have overlay
		// Inodes cached as children. So explicitly disallow this
		// scenario and avoid plumbing Dirents through to do copy up.
		panic("overlay Inodes cached in ramfs directories are not supported")
	}
	i.InodeOperations.AddLink()
}

// DropLink calls i.InodeOperations.DropLink.
func (i *Inode) DropLink() {
	if i.overlay != nil {
		// Same as AddLink.
		panic("overlay Inodes cached in ramfs directories are not supported")
	}
	i.InodeOperations.DropLink()
}

// IsVirtual calls i.InodeOperations.IsVirtual.
func (i *Inode) IsVirtual() bool {
	if i.overlay != nil {
		// An overlay configuration does not support virtual files.
		return false
	}
	return i.InodeOperations.IsVirtual()
}

// StatFS calls i.InodeOperations.StatFS.
func (i *Inode) StatFS(ctx context.Context) (Info, error) {
	if i.overlay != nil {
		return overlayStatFS(ctx, i.overlay)
	}
	return i.InodeOperations.StatFS(ctx)
}

// CheckOwnership checks whether `ctx` owns this Inode or may act as its owner.
// Compare Linux's fs/inode.c:inode_owner_or_capable().
func (i *Inode) CheckOwnership(ctx context.Context) bool {
	uattr, err := i.UnstableAttr(ctx)
	if err != nil {
		return false
	}
	creds := auth.CredentialsFromContext(ctx)
	if uattr.Owner.UID == creds.EffectiveKUID {
		return true
	}
	if creds.HasCapability(linux.CAP_FOWNER) && creds.UserNamespace.MapFromKUID(uattr.Owner.UID).Ok() {
		return true
	}
	return false
}

// CheckCapability checks whether `ctx` has capability `cp` with respect to
// operations on this Inode.
//
// Compare Linux's kernel/capability.c:capable_wrt_inode_uidgid().
func (i *Inode) CheckCapability(ctx context.Context, cp linux.Capability) bool {
	uattr, err := i.UnstableAttr(ctx)
	if err != nil {
		return false
	}
	creds := auth.CredentialsFromContext(ctx)
	if !creds.UserNamespace.MapFromKUID(uattr.Owner.UID).Ok() {
		return false
	}
	if !creds.UserNamespace.MapFromKGID(uattr.Owner.GID).Ok() {
		return false
	}
	return creds.HasCapability(cp)
}

func (i *Inode) lockAppendMu(appendMode bool) func() {
	if appendMode {
		i.appendMu.Lock()
		return i.appendMu.Unlock
	}
	i.appendMu.RLock()
	return i.appendMu.RUnlock
}
