// Copyright 2018 Google Inc.
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

// Package ramfs implements an in-memory file system that can be associated with
// any device.
package ramfs

import (
	"errors"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

var (
	// ErrInvalidOp indicates the operation is not valid.
	ErrInvalidOp = errors.New("invalid operation")

	// ErrDenied indicates the operation was denied.
	ErrDenied = errors.New("operation denied")

	// ErrNotFound indicates that a node was not found on a walk.
	ErrNotFound = errors.New("node not found")

	// ErrCrossDevice indicates a cross-device link or rename.
	ErrCrossDevice = errors.New("can't link across filesystems")

	// ErrIsDirectory indicates that the operation failed because
	// the node is a directory.
	ErrIsDirectory = errors.New("is a directory")

	// ErrNotDirectory indicates that the operation failed because
	// the node is a not directory.
	ErrNotDirectory = errors.New("not a directory")

	// ErrNotEmpty indicates that the operation failed because the
	// directory is not empty.
	ErrNotEmpty = errors.New("directory not empty")
)

// Entry represents common internal state for file and directory nodes.
// This may be used by other packages to easily create ramfs files.
type Entry struct {
	waiter.AlwaysReady    `state:"nosave"`
	fsutil.NoMappable     `state:"nosave"`
	fsutil.NoopWriteOut   `state:"nosave"`
	fsutil.InodeNotSocket `state:"nosave"`

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// unstable is unstable attributes.
	unstable fs.UnstableAttr

	// xattrs are the extended attributes of the Entry.
	xattrs map[string][]byte
}

// InitEntry initializes an entry.
func (e *Entry) InitEntry(ctx context.Context, owner fs.FileOwner, p fs.FilePermissions) {
	e.InitEntryWithAttr(ctx, fs.WithCurrentTime(ctx, fs.UnstableAttr{
		Owner: owner,
		Perms: p,
		// Always start unlinked.
		Links: 0,
	}))
}

// InitEntryWithAttr initializes an entry with a complete set of attributes.
func (e *Entry) InitEntryWithAttr(ctx context.Context, uattr fs.UnstableAttr) {
	e.unstable = uattr
	e.xattrs = make(map[string][]byte)
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (e *Entry) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	e.mu.Lock()
	attr := e.unstable
	e.mu.Unlock()
	return attr, nil
}

// Check implements fs.InodeOperations.Check.
func (*Entry) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// Getxattr implements fs.InodeOperations.Getxattr.
func (e *Entry) Getxattr(inode *fs.Inode, name string) ([]byte, error) {
	// Hot path. Avoid defers.
	e.mu.Lock()
	value, ok := e.xattrs[name]
	e.mu.Unlock()
	if ok {
		return value, nil
	}
	return nil, syserror.ENOATTR
}

// Setxattr implements fs.InodeOperations.Setxattr.
func (e *Entry) Setxattr(inode *fs.Inode, name string, value []byte) error {
	e.mu.Lock()
	e.xattrs[name] = value
	e.mu.Unlock()
	return nil
}

// Listxattr implements fs.InodeOperations.Listxattr.
func (e *Entry) Listxattr(inode *fs.Inode) (map[string]struct{}, error) {
	e.mu.Lock()
	names := make(map[string]struct{}, len(e.xattrs))
	for name := range e.xattrs {
		names[name] = struct{}{}
	}
	e.mu.Unlock()
	return names, nil
}

// GetFile returns a fs.File backed by the dirent argument and flags.
func (*Entry) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fsutil.NewHandle(ctx, d, flags, d.Inode.HandleOps()), nil
}

// SetPermissions always sets the permissions.
func (e *Entry) SetPermissions(ctx context.Context, inode *fs.Inode, p fs.FilePermissions) bool {
	e.mu.Lock()
	e.unstable.Perms = p
	e.unstable.StatusChangeTime = ktime.NowFromContext(ctx)
	e.mu.Unlock()
	return true
}

// SetOwner always sets ownership.
func (e *Entry) SetOwner(ctx context.Context, inode *fs.Inode, owner fs.FileOwner) error {
	e.mu.Lock()
	if owner.UID.Ok() {
		e.unstable.Owner.UID = owner.UID
	}
	if owner.GID.Ok() {
		e.unstable.Owner.GID = owner.GID
	}
	e.mu.Unlock()
	return nil
}

// SetTimestamps sets the timestamps.
func (e *Entry) SetTimestamps(ctx context.Context, inode *fs.Inode, ts fs.TimeSpec) error {
	if ts.ATimeOmit && ts.MTimeOmit {
		return nil
	}

	e.mu.Lock()
	now := ktime.NowFromContext(ctx)
	if !ts.ATimeOmit {
		if ts.ATimeSetSystemTime {
			e.unstable.AccessTime = now
		} else {
			e.unstable.AccessTime = ts.ATime
		}
	}
	if !ts.MTimeOmit {
		if ts.MTimeSetSystemTime {
			e.unstable.ModificationTime = now
		} else {
			e.unstable.ModificationTime = ts.MTime
		}
	}
	e.unstable.StatusChangeTime = now
	e.mu.Unlock()
	return nil
}

// NotifyStatusChange updates the status change time (ctime).
func (e *Entry) NotifyStatusChange(ctx context.Context) {
	e.mu.Lock()
	e.unstable.StatusChangeTime = ktime.NowFromContext(ctx)
	e.mu.Unlock()
}

// StatusChangeTime returns the last status change time for this node.
func (e *Entry) StatusChangeTime() ktime.Time {
	e.mu.Lock()
	t := e.unstable.StatusChangeTime
	e.mu.Unlock()
	return t
}

// NotifyModification updates the modification time and the status change time.
func (e *Entry) NotifyModification(ctx context.Context) {
	e.mu.Lock()
	now := ktime.NowFromContext(ctx)
	e.unstable.ModificationTime = now
	e.unstable.StatusChangeTime = now
	e.mu.Unlock()
}

// ModificationTime returns the last modification time for this node.
func (e *Entry) ModificationTime() ktime.Time {
	e.mu.Lock()
	t := e.unstable.ModificationTime
	e.mu.Unlock()
	return t
}

// NotifyAccess updates the access time.
func (e *Entry) NotifyAccess(ctx context.Context) {
	e.mu.Lock()
	now := ktime.NowFromContext(ctx)
	e.unstable.AccessTime = now
	e.mu.Unlock()
}

// AccessTime returns the last access time for this node.
func (e *Entry) AccessTime() ktime.Time {
	e.mu.Lock()
	t := e.unstable.AccessTime
	e.mu.Unlock()
	return t
}

// Permissions returns permissions on this entry.
func (e *Entry) Permissions() fs.FilePermissions {
	e.mu.Lock()
	p := e.unstable.Perms
	e.mu.Unlock()
	return p
}

// Lookup is not supported by default.
func (*Entry) Lookup(context.Context, *fs.Inode, string) (*fs.Dirent, error) {
	return nil, ErrInvalidOp
}

// Create is not supported by default.
func (*Entry) Create(context.Context, *fs.Inode, string, fs.FileFlags, fs.FilePermissions) (*fs.File, error) {
	return nil, ErrInvalidOp
}

// CreateLink is not supported by default.
func (*Entry) CreateLink(context.Context, *fs.Inode, string, string) error {
	return ErrInvalidOp
}

// CreateHardLink is not supported by default.
func (*Entry) CreateHardLink(context.Context, *fs.Inode, *fs.Inode, string) error {
	return ErrInvalidOp
}

// IsVirtual returns true.
func (*Entry) IsVirtual() bool {
	return true
}

// CreateDirectory is not supported by default.
func (*Entry) CreateDirectory(context.Context, *fs.Inode, string, fs.FilePermissions) error {
	return ErrInvalidOp
}

// Bind is not supported by default.
func (*Entry) Bind(context.Context, *fs.Inode, string, unix.BoundEndpoint, fs.FilePermissions) error {
	return ErrInvalidOp
}

// CreateFifo implements fs.InodeOperations.CreateFifo. CreateFifo is not supported by
// default.
func (*Entry) CreateFifo(context.Context, *fs.Inode, string, fs.FilePermissions) error {
	return ErrInvalidOp
}

// Remove is not supported by default.
func (*Entry) Remove(context.Context, *fs.Inode, string) error {
	return ErrInvalidOp
}

// RemoveDirectory is not supported by default.
func (*Entry) RemoveDirectory(context.Context, *fs.Inode, string) error {
	return ErrInvalidOp
}

// StatFS always returns ENOSYS.
func (*Entry) StatFS(context.Context) (fs.Info, error) {
	return fs.Info{}, syscall.ENOSYS
}

// Rename implements fs.InodeOperations.Rename.
func (e *Entry) Rename(ctx context.Context, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string) error {
	return Rename(ctx, oldParent.InodeOperations, oldName, newParent.InodeOperations, newName)
}

// Rename renames from a *ramfs.Dir to another *ramfs.Dir.
func Rename(ctx context.Context, oldParent fs.InodeOperations, oldName string, newParent fs.InodeOperations, newName string) error {
	op, ok := oldParent.(*Dir)
	if !ok {
		return ErrCrossDevice
	}
	np, ok := newParent.(*Dir)
	if !ok {
		return ErrCrossDevice
	}

	np.mu.Lock()
	defer np.mu.Unlock()

	// Check whether the ramfs entry to be replaced is a non-empty directory.
	if replaced, ok := np.children[newName]; ok {
		if fs.IsDir(replaced.StableAttr) {
			// FIXME: simplify by pinning children of ramfs-backed directories
			// in the Dirent tree: this allows us to generalize ramfs operations without
			// relying on an implementation of Readdir (which may do anything, like require
			// that the file be open ... which would be reasonable).
			dirCtx := &fs.DirCtx{}
			_, err := replaced.HandleOps().DeprecatedReaddir(ctx, dirCtx, 0)
			if err != nil {
				return err
			}
			attrs := dirCtx.DentAttrs()

			// ramfs-backed directories should not contain "." and "..", but we do this
			// just in case.
			delete(attrs, ".")
			delete(attrs, "..")

			// If the directory to be replaced is not empty, reject the rename.
			if len(attrs) != 0 {
				return ErrNotEmpty
			}
		}
	}

	// Be careful, we may have already grabbed this mutex above.
	if op != np {
		op.mu.Lock()
		defer op.mu.Unlock()
	}

	// Do the swap.
	n := op.children[oldName]
	op.removeChildLocked(ctx, oldName)
	np.addChildLocked(newName, n)

	// Update ctime.
	n.NotifyStatusChange(ctx)

	return nil
}

// Truncate is not supported by default.
func (*Entry) Truncate(context.Context, *fs.Inode, int64) error {
	return ErrInvalidOp
}

// Readlink always returns ENOLINK.
func (*Entry) Readlink(context.Context, *fs.Inode) (string, error) {
	return "", syscall.ENOLINK
}

// Getlink always returns ENOLINK.
func (*Entry) Getlink(context.Context, *fs.Inode) (*fs.Dirent, error) {
	return nil, syscall.ENOLINK
}

// Release is a no-op.
func (e *Entry) Release(context.Context) {}

// AddLink implements InodeOperationss.AddLink.
func (e *Entry) AddLink() {
	e.mu.Lock()
	e.unstable.Links++
	e.mu.Unlock()
}

// DropLink implements InodeOperationss.DropLink.
func (e *Entry) DropLink() {
	e.mu.Lock()
	e.unstable.Links--
	e.mu.Unlock()
}

// DeprecatedReaddir is not supported by default.
func (*Entry) DeprecatedReaddir(context.Context, *fs.DirCtx, int) (int, error) {
	return 0, ErrNotDirectory
}

// DeprecatedPreadv always returns ErrInvalidOp.
func (*Entry) DeprecatedPreadv(context.Context, usermem.IOSequence, int64) (int64, error) {
	return 0, ErrInvalidOp
}

// DeprecatedPwritev always returns ErrInvalidOp.
func (*Entry) DeprecatedPwritev(context.Context, usermem.IOSequence, int64) (int64, error) {
	return 0, ErrInvalidOp
}

// DeprecatedFsync is a noop.
func (*Entry) DeprecatedFsync() error {
	// Ignore, this is in memory.
	return nil
}

// DeprecatedFlush always returns nil.
func (*Entry) DeprecatedFlush() error {
	return nil
}

// DeprecatedMappable implements fs.InodeOperations.DeprecatedMappable.
func (*Entry) DeprecatedMappable(context.Context, *fs.Inode) (memmap.Mappable, bool) {
	return nil, false
}

func init() {
	// Register ramfs errors.
	syserror.AddErrorTranslation(ErrInvalidOp, syscall.EINVAL)
	syserror.AddErrorTranslation(ErrDenied, syscall.EACCES)
	syserror.AddErrorTranslation(ErrNotFound, syscall.ENOENT)
	syserror.AddErrorTranslation(ErrCrossDevice, syscall.EXDEV)
	syserror.AddErrorTranslation(ErrIsDirectory, syscall.EISDIR)
	syserror.AddErrorTranslation(ErrNotDirectory, syscall.ENOTDIR)
	syserror.AddErrorTranslation(ErrNotEmpty, syscall.ENOTEMPTY)
}
