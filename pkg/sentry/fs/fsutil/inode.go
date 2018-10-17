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

package fsutil

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// NewSimpleInodeOperations constructs fs.InodeOperations from InodeSimpleAttributes.
func NewSimpleInodeOperations(i InodeSimpleAttributes) fs.InodeOperations {
	return &simpleInodeOperations{InodeSimpleAttributes: i}
}

// simpleInodeOperations is a simple implementation of Inode.
//
// +stateify savable
type simpleInodeOperations struct {
	DeprecatedFileOperations  `state:"nosave"`
	InodeNotDirectory         `state:"nosave"`
	InodeNotSocket            `state:"nosave"`
	InodeNotRenameable        `state:"nosave"`
	InodeNotOpenable          `state:"nosave"`
	InodeNotVirtual           `state:"nosave"`
	InodeNotSymlink           `state:"nosave"`
	InodeNoExtendedAttributes `state:"nosave"`
	NoMappable                `state:"nosave"`
	NoopWriteOut              `state:"nosave"`

	InodeSimpleAttributes
}

// InodeSimpleAttributes implements a subset of the Inode interface. It provides
// read-only access to attributes.
//
// +stateify savable
type InodeSimpleAttributes struct {
	// FSType is the filesystem type reported by StatFS.
	FSType uint64

	// UAttr are the unstable attributes of the Inode.
	UAttr fs.UnstableAttr
}

// Release implements fs.InodeOperations.Release.
func (i *InodeSimpleAttributes) Release(context.Context) {}

// StatFS implements fs.InodeOperations.StatFS.
func (i *InodeSimpleAttributes) StatFS(context.Context) (fs.Info, error) {
	return fs.Info{Type: i.FSType}, nil
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (i *InodeSimpleAttributes) UnstableAttr(context.Context, *fs.Inode) (fs.UnstableAttr, error) {
	return i.UAttr, nil
}

// Check implements fs.InodeOperations.Check.
func (i *InodeSimpleAttributes) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// AddLink implements fs.InodeOperations.AddLink.
func (*InodeSimpleAttributes) AddLink() {}

// DropLink implements fs.InodeOperations.DropLink.
func (*InodeSimpleAttributes) DropLink() {}

// NotifyStatusChange implements fs.fs.InodeOperations.
func (i *InodeSimpleAttributes) NotifyStatusChange(ctx context.Context) {
	i.UAttr.StatusChangeTime = ktime.NowFromContext(ctx)
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (*InodeSimpleAttributes) SetPermissions(context.Context, *fs.Inode, fs.FilePermissions) bool {
	return false
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (*InodeSimpleAttributes) SetOwner(context.Context, *fs.Inode, fs.FileOwner) error {
	return syserror.EINVAL
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (*InodeSimpleAttributes) SetTimestamps(context.Context, *fs.Inode, fs.TimeSpec) error {
	return syserror.EINVAL
}

// Truncate implements fs.InodeOperations.Truncate.
func (*InodeSimpleAttributes) Truncate(context.Context, *fs.Inode, int64) error {
	return syserror.EINVAL
}

// InMemoryAttributes implements utilities for updating in-memory unstable
// attributes and extended attributes. It is not thread-safe.
//
// Users need not initialize Xattrs to non-nil (it will be initialized
// when the first extended attribute is set.
//
// +stateify savable
type InMemoryAttributes struct {
	Unstable fs.UnstableAttr
	Xattrs   map[string][]byte
}

// SetPermissions updates the permissions to p.
func (i *InMemoryAttributes) SetPermissions(ctx context.Context, p fs.FilePermissions) bool {
	i.Unstable.Perms = p
	i.Unstable.StatusChangeTime = ktime.NowFromContext(ctx)
	return true
}

// SetOwner updates the file owner to owner.
func (i *InMemoryAttributes) SetOwner(ctx context.Context, owner fs.FileOwner) error {
	if owner.UID.Ok() {
		i.Unstable.Owner.UID = owner.UID
	}
	if owner.GID.Ok() {
		i.Unstable.Owner.GID = owner.GID
	}
	return nil
}

// SetTimestamps sets the timestamps to ts.
func (i *InMemoryAttributes) SetTimestamps(ctx context.Context, ts fs.TimeSpec) error {
	if ts.ATimeOmit && ts.MTimeOmit {
		return nil
	}

	now := ktime.NowFromContext(ctx)
	if !ts.ATimeOmit {
		if ts.ATimeSetSystemTime {
			i.Unstable.AccessTime = now
		} else {
			i.Unstable.AccessTime = ts.ATime
		}
	}
	if !ts.MTimeOmit {
		if ts.MTimeSetSystemTime {
			i.Unstable.ModificationTime = now
		} else {
			i.Unstable.ModificationTime = ts.MTime
		}
	}
	i.Unstable.StatusChangeTime = now
	return nil
}

// TouchAccessTime updates access time to the current time.
func (i *InMemoryAttributes) TouchAccessTime(ctx context.Context) {
	i.Unstable.AccessTime = ktime.NowFromContext(ctx)
}

// TouchModificationTime updates modification and status change
// time to the current time.
func (i *InMemoryAttributes) TouchModificationTime(ctx context.Context) {
	now := ktime.NowFromContext(ctx)
	i.Unstable.ModificationTime = now
	i.Unstable.StatusChangeTime = now
}

// TouchStatusChangeTime updates status change time to the current time.
func (i *InMemoryAttributes) TouchStatusChangeTime(ctx context.Context) {
	i.Unstable.StatusChangeTime = ktime.NowFromContext(ctx)
}

// Getxattr returns the extended attribute at name or ENOATTR if
// it isn't set.
func (i *InMemoryAttributes) Getxattr(name string) ([]byte, error) {
	if value, ok := i.Xattrs[name]; ok {
		return value, nil
	}
	return nil, syserror.ENOATTR
}

// Setxattr sets the extended attribute at name to value.
func (i *InMemoryAttributes) Setxattr(name string, value []byte) error {
	if i.Xattrs == nil {
		i.Xattrs = make(map[string][]byte)
	}
	i.Xattrs[name] = value
	return nil
}

// Listxattr returns the set of all currently set extended attributes.
func (i *InMemoryAttributes) Listxattr() (map[string]struct{}, error) {
	names := make(map[string]struct{}, len(i.Xattrs))
	for name := range i.Xattrs {
		names[name] = struct{}{}
	}
	return names, nil
}

// NoMappable returns a nil memmap.Mappable.
type NoMappable struct{}

// Mappable implements fs.InodeOperations.Mappable.
func (NoMappable) Mappable(*fs.Inode) memmap.Mappable {
	return nil
}

// NoopWriteOut is a no-op implementation of Inode.WriteOut.
type NoopWriteOut struct{}

// WriteOut is a no-op.
func (NoopWriteOut) WriteOut(context.Context, *fs.Inode) error {
	return nil
}

// InodeNotDirectory can be used by Inodes that are not directories.
type InodeNotDirectory struct{}

// Lookup implements fs.InodeOperations.Lookup.
func (InodeNotDirectory) Lookup(context.Context, *fs.Inode, string) (*fs.Dirent, error) {
	return nil, syserror.ENOTDIR
}

// Create implements fs.InodeOperations.Create.
func (InodeNotDirectory) Create(context.Context, *fs.Inode, string, fs.FileFlags, fs.FilePermissions) (*fs.File, error) {
	return nil, syserror.ENOTDIR
}

// CreateLink implements fs.InodeOperations.CreateLink.
func (InodeNotDirectory) CreateLink(context.Context, *fs.Inode, string, string) error {
	return syserror.ENOTDIR
}

// CreateHardLink implements fs.InodeOperations.CreateHardLink.
func (InodeNotDirectory) CreateHardLink(context.Context, *fs.Inode, *fs.Inode, string) error {
	return syserror.ENOTDIR
}

// CreateDirectory implements fs.InodeOperations.CreateDirectory.
func (InodeNotDirectory) CreateDirectory(context.Context, *fs.Inode, string, fs.FilePermissions) error {
	return syserror.ENOTDIR
}

// Bind implements fs.InodeOperations.Bind.
func (InodeNotDirectory) Bind(context.Context, *fs.Inode, string, transport.BoundEndpoint, fs.FilePermissions) (*fs.Dirent, error) {
	return nil, syserror.ENOTDIR
}

// CreateFifo implements fs.InodeOperations.CreateFifo.
func (InodeNotDirectory) CreateFifo(context.Context, *fs.Inode, string, fs.FilePermissions) error {
	return syserror.ENOTDIR
}

// Remove implements fs.InodeOperations.Remove.
func (InodeNotDirectory) Remove(context.Context, *fs.Inode, string) error {
	return syserror.ENOTDIR
}

// RemoveDirectory implements fs.InodeOperations.RemoveDirectory.
func (InodeNotDirectory) RemoveDirectory(context.Context, *fs.Inode, string) error {
	return syserror.ENOTDIR
}

// InodeNotSocket can be used by Inodes that are not sockets.
type InodeNotSocket struct{}

// BoundEndpoint implements fs.InodeOperations.BoundEndpoint.
func (InodeNotSocket) BoundEndpoint(*fs.Inode, string) transport.BoundEndpoint {
	return nil
}

// InodeNotRenameable can be used by Inodes that cannot be renamed.
type InodeNotRenameable struct{}

// Rename implements fs.InodeOperations.Rename.
func (InodeNotRenameable) Rename(context.Context, *fs.Inode, string, *fs.Inode, string) error {
	return syserror.EINVAL
}

// InodeNotOpenable can be used by Inodes that cannot be opened.
type InodeNotOpenable struct{}

// GetFile implements fs.InodeOperations.GetFile.
func (InodeNotOpenable) GetFile(context.Context, *fs.Dirent, fs.FileFlags) (*fs.File, error) {
	return nil, syserror.EIO
}

// InodeNotVirtual can be used by Inodes that are not virtual.
type InodeNotVirtual struct{}

// IsVirtual implements fs.InodeOperations.IsVirtual.
func (InodeNotVirtual) IsVirtual() bool {
	return false
}

// InodeNotSymlink can be used by Inodes that are not symlinks.
type InodeNotSymlink struct{}

// Readlink implements fs.InodeOperations.Readlink.
func (InodeNotSymlink) Readlink(context.Context, *fs.Inode) (string, error) {
	return "", syserror.ENOLINK
}

// Getlink implements fs.InodeOperations.Getlink.
func (InodeNotSymlink) Getlink(context.Context, *fs.Inode) (*fs.Dirent, error) {
	return nil, syserror.ENOLINK
}

// InodeNoExtendedAttributes can be used by Inodes that do not support
// extended attributes.
type InodeNoExtendedAttributes struct{}

// Getxattr implements fs.InodeOperations.Getxattr.
func (InodeNoExtendedAttributes) Getxattr(*fs.Inode, string) ([]byte, error) {
	return nil, syserror.EOPNOTSUPP
}

// Setxattr implements fs.InodeOperations.Setxattr.
func (InodeNoExtendedAttributes) Setxattr(*fs.Inode, string, []byte) error {
	return syserror.EOPNOTSUPP
}

// Listxattr implements fs.InodeOperations.Listxattr.
func (InodeNoExtendedAttributes) Listxattr(*fs.Inode) (map[string]struct{}, error) {
	return nil, syserror.EOPNOTSUPP
}

// DeprecatedFileOperations panics if any deprecated Inode method is called.
type DeprecatedFileOperations struct{}

// Readiness implements fs.InodeOperations.Waitable.Readiness.
func (DeprecatedFileOperations) Readiness(waiter.EventMask) waiter.EventMask {
	panic("not implemented")
}

// EventRegister implements fs.InodeOperations.Waitable.EventRegister.
func (DeprecatedFileOperations) EventRegister(*waiter.Entry, waiter.EventMask) {
	panic("not implemented")
}

// EventUnregister implements fs.InodeOperations.Waitable.EventUnregister.
func (DeprecatedFileOperations) EventUnregister(*waiter.Entry) {
	panic("not implemented")
}

// DeprecatedPreadv implements fs.InodeOperations.DeprecatedPreadv.
func (DeprecatedFileOperations) DeprecatedPreadv(context.Context, usermem.IOSequence, int64) (int64, error) {
	panic("not implemented")
}

// DeprecatedPwritev implements fs.InodeOperations.DeprecatedPwritev.
func (DeprecatedFileOperations) DeprecatedPwritev(context.Context, usermem.IOSequence, int64) (int64, error) {
	panic("not implemented")
}

// DeprecatedReaddir implements fs.InodeOperations.DeprecatedReaddir.
func (DeprecatedFileOperations) DeprecatedReaddir(context.Context, *fs.DirCtx, int) (int, error) {
	panic("not implemented")
}

// DeprecatedFsync implements fs.InodeOperations.DeprecatedFsync.
func (DeprecatedFileOperations) DeprecatedFsync() error {
	panic("not implemented")
}

// DeprecatedFlush implements fs.InodeOperations.DeprecatedFlush.
func (DeprecatedFileOperations) DeprecatedFlush() error {
	panic("not implemented")
}

// DeprecatedMappable implements fs.InodeOperations.DeprecatedMappable.
func (DeprecatedFileOperations) DeprecatedMappable(context.Context, *fs.Inode) (memmap.Mappable, bool) {
	panic("not implemented")
}
