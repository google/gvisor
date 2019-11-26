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

package fsutil

import (
	"sync"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SimpleFileInode is a simple implementation of InodeOperations.
//
// +stateify savable
type SimpleFileInode struct {
	InodeGenericChecker       `state:"nosave"`
	InodeNoExtendedAttributes `state:"nosave"`
	InodeNoopRelease          `state:"nosave"`
	InodeNoopWriteOut         `state:"nosave"`
	InodeNotAllocatable       `state:"nosave"`
	InodeNotDirectory         `state:"nosave"`
	InodeNotMappable          `state:"nosave"`
	InodeNotOpenable          `state:"nosave"`
	InodeNotSocket            `state:"nosave"`
	InodeNotSymlink           `state:"nosave"`
	InodeNotTruncatable       `state:"nosave"`
	InodeNotVirtual           `state:"nosave"`

	InodeSimpleAttributes
}

// NewSimpleFileInode returns a new SimpleFileInode.
func NewSimpleFileInode(ctx context.Context, owner fs.FileOwner, perms fs.FilePermissions, typ uint64) *SimpleFileInode {
	return &SimpleFileInode{
		InodeSimpleAttributes: NewInodeSimpleAttributes(ctx, owner, perms, typ),
	}
}

// NoReadWriteFileInode is an implementation of InodeOperations that supports
// opening files that are not readable or writeable.
//
// +stateify savable
type NoReadWriteFileInode struct {
	InodeGenericChecker       `state:"nosave"`
	InodeNoExtendedAttributes `state:"nosave"`
	InodeNoopRelease          `state:"nosave"`
	InodeNoopWriteOut         `state:"nosave"`
	InodeNotAllocatable       `state:"nosave"`
	InodeNotDirectory         `state:"nosave"`
	InodeNotMappable          `state:"nosave"`
	InodeNotSocket            `state:"nosave"`
	InodeNotSymlink           `state:"nosave"`
	InodeNotTruncatable       `state:"nosave"`
	InodeNotVirtual           `state:"nosave"`

	InodeSimpleAttributes
}

// NewNoReadWriteFileInode returns a new NoReadWriteFileInode.
func NewNoReadWriteFileInode(ctx context.Context, owner fs.FileOwner, perms fs.FilePermissions, typ uint64) *NoReadWriteFileInode {
	return &NoReadWriteFileInode{
		InodeSimpleAttributes: NewInodeSimpleAttributes(ctx, owner, perms, typ),
	}
}

// GetFile implements fs.InodeOperations.GetFile.
func (*NoReadWriteFileInode) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &NoReadWriteFile{}), nil
}

// InodeSimpleAttributes implements methods for updating in-memory unstable
// attributes.
//
// +stateify savable
type InodeSimpleAttributes struct {
	// fsType is the immutable filesystem type that will be returned by
	// StatFS.
	fsType uint64

	// mu protects unstable.
	mu       sync.RWMutex `state:"nosave"`
	unstable fs.UnstableAttr
}

// NewInodeSimpleAttributes returns a new InodeSimpleAttributes with the given
// owner and permissions, and all timestamps set to the current time.
func NewInodeSimpleAttributes(ctx context.Context, owner fs.FileOwner, perms fs.FilePermissions, typ uint64) InodeSimpleAttributes {
	return NewInodeSimpleAttributesWithUnstable(fs.WithCurrentTime(ctx, fs.UnstableAttr{
		Owner: owner,
		Perms: perms,
	}), typ)
}

// NewInodeSimpleAttributesWithUnstable returns a new InodeSimpleAttributes
// with the given unstable attributes.
func NewInodeSimpleAttributesWithUnstable(uattr fs.UnstableAttr, typ uint64) InodeSimpleAttributes {
	return InodeSimpleAttributes{
		fsType:   typ,
		unstable: uattr,
	}
}

// UnstableAttr implements fs.InodeOperations.UnstableAttr.
func (i *InodeSimpleAttributes) UnstableAttr(ctx context.Context, _ *fs.Inode) (fs.UnstableAttr, error) {
	i.mu.RLock()
	u := i.unstable
	i.mu.RUnlock()
	return u, nil
}

// SetPermissions implements fs.InodeOperations.SetPermissions.
func (i *InodeSimpleAttributes) SetPermissions(ctx context.Context, _ *fs.Inode, p fs.FilePermissions) bool {
	i.mu.Lock()
	i.unstable.SetPermissions(ctx, p)
	i.mu.Unlock()
	return true
}

// SetOwner implements fs.InodeOperations.SetOwner.
func (i *InodeSimpleAttributes) SetOwner(ctx context.Context, _ *fs.Inode, owner fs.FileOwner) error {
	i.mu.Lock()
	i.unstable.SetOwner(ctx, owner)
	i.mu.Unlock()
	return nil
}

// SetTimestamps implements fs.InodeOperations.SetTimestamps.
func (i *InodeSimpleAttributes) SetTimestamps(ctx context.Context, _ *fs.Inode, ts fs.TimeSpec) error {
	i.mu.Lock()
	i.unstable.SetTimestamps(ctx, ts)
	i.mu.Unlock()
	return nil
}

// AddLink implements fs.InodeOperations.AddLink.
func (i *InodeSimpleAttributes) AddLink() {
	i.mu.Lock()
	i.unstable.Links++
	i.mu.Unlock()
}

// DropLink implements fs.InodeOperations.DropLink.
func (i *InodeSimpleAttributes) DropLink() {
	i.mu.Lock()
	i.unstable.Links--
	i.mu.Unlock()
}

// StatFS implements fs.InodeOperations.StatFS.
func (i *InodeSimpleAttributes) StatFS(context.Context) (fs.Info, error) {
	if i.fsType == 0 {
		return fs.Info{}, syserror.ENOSYS
	}
	return fs.Info{Type: i.fsType}, nil
}

// NotifyAccess updates the access time.
func (i *InodeSimpleAttributes) NotifyAccess(ctx context.Context) {
	i.mu.Lock()
	i.unstable.AccessTime = ktime.NowFromContext(ctx)
	i.mu.Unlock()
}

// NotifyModification updates the modification time.
func (i *InodeSimpleAttributes) NotifyModification(ctx context.Context) {
	i.mu.Lock()
	i.unstable.ModificationTime = ktime.NowFromContext(ctx)
	i.mu.Unlock()
}

// NotifyStatusChange updates the status change time.
func (i *InodeSimpleAttributes) NotifyStatusChange(ctx context.Context) {
	i.mu.Lock()
	i.unstable.StatusChangeTime = ktime.NowFromContext(ctx)
	i.mu.Unlock()
}

// NotifyModificationAndStatusChange updates the modification and status change
// times.
func (i *InodeSimpleAttributes) NotifyModificationAndStatusChange(ctx context.Context) {
	i.mu.Lock()
	now := ktime.NowFromContext(ctx)
	i.unstable.ModificationTime = now
	i.unstable.StatusChangeTime = now
	i.mu.Unlock()
}

// InodeSimpleExtendedAttributes implements
// fs.InodeOperations.{Get,Set,List}xattr.
//
// +stateify savable
type InodeSimpleExtendedAttributes struct {
	// mu protects xattrs.
	mu     sync.RWMutex `state:"nosave"`
	xattrs map[string][]byte
}

// Getxattr implements fs.InodeOperations.Getxattr.
func (i *InodeSimpleExtendedAttributes) Getxattr(_ *fs.Inode, name string) ([]byte, error) {
	i.mu.RLock()
	value, ok := i.xattrs[name]
	i.mu.RUnlock()
	if !ok {
		return []byte{}, syserror.ENOATTR
	}
	return value, nil
}

// Setxattr implements fs.InodeOperations.Setxattr.
func (i *InodeSimpleExtendedAttributes) Setxattr(_ *fs.Inode, name string, value []byte) error {
	i.mu.Lock()
	if i.xattrs == nil {
		i.xattrs = make(map[string][]byte)
	}
	i.xattrs[name] = value
	i.mu.Unlock()
	return nil
}

// Listxattr implements fs.InodeOperations.Listxattr.
func (i *InodeSimpleExtendedAttributes) Listxattr(_ *fs.Inode) (map[string]struct{}, error) {
	i.mu.RLock()
	names := make(map[string]struct{}, len(i.xattrs))
	for name := range i.xattrs {
		names[name] = struct{}{}
	}
	i.mu.RUnlock()
	return names, nil
}

// staticFile is a file with static contents. It is returned by
// InodeStaticFileGetter.GetFile.
//
// +stateify savable
type staticFile struct {
	FileGenericSeek          `state:"nosave"`
	FileNoIoctl              `state:"nosave"`
	FileNoMMap               `state:"nosave"`
	FileNoSplice             `state:"nosave"`
	FileNoopFsync            `state:"nosave"`
	FileNoopFlush            `state:"nosave"`
	FileNoopRelease          `state:"nosave"`
	FileNoopWrite            `state:"nosave"`
	FileNotDirReaddir        `state:"nosave"`
	FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady       `state:"nosave"`

	FileStaticContentReader
}

// InodeNoStatFS implement StatFS by retuning ENOSYS.
type InodeNoStatFS struct{}

// StatFS implements fs.InodeOperations.StatFS.
func (InodeNoStatFS) StatFS(context.Context) (fs.Info, error) {
	return fs.Info{}, syserror.ENOSYS
}

// InodeStaticFileGetter implements GetFile for a file with static contents.
//
// +stateify savable
type InodeStaticFileGetter struct {
	Contents []byte
}

// GetFile implements fs.InodeOperations.GetFile.
func (i *InodeStaticFileGetter) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &staticFile{
		FileStaticContentReader: NewFileStaticContentReader(i.Contents),
	}), nil
}

// InodeNotMappable returns a nil memmap.Mappable.
type InodeNotMappable struct{}

// Mappable implements fs.InodeOperations.Mappable.
func (InodeNotMappable) Mappable(*fs.Inode) memmap.Mappable {
	return nil
}

// InodeNoopWriteOut is a no-op implementation of fs.InodeOperations.WriteOut.
type InodeNoopWriteOut struct{}

// WriteOut is a no-op.
func (InodeNoopWriteOut) WriteOut(context.Context, *fs.Inode) error {
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

// Rename implements fs.FileOperations.Rename.
func (InodeNotDirectory) Rename(context.Context, *fs.Inode, *fs.Inode, string, *fs.Inode, string, bool) error {
	return syserror.EINVAL
}

// InodeNotSocket can be used by Inodes that are not sockets.
type InodeNotSocket struct{}

// BoundEndpoint implements fs.InodeOperations.BoundEndpoint.
func (InodeNotSocket) BoundEndpoint(*fs.Inode, string) transport.BoundEndpoint {
	return nil
}

// InodeNotTruncatable can be used by Inodes that cannot be truncated.
type InodeNotTruncatable struct{}

// Truncate implements fs.InodeOperations.Truncate.
func (InodeNotTruncatable) Truncate(context.Context, *fs.Inode, int64) error {
	return syserror.EINVAL
}

// InodeIsDirTruncate implements fs.InodeOperations.Truncate for directories.
type InodeIsDirTruncate struct{}

// Truncate implements fs.InodeOperations.Truncate.
func (InodeIsDirTruncate) Truncate(context.Context, *fs.Inode, int64) error {
	return syserror.EISDIR
}

// InodeNoopTruncate implements fs.InodeOperations.Truncate as a noop.
type InodeNoopTruncate struct{}

// Truncate implements fs.InodeOperations.Truncate.
func (InodeNoopTruncate) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// InodeNotRenameable can be used by Inodes that cannot be truncated.
type InodeNotRenameable struct{}

// Rename implements fs.InodeOperations.Rename.
func (InodeNotRenameable) Rename(context.Context, *fs.Inode, *fs.Inode, string, *fs.Inode, string, bool) error {
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

// InodeVirtual can be used by Inodes that are virtual.
type InodeVirtual struct{}

// IsVirtual implements fs.InodeOperations.IsVirtual.
func (InodeVirtual) IsVirtual() bool {
	return true
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
	return []byte{}, syserror.EOPNOTSUPP
}

// Setxattr implements fs.InodeOperations.Setxattr.
func (InodeNoExtendedAttributes) Setxattr(*fs.Inode, string, []byte) error {
	return syserror.EOPNOTSUPP
}

// Listxattr implements fs.InodeOperations.Listxattr.
func (InodeNoExtendedAttributes) Listxattr(*fs.Inode) (map[string]struct{}, error) {
	return nil, syserror.EOPNOTSUPP
}

// InodeNoopRelease implements fs.InodeOperations.Release as a noop.
type InodeNoopRelease struct{}

// Release implements fs.InodeOperations.Release.
func (InodeNoopRelease) Release(context.Context) {}

// InodeGenericChecker implements fs.InodeOperations.Check with a generic
// implementation.
type InodeGenericChecker struct{}

// Check implements fs.InodeOperations.Check.
func (InodeGenericChecker) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// InodeDenyWriteChecker implements fs.InodeOperations.Check which denies all
// write operations.
type InodeDenyWriteChecker struct{}

// Check implements fs.InodeOperations.Check.
func (InodeDenyWriteChecker) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	if p.Write {
		return false
	}
	return fs.ContextCanAccessFile(ctx, inode, p)
}

//InodeNotAllocatable can be used by Inodes that do not support Allocate().
type InodeNotAllocatable struct{}

func (InodeNotAllocatable) Allocate(_ context.Context, _ *fs.Inode, _, _ int64) error {
	return syserror.EOPNOTSUPP
}

// InodeNoopAllocate implements fs.InodeOperations.Allocate as a noop.
type InodeNoopAllocate struct{}

// Allocate implements fs.InodeOperations.Allocate.
func (InodeNoopAllocate) Allocate(_ context.Context, _ *fs.Inode, _, _ int64) error {
	return nil
}

// InodeIsDirAllocate implements fs.InodeOperations.Allocate for directories.
type InodeIsDirAllocate struct{}

// Allocate implements fs.InodeOperations.Allocate.
func (InodeIsDirAllocate) Allocate(_ context.Context, _ *fs.Inode, _, _ int64) error {
	return syserror.EISDIR
}
