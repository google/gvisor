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
	"errors"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
)

var (
	// ErrResolveViaReadlink is a special error value returned by
	// InodeOperations.Getlink() to indicate that a link should be
	// resolved automatically by walking to the path returned by
	// InodeOperations.Readlink().
	ErrResolveViaReadlink = errors.New("link should be resolved via Readlink()")
)

// TimeSpec contains access and modification timestamps. If either ATimeOmit or
// MTimeOmit is true, then the corresponding timestamp should not be updated.
// If either ATimeSetSystemTime or MTimeSetSystemTime are set then the
// corresponding timestamp should be ignored and the time will be set to the
// current system time.
type TimeSpec struct {
	ATime              ktime.Time
	ATimeOmit          bool
	ATimeSetSystemTime bool
	MTime              ktime.Time
	MTimeOmit          bool
	MTimeSetSystemTime bool
}

// InodeOperations are operations on an Inode that diverge per file system.
//
// Objects that implement InodeOperations may cache file system "private"
// data that is useful for implementing these methods. In contrast, Inode
// contains state that is common to all Inodes; this state may be optionally
// used by InodeOperations. An object that implements InodeOperations may
// not take a reference on an Inode.
type InodeOperations interface {
	// Release releases all private file system data held by this object.
	// Once Release is called, this object is dead (no other methods will
	// ever be called).
	Release(context.Context)

	// Lookup loads an Inode at name under dir into a Dirent. The name
	// is a valid component path: it contains no "/"s nor is the empty
	// string.
	//
	// Lookup may return one of:
	//
	// * A nil Dirent and a non-nil error. If the reason that Lookup failed
	//   was because the name does not exist under Inode, then must return
	//   syserror.ENOENT.
	//
	// * If name does not exist under dir and the file system wishes this
	//   fact to be cached, a non-nil Dirent containing a nil Inode and a
	//   nil error. This is a negative Dirent and must have exactly one
	//   reference (at-construction reference).
	//
	// * If name does exist under this dir, a non-nil Dirent containing a
	//   non-nil Inode, and a nil error. File systems that take extra
	//   references on this Dirent should implement DirentOperations.
	Lookup(ctx context.Context, dir *Inode, name string) (*Dirent, error)

	// Create creates an Inode at name under dir and returns a new File
	// whose Dirent backs the new Inode. Implementations must ensure that
	// name does not already exist. Create may return one of:
	//
	// * A nil File and a non-nil error.
	//
	// * A non-nil File and a nil error. File.Dirent will be a new Dirent,
	// with a single reference held by File. File systems that take extra
	// references on this Dirent should implement DirentOperations.
	//
	// The caller must ensure that this operation is permitted.
	Create(ctx context.Context, dir *Inode, name string, flags FileFlags, perm FilePermissions) (*File, error)

	// CreateDirectory creates a new directory under this dir.
	// CreateDirectory should otherwise do the same as Create.
	//
	// The caller must ensure that this operation is permitted.
	CreateDirectory(ctx context.Context, dir *Inode, name string, perm FilePermissions) error

	// CreateLink creates a symbolic link under dir between newname
	// and oldname. CreateLink should otherwise do the same as Create.
	//
	// The caller must ensure that this operation is permitted.
	CreateLink(ctx context.Context, dir *Inode, oldname string, newname string) error

	// CreateHardLink creates a hard link under dir between the target
	// Inode and name.
	//
	// The caller must ensure this operation is permitted.
	CreateHardLink(ctx context.Context, dir *Inode, target *Inode, name string) error

	// CreateFifo creates a new named pipe under dir at name.
	//
	// The caller must ensure that this operation is permitted.
	CreateFifo(ctx context.Context, dir *Inode, name string, perm FilePermissions) error

	// Remove removes the given named non-directory under dir.
	//
	// The caller must ensure that this operation is permitted.
	Remove(ctx context.Context, dir *Inode, name string) error

	// RemoveDirectory removes the given named directory under dir.
	//
	// The caller must ensure that this operation is permitted.
	//
	// RemoveDirectory should check that the directory to be
	// removed is empty.
	RemoveDirectory(ctx context.Context, dir *Inode, name string) error

	// Rename atomically renames oldName under oldParent to newName under
	// newParent where oldParent and newParent are directories. inode is
	// the Inode of this InodeOperations.
	//
	// If replacement is true, then newName already exists and this call
	// will replace it with oldName.
	//
	// Implementations are responsible for rejecting renames that replace
	// non-empty directories.
	Rename(ctx context.Context, inode *Inode, oldParent *Inode, oldName string, newParent *Inode, newName string, replacement bool) error

	// Bind binds a new socket under dir at the given name.
	//
	// The caller must ensure that this operation is permitted.
	Bind(ctx context.Context, dir *Inode, name string, data transport.BoundEndpoint, perm FilePermissions) (*Dirent, error)

	// BoundEndpoint returns the socket endpoint at path stored in
	// or generated by an Inode.
	//
	// The path is only relevant for generated endpoint because stored
	// endpoints already know their path. It is ok for the endpoint to
	// hold onto their path because the only way to change a bind
	// address is to rebind the socket.
	//
	// This is valid iff the type of the Inode is a Socket, which
	// generally implies that this Inode was created via CreateSocket.
	//
	// If there is no socket endpoint available, nil will be returned.
	BoundEndpoint(inode *Inode, path string) transport.BoundEndpoint

	// GetFile returns a new open File backed by a Dirent and FileFlags.
	//
	// Special Inode types may block using ctx.Sleeper. RegularFiles,
	// Directories, and Symlinks must not block (see doCopyUp).
	//
	// The returned File will uniquely back an application fd.
	GetFile(ctx context.Context, d *Dirent, flags FileFlags) (*File, error)

	// UnstableAttr returns the most up-to-date "unstable" attributes of
	// an Inode, where "unstable" means that they change in response to
	// file system events.
	UnstableAttr(ctx context.Context, inode *Inode) (UnstableAttr, error)

	// Getxattr retrieves the value of extended attribute name. Inodes that
	// do not support extended attributes return EOPNOTSUPP. Inodes that
	// support extended attributes but don't have a value at name return
	// ENODATA.
	Getxattr(inode *Inode, name string) (string, error)

	// Setxattr sets the value of extended attribute name. Inodes that
	// do not support extended attributes return EOPNOTSUPP.
	Setxattr(inode *Inode, name, value string) error

	// Listxattr returns the set of all extended attributes names that
	// have values. Inodes that do not support extended attributes return
	// EOPNOTSUPP.
	Listxattr(inode *Inode) (map[string]struct{}, error)

	// Check determines whether an Inode can be accessed with the
	// requested permission mask using the context (which gives access
	// to Credentials and UserNamespace).
	Check(ctx context.Context, inode *Inode, p PermMask) bool

	// SetPermissions sets new permissions for an Inode.  Returns false
	// if it was not possible to set the new permissions.
	//
	// The caller must ensure that this operation is permitted.
	SetPermissions(ctx context.Context, inode *Inode, f FilePermissions) bool

	// SetOwner sets the ownership for this file.
	//
	// If either UID or GID are set to auth.NoID, its value will not be
	// changed.
	//
	// The caller must ensure that this operation is permitted.
	SetOwner(ctx context.Context, inode *Inode, owner FileOwner) error

	// SetTimestamps sets the access and modification timestamps of an
	// Inode according to the access and modification times in the TimeSpec.
	//
	// If either ATimeOmit or MTimeOmit is set, then the corresponding
	// timestamp is not updated.
	//
	// If either ATimeSetSystemTime or MTimeSetSystemTime is true, that
	// timestamp is set to the current time instead.
	//
	// The caller must ensure that this operation is permitted.
	SetTimestamps(ctx context.Context, inode *Inode, ts TimeSpec) error

	// Truncate changes the size of an Inode. Truncate should not check
	// permissions internally, as it is used for both sys_truncate and
	// sys_ftruncate.
	//
	// Implementations need not check that length >= 0.
	Truncate(ctx context.Context, inode *Inode, size int64) error

	// Allocate allows the caller to reserve disk space for the inode.
	// It's equivalent to fallocate(2) with 'mode=0'.
	Allocate(ctx context.Context, inode *Inode, offset int64, length int64) error

	// WriteOut writes cached Inode state to a backing filesystem in a
	// synchronous manner.
	//
	// File systems that do not cache metadata or data via an Inode
	// implement WriteOut as a no-op. File systems that are entirely in
	// memory also implement WriteOut as a no-op. Otherwise file systems
	// call Inode.Sync to write back page cached data and cached metadata
	// followed by syncing writeback handles.
	//
	// It derives from include/linux/fs.h:super_operations->write_inode.
	WriteOut(ctx context.Context, inode *Inode) error

	// Readlink reads the symlink path of an Inode.
	//
	// Readlink is permitted to return a different path depending on ctx,
	// the request originator.
	//
	// The caller must ensure that this operation is permitted.
	//
	// Readlink should check that Inode is a symlink and its content is
	// at least readable.
	Readlink(ctx context.Context, inode *Inode) (string, error)

	// Getlink resolves a symlink to a target *Dirent.
	//
	// Filesystems that can resolve the link by walking to the path returned
	// by Readlink should return (nil, ErrResolveViaReadlink), which
	// triggers link resolution via Realink and Lookup.
	//
	// Some links cannot be followed by Lookup. In this case, Getlink can
	// return the Dirent of the link target. The caller holds a reference
	// to the Dirent. Filesystems that return a non-nil *Dirent from Getlink
	// cannot participate in an overlay because it is impossible for the
	// overlay to ascertain whether or not the *Dirent should contain an
	// overlayEntry.
	//
	// Any error returned from Getlink other than ErrResolveViaReadlink
	// indicates the caller's inability to traverse this Inode as a link
	// (e.g. syserror.ENOLINK indicates that the Inode is not a link,
	// syscall.EPERM indicates that traversing the link is not allowed, etc).
	Getlink(context.Context, *Inode) (*Dirent, error)

	// Mappable returns a memmap.Mappable that provides memory mappings of the
	// Inode's data. Mappable may return nil if this is not supported. The
	// returned Mappable must remain valid until InodeOperations.Release is
	// called.
	Mappable(*Inode) memmap.Mappable

	// The below methods require cleanup.

	// AddLink increments the hard link count of an Inode.
	//
	// Remove in favor of Inode.IncLink.
	AddLink()

	// DropLink decrements the hard link count of an Inode.
	//
	// Remove in favor of Inode.DecLink.
	DropLink()

	// NotifyStatusChange sets the status change time to the current time.
	//
	// Remove in favor of updating the Inode's cached status change time.
	NotifyStatusChange(ctx context.Context)

	// IsVirtual indicates whether or not this corresponds to a virtual
	// resource.
	//
	// If IsVirtual returns true, then caching will be disabled for this
	// node, and fs.Dirent.Freeze() will not stop operations on the node.
	//
	// Remove in favor of freezing specific mounts.
	IsVirtual() bool

	// StatFS returns a filesystem Info implementation or an error.  If
	// the filesystem does not support this operation (maybe in the future
	// it will), then ENOSYS should be returned.
	StatFS(context.Context) (Info, error)
}
