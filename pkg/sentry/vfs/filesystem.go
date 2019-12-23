// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
)

// A Filesystem is a tree of nodes represented by Dentries, which forms part of
// a VirtualFilesystem.
//
// Filesystems are reference-counted. Unless otherwise specified, all
// Filesystem methods require that a reference is held.
//
// Filesystem is analogous to Linux's struct super_block.
type Filesystem struct {
	// refs is the reference count. refs is accessed using atomic memory
	// operations.
	refs int64

	// vfs is the VirtualFilesystem that uses this Filesystem. vfs is
	// immutable.
	vfs *VirtualFilesystem

	// impl is the FilesystemImpl associated with this Filesystem. impl is
	// immutable. This should be the last field in Dentry.
	impl FilesystemImpl
}

// Init must be called before first use of fs.
func (fs *Filesystem) Init(vfsObj *VirtualFilesystem, impl FilesystemImpl) {
	fs.refs = 1
	fs.vfs = vfsObj
	fs.impl = impl
	vfsObj.filesystemsMu.Lock()
	vfsObj.filesystems[fs] = struct{}{}
	vfsObj.filesystemsMu.Unlock()
}

// VirtualFilesystem returns the containing VirtualFilesystem.
func (fs *Filesystem) VirtualFilesystem() *VirtualFilesystem {
	return fs.vfs
}

// Impl returns the FilesystemImpl associated with fs.
func (fs *Filesystem) Impl() FilesystemImpl {
	return fs.impl
}

// IncRef increments fs' reference count.
func (fs *Filesystem) IncRef() {
	if atomic.AddInt64(&fs.refs, 1) <= 1 {
		panic("Filesystem.IncRef() called without holding a reference")
	}
}

// TryIncRef increments fs' reference count and returns true. If fs' reference
// count is zero, TryIncRef does nothing and returns false.
//
// TryIncRef does not require that a reference is held on fs.
func (fs *Filesystem) TryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&fs.refs)
		if refs <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&fs.refs, refs, refs+1) {
			return true
		}
	}
}

// DecRef decrements fs' reference count.
func (fs *Filesystem) DecRef() {
	if refs := atomic.AddInt64(&fs.refs, -1); refs == 0 {
		fs.vfs.filesystemsMu.Lock()
		delete(fs.vfs.filesystems, fs)
		fs.vfs.filesystemsMu.Unlock()
		fs.impl.Release()
	} else if refs < 0 {
		panic("Filesystem.decRef() called without holding a reference")
	}
}

// FilesystemImpl contains implementation details for a Filesystem.
// Implementations of FilesystemImpl should contain their associated Filesystem
// by value as their first field.
//
// All methods that take a ResolvingPath must resolve the path before
// performing any other checks, including rejection of the operation if not
// supported by the FilesystemImpl. This is because the final FilesystemImpl
// (responsible for actually implementing the operation) isn't known until path
// resolution is complete.
//
// Unless otherwise specified, FilesystemImpl methods are responsible for
// performing permission checks. In many cases, vfs package functions in
// permissions.go may be used to help perform these checks.
//
// When multiple specified error conditions apply to a given method call, the
// implementation may return any applicable errno unless otherwise specified,
// but returning the earliest error specified is preferable to maximize
// compatibility with Linux.
//
// All methods may return errors not specified, notably including:
//
// - ENOENT if a required path component does not exist.
//
// - ENOTDIR if an intermediate path component is not a directory.
//
// - Errors from vfs-package functions (ResolvingPath.Resolve*(),
// Mount.CheckBeginWrite(), permission-checking functions, etc.)
//
// For all methods that take or return linux.Statx, Statx.Uid and Statx.Gid
// should be interpreted as IDs in the root UserNamespace (i.e. as auth.KUID
// and auth.KGID respectively).
//
// FilesystemImpl combines elements of Linux's struct super_operations and
// struct inode_operations, for reasons described in the documentation for
// Dentry.
type FilesystemImpl interface {
	// Release is called when the associated Filesystem reaches zero
	// references.
	Release()

	// Sync "causes all pending modifications to filesystem metadata and cached
	// file data to be written to the underlying [filesystem]", as by syncfs(2).
	Sync(ctx context.Context) error

	// GetDentryAt returns a Dentry representing the file at rp. A reference is
	// taken on the returned Dentry.
	//
	// GetDentryAt does not correspond directly to a Linux syscall; it is used
	// in the implementation of:
	//
	// - Syscalls that need to resolve two paths: link(), linkat().
	//
	// - Syscalls that need to refer to a filesystem position outside the
	// context of a file description: chdir(), fchdir(), chroot(), mount(),
	// umount().
	GetDentryAt(ctx context.Context, rp *ResolvingPath, opts GetDentryOptions) (*Dentry, error)

	// GetParentDentryAt returns a Dentry representing the directory at the
	// second-to-last path component in rp. (Note that, despite the name, this
	// is not necessarily the parent directory of the file at rp, since the
	// last path component in rp may be "." or "..".) A reference is taken on
	// the returned Dentry.
	//
	// GetParentDentryAt does not correspond directly to a Linux syscall; it is
	// used in the implementation of the rename() family of syscalls, which
	// must resolve the parent directories of two paths.
	//
	// Preconditions: !rp.Done().
	//
	// Postconditions: If GetParentDentryAt returns a nil error, then
	// rp.Final(). If GetParentDentryAt returns an error returned by
	// ResolvingPath.Resolve*(), then !rp.Done().
	GetParentDentryAt(ctx context.Context, rp *ResolvingPath) (*Dentry, error)

	// LinkAt creates a hard link at rp representing the same file as vd. It
	// does not take ownership of references on vd.
	//
	// Errors:
	//
	// - If the last path component in rp is "." or "..", LinkAt returns
	// EEXIST.
	//
	// - If a file already exists at rp, LinkAt returns EEXIST.
	//
	// - If rp.MustBeDir(), LinkAt returns ENOENT.
	//
	// - If the directory in which the link would be created has been removed
	// by RmdirAt or RenameAt, LinkAt returns ENOENT.
	//
	// - If rp.Mount != vd.Mount(), LinkAt returns EXDEV.
	//
	// - If vd represents a directory, LinkAt returns EPERM.
	//
	// - If vd represents a file for which all existing links have been
	// removed, or a file created by open(O_TMPFILE|O_EXCL), LinkAt returns
	// ENOENT. Equivalently, if vd represents a file with a link count of 0 not
	// created by open(O_TMPFILE) without O_EXCL, LinkAt returns ENOENT.
	//
	// Preconditions: !rp.Done(). For the final path component in rp,
	// !rp.ShouldFollowSymlink().
	//
	// Postconditions: If LinkAt returns an error returned by
	// ResolvingPath.Resolve*(), then !rp.Done().
	LinkAt(ctx context.Context, rp *ResolvingPath, vd VirtualDentry) error

	// MkdirAt creates a directory at rp.
	//
	// Errors:
	//
	// - If the last path component in rp is "." or "..", MkdirAt returns
	// EEXIST.
	//
	// - If a file already exists at rp, MkdirAt returns EEXIST.
	//
	// - If the directory in which the new directory would be created has been
	// removed by RmdirAt or RenameAt, MkdirAt returns ENOENT.
	//
	// Preconditions: !rp.Done(). For the final path component in rp,
	// !rp.ShouldFollowSymlink().
	//
	// Postconditions: If MkdirAt returns an error returned by
	// ResolvingPath.Resolve*(), then !rp.Done().
	MkdirAt(ctx context.Context, rp *ResolvingPath, opts MkdirOptions) error

	// MknodAt creates a regular file, device special file, or named pipe at
	// rp.
	//
	// Errors:
	//
	// - If the last path component in rp is "." or "..", MknodAt returns
	// EEXIST.
	//
	// - If a file already exists at rp, MknodAt returns EEXIST.
	//
	// - If rp.MustBeDir(), MknodAt returns ENOENT.
	//
	// - If the directory in which the file would be created has been removed
	// by RmdirAt or RenameAt, MknodAt returns ENOENT.
	//
	// Preconditions: !rp.Done(). For the final path component in rp,
	// !rp.ShouldFollowSymlink().
	//
	// Postconditions: If MknodAt returns an error returned by
	// ResolvingPath.Resolve*(), then !rp.Done().
	MknodAt(ctx context.Context, rp *ResolvingPath, opts MknodOptions) error

	// OpenAt returns an FileDescription providing access to the file at rp. A
	// reference is taken on the returned FileDescription.
	//
	// Errors:
	//
	// - If opts.Flags specifies O_TMPFILE and this feature is unsupported by
	// the implementation, OpenAt returns EOPNOTSUPP. (All other unsupported
	// features are silently ignored, consistently with Linux's open*(2).)
	OpenAt(ctx context.Context, rp *ResolvingPath, opts OpenOptions) (*FileDescription, error)

	// ReadlinkAt returns the target of the symbolic link at rp.
	//
	// Errors:
	//
	// - If the file at rp is not a symbolic link, ReadlinkAt returns EINVAL.
	ReadlinkAt(ctx context.Context, rp *ResolvingPath) (string, error)

	// RenameAt renames the file named oldName in directory oldParentVD to rp.
	// It does not take ownership of references on oldParentVD.
	//
	// Errors [1]:
	//
	// - If opts.Flags specifies unsupported options, RenameAt returns EINVAL.
	//
	// - If the last path component in rp is "." or "..", and opts.Flags
	// contains RENAME_NOREPLACE, RenameAt returns EEXIST.
	//
	// - If the last path component in rp is "." or "..", and opts.Flags does
	// not contain RENAME_NOREPLACE, RenameAt returns EBUSY.
	//
	// - If rp.Mount != oldParentVD.Mount(), RenameAt returns EXDEV.
	//
	// - If the renamed file is not a directory, and opts.MustBeDir is true,
	// RenameAt returns ENOTDIR.
	//
	// - If renaming would replace an existing file and opts.Flags contains
	// RENAME_NOREPLACE, RenameAt returns EEXIST.
	//
	// - If there is no existing file at rp and opts.Flags contains
	// RENAME_EXCHANGE, RenameAt returns ENOENT.
	//
	// - If there is an existing non-directory file at rp, and rp.MustBeDir()
	// is true, RenameAt returns ENOTDIR.
	//
	// - If the renamed file is not a directory, opts.Flags does not contain
	// RENAME_EXCHANGE, and rp.MustBeDir() is true, RenameAt returns ENOTDIR.
	// (This check is not subsumed by the check for directory replacement below
	// since it applies even if there is no file to replace.)
	//
	// - If the renamed file is a directory, and the new parent directory of
	// the renamed file is either the renamed directory or a descendant
	// subdirectory of the renamed directory, RenameAt returns EINVAL.
	//
	// - If renaming would exchange the renamed file with an ancestor directory
	// of the renamed file, RenameAt returns EINVAL.
	//
	// - If renaming would replace an ancestor directory of the renamed file,
	// RenameAt returns ENOTEMPTY. (This check would be subsumed by the
	// non-empty directory check below; however, this check takes place before
	// the self-rename check.)
	//
	// - If the renamed file would replace or exchange with itself (i.e. the
	// source and destination paths resolve to the same file), RenameAt returns
	// nil, skipping the checks described below.
	//
	// - If the source or destination directory is not writable by the provider
	// of rp.Credentials(), RenameAt returns EACCES.
	//
	// - If the renamed file is a directory, and renaming would replace a
	// non-directory file, RenameAt returns ENOTDIR.
	//
	// - If the renamed file is not a directory, and renaming would replace a
	// directory, RenameAt returns EISDIR.
	//
	// - If the new parent directory of the renamed file has been removed by
	// RmdirAt or a preceding call to RenameAt, RenameAt returns ENOENT.
	//
	// - If the renamed file is a directory, it is not writable by the
	// provider of rp.Credentials(), and the source and destination parent
	// directories are different, RenameAt returns EACCES. (This is nominally
	// required to change the ".." entry in the renamed directory.)
	//
	// - If renaming would replace a non-empty directory, RenameAt returns
	// ENOTEMPTY.
	//
	// Preconditions: !rp.Done(). For the final path component in rp,
	// !rp.ShouldFollowSymlink(). oldName is not "." or "..".
	//
	// Postconditions: If RenameAt returns an error returned by
	// ResolvingPath.Resolve*(), then !rp.Done().
	//
	// [1] "The worst of all namespace operations - renaming directory.
	// "Perverted" doesn't even start to describe it. Somebody in UCB had a
	// heck of a trip..." - fs/namei.c:vfs_rename()
	RenameAt(ctx context.Context, rp *ResolvingPath, oldParentVD VirtualDentry, oldName string, opts RenameOptions) error

	// RmdirAt removes the directory at rp.
	//
	// Errors:
	//
	// - If the last path component in rp is ".", RmdirAt returns EINVAL.
	//
	// - If the last path component in rp is "..", RmdirAt returns ENOTEMPTY.
	//
	// - If no file exists at rp, RmdirAt returns ENOENT.
	//
	// - If the file at rp exists but is not a directory, RmdirAt returns
	// ENOTDIR.
	//
	// Preconditions: !rp.Done(). For the final path component in rp,
	// !rp.ShouldFollowSymlink().
	//
	// Postconditions: If RmdirAt returns an error returned by
	// ResolvingPath.Resolve*(), then !rp.Done().
	RmdirAt(ctx context.Context, rp *ResolvingPath) error

	// SetStatAt updates metadata for the file at the given path.
	//
	// Errors:
	//
	// - If opts specifies unsupported options, SetStatAt returns EINVAL.
	SetStatAt(ctx context.Context, rp *ResolvingPath, opts SetStatOptions) error

	// StatAt returns metadata for the file at rp.
	StatAt(ctx context.Context, rp *ResolvingPath, opts StatOptions) (linux.Statx, error)

	// StatFSAt returns metadata for the filesystem containing the file at rp.
	// (This method takes a path because a FilesystemImpl may consist of any
	// number of constituent filesystems.)
	StatFSAt(ctx context.Context, rp *ResolvingPath) (linux.Statfs, error)

	// SymlinkAt creates a symbolic link at rp referring to the given target.
	//
	// Errors:
	//
	// - If the last path component in rp is "." or "..", SymlinkAt returns
	// EEXIST.
	//
	// - If a file already exists at rp, SymlinkAt returns EEXIST.
	//
	// - If rp.MustBeDir(), SymlinkAt returns ENOENT.
	//
	// - If the directory in which the symbolic link would be created has been
	// removed by RmdirAt or RenameAt, SymlinkAt returns ENOENT.
	//
	// Preconditions: !rp.Done(). For the final path component in rp,
	// !rp.ShouldFollowSymlink().
	//
	// Postconditions: If SymlinkAt returns an error returned by
	// ResolvingPath.Resolve*(), then !rp.Done().
	SymlinkAt(ctx context.Context, rp *ResolvingPath, target string) error

	// UnlinkAt removes the file at rp.
	//
	// Errors:
	//
	// - If the last path component in rp is "." or "..", UnlinkAt returns
	// EISDIR.
	//
	// - If no file exists at rp, UnlinkAt returns ENOENT.
	//
	// - If rp.MustBeDir(), and the file at rp exists and is not a directory,
	// UnlinkAt returns ENOTDIR.
	//
	// - If the file at rp exists but is a directory, UnlinkAt returns EISDIR.
	//
	// Preconditions: !rp.Done(). For the final path component in rp,
	// !rp.ShouldFollowSymlink().
	//
	// Postconditions: If UnlinkAt returns an error returned by
	// ResolvingPath.Resolve*(), then !rp.Done().
	UnlinkAt(ctx context.Context, rp *ResolvingPath) error

	// ListxattrAt returns all extended attribute names for the file at rp.
	ListxattrAt(ctx context.Context, rp *ResolvingPath) ([]string, error)

	// GetxattrAt returns the value associated with the given extended
	// attribute for the file at rp.
	GetxattrAt(ctx context.Context, rp *ResolvingPath, name string) (string, error)

	// SetxattrAt changes the value associated with the given extended
	// attribute for the file at rp.
	SetxattrAt(ctx context.Context, rp *ResolvingPath, opts SetxattrOptions) error

	// RemovexattrAt removes the given extended attribute from the file at rp.
	RemovexattrAt(ctx context.Context, rp *ResolvingPath, name string) error

	// PrependPath prepends a path from vd to vd.Mount().Root() to b.
	//
	// If vfsroot.Ok(), it is the contextual VFS root; if it is encountered
	// before vd.Mount().Root(), PrependPath should stop prepending path
	// components and return a PrependPathAtVFSRootError.
	//
	// If traversal of vd.Dentry()'s ancestors encounters an independent
	// ("root") Dentry that is not vd.Mount().Root() (i.e. vd.Dentry() is not a
	// descendant of vd.Mount().Root()), PrependPath should stop prepending
	// path components and return a PrependPathAtNonMountRootError.
	//
	// Filesystems for which Dentries do not have meaningful paths may prepend
	// an arbitrary descriptive string to b and then return a
	// PrependPathSyntheticError.
	//
	// Most implementations can acquire the appropriate locks to ensure that
	// Dentry.Name() and Dentry.Parent() are fixed for vd.Dentry() and all of
	// its ancestors, then call GenericPrependPath.
	//
	// Preconditions: vd.Mount().Filesystem().Impl() == this FilesystemImpl.
	PrependPath(ctx context.Context, vfsroot, vd VirtualDentry, b *fspath.Builder) error

	// TODO: inotify_add_watch(); bind()
}

// PrependPathAtVFSRootError is returned by implementations of
// FilesystemImpl.PrependPath() when they encounter the contextual VFS root.
type PrependPathAtVFSRootError struct{}

// Error implements error.Error.
func (PrependPathAtVFSRootError) Error() string {
	return "vfs.FilesystemImpl.PrependPath() reached VFS root"
}

// PrependPathAtNonMountRootError is returned by implementations of
// FilesystemImpl.PrependPath() when they encounter an independent ancestor
// Dentry that is not the Mount root.
type PrependPathAtNonMountRootError struct{}

// Error implements error.Error.
func (PrependPathAtNonMountRootError) Error() string {
	return "vfs.FilesystemImpl.PrependPath() reached root other than Mount root"
}

// PrependPathSyntheticError is returned by implementations of
// FilesystemImpl.PrependPath() for which prepended names do not represent real
// paths.
type PrependPathSyntheticError struct{}

// Error implements error.Error.
func (PrependPathSyntheticError) Error() string {
	return "vfs.FilesystemImpl.PrependPath() prepended synthetic name"
}
