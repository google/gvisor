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

// Package vfs implements a virtual filesystem layer.
//
// Lock order:
//
// FilesystemImpl/FileDescriptionImpl locks
//   VirtualFilesystem.mountMu
//     Dentry.mu
//       Locks acquired by FilesystemImpls between Prepare{Delete,Rename}Dentry and Commit{Delete,Rename*}Dentry
//     VirtualFilesystem.filesystemsMu
// VirtualFilesystem.fsTypesMu
//
// Locking Dentry.mu in multiple Dentries requires holding
// VirtualFilesystem.mountMu.
package vfs

import (
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

// A VirtualFilesystem (VFS for short) combines Filesystems in trees of Mounts.
//
// There is no analogue to the VirtualFilesystem type in Linux, as the
// equivalent state in Linux is global.
type VirtualFilesystem struct {
	// mountMu serializes mount mutations.
	//
	// mountMu is analogous to Linux's namespace_sem.
	mountMu sync.Mutex

	// mounts maps (mount parent, mount point) pairs to mounts. (Since mounts
	// are uniquely namespaced, including mount parent in the key correctly
	// handles both bind mounts and mount namespaces; Linux does the same.)
	// Synchronization between mutators and readers is provided by mounts.seq;
	// synchronization between mutators is provided by mountMu.
	//
	// mounts is used to follow mount points during path traversal. We use a
	// single table rather than per-Dentry tables to reduce size (and therefore
	// cache footprint) for the vast majority of Dentries that are not mount
	// points.
	//
	// mounts is analogous to Linux's mount_hashtable.
	mounts mountTable

	// mountpoints maps mount points to mounts at those points in all
	// namespaces. mountpoints is protected by mountMu.
	//
	// mountpoints is used to find mounts that must be umounted due to
	// removal of a mount point Dentry from another mount namespace. ("A file
	// or directory that is a mount point in one namespace that is not a mount
	// point in another namespace, may be renamed, unlinked, or removed
	// (rmdir(2)) in the mount namespace in which it is not a mount point
	// (subject to the usual permission checks)." - mount_namespaces(7))
	//
	// mountpoints is analogous to Linux's mountpoint_hashtable.
	mountpoints map[*Dentry]map[*Mount]struct{}

	// filesystems contains all Filesystems. filesystems is protected by
	// filesystemsMu.
	filesystemsMu sync.Mutex
	filesystems   map[*Filesystem]struct{}

	// fsTypes contains all FilesystemTypes that are usable in the
	// VirtualFilesystem. fsTypes is protected by fsTypesMu.
	fsTypesMu sync.RWMutex
	fsTypes   map[string]FilesystemType
}

// New returns a new VirtualFilesystem with no mounts or FilesystemTypes.
func New() *VirtualFilesystem {
	vfs := &VirtualFilesystem{
		mountpoints: make(map[*Dentry]map[*Mount]struct{}),
		filesystems: make(map[*Filesystem]struct{}),
		fsTypes:     make(map[string]FilesystemType),
	}
	vfs.mounts.Init()
	return vfs
}

// PathOperation specifies the path operated on by a VFS method.
//
// PathOperation is passed to VFS methods by pointer to reduce memory copying:
// it's somewhat large and should never escape. (Options structs are passed by
// pointer to VFS and FileDescription methods for the same reason.)
type PathOperation struct {
	// Root is the VFS root. References on Root are borrowed from the provider
	// of the PathOperation.
	//
	// Invariants: Root.Ok().
	Root VirtualDentry

	// Start is the starting point for the path traversal. References on Start
	// are borrowed from the provider of the PathOperation (i.e. the caller of
	// the VFS method to which the PathOperation was passed).
	//
	// Invariants: Start.Ok(). If Pathname.Absolute, then Start == Root.
	Start VirtualDentry

	// Path is the pathname traversed by this operation.
	Pathname string

	// If FollowFinalSymlink is true, and the Dentry traversed by the final
	// path component represents a symbolic link, the symbolic link should be
	// followed.
	FollowFinalSymlink bool
}

// GetDentryAt returns a VirtualDentry representing the given path, at which a
// file must exist. A reference is taken on the returned VirtualDentry.
func (vfs *VirtualFilesystem) GetDentryAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *GetDentryOptions) (VirtualDentry, error) {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return VirtualDentry{}, err
	}
	for {
		d, err := rp.mount.fs.impl.GetDentryAt(ctx, rp, *opts)
		if err == nil {
			vd := VirtualDentry{
				mount:  rp.mount,
				dentry: d,
			}
			rp.mount.IncRef()
			vfs.putResolvingPath(rp)
			return vd, nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return VirtualDentry{}, err
		}
	}
}

// LinkAt creates a hard link at newpop representing the existing file at
// oldpop.
func (vfs *VirtualFilesystem) LinkAt(ctx context.Context, creds *auth.Credentials, oldpop, newpop *PathOperation) error {
	oldVD, err := vfs.GetDentryAt(ctx, creds, oldpop, &GetDentryOptions{})
	if err != nil {
		return err
	}
	rp, err := vfs.getResolvingPath(creds, newpop)
	if err != nil {
		oldVD.DecRef()
		return err
	}
	for {
		err := rp.mount.fs.impl.LinkAt(ctx, rp, oldVD)
		if err == nil {
			oldVD.DecRef()
			vfs.putResolvingPath(rp)
			return nil
		}
		if !rp.handleError(err) {
			oldVD.DecRef()
			vfs.putResolvingPath(rp)
			return err
		}
	}
}

// MkdirAt creates a directory at the given path.
func (vfs *VirtualFilesystem) MkdirAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *MkdirOptions) error {
	// "Under Linux, apart from the permission bits, the S_ISVTX mode bit is
	// also honored." - mkdir(2)
	opts.Mode &= 0777 | linux.S_ISVTX
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return err
	}
	for {
		err := rp.mount.fs.impl.MkdirAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(rp)
			return nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return err
		}
	}
}

// MknodAt creates a file of the given mode at the given path. It returns an
// error from the syserror package.
func (vfs *VirtualFilesystem) MknodAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *MknodOptions) error {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return nil
	}
	for {
		if err = rp.mount.fs.impl.MknodAt(ctx, rp, *opts); err == nil {
			vfs.putResolvingPath(rp)
			return nil
		}
		// Handle mount traversals.
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return err
		}
	}
}

// OpenAt returns a FileDescription providing access to the file at the given
// path. A reference is taken on the returned FileDescription.
func (vfs *VirtualFilesystem) OpenAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *OpenOptions) (*FileDescription, error) {
	// Remove:
	//
	// - O_LARGEFILE, which we always report in FileDescription status flags
	// since only 64-bit architectures are supported at this time.
	//
	// - O_CLOEXEC, which affects file descriptors and therefore must be
	// handled outside of VFS.
	//
	// - Unknown flags.
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_NOCTTY | linux.O_TRUNC | linux.O_APPEND | linux.O_NONBLOCK | linux.O_DSYNC | linux.O_ASYNC | linux.O_DIRECT | linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NOATIME | linux.O_SYNC | linux.O_PATH | linux.O_TMPFILE
	// Linux's __O_SYNC (which we call linux.O_SYNC) implies O_DSYNC.
	if opts.Flags&linux.O_SYNC != 0 {
		opts.Flags |= linux.O_DSYNC
	}
	// Linux's __O_TMPFILE (which we call linux.O_TMPFILE) must be specified
	// with O_DIRECTORY and a writable access mode (to ensure that it fails on
	// filesystem implementations that do not support it).
	if opts.Flags&linux.O_TMPFILE != 0 {
		if opts.Flags&linux.O_DIRECTORY == 0 {
			return nil, syserror.EINVAL
		}
		if opts.Flags&linux.O_CREAT != 0 {
			return nil, syserror.EINVAL
		}
		if opts.Flags&linux.O_ACCMODE == linux.O_RDONLY {
			return nil, syserror.EINVAL
		}
	}
	// O_PATH causes most other flags to be ignored.
	if opts.Flags&linux.O_PATH != 0 {
		opts.Flags &= linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_PATH
	}
	// "On Linux, the following bits are also honored in mode: [S_ISUID,
	// S_ISGID, S_ISVTX]" - open(2)
	opts.Mode &= 0777 | linux.S_ISUID | linux.S_ISGID | linux.S_ISVTX

	if opts.Flags&linux.O_NOFOLLOW != 0 {
		pop.FollowFinalSymlink = false
	}
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return nil, err
	}
	if opts.Flags&linux.O_DIRECTORY != 0 {
		rp.mustBeDir = true
		rp.mustBeDirOrig = true
	}
	for {
		fd, err := rp.mount.fs.impl.OpenAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(rp)
			return fd, nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return nil, err
		}
	}
}

// ReadlinkAt returns the target of the symbolic link at the given path.
func (vfs *VirtualFilesystem) ReadlinkAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation) (string, error) {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return "", err
	}
	for {
		target, err := rp.mount.fs.impl.ReadlinkAt(ctx, rp)
		if err == nil {
			vfs.putResolvingPath(rp)
			return target, nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return "", err
		}
	}
}

// RenameAt renames the file at oldpop to newpop.
func (vfs *VirtualFilesystem) RenameAt(ctx context.Context, creds *auth.Credentials, oldpop, newpop *PathOperation, opts *RenameOptions) error {
	oldVD, err := vfs.GetDentryAt(ctx, creds, oldpop, &GetDentryOptions{})
	if err != nil {
		return err
	}
	rp, err := vfs.getResolvingPath(creds, newpop)
	if err != nil {
		oldVD.DecRef()
		return err
	}
	for {
		err := rp.mount.fs.impl.RenameAt(ctx, rp, oldVD, *opts)
		if err == nil {
			oldVD.DecRef()
			vfs.putResolvingPath(rp)
			return nil
		}
		if !rp.handleError(err) {
			oldVD.DecRef()
			vfs.putResolvingPath(rp)
			return err
		}
	}
}

// RmdirAt removes the directory at the given path.
func (vfs *VirtualFilesystem) RmdirAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation) error {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return err
	}
	for {
		err := rp.mount.fs.impl.RmdirAt(ctx, rp)
		if err == nil {
			vfs.putResolvingPath(rp)
			return nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return err
		}
	}
}

// SetStatAt changes metadata for the file at the given path.
func (vfs *VirtualFilesystem) SetStatAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *SetStatOptions) error {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return err
	}
	for {
		err := rp.mount.fs.impl.SetStatAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(rp)
			return nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return err
		}
	}
}

// StatAt returns metadata for the file at the given path.
func (vfs *VirtualFilesystem) StatAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *StatOptions) (linux.Statx, error) {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return linux.Statx{}, err
	}
	for {
		stat, err := rp.mount.fs.impl.StatAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(rp)
			return stat, nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return linux.Statx{}, err
		}
	}
}

// StatFSAt returns metadata for the filesystem containing the file at the
// given path.
func (vfs *VirtualFilesystem) StatFSAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation) (linux.Statfs, error) {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return linux.Statfs{}, err
	}
	for {
		statfs, err := rp.mount.fs.impl.StatFSAt(ctx, rp)
		if err == nil {
			vfs.putResolvingPath(rp)
			return statfs, nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return linux.Statfs{}, err
		}
	}
}

// SymlinkAt creates a symbolic link at the given path with the given target.
func (vfs *VirtualFilesystem) SymlinkAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, target string) error {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return err
	}
	for {
		err := rp.mount.fs.impl.SymlinkAt(ctx, rp, target)
		if err == nil {
			vfs.putResolvingPath(rp)
			return nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return err
		}
	}
}

// UnlinkAt deletes the non-directory file at the given path.
func (vfs *VirtualFilesystem) UnlinkAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation) error {
	rp, err := vfs.getResolvingPath(creds, pop)
	if err != nil {
		return err
	}
	for {
		err := rp.mount.fs.impl.UnlinkAt(ctx, rp)
		if err == nil {
			vfs.putResolvingPath(rp)
			return nil
		}
		if !rp.handleError(err) {
			vfs.putResolvingPath(rp)
			return err
		}
	}
}

// SyncAllFilesystems has the semantics of Linux's sync(2).
func (vfs *VirtualFilesystem) SyncAllFilesystems(ctx context.Context) error {
	fss := make(map[*Filesystem]struct{})
	vfs.filesystemsMu.Lock()
	for fs := range vfs.filesystems {
		if !fs.TryIncRef() {
			continue
		}
		fss[fs] = struct{}{}
	}
	vfs.filesystemsMu.Unlock()
	var retErr error
	for fs := range fss {
		if err := fs.impl.Sync(ctx); err != nil && retErr == nil {
			retErr = err
		}
		fs.DecRef()
	}
	return retErr
}

// A VirtualDentry represents a node in a VFS tree, by combining a Dentry
// (which represents a node in a Filesystem's tree) and a Mount (which
// represents the Filesystem's position in a VFS mount tree).
//
// VirtualDentry's semantics are similar to that of a Go interface object
// representing a pointer: it is a copyable value type that represents
// references to another entity. The zero value of VirtualDentry is an "empty
// VirtualDentry", directly analogous to a nil interface object.
// VirtualDentry.Ok() checks that a VirtualDentry is not zero-valued; unless
// otherwise specified, all other VirtualDentry methods require
// VirtualDentry.Ok() == true.
//
// Mounts and Dentries are reference-counted, requiring that users call
// VirtualDentry.{Inc,Dec}Ref() as appropriate. We often colloquially refer to
// references on the Mount and Dentry referred to by a VirtualDentry as
// references on the VirtualDentry itself. Unless otherwise specified, all
// VirtualDentry methods require that a reference is held on the VirtualDentry.
//
// VirtualDentry is analogous to Linux's struct path.
type VirtualDentry struct {
	mount  *Mount
	dentry *Dentry
}

// Ok returns true if vd is not empty. It does not require that a reference is
// held.
func (vd VirtualDentry) Ok() bool {
	return vd.mount != nil
}

// IncRef increments the reference counts on the Mount and Dentry represented
// by vd.
func (vd VirtualDentry) IncRef() {
	vd.mount.IncRef()
	vd.dentry.IncRef()
}

// DecRef decrements the reference counts on the Mount and Dentry represented
// by vd.
func (vd VirtualDentry) DecRef() {
	vd.dentry.DecRef()
	vd.mount.DecRef()
}

// Mount returns the Mount associated with vd. It does not take a reference on
// the returned Mount.
func (vd VirtualDentry) Mount() *Mount {
	return vd.mount
}

// Dentry returns the Dentry associated with vd. It does not take a reference
// on the returned Dentry.
func (vd VirtualDentry) Dentry() *Dentry {
	return vd.dentry
}
