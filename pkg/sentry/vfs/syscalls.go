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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

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

// MkdirAt creates a directory at the given path.
func (vfs *VirtualFilesystem) MkdirAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *MkdirOptions) error {
	// "Under Linux, apart from the permission bits, the S_ISVTX mode bit is
	// also honored." - mkdir(2)
	opts.Mode &= 01777
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
	opts.Mode &= 07777

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

// StatusFlags returns file description status flags.
func (fd *FileDescription) StatusFlags(ctx context.Context) (uint32, error) {
	flags, err := fd.impl.StatusFlags(ctx)
	flags |= linux.O_LARGEFILE
	return flags, err
}

// SetStatusFlags sets file description status flags.
func (fd *FileDescription) SetStatusFlags(ctx context.Context, flags uint32) error {
	return fd.impl.SetStatusFlags(ctx, flags)
}

// TODO:
//
// - VFS.SyncAllFilesystems() for sync(2)
//
// - Something for syncfs(2)
//
// - VFS.LinkAt()
//
// - VFS.ReadlinkAt()
//
// - VFS.RenameAt()
//
// - VFS.RmdirAt()
//
// - VFS.SetStatAt()
//
// - VFS.StatFSAt()
//
// - VFS.SymlinkAt()
//
// - VFS.UmountAt()
//
// - VFS.UnlinkAt()
//
// - FileDescription.(almost everything)
