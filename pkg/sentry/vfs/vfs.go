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
// EpollInstance.interestMu
//   FileDescription.epollMu
//     FilesystemImpl/FileDescriptionImpl locks
//       VirtualFilesystem.mountMu
//         Dentry.mu
//           Locks acquired by FilesystemImpls between Prepare{Delete,Rename}Dentry and Commit{Delete,Rename*}Dentry
//         VirtualFilesystem.filesystemsMu
//       EpollInstance.mu
//       Inotify.mu
//         Watches.mu
//           Inotify.evMu
// VirtualFilesystem.fsTypesMu
//
// Locking Dentry.mu in multiple Dentries requires holding
// VirtualFilesystem.mountMu. Locking EpollInstance.interestMu in multiple
// EpollInstances requires holding epollCycleMu.
package vfs

import (
	"fmt"
	"path"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// A VirtualFilesystem (VFS for short) combines Filesystems in trees of Mounts.
//
// There is no analogue to the VirtualFilesystem type in Linux, as the
// equivalent state in Linux is global.
//
// +stateify savable
type VirtualFilesystem struct {
	// mountMu serializes mount mutations.
	//
	// mountMu is analogous to Linux's namespace_sem.
	mountMu sync.Mutex `state:"nosave"`

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
	mounts mountTable `state:".([]*Mount)"`

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

	// lastMountID is the last allocated mount ID. lastMountID is accessed
	// using atomic memory operations.
	lastMountID uint64

	// anonMount is a Mount, not included in mounts or mountpoints,
	// representing an anonFilesystem. anonMount is used to back
	// VirtualDentries returned by VirtualFilesystem.NewAnonVirtualDentry().
	// anonMount is immutable.
	//
	// anonMount is analogous to Linux's anon_inode_mnt.
	anonMount *Mount

	// devices contains all registered Devices. devices is protected by
	// devicesMu.
	devicesMu sync.RWMutex `state:"nosave"`
	devices   map[devTuple]*registeredDevice

	// anonBlockDevMinor contains all allocated anonymous block device minor
	// numbers. anonBlockDevMinorNext is a lower bound for the smallest
	// unallocated anonymous block device number. anonBlockDevMinorNext and
	// anonBlockDevMinor are protected by anonBlockDevMinorMu.
	anonBlockDevMinorMu   sync.Mutex `state:"nosave"`
	anonBlockDevMinorNext uint32
	anonBlockDevMinor     map[uint32]struct{}

	// fsTypes contains all registered FilesystemTypes. fsTypes is protected by
	// fsTypesMu.
	fsTypesMu sync.RWMutex `state:"nosave"`
	fsTypes   map[string]*registeredFilesystemType

	// filesystems contains all Filesystems. filesystems is protected by
	// filesystemsMu.
	filesystemsMu sync.Mutex `state:"nosave"`
	filesystems   map[*Filesystem]struct{}
}

// Init initializes a new VirtualFilesystem with no mounts or FilesystemTypes.
func (vfs *VirtualFilesystem) Init(ctx context.Context) error {
	if vfs.mountpoints != nil {
		panic("VFS already initialized")
	}
	vfs.mountpoints = make(map[*Dentry]map[*Mount]struct{})
	vfs.devices = make(map[devTuple]*registeredDevice)
	vfs.anonBlockDevMinorNext = 1
	vfs.anonBlockDevMinor = make(map[uint32]struct{})
	vfs.fsTypes = make(map[string]*registeredFilesystemType)
	vfs.filesystems = make(map[*Filesystem]struct{})
	vfs.mounts.Init()

	// Construct vfs.anonMount.
	anonfsDevMinor, err := vfs.GetAnonBlockDevMinor()
	if err != nil {
		// This shouldn't be possible since anonBlockDevMinorNext was
		// initialized to 1 above (no device numbers have been allocated yet).
		panic(fmt.Sprintf("VirtualFilesystem.Init: device number allocation for anonfs failed: %v", err))
	}
	anonfs := anonFilesystem{
		devMinor: anonfsDevMinor,
	}
	anonfs.vfsfs.Init(vfs, &anonFilesystemType{}, &anonfs)
	defer anonfs.vfsfs.DecRef(ctx)
	anonMount, err := vfs.NewDisconnectedMount(&anonfs.vfsfs, nil, &MountOptions{})
	if err != nil {
		// We should not be passing any MountOptions that would cause
		// construction of this mount to fail.
		panic(fmt.Sprintf("VirtualFilesystem.Init: anonfs mount failed: %v", err))
	}
	vfs.anonMount = anonMount

	return nil
}

// Release drops references on filesystem objects held by vfs.
//
// Precondition: This must be called after VFS.Init() has succeeded.
func (vfs *VirtualFilesystem) Release(ctx context.Context) {
	vfs.anonMount.DecRef(ctx)
	for _, fst := range vfs.fsTypes {
		fst.fsType.Release(ctx)
	}
}

// PathOperation specifies the path operated on by a VFS method.
//
// PathOperation is passed to VFS methods by pointer to reduce memory copying:
// it's somewhat large and should never escape. (Options structs are passed by
// pointer to VFS and FileDescription methods for the same reason.)
//
// +stateify savable
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
	// Invariants: Start.Ok(). If Path.Absolute, then Start == Root.
	Start VirtualDentry

	// Path is the pathname traversed by this operation.
	Path fspath.Path

	// If FollowFinalSymlink is true, and the Dentry traversed by the final
	// path component represents a symbolic link, the symbolic link should be
	// followed.
	FollowFinalSymlink bool
}

// AccessAt checks whether a user with creds has access to the file at
// the given path.
func (vfs *VirtualFilesystem) AccessAt(ctx context.Context, creds *auth.Credentials, ats AccessTypes, pop *PathOperation) error {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.AccessAt(ctx, rp, creds, ats)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// GetDentryAt returns a VirtualDentry representing the given path, at which a
// file must exist. A reference is taken on the returned VirtualDentry.
func (vfs *VirtualFilesystem) GetDentryAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *GetDentryOptions) (VirtualDentry, error) {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		d, err := rp.mount.fs.impl.GetDentryAt(ctx, rp, *opts)
		if err == nil {
			vd := VirtualDentry{
				mount:  rp.mount,
				dentry: d,
			}
			rp.mount.IncRef()
			vfs.putResolvingPath(ctx, rp)
			return vd, nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return VirtualDentry{}, err
		}
	}
}

// Preconditions: pop.Path.Begin.Ok().
func (vfs *VirtualFilesystem) getParentDirAndName(ctx context.Context, creds *auth.Credentials, pop *PathOperation) (VirtualDentry, string, error) {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		parent, err := rp.mount.fs.impl.GetParentDentryAt(ctx, rp)
		if err == nil {
			parentVD := VirtualDentry{
				mount:  rp.mount,
				dentry: parent,
			}
			rp.mount.IncRef()
			name := rp.Component()
			vfs.putResolvingPath(ctx, rp)
			return parentVD, name, nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.GetParentDentryAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return VirtualDentry{}, "", err
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

	if !newpop.Path.Begin.Ok() {
		oldVD.DecRef(ctx)
		if newpop.Path.Absolute {
			return syserror.EEXIST
		}
		return syserror.ENOENT
	}
	if newpop.FollowFinalSymlink {
		oldVD.DecRef(ctx)
		ctx.Warningf("VirtualFilesystem.LinkAt: file creation paths can't follow final symlink")
		return syserror.EINVAL
	}

	rp := vfs.getResolvingPath(creds, newpop)
	for {
		err := rp.mount.fs.impl.LinkAt(ctx, rp, oldVD)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			oldVD.DecRef(ctx)
			return nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.LinkAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			oldVD.DecRef(ctx)
			return err
		}
	}
}

// MkdirAt creates a directory at the given path.
func (vfs *VirtualFilesystem) MkdirAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *MkdirOptions) error {
	if !pop.Path.Begin.Ok() {
		// pop.Path should not be empty in operations that create/delete files.
		// This is consistent with mkdirat(dirfd, "", mode).
		if pop.Path.Absolute {
			return syserror.EEXIST
		}
		return syserror.ENOENT
	}
	if pop.FollowFinalSymlink {
		ctx.Warningf("VirtualFilesystem.MkdirAt: file creation paths can't follow final symlink")
		return syserror.EINVAL
	}
	// "Under Linux, apart from the permission bits, the S_ISVTX mode bit is
	// also honored." - mkdir(2)
	opts.Mode &= 0777 | linux.S_ISVTX

	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.MkdirAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.MkdirAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// MknodAt creates a file of the given mode at the given path. It returns an
// error from the syserror package.
func (vfs *VirtualFilesystem) MknodAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *MknodOptions) error {
	if !pop.Path.Begin.Ok() {
		// pop.Path should not be empty in operations that create/delete files.
		// This is consistent with mknodat(dirfd, "", mode, dev).
		if pop.Path.Absolute {
			return syserror.EEXIST
		}
		return syserror.ENOENT
	}
	if pop.FollowFinalSymlink {
		ctx.Warningf("VirtualFilesystem.MknodAt: file creation paths can't follow final symlink")
		return syserror.EINVAL
	}

	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.MknodAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.MknodAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// OpenAt returns a FileDescription providing access to the file at the given
// path. A reference is taken on the returned FileDescription.
func (vfs *VirtualFilesystem) OpenAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *OpenOptions) (*FileDescription, error) {
	// Remove:
	//
	// - O_CLOEXEC, which affects file descriptors and therefore must be
	// handled outside of VFS.
	//
	// - Unknown flags.
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_NOCTTY | linux.O_TRUNC | linux.O_APPEND | linux.O_NONBLOCK | linux.O_DSYNC | linux.O_ASYNC | linux.O_DIRECT | linux.O_LARGEFILE | linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NOATIME | linux.O_SYNC | linux.O_PATH | linux.O_TMPFILE
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
	rp := vfs.getResolvingPath(creds, pop)
	if opts.Flags&linux.O_DIRECTORY != 0 {
		rp.mustBeDir = true
		rp.mustBeDirOrig = true
	}
	for {
		fd, err := rp.mount.fs.impl.OpenAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)

			if opts.FileExec {
				if fd.Mount().Flags.NoExec {
					fd.DecRef(ctx)
					return nil, syserror.EACCES
				}

				// Only a regular file can be executed.
				stat, err := fd.Stat(ctx, StatOptions{Mask: linux.STATX_TYPE})
				if err != nil {
					fd.DecRef(ctx)
					return nil, err
				}
				if stat.Mask&linux.STATX_TYPE == 0 || stat.Mode&linux.S_IFMT != linux.S_IFREG {
					fd.DecRef(ctx)
					return nil, syserror.EACCES
				}
			}

			fd.Dentry().InotifyWithParent(ctx, linux.IN_OPEN, 0, PathEvent)
			return fd, nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return nil, err
		}
	}
}

// ReadlinkAt returns the target of the symbolic link at the given path.
func (vfs *VirtualFilesystem) ReadlinkAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation) (string, error) {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		target, err := rp.mount.fs.impl.ReadlinkAt(ctx, rp)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return target, nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return "", err
		}
	}
}

// RenameAt renames the file at oldpop to newpop.
func (vfs *VirtualFilesystem) RenameAt(ctx context.Context, creds *auth.Credentials, oldpop, newpop *PathOperation, opts *RenameOptions) error {
	if !oldpop.Path.Begin.Ok() {
		if oldpop.Path.Absolute {
			return syserror.EBUSY
		}
		return syserror.ENOENT
	}
	if oldpop.FollowFinalSymlink {
		ctx.Warningf("VirtualFilesystem.RenameAt: source path can't follow final symlink")
		return syserror.EINVAL
	}

	oldParentVD, oldName, err := vfs.getParentDirAndName(ctx, creds, oldpop)
	if err != nil {
		return err
	}
	if oldName == "." || oldName == ".." {
		oldParentVD.DecRef(ctx)
		return syserror.EBUSY
	}

	if !newpop.Path.Begin.Ok() {
		oldParentVD.DecRef(ctx)
		if newpop.Path.Absolute {
			return syserror.EBUSY
		}
		return syserror.ENOENT
	}
	if newpop.FollowFinalSymlink {
		oldParentVD.DecRef(ctx)
		ctx.Warningf("VirtualFilesystem.RenameAt: destination path can't follow final symlink")
		return syserror.EINVAL
	}

	rp := vfs.getResolvingPath(creds, newpop)
	renameOpts := *opts
	if oldpop.Path.Dir {
		renameOpts.MustBeDir = true
	}
	for {
		err := rp.mount.fs.impl.RenameAt(ctx, rp, oldParentVD, oldName, renameOpts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			oldParentVD.DecRef(ctx)
			return nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.RenameAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			oldParentVD.DecRef(ctx)
			return err
		}
	}
}

// RmdirAt removes the directory at the given path.
func (vfs *VirtualFilesystem) RmdirAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation) error {
	if !pop.Path.Begin.Ok() {
		// pop.Path should not be empty in operations that create/delete files.
		// This is consistent with unlinkat(dirfd, "", AT_REMOVEDIR).
		if pop.Path.Absolute {
			return syserror.EBUSY
		}
		return syserror.ENOENT
	}
	if pop.FollowFinalSymlink {
		ctx.Warningf("VirtualFilesystem.RmdirAt: file deletion paths can't follow final symlink")
		return syserror.EINVAL
	}

	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.RmdirAt(ctx, rp)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.RmdirAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// SetStatAt changes metadata for the file at the given path.
func (vfs *VirtualFilesystem) SetStatAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *SetStatOptions) error {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.SetStatAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// StatAt returns metadata for the file at the given path.
func (vfs *VirtualFilesystem) StatAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *StatOptions) (linux.Statx, error) {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		stat, err := rp.mount.fs.impl.StatAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return stat, nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return linux.Statx{}, err
		}
	}
}

// StatFSAt returns metadata for the filesystem containing the file at the
// given path.
func (vfs *VirtualFilesystem) StatFSAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation) (linux.Statfs, error) {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		statfs, err := rp.mount.fs.impl.StatFSAt(ctx, rp)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return statfs, nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return linux.Statfs{}, err
		}
	}
}

// SymlinkAt creates a symbolic link at the given path with the given target.
func (vfs *VirtualFilesystem) SymlinkAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, target string) error {
	if !pop.Path.Begin.Ok() {
		// pop.Path should not be empty in operations that create/delete files.
		// This is consistent with symlinkat(oldpath, newdirfd, "").
		if pop.Path.Absolute {
			return syserror.EEXIST
		}
		return syserror.ENOENT
	}
	if pop.FollowFinalSymlink {
		ctx.Warningf("VirtualFilesystem.SymlinkAt: file creation paths can't follow final symlink")
		return syserror.EINVAL
	}

	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.SymlinkAt(ctx, rp, target)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.SymlinkAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// UnlinkAt deletes the non-directory file at the given path.
func (vfs *VirtualFilesystem) UnlinkAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation) error {
	if !pop.Path.Begin.Ok() {
		// pop.Path should not be empty in operations that create/delete files.
		// This is consistent with unlinkat(dirfd, "", 0).
		if pop.Path.Absolute {
			return syserror.EBUSY
		}
		return syserror.ENOENT
	}
	if pop.FollowFinalSymlink {
		ctx.Warningf("VirtualFilesystem.UnlinkAt: file deletion paths can't follow final symlink")
		return syserror.EINVAL
	}

	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.UnlinkAt(ctx, rp)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.UnlinkAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// BoundEndpointAt gets the bound endpoint at the given path, if one exists.
func (vfs *VirtualFilesystem) BoundEndpointAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *BoundEndpointOptions) (transport.BoundEndpoint, error) {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		bep, err := rp.mount.fs.impl.BoundEndpointAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return bep, nil
		}
		if checkInvariants {
			if rp.canHandleError(err) && rp.Done() {
				panic(fmt.Sprintf("%T.BoundEndpointAt() consumed all path components and returned %v", rp.mount.fs.impl, err))
			}
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return nil, err
		}
	}
}

// ListXattrAt returns all extended attribute names for the file at the given
// path.
func (vfs *VirtualFilesystem) ListXattrAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, size uint64) ([]string, error) {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		names, err := rp.mount.fs.impl.ListXattrAt(ctx, rp, size)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return names, nil
		}
		if err == syserror.ENOTSUP {
			// Linux doesn't actually return ENOTSUP in this case; instead,
			// fs/xattr.c:vfs_listxattr() falls back to allowing the security
			// subsystem to return security extended attributes, which by
			// default don't exist.
			vfs.putResolvingPath(ctx, rp)
			return nil, nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return nil, err
		}
	}
}

// GetXattrAt returns the value associated with the given extended attribute
// for the file at the given path.
func (vfs *VirtualFilesystem) GetXattrAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *GetXattrOptions) (string, error) {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		val, err := rp.mount.fs.impl.GetXattrAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return val, nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return "", err
		}
	}
}

// SetXattrAt changes the value associated with the given extended attribute
// for the file at the given path.
func (vfs *VirtualFilesystem) SetXattrAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *SetXattrOptions) error {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.SetXattrAt(ctx, rp, *opts)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// RemoveXattrAt removes the given extended attribute from the file at rp.
func (vfs *VirtualFilesystem) RemoveXattrAt(ctx context.Context, creds *auth.Credentials, pop *PathOperation, name string) error {
	rp := vfs.getResolvingPath(creds, pop)
	for {
		err := rp.mount.fs.impl.RemoveXattrAt(ctx, rp, name)
		if err == nil {
			vfs.putResolvingPath(ctx, rp)
			return nil
		}
		if !rp.handleError(ctx, err) {
			vfs.putResolvingPath(ctx, rp)
			return err
		}
	}
}

// SyncAllFilesystems has the semantics of Linux's sync(2).
func (vfs *VirtualFilesystem) SyncAllFilesystems(ctx context.Context) error {
	var retErr error
	for fs := range vfs.getFilesystems() {
		if err := fs.impl.Sync(ctx); err != nil && retErr == nil {
			retErr = err
		}
		fs.DecRef(ctx)
	}
	return retErr
}

func (vfs *VirtualFilesystem) getFilesystems() map[*Filesystem]struct{} {
	fss := make(map[*Filesystem]struct{})
	vfs.filesystemsMu.Lock()
	defer vfs.filesystemsMu.Unlock()
	for fs := range vfs.filesystems {
		if !fs.TryIncRef() {
			continue
		}
		fss[fs] = struct{}{}
	}
	return fss
}

// MkdirAllAt recursively creates non-existent directories on the given path
// (including the last component).
func (vfs *VirtualFilesystem) MkdirAllAt(ctx context.Context, currentPath string, root VirtualDentry, creds *auth.Credentials, mkdirOpts *MkdirOptions) error {
	pop := &PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(currentPath),
	}
	stat, err := vfs.StatAt(ctx, creds, pop, &StatOptions{Mask: linux.STATX_TYPE})
	switch err {
	case nil:
		if stat.Mask&linux.STATX_TYPE == 0 || stat.Mode&linux.FileTypeMask != linux.ModeDirectory {
			return syserror.ENOTDIR
		}
		// Directory already exists.
		return nil
	case syserror.ENOENT:
		// Expected, we will create the dir.
	default:
		return fmt.Errorf("stat failed for %q during directory creation: %w", currentPath, err)
	}

	// Recurse to ensure parent is created and then create the final directory.
	if err := vfs.MkdirAllAt(ctx, path.Dir(currentPath), root, creds, mkdirOpts); err != nil {
		return err
	}
	if err := vfs.MkdirAt(ctx, creds, pop, mkdirOpts); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", currentPath, err)
	}
	return nil
}

// MakeSyntheticMountpoint creates parent directories of target if they do not
// exist and attempts to create a directory for the mountpoint. If a
// non-directory file already exists there then we allow it.
func (vfs *VirtualFilesystem) MakeSyntheticMountpoint(ctx context.Context, target string, root VirtualDentry, creds *auth.Credentials) error {
	mkdirOpts := &MkdirOptions{Mode: 0777, ForSyntheticMountpoint: true}

	// Make sure the parent directory of target exists.
	if err := vfs.MkdirAllAt(ctx, path.Dir(target), root, creds, mkdirOpts); err != nil {
		return fmt.Errorf("failed to create parent directory of mountpoint %q: %w", target, err)
	}

	// Attempt to mkdir the final component. If a file (of any type) exists
	// then we let allow mounting on top of that because we do not require the
	// target to be an existing directory, unlike Linux mount(2).
	if err := vfs.MkdirAt(ctx, creds, &PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(target),
	}, mkdirOpts); err != nil && err != syserror.EEXIST {
		return fmt.Errorf("failed to create mountpoint %q: %w", target, err)
	}
	return nil
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
//
// +stateify savable
type VirtualDentry struct {
	mount  *Mount
	dentry *Dentry
}

// MakeVirtualDentry creates a VirtualDentry.
func MakeVirtualDentry(mount *Mount, dentry *Dentry) VirtualDentry {
	return VirtualDentry{
		mount:  mount,
		dentry: dentry,
	}
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
func (vd VirtualDentry) DecRef(ctx context.Context) {
	vd.dentry.DecRef(ctx)
	vd.mount.DecRef(ctx)
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
