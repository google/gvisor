// Copyright 2020 The gVisor Authors.
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

// Package host provides a filesystem implementation for host files imported as
// file descriptors.
package host

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	kernfs.Filesystem
}

// ImportFD takes an fd from the host and wraps it with a FileDescription.
// This is roughly equivalent to fs/host:newFileFromDonatedFD().
func ImportFD(mnt *vfs.Mount, hostFD int, ownerUID auth.KUID, ownerGID auth.KGID, isTTY bool) (*vfs.FileDescription, error) {
	// Must be importing to a mount of host.filesystem.
	fs, ok := mnt.Filesystem().Impl().(*filesystem)
	if !ok {
		return nil, syserror.ENODEV
	}

	// Retrieve metadata.
	var s syscall.Stat_t
	if err := syscall.Fstat(hostFD, &s); err != nil {
		return nil, err
	}

	inode := &inode{
		hostFD:  hostFD,
		donated: true,
		ino:     fs.NextIno(),
		mode:    linux.FileMode(s.Mode),
		uid:     ownerUID,
		gid:     ownerGID,
	}

	fileType := s.Mode & syscall.S_IFMT
	// Pipes, character devices, and sockets can return EWOULDBLOCK for
	// operations that would block.
	mayBlock := fileType == syscall.S_IFIFO || fileType == syscall.S_IFCHR || fileType == syscall.S_IFSOCK

	var (
		vfsfd  *vfs.FileDescription
		fdImpl vfs.FileDescriptionImpl
	)
	if fileType == syscall.S_IFSOCK {
		if isTTY {
			return nil, fmt.Errorf("cannot import host socket as TTY")
		}
		fd := &socketFD{
			hostFileDescription: hostFileDescription{
				inode:    inode,
				mayBlock: mayBlock,
			},
		}
		vfsfd = &fd.vfsfd
		fdImpl = fd
	} else {
		if isTTY {
			fd := &ttyFileFD{
				hostFileDescription: hostFileDescription{
					inode:    inode,
					mayBlock: mayBlock,
				},
			}
			vfsfd = &fd.vfsfd
			fdImpl = fd
		} else {
			// For simplicity, set offset to 0. Technically, we should
			// only set to 0 on files that are not seekable (sockets, pipes, etc.),
			// and use the offset from the host fd otherwise.
			fd := &defaultFileFD{
				hostFileDescription: hostFileDescription{
					inode:    inode,
					mayBlock: mayBlock,
				},
				fileType: fileType,
				mu:       sync.Mutex{},
				offset:   0, /* offset */
			}
			vfsfd = &fd.vfsfd
			fdImpl = fd
		}
	}

	flags, err := fileFlagsFromHostFD(hostFD)
	if err != nil {
		return nil, err
	}

	d := &kernfs.Dentry{}
	d.Init(inode)
	mnt.IncRef()
	if err := vfsfd.Init(fdImpl, uint32(flags), mnt, d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
		mnt.DecRef()
		return nil, err
	}
	return vfsfd, nil
}

// Note that these flags may become out of date, since they can be modified
// on the host, e.g. with fcntl.
func fileFlagsFromHostFD(hostFD int) (int, error) {
	flags, err := unix.FcntlInt(uintptr(hostFD), syscall.F_GETFL, 0)
	if err != nil {
		log.Warningf("Failed to get file flags for donated FD %d: %v", hostFD, err)
		return 0, err
	}
	// TODO(gvisor.dev/issue/1672): implement behavior corresponding to these allowed flags.
	flags &= syscall.O_ACCMODE | syscall.O_DIRECT | syscall.O_NONBLOCK | syscall.O_DSYNC | syscall.O_SYNC | syscall.O_APPEND
	return flags, nil
}

// inode implements kernfs.Inode.
type inode struct {
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink

	// When the reference count reaches zero, the host fd is closed.
	refs.AtomicRefCount

	// hostFD is the host fd that this file was originally created from, which
	// must be available at time of restore. The FD can be closed after
	// descriptor is created. Only set if donated is true.
	//
	// This field is initialized at creation time and is immutable.
	hostFD int

	// donated is true if the host fd was donated by another process.
	//
	// This field is initialized at creation time and is immutable.
	donated bool

	// ino is an inode number unique within this filesystem.
	ino uint64

	// mu protects the inode metadata below.
	mu sync.Mutex

	// mode is the file mode of this inode. Note that this value may become out
	// of date if the mode is changed on the host, e.g. with chmod.
	mode linux.FileMode

	// uid and gid of the file owner. Note that these refer to the owner of the
	// file created on import, not the fd on the host.
	uid auth.KUID
	gid auth.KGID
}

// CheckPermissions implements kernfs.Inode.
func (i *inode) CheckPermissions(ctx context.Context, creds *auth.Credentials, atx vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, atx, false /* isDir */, uint16(i.mode), i.uid, i.gid)
}

// Mode implements kernfs.Inode.
func (i *inode) Mode() linux.FileMode {
	return i.mode
}

// Stat implements kernfs.Inode.
func (i *inode) Stat(_ *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	var s unix.Statx_t
	if err := unix.Statx(i.hostFD, "", int(unix.AT_EMPTY_PATH|opts.Sync), int(opts.Mask), &s); err != nil {
		return linux.Statx{}, err
	}
	ls := unixToLinuxStatx(s)

	// Use our own internal inode number and file owner.
	ls.Ino = i.ino
	ls.UID = uint32(i.uid)
	ls.GID = uint32(i.gid)

	// Update file mode from the host.
	i.mode = linux.FileMode(ls.Mode)

	return ls, nil
}

// SetStat implements kernfs.Inode.
func (i *inode) SetStat(_ *vfs.Filesystem, opts vfs.SetStatOptions) error {
	s := opts.Stat

	m := s.Mask
	if m == 0 {
		return nil
	}
	if m&(linux.STATX_UID|linux.STATX_GID) != 0 {
		return syserror.EPERM
	}
	if m&linux.STATX_MODE != 0 {
		if err := syscall.Fchmod(i.hostFD, uint32(s.Mode)); err != nil {
			return err
		}
		i.mode = linux.FileMode(s.Mode)
	}
	if m&linux.STATX_SIZE != 0 {
		if err := syscall.Ftruncate(i.hostFD, int64(s.Size)); err != nil {
			return err
		}
	}
	if m&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		timestamps := []unix.Timespec{
			toTimespec(s.Atime, m&linux.STATX_ATIME == 0),
			toTimespec(s.Mtime, m&linux.STATX_MTIME == 0),
		}
		if err := unix.UtimesNanoAt(i.hostFD, "", timestamps, int(unix.AT_EMPTY_PATH)); err != nil {
			return err
		}
	}
	return nil
}

// DecRef implements kernfs.Inode.
func (i *inode) DecRef() {
	i.AtomicRefCount.DecRefWithDestructor(i.Destroy)
}

// Destroy implements kernfs.Inode.
func (i *inode) Destroy() {
	if err := unix.Close(i.hostFD); err != nil {
		log.Warningf("failed to close host fd %d: %v", i.hostFD, err)
	}
}

// Open implements kernfs.Inode.
func (i *inode) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// TODO(gvisor.dev/issue/1672): Implement open() for /proc/[pid]/fd/[fd] files.
	return nil, syserror.ENODEV
}

// hostFileDescription is embedded by host fd implementations of FileDescriptionImpl.
type hostFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl

	inode *inode

	// mayBlock is true if the host fd points to a file that can return
	// EWOULDBLOCK for I/O operations.
	//
	// This field is initialized at creation time and is immutable.
	mayBlock bool
}

// SetStat implements vfs.FileDescriptionImpl.
func (f *hostFileDescription) SetStat(_ context.Context, opts vfs.SetStatOptions) error {
	return f.inode.SetStat(nil, opts)
}

// Stat implements vfs.FileDescriptionImpl.
func (f *hostFileDescription) Stat(_ context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	return f.inode.Stat(nil, opts)
}

// Release implements vfs.FileDescriptionImpl.
func (f *hostFileDescription) Release() {
	// noop
}

// socketFD implements vfs.FileDescriptionImpl.
//
// TODO(gvisor.dev/issue/1672): Implement socket fds.
type socketFD struct {
	hostFileDescription
}

// ttyFileFD implements vfs.FileDescriptionImpl.
//
// TODO(gvisor.dev/issue/1672): Implement TTY fds.
type ttyFileFD struct {
	hostFileDescription
}
