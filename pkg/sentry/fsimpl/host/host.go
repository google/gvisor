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
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// hostFDDentry implements AnonDentryImpl (and by extension, DentryImpl).
type hostFDDentry struct {
	vfs.AnonDentryDefaultImpl

	// donated is true if the host fd was donated by another process.
	//
	// This field is initialized at creation time and is immutable.
	donated bool

	// hostFD is the host fd that this file was originally created from, which
	// must be available at time of restore. The FD can be closed after
	// descriptor is created. Only set if donated is true.
	//
	// This field is initialized at creation time and is immutable.
	hostFD int

	// ownerUID is the UID of the file owner.
	ownerUID auth.KUID

	// ownerGID is the GID of the file owner.
	ownerGID auth.KGID

	// refs points to a reference count, which is accessed using atomic memory
	// operations.
	//
	// The reference count is shared by all dentries holding the same host fd,
	// which could be more than one if /proc/[pid]/fd/[fd] is opened. When the
	// reference count reaches zero, the host fd is closed.
	refs *int64
}

// IncRef implements AnonDentryImpl.
func (d *hostFDDentry) IncRef() {
	if atomic.AddInt64(d.refs, 1) <= 1 {
		panic("hostFDDentry.IncRef() called without holding a reference")
	}
}

// TryIncRef implements AnonDentryImpl.
func (d *hostFDDentry) TryIncRef() bool {
	for {
		refs := atomic.LoadInt64(d.refs)
		if refs == 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(d.refs, refs, refs+1) {
			return true
		}
	}
}

// DecRef implements AnonDentryImpl.
func (d *hostFDDentry) DecRef() {
	if refs := atomic.AddInt64(d.refs, -1); refs == 0 {
		if err := unix.Close(d.hostFD); err != nil {
			log.Warningf("failed to close host fd %d: %v", err)
		}
	} else if refs < 0 {
		panic("hostFDDentry.DecRef() called without holding a reference")
	}
}

// Open implements AnonDentryImpl.
func (d *hostFDDentry) Open(context.Context, vfs.OpenOptions) (*vfs.FileDescription, error) {
	// TODO(gvisor.dev/issue/1672): Implement open() for /proc/[pid]/fd/[fd] files.
	return nil, syserror.ENODEV
}

// SetStat implements AnonDentryImpl.
func (d *hostFDDentry) SetStat(_ context.Context, opts vfs.SetStatOptions) error {
	s := opts.Stat

	m := s.Mask
	if m == 0 {
		return nil
	}
	if m&(linux.STATX_UID|linux.STATX_GID) > 0 {
		return syserror.EPERM
	}
	if m&linux.STATX_MODE != 0 {
		if err := syscall.Fchmod(d.hostFD, uint32(s.Mode)); err != nil {
			return err
		}
	}
	if m&linux.STATX_SIZE != 0 {
		if err := syscall.Ftruncate(d.hostFD, int64(s.Size)); err != nil {
			return err
		}
	}
	if m&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		timestamps := []unix.Timespec{
			toTimespec(s.Atime, m&linux.STATX_ATIME == 0),
			toTimespec(s.Mtime, m&linux.STATX_MTIME == 0),
		}
		if err := unix.UtimesNanoAt(d.hostFD, "", timestamps, int(unix.AT_EMPTY_PATH)); err != nil {
			return err
		}
	}
	return nil
}

// Stat implements AnonDentryImpl.
func (d *hostFDDentry) Stat(_ context.Context, _ *vfs.AnonFilesystem, opts vfs.StatOptions) (linux.Statx, error) {
	var s unix.Statx_t
	if err := unix.Statx(d.hostFD, "", int(unix.AT_EMPTY_PATH|opts.Sync), int(opts.Mask), &s); err != nil {
		return linux.Statx{}, err
	}
	s.Uid = uint32(d.ownerUID)
	s.Gid = uint32(d.ownerGID)
	return unixToLinuxStatx(s), nil
}

// hostFileDescription is embedded by host fd implementations of FileDescriptionImpl.
type hostFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl

	// UseDentryMetadata should be true on host fd implementations, so that
	// SetStat and Stat use the definitions in hostFDDentry.
	vfs.DentryMetadataFileDescriptionImpl

	// wouldBlock is true if the host fd points to a file that can return
	// EWOULDBLOCK for operations that would block.
	//
	// This field is initialized at creation time and is immutable.
	wouldBlock bool

	// Keep an immutable hostfd here too for convenience/performance??
	hostFD int
}

// Release implements FileDescriptionImpl.
func (f *hostFileDescription) Release() {
	// noop
}

// socketFD implements FileDescriptionImpl.
//
// TODO(gvisor.dev/issue/1672): Implement socket fds.
type socketFD struct {
	hostFileDescription
}

// ttyFileFD implements FileDescriptionImpl.
//
// TODO(gvisor.dev/issue/1672): Implement TTY fds.
type ttyFileFD struct {
	hostFileDescription
}

// ImportHostFD takes an fd from the host and wraps it with a FileDescription.
// This is roughly equivalent to fs/host:newFileFromDonatedFD().
func ImportHostFD(v *vfs.VirtualFilesystem, hostFD int, ownerUID auth.KUID, ownerGID auth.KGID, isTTY bool) (*vfs.FileDescription, error) {

	// Retrieve metadata.
	var s syscall.Stat_t
	if err := syscall.Fstat(hostFD, &s); err != nil {
		return nil, err
	}

	// Get file flags from the host fd to store in FileDescription.
	//
	// Note that these flags may become out-of-date, since they can be modified
	// on the host by fcntl.
	flags, err := unix.FcntlInt(uintptr(hostFD), syscall.F_GETFL, 0)
	if err != nil {
		log.Warningf("Failed to get file flags for donated FD %d: %v", hostFD, err)
		return nil, err
	}

	// TODO(gvisor.dev/issue/1672): implement behavior corresponding to these allowed flags.
	flags &= syscall.O_ACCMODE | syscall.O_DIRECT | syscall.O_NONBLOCK | syscall.O_DSYNC | syscall.O_SYNC | syscall.O_APPEND | syscall.O_RDONLY | syscall.O_WRONLY | syscall.O_RDWR

	fileType := s.Mode & syscall.S_IFMT
	fd := hostFileDescription{
		// Pipes, character devices, and sockets can return EWOULDBLOCK for
		// operations that would block.
		wouldBlock: fileType == syscall.S_IFIFO || fileType == syscall.S_IFCHR || fileType == syscall.S_IFSOCK,
		hostFD:     hostFD,
	}
	donated := true
	var refCount int64 = 1
	vd := v.NewAnonVirtualDentry(&hostFDDentry{
		vfs.AnonDentryDefaultImpl{SyntheticName: fmt.Sprintf("hostfd:[%d]", hostFD)},
		donated,
		hostFD,
		ownerUID,
		ownerGID,
		&refCount,
	})
	opts := vfs.FileDescriptionOptions{UseDentryMetadata: true}
	if fileType == syscall.S_IFSOCK {
		if isTTY {
			return nil, fmt.Errorf("cannot import host socket as TTY")
		}
		if err := fd.vfsfd.Init(&socketFD{fd}, uint32(flags), vd.Mount(), vd.Dentry(), &opts); err != nil {
			return nil, err
		}
	} else {
		if isTTY {
			if err := fd.vfsfd.Init(&ttyFileFD{fd}, uint32(flags), vd.Mount(), vd.Dentry(), &opts); err != nil {
				return nil, err
			}
		} else {
			// For simplicity, set offset to 0. Technically, we should
			// only set to 0 on files that are not seekable (sockets, pipes, etc.),
			// and use the offset from the host fd otherwise.
			defaultFD := defaultFileFD{fd, fileType, sync.Mutex{}, 0 /* offset */}
			if err := fd.vfsfd.Init(&defaultFD, uint32(flags), vd.Mount(), vd.Dentry(), &opts); err != nil {
				return nil, err
			}
		}
	}

	return &fd.vfsfd, nil
}
