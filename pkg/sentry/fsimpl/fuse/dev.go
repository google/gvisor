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

package fuse

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const fuseDevMinor = 229

// This is equivalent to linux.SizeOfFUSEHeaderIn
const fuseHeaderOutSize = 16

// fuseDevice implements vfs.Device for /dev/fuse.
//
// +stateify savable
type fuseDevice struct{}

// Open implements vfs.Device.Open.
func (fuseDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	var fd DeviceFD
	if err := fd.vfsfd.Init(&fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// DeviceFD implements vfs.FileDescriptionImpl for /dev/fuse.
//
// +stateify savable
type DeviceFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// mu protects all the queues, maps, buffers and cursors and nextOpID.
	mu sync.Mutex `state:"nosave"`

	// conn is the FUSE connection that this FD is being used for.
	//
	// +checklocks:mu
	conn *connection
}

// RegisterFileAsyncHandler implements vfs.FileDescriptionImpl.RegisterFileAsyncHandler.
func (*DeviceFD) RegisterFileAsyncHandler(*vfs.FileDescription) error {
	return linuxerr.EPERM
}

// UnregisterFileAsyncHandler implements vfs.FileDescriptionImpl.UnregisterFileAsyncHandler.
func (*DeviceFD) UnregisterFileAsyncHandler(*vfs.FileDescription) {}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *DeviceFD) Release(ctx context.Context) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if fd.conn != nil {
		fd.conn.DecRef(ctx)
		fd.conn = nil
	}
}

// connected returns true if fd.conn is set and the connection has not been
// aborted.
// +checklocks:fd.mu
func (fd *DeviceFD) connected() bool {
	if fd.conn != nil {
		fd.conn.mu.Lock()
		defer fd.conn.mu.Unlock()
		return fd.conn.connected
	}
	return false
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *DeviceFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is
	// mounted. If there is an active connection we know there is at least one
	// filesystem mounted.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}

	return 0, linuxerr.ENOSYS
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *DeviceFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}
	return fd.conn.read(ctx, dst)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *DeviceFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is
	// mounted. If there is an active connection we know there is at least one
	// filesystem mounted.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}

	return 0, linuxerr.ENOSYS
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *DeviceFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}
	return fd.conn.write(ctx, src)
}

// Readiness implements vfs.FileDescriptionImpl.Readiness.
func (fd *DeviceFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	var ready waiter.EventMask

	if !fd.connected() {
		ready |= waiter.EventErr
		return ready & mask
	}
	return fd.conn.readiness(ready) & mask
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *DeviceFD) EventRegister(e *waiter.Entry) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return linuxerr.EPERM
	}
	fd.conn.waitQueue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *DeviceFD) EventUnregister(e *waiter.Entry) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return
	}
	fd.conn.waitQueue.EventUnregister(e)
}

// Epollable implements FileDescriptionImpl.Epollable.
func (fd *DeviceFD) Epollable() bool {
	return true
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *DeviceFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	// Operations on /dev/fuse don't make sense until a FUSE filesystem is
	// mounted. If there is an active connection we know there is at least one
	// filesystem mounted.
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.connected() {
		return 0, linuxerr.EPERM
	}

	return 0, linuxerr.ENOSYS
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *DeviceFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	switch cmd {
	case linux.FUSE_DEV_IOC_CLONE:
		t := kernel.TaskFromContext(ctx)
		if t == nil {
			return 0, linuxerr.ESRCH
		}
		var userFuseFD int32
		if _, err := primitive.CopyInt32In(t, args[2].Pointer(), &userFuseFD); err != nil {
			return 0, err
		}
		userFuseFile, _ := t.FDTable().Get(userFuseFD)
		if userFuseFile == nil {
			return 0, linuxerr.EBADF
		}
		defer userFuseFile.DecRef(ctx)
		fuseFD, ok := userFuseFile.Impl().(*DeviceFD)
		if !ok {
			return 0, linuxerr.EINVAL
		}

		fuseFD.mu.Lock()
		if fuseFD.conn == nil {
			fuseFD.mu.Unlock()
			return 0, linuxerr.EINVAL
		}
		conn := fuseFD.conn
		conn.IncRef()
		fuseFD.mu.Unlock()

		fd.mu.Lock()
		defer fd.mu.Unlock()
		if fd.conn != nil {
			conn.DecRef(ctx)
			return 0, linuxerr.EINVAL
		}
		fd.conn = conn

		return 0, nil
	}

	return 0, linuxerr.ENOSYS
}
