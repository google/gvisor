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

package pipe

import (
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// This file contains types enabling the pipe package to be used with the vfs
// package.

// VFSPipe represents the actual pipe, analagous to an inode. VFSPipes should
// not be copied.
type VFSPipe struct {
	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// pipe is the underlying pipe.
	pipe Pipe

	// Channels for synchronizing the creation of new readers and writers
	// of this fifo. See waitFor and newHandleLocked.
	//
	// These are not saved/restored because all waiters are unblocked on
	// save, and either automatically restart (via ERESTARTSYS) or return
	// EINTR on resume. On restarts via ERESTARTSYS, the appropriate
	// channel will be recreated.
	rWakeup chan struct{} `state:"nosave"`
	wWakeup chan struct{} `state:"nosave"`
}

// NewVFSPipe returns an initialized VFSPipe.
func NewVFSPipe(sizeBytes, atomicIOBytes int64) *VFSPipe {
	var vp VFSPipe
	initPipe(&vp.pipe, true /* isNamed */, sizeBytes, atomicIOBytes)
	return &vp
}

// NewVFSPipeFD opens a named pipe. Named pipes have special blocking semantics
// during open:
//
// "Normally, opening the FIFO blocks until the other end is opened also. A
// process can open a FIFO in nonblocking mode. In this case, opening for
// read-only will succeed even if no-one has opened on the write side yet,
// opening for write-only will fail with ENXIO (no such device or address)
// unless the other end has already been opened. Under Linux, opening a FIFO
// for read and write will succeed both in blocking and nonblocking mode. POSIX
// leaves this behavior undefined. This can be used to open a FIFO for writing
// while there are no readers available." - fifo(7)
func (vp *VFSPipe) NewVFSPipeFD(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, vfsfd *vfs.FileDescription, flags uint32) (*VFSPipeFD, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	readable := vfs.MayReadFileWithOpenFlags(flags)
	writable := vfs.MayWriteFileWithOpenFlags(flags)
	if !readable && !writable {
		return nil, syserror.EINVAL
	}

	vfd, err := vp.open(rp, vfsd, vfsfd, flags)
	if err != nil {
		return nil, err
	}

	switch {
	case readable && writable:
		// Pipes opened for read-write always succeed without blocking.
		newHandleLocked(&vp.rWakeup)
		newHandleLocked(&vp.wWakeup)

	case readable:
		newHandleLocked(&vp.rWakeup)
		// If this pipe is being opened as nonblocking and there's no
		// writer, we have to wait for a writer to open the other end.
		if flags&linux.O_NONBLOCK == 0 && !vp.pipe.HasWriters() && !waitFor(&vp.mu, &vp.wWakeup, ctx) {
			return nil, syserror.EINTR
		}

	case writable:
		newHandleLocked(&vp.wWakeup)

		if !vp.pipe.HasReaders() {
			// Nonblocking, write-only opens fail with ENXIO when
			// the read side isn't open yet.
			if flags&linux.O_NONBLOCK != 0 {
				return nil, syserror.ENXIO
			}
			// Wait for a reader to open the other end.
			if !waitFor(&vp.mu, &vp.rWakeup, ctx) {
				return nil, syserror.EINTR
			}
		}

	default:
		panic("invalid pipe flags: must be readable, writable, or both")
	}

	return vfd, nil
}

// Preconditions: vp.mu must be held.
func (vp *VFSPipe) open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, vfsfd *vfs.FileDescription, flags uint32) (*VFSPipeFD, error) {
	var fd VFSPipeFD
	fd.flags = flags
	fd.readable = vfs.MayReadFileWithOpenFlags(flags)
	fd.writable = vfs.MayWriteFileWithOpenFlags(flags)
	fd.vfsfd = vfsfd
	fd.pipe = &vp.pipe
	if fd.writable {
		// The corresponding Mount.EndWrite() is in VFSPipe.Release().
		if err := rp.Mount().CheckBeginWrite(); err != nil {
			return nil, err
		}
	}

	switch {
	case fd.readable && fd.writable:
		vp.pipe.rOpen()
		vp.pipe.wOpen()
	case fd.readable:
		vp.pipe.rOpen()
	case fd.writable:
		vp.pipe.wOpen()
	default:
		panic("invalid pipe flags: must be readable, writable, or both")
	}

	return &fd, nil
}

// VFSPipeFD implements a subset of vfs.FileDescriptionImpl for pipes. It is
// expected that filesystesm will use this in a struct implementing
// vfs.FileDescriptionImpl.
type VFSPipeFD struct {
	pipe     *Pipe
	flags    uint32
	readable bool
	writable bool
	vfsfd    *vfs.FileDescription
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *VFSPipeFD) Release() {
	var event waiter.EventMask
	if fd.readable {
		fd.pipe.rClose()
		event |= waiter.EventIn
	}
	if fd.writable {
		fd.pipe.wClose()
		event |= waiter.EventOut
	}
	if event == 0 {
		panic("invalid pipe flags: must be readable, writable, or both")
	}

	if fd.writable {
		fd.vfsfd.VirtualDentry().Mount().EndWrite()
	}

	fd.pipe.Notify(event)
}

// OnClose implements vfs.FileDescriptionImpl.OnClose.
func (fd *VFSPipeFD) OnClose(_ context.Context) error {
	return nil
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *VFSPipeFD) PRead(_ context.Context, _ usermem.IOSequence, _ int64, _ vfs.ReadOptions) (int64, error) {
	return 0, syserror.ESPIPE
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *VFSPipeFD) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	if !fd.readable {
		return 0, syserror.EINVAL
	}

	return fd.pipe.Read(ctx, dst)
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *VFSPipeFD) PWrite(_ context.Context, _ usermem.IOSequence, _ int64, _ vfs.WriteOptions) (int64, error) {
	return 0, syserror.ESPIPE
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *VFSPipeFD) Write(ctx context.Context, src usermem.IOSequence, _ vfs.WriteOptions) (int64, error) {
	if !fd.writable {
		return 0, syserror.EINVAL
	}

	return fd.pipe.Write(ctx, src)
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *VFSPipeFD) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return fd.pipe.Ioctl(ctx, uio, args)
}
