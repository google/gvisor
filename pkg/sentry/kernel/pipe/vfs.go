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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
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
func NewVFSPipe(isNamed bool, sizeBytes, atomicIOBytes int64) *VFSPipe {
	var vp VFSPipe
	initPipe(&vp.pipe, isNamed, sizeBytes, atomicIOBytes)
	return &vp
}

// ReaderWriterPair returns read-only and write-only FDs for vp.
//
// Preconditions: statusFlags should not contain an open access mode.
func (vp *VFSPipe) ReaderWriterPair(mnt *vfs.Mount, vfsd *vfs.Dentry, statusFlags uint32) (*vfs.FileDescription, *vfs.FileDescription) {
	// Connected pipes share the same locks.
	locks := &vfs.FileLocks{}
	return vp.newFD(mnt, vfsd, linux.O_RDONLY|statusFlags, locks), vp.newFD(mnt, vfsd, linux.O_WRONLY|statusFlags, locks)
}

// Open opens the pipe represented by vp.
func (vp *VFSPipe) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, statusFlags uint32, locks *vfs.FileLocks) (*vfs.FileDescription, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	readable := vfs.MayReadFileWithOpenFlags(statusFlags)
	writable := vfs.MayWriteFileWithOpenFlags(statusFlags)
	if !readable && !writable {
		return nil, syserror.EINVAL
	}

	fd := vp.newFD(mnt, vfsd, statusFlags, locks)

	// Named pipes have special blocking semantics during open:
	//
	// "Normally, opening the FIFO blocks until the other end is opened also. A
	// process can open a FIFO in nonblocking mode. In this case, opening for
	// read-only will succeed even if no-one has opened on the write side yet,
	// opening for write-only will fail with ENXIO (no such device or address)
	// unless the other end has already been opened. Under Linux, opening a
	// FIFO for read and write will succeed both in blocking and nonblocking
	// mode. POSIX leaves this behavior undefined. This can be used to open a
	// FIFO for writing while there are no readers available." - fifo(7)
	switch {
	case readable && writable:
		// Pipes opened for read-write always succeed without blocking.
		newHandleLocked(&vp.rWakeup)
		newHandleLocked(&vp.wWakeup)

	case readable:
		newHandleLocked(&vp.rWakeup)
		// If this pipe is being opened as blocking and there's no
		// writer, we have to wait for a writer to open the other end.
		if vp.pipe.isNamed && statusFlags&linux.O_NONBLOCK == 0 && !vp.pipe.HasWriters() && !waitFor(&vp.mu, &vp.wWakeup, ctx) {
			fd.DecRef(ctx)
			return nil, syserror.EINTR
		}

	case writable:
		newHandleLocked(&vp.wWakeup)

		if vp.pipe.isNamed && !vp.pipe.HasReaders() {
			// Non-blocking, write-only opens fail with ENXIO when the read
			// side isn't open yet.
			if statusFlags&linux.O_NONBLOCK != 0 {
				fd.DecRef(ctx)
				return nil, syserror.ENXIO
			}
			// Wait for a reader to open the other end.
			if !waitFor(&vp.mu, &vp.rWakeup, ctx) {
				fd.DecRef(ctx)
				return nil, syserror.EINTR
			}
		}

	default:
		panic("invalid pipe flags: must be readable, writable, or both")
	}

	return fd, nil
}

// Preconditions: vp.mu must be held.
func (vp *VFSPipe) newFD(mnt *vfs.Mount, vfsd *vfs.Dentry, statusFlags uint32, locks *vfs.FileLocks) *vfs.FileDescription {
	fd := &VFSPipeFD{
		pipe: &vp.pipe,
	}
	fd.LockFD.Init(locks)
	fd.vfsfd.Init(fd, statusFlags, mnt, vfsd, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	})

	switch {
	case fd.vfsfd.IsReadable() && fd.vfsfd.IsWritable():
		vp.pipe.rOpen()
		vp.pipe.wOpen()
	case fd.vfsfd.IsReadable():
		vp.pipe.rOpen()
	case fd.vfsfd.IsWritable():
		vp.pipe.wOpen()
	default:
		panic("invalid pipe flags: must be readable, writable, or both")
	}

	return &fd.vfsfd
}

// VFSPipeFD implements vfs.FileDescriptionImpl for pipes. It also implements
// non-atomic usermem.IO methods, allowing it to be passed as usermem.IO to
// other FileDescriptions for splice(2) and tee(2).
type VFSPipeFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD

	pipe *Pipe
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *VFSPipeFD) Release(context.Context) {
	var event waiter.EventMask
	if fd.vfsfd.IsReadable() {
		fd.pipe.rClose()
		event |= waiter.EventOut
	}
	if fd.vfsfd.IsWritable() {
		fd.pipe.wClose()
		event |= waiter.EventIn | waiter.EventHUp
	}
	if event == 0 {
		panic("invalid pipe flags: must be readable, writable, or both")
	}

	fd.pipe.Notify(event)
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *VFSPipeFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	switch {
	case fd.vfsfd.IsReadable() && fd.vfsfd.IsWritable():
		return fd.pipe.rwReadiness()
	case fd.vfsfd.IsReadable():
		return fd.pipe.rReadiness()
	case fd.vfsfd.IsWritable():
		return fd.pipe.wReadiness()
	default:
		panic("pipe FD is neither readable nor writable")
	}
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *VFSPipeFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return syserror.ESPIPE
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *VFSPipeFD) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	fd.pipe.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *VFSPipeFD) EventUnregister(e *waiter.Entry) {
	fd.pipe.EventUnregister(e)
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *VFSPipeFD) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	return fd.pipe.Read(ctx, dst)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *VFSPipeFD) Write(ctx context.Context, src usermem.IOSequence, _ vfs.WriteOptions) (int64, error) {
	return fd.pipe.Write(ctx, src)
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *VFSPipeFD) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	return fd.pipe.Ioctl(ctx, uio, args)
}

// PipeSize implements fcntl(F_GETPIPE_SZ).
func (fd *VFSPipeFD) PipeSize() int64 {
	// Inline Pipe.FifoSize() rather than calling it with nil Context and
	// fs.File and ignoring the returned error (which is always nil).
	fd.pipe.mu.Lock()
	defer fd.pipe.mu.Unlock()
	return fd.pipe.max
}

// SetPipeSize implements fcntl(F_SETPIPE_SZ).
func (fd *VFSPipeFD) SetPipeSize(size int64) (int64, error) {
	return fd.pipe.SetFifoSize(size)
}

// IOSequence returns a useremm.IOSequence that reads up to count bytes from,
// or writes up to count bytes to, fd.
func (fd *VFSPipeFD) IOSequence(count int64) usermem.IOSequence {
	return usermem.IOSequence{
		IO:    fd,
		Addrs: usermem.AddrRangeSeqOf(usermem.AddrRange{0, usermem.Addr(count)}),
	}
}

// CopyIn implements usermem.IO.CopyIn.
func (fd *VFSPipeFD) CopyIn(ctx context.Context, addr usermem.Addr, dst []byte, opts usermem.IOOpts) (int, error) {
	origCount := int64(len(dst))
	n, err := fd.pipe.read(ctx, readOps{
		left: func() int64 {
			return int64(len(dst))
		},
		limit: func(l int64) {
			dst = dst[:l]
		},
		read: func(view *buffer.View) (int64, error) {
			n, err := view.ReadAt(dst, 0)
			view.TrimFront(int64(n))
			return int64(n), err
		},
	})
	if n > 0 {
		fd.pipe.Notify(waiter.EventOut)
	}
	if err == nil && n != origCount {
		return int(n), syserror.ErrWouldBlock
	}
	return int(n), err
}

// CopyOut implements usermem.IO.CopyOut.
func (fd *VFSPipeFD) CopyOut(ctx context.Context, addr usermem.Addr, src []byte, opts usermem.IOOpts) (int, error) {
	origCount := int64(len(src))
	n, err := fd.pipe.write(ctx, writeOps{
		left: func() int64 {
			return int64(len(src))
		},
		limit: func(l int64) {
			src = src[:l]
		},
		write: func(view *buffer.View) (int64, error) {
			view.Append(src)
			return int64(len(src)), nil
		},
	})
	if n > 0 {
		fd.pipe.Notify(waiter.EventIn)
	}
	if err == nil && n != origCount {
		return int(n), syserror.ErrWouldBlock
	}
	return int(n), err
}

// ZeroOut implements usermem.IO.ZeroOut.
func (fd *VFSPipeFD) ZeroOut(ctx context.Context, addr usermem.Addr, toZero int64, opts usermem.IOOpts) (int64, error) {
	origCount := toZero
	n, err := fd.pipe.write(ctx, writeOps{
		left: func() int64 {
			return toZero
		},
		limit: func(l int64) {
			toZero = l
		},
		write: func(view *buffer.View) (int64, error) {
			view.Grow(view.Size()+toZero, true /* zero */)
			return toZero, nil
		},
	})
	if n > 0 {
		fd.pipe.Notify(waiter.EventIn)
	}
	if err == nil && n != origCount {
		return n, syserror.ErrWouldBlock
	}
	return n, err
}

// CopyInTo implements usermem.IO.CopyInTo.
func (fd *VFSPipeFD) CopyInTo(ctx context.Context, ars usermem.AddrRangeSeq, dst safemem.Writer, opts usermem.IOOpts) (int64, error) {
	count := ars.NumBytes()
	if count == 0 {
		return 0, nil
	}
	origCount := count
	n, err := fd.pipe.read(ctx, readOps{
		left: func() int64 {
			return count
		},
		limit: func(l int64) {
			count = l
		},
		read: func(view *buffer.View) (int64, error) {
			n, err := view.ReadToSafememWriter(dst, uint64(count))
			view.TrimFront(int64(n))
			return int64(n), err
		},
	})
	if n > 0 {
		fd.pipe.Notify(waiter.EventOut)
	}
	if err == nil && n != origCount {
		return n, syserror.ErrWouldBlock
	}
	return n, err
}

// CopyOutFrom implements usermem.IO.CopyOutFrom.
func (fd *VFSPipeFD) CopyOutFrom(ctx context.Context, ars usermem.AddrRangeSeq, src safemem.Reader, opts usermem.IOOpts) (int64, error) {
	count := ars.NumBytes()
	if count == 0 {
		return 0, nil
	}
	origCount := count
	n, err := fd.pipe.write(ctx, writeOps{
		left: func() int64 {
			return count
		},
		limit: func(l int64) {
			count = l
		},
		write: func(view *buffer.View) (int64, error) {
			n, err := view.WriteFromSafememReader(src, uint64(count))
			return int64(n), err
		},
	})
	if n > 0 {
		fd.pipe.Notify(waiter.EventIn)
	}
	if err == nil && n != origCount {
		return n, syserror.ErrWouldBlock
	}
	return n, err
}

// SwapUint32 implements usermem.IO.SwapUint32.
func (fd *VFSPipeFD) SwapUint32(ctx context.Context, addr usermem.Addr, new uint32, opts usermem.IOOpts) (uint32, error) {
	// How did a pipe get passed as the virtual address space to futex(2)?
	panic("VFSPipeFD.SwapUint32 called unexpectedly")
}

// CompareAndSwapUint32 implements usermem.IO.CompareAndSwapUint32.
func (fd *VFSPipeFD) CompareAndSwapUint32(ctx context.Context, addr usermem.Addr, old, new uint32, opts usermem.IOOpts) (uint32, error) {
	panic("VFSPipeFD.CompareAndSwapUint32 called unexpectedly")
}

// LoadUint32 implements usermem.IO.LoadUint32.
func (fd *VFSPipeFD) LoadUint32(ctx context.Context, addr usermem.Addr, opts usermem.IOOpts) (uint32, error) {
	panic("VFSPipeFD.LoadUint32 called unexpectedly")
}

// Splice reads up to count bytes from src and writes them to dst. It returns
// the number of bytes moved.
//
// Preconditions: count > 0.
func Splice(ctx context.Context, dst, src *VFSPipeFD, count int64) (int64, error) {
	return spliceOrTee(ctx, dst, src, count, true /* removeFromSrc */)
}

// Tee reads up to count bytes from src and writes them to dst, without
// removing the read bytes from src. It returns the number of bytes copied.
//
// Preconditions: count > 0.
func Tee(ctx context.Context, dst, src *VFSPipeFD, count int64) (int64, error) {
	return spliceOrTee(ctx, dst, src, count, false /* removeFromSrc */)
}

// Preconditions: count > 0.
func spliceOrTee(ctx context.Context, dst, src *VFSPipeFD, count int64, removeFromSrc bool) (int64, error) {
	if dst.pipe == src.pipe {
		return 0, syserror.EINVAL
	}

	lockTwoPipes(dst.pipe, src.pipe)
	defer dst.pipe.mu.Unlock()
	defer src.pipe.mu.Unlock()

	n, err := dst.pipe.writeLocked(ctx, writeOps{
		left: func() int64 {
			return count
		},
		limit: func(l int64) {
			count = l
		},
		write: func(dstView *buffer.View) (int64, error) {
			return src.pipe.readLocked(ctx, readOps{
				left: func() int64 {
					return count
				},
				limit: func(l int64) {
					count = l
				},
				read: func(srcView *buffer.View) (int64, error) {
					n, err := srcView.ReadToSafememWriter(dstView, uint64(count))
					if n > 0 && removeFromSrc {
						srcView.TrimFront(int64(n))
					}
					return int64(n), err
				},
			})
		},
	})
	if n > 0 {
		dst.pipe.Notify(waiter.EventIn)
		src.pipe.Notify(waiter.EventOut)
	}
	return n, err
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (fd *VFSPipeFD) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return fd.Locks().LockPOSIX(ctx, &fd.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (fd *VFSPipeFD) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return fd.Locks().UnlockPOSIX(ctx, &fd.vfsfd, uid, start, length, whence)
}
