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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// This file contains types enabling the pipe package to be used with the vfs
// package.

// VFSPipe represents the actual pipe, analagous to an inode. VFSPipes should
// not be copied.
//
// +stateify savable
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
func NewVFSPipe(isNamed bool, sizeBytes int64) *VFSPipe {
	var vp VFSPipe
	initPipe(&vp.pipe, isNamed, sizeBytes)
	return &vp
}

// ReaderWriterPair returns read-only and write-only FDs for vp.
//
// Preconditions: statusFlags should not contain an open access mode.
func (vp *VFSPipe) ReaderWriterPair(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, statusFlags uint32) (*vfs.FileDescription, *vfs.FileDescription, error) {
	// Connected pipes share the same locks.
	locks := &vfs.FileLocks{}
	r, err := vp.newFD(mnt, vfsd, linux.O_RDONLY|statusFlags, locks)
	if err != nil {
		return nil, nil, err
	}
	w, err := vp.newFD(mnt, vfsd, linux.O_WRONLY|statusFlags, locks)
	if err != nil {
		r.DecRef(ctx)
		return nil, nil, err
	}
	return r, w, nil
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (*VFSPipe) Allocate(context.Context, uint64, uint64, uint64) error {
	return linuxerr.ESPIPE
}

// Open opens the pipe represented by vp.
func (vp *VFSPipe) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, statusFlags uint32, locks *vfs.FileLocks) (*vfs.FileDescription, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	readable := vfs.MayReadFileWithOpenFlags(statusFlags)
	writable := vfs.MayWriteFileWithOpenFlags(statusFlags)
	if !readable && !writable {
		return nil, linuxerr.EINVAL
	}

	fd, err := vp.newFD(mnt, vfsd, statusFlags, locks)
	if err != nil {
		return nil, err
	}

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
			return nil, linuxerr.EINTR
		}

	case writable:
		newHandleLocked(&vp.wWakeup)

		if vp.pipe.isNamed && !vp.pipe.HasReaders() {
			// Non-blocking, write-only opens fail with ENXIO when the read
			// side isn't open yet.
			if statusFlags&linux.O_NONBLOCK != 0 {
				fd.DecRef(ctx)
				return nil, linuxerr.ENXIO
			}
			// Wait for a reader to open the other end.
			if !waitFor(&vp.mu, &vp.rWakeup, ctx) {
				fd.DecRef(ctx)
				return nil, linuxerr.EINTR
			}
		}

	default:
		panic("invalid pipe flags: must be readable, writable, or both")
	}

	return fd, nil
}

// Preconditions: vp.mu must be held.
func (vp *VFSPipe) newFD(mnt *vfs.Mount, vfsd *vfs.Dentry, statusFlags uint32, locks *vfs.FileLocks) (*vfs.FileDescription, error) {
	fd := &VFSPipeFD{
		pipe: &vp.pipe,
	}
	fd.LockFD.Init(locks)
	if err := fd.vfsfd.Init(fd, statusFlags, mnt, vfsd, &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}

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

	return &fd.vfsfd, nil
}

// VFSPipeFD implements vfs.FileDescriptionImpl for pipes. It also implements
// non-atomic usermem.IO methods, allowing it to be passed as usermem.IO to
// other FileDescriptions for splice(2) and tee(2).
//
// +stateify savable
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
		event |= waiter.WritableEvents
	}
	if fd.vfsfd.IsWritable() {
		fd.pipe.wClose()
		event |= waiter.ReadableEvents | waiter.EventHUp
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
	return linuxerr.ESPIPE
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
	// Inline Pipe.FifoSize() since we don't have a fs.File.
	fd.pipe.mu.Lock()
	defer fd.pipe.mu.Unlock()
	return fd.pipe.max
}

// SetPipeSize implements fcntl(F_SETPIPE_SZ).
func (fd *VFSPipeFD) SetPipeSize(size int64) (int64, error) {
	return fd.pipe.SetFifoSize(size)
}

// SpliceToNonPipe performs a splice operation from fd to a non-pipe file.
func (fd *VFSPipeFD) SpliceToNonPipe(ctx context.Context, out *vfs.FileDescription, off, count int64) (int64, error) {
	fd.pipe.mu.Lock()

	// Cap the sequence at number of bytes actually available.
	if count > fd.pipe.size {
		count = fd.pipe.size
	}
	src := usermem.IOSequence{
		IO:    fd,
		Addrs: hostarch.AddrRangeSeqOf(hostarch.AddrRange{0, hostarch.Addr(count)}),
	}

	var (
		n   int64
		err error
	)
	if off == -1 {
		n, err = out.Write(ctx, src, vfs.WriteOptions{})
	} else {
		n, err = out.PWrite(ctx, src, off, vfs.WriteOptions{})
	}
	if n > 0 {
		fd.pipe.consumeLocked(n)
	}

	fd.pipe.mu.Unlock()

	if n > 0 {
		fd.pipe.Notify(waiter.WritableEvents)
	}
	return n, err
}

// SpliceFromNonPipe performs a splice operation from a non-pipe file to fd.
func (fd *VFSPipeFD) SpliceFromNonPipe(ctx context.Context, in *vfs.FileDescription, off, count int64) (int64, error) {
	dst := usermem.IOSequence{
		IO:    fd,
		Addrs: hostarch.AddrRangeSeqOf(hostarch.AddrRange{0, hostarch.Addr(count)}),
	}

	var (
		n   int64
		err error
	)
	fd.pipe.mu.Lock()
	if off == -1 {
		n, err = in.Read(ctx, dst, vfs.ReadOptions{})
	} else {
		n, err = in.PRead(ctx, dst, off, vfs.ReadOptions{})
	}
	fd.pipe.mu.Unlock()

	if n > 0 {
		fd.pipe.Notify(waiter.ReadableEvents)
	}
	return n, err
}

// CopyIn implements usermem.IO.CopyIn. Note that it is the caller's
// responsibility to call fd.pipe.consumeLocked() and
// fd.pipe.Notify(waiter.WritableEvents) after the read is completed.
//
// Preconditions: fd.pipe.mu must be locked.
func (fd *VFSPipeFD) CopyIn(ctx context.Context, addr hostarch.Addr, dst []byte, opts usermem.IOOpts) (int, error) {
	n, err := fd.pipe.peekLocked(int64(len(dst)), func(srcs safemem.BlockSeq) (uint64, error) {
		return safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(dst)), srcs)
	})
	return int(n), err
}

// CopyOut implements usermem.IO.CopyOut. Note that it is the caller's
// responsibility to call fd.pipe.Notify(waiter.ReadableEvents) after the write
// is completed.
//
// Preconditions: fd.pipe.mu must be locked.
func (fd *VFSPipeFD) CopyOut(ctx context.Context, addr hostarch.Addr, src []byte, opts usermem.IOOpts) (int, error) {
	n, err := fd.pipe.writeLocked(int64(len(src)), func(dsts safemem.BlockSeq) (uint64, error) {
		return safemem.CopySeq(dsts, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(src)))
	})
	return int(n), err
}

// ZeroOut implements usermem.IO.ZeroOut.
//
// Preconditions: fd.pipe.mu must be locked.
func (fd *VFSPipeFD) ZeroOut(ctx context.Context, addr hostarch.Addr, toZero int64, opts usermem.IOOpts) (int64, error) {
	n, err := fd.pipe.writeLocked(toZero, func(dsts safemem.BlockSeq) (uint64, error) {
		return safemem.ZeroSeq(dsts)
	})
	return n, err
}

// CopyInTo implements usermem.IO.CopyInTo. Note that it is the caller's
// responsibility to call fd.pipe.consumeLocked() and
// fd.pipe.Notify(waiter.WritableEvents) after the read is completed.
//
// Preconditions: fd.pipe.mu must be locked.
func (fd *VFSPipeFD) CopyInTo(ctx context.Context, ars hostarch.AddrRangeSeq, dst safemem.Writer, opts usermem.IOOpts) (int64, error) {
	return fd.pipe.peekLocked(ars.NumBytes(), func(srcs safemem.BlockSeq) (uint64, error) {
		return dst.WriteFromBlocks(srcs)
	})
}

// CopyOutFrom implements usermem.IO.CopyOutFrom. Note that it is the caller's
// responsibility to call fd.pipe.Notify(waiter.ReadableEvents) after the write
// is completed.
//
// Preconditions: fd.pipe.mu must be locked.
func (fd *VFSPipeFD) CopyOutFrom(ctx context.Context, ars hostarch.AddrRangeSeq, src safemem.Reader, opts usermem.IOOpts) (int64, error) {
	return fd.pipe.writeLocked(ars.NumBytes(), func(dsts safemem.BlockSeq) (uint64, error) {
		return src.ReadToBlocks(dsts)
	})
}

// SwapUint32 implements usermem.IO.SwapUint32.
func (fd *VFSPipeFD) SwapUint32(ctx context.Context, addr hostarch.Addr, new uint32, opts usermem.IOOpts) (uint32, error) {
	// How did a pipe get passed as the virtual address space to futex(2)?
	panic("VFSPipeFD.SwapUint32 called unexpectedly")
}

// CompareAndSwapUint32 implements usermem.IO.CompareAndSwapUint32.
func (fd *VFSPipeFD) CompareAndSwapUint32(ctx context.Context, addr hostarch.Addr, old, new uint32, opts usermem.IOOpts) (uint32, error) {
	panic("VFSPipeFD.CompareAndSwapUint32 called unexpectedly")
}

// LoadUint32 implements usermem.IO.LoadUint32.
func (fd *VFSPipeFD) LoadUint32(ctx context.Context, addr hostarch.Addr, opts usermem.IOOpts) (uint32, error) {
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
		return 0, linuxerr.EINVAL
	}

	lockTwoPipes(dst.pipe, src.pipe)
	n, err := dst.pipe.writeLocked(count, func(dsts safemem.BlockSeq) (uint64, error) {
		n, err := src.pipe.peekLocked(int64(dsts.NumBytes()), func(srcs safemem.BlockSeq) (uint64, error) {
			return safemem.CopySeq(dsts, srcs)
		})
		if n > 0 && removeFromSrc {
			src.pipe.consumeLocked(n)
		}
		return uint64(n), err
	})
	dst.pipe.mu.Unlock()
	src.pipe.mu.Unlock()

	if n > 0 {
		dst.pipe.Notify(waiter.ReadableEvents)
		if removeFromSrc {
			src.pipe.Notify(waiter.WritableEvents)
		}
	}
	return n, err
}
