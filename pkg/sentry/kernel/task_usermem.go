// Copyright 2018 The gVisor Authors.
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

package kernel

import (
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/usermem"
)

const iovecLength = 16

// MAX_RW_COUNT is the maximum size in bytes of a single read or write.
// Reads and writes that exceed this size may be silently truncated.
// (Linux: include/linux/fs.h:MAX_RW_COUNT)
var MAX_RW_COUNT = int(hostarch.Addr(math.MaxInt32).RoundDown())

// Activate ensures that the task has an active address space.
func (t *Task) Activate() {
	if mm := t.MemoryManager(); mm != nil {
		if err := mm.Activate(t); err != nil {
			panic("unable to activate mm: " + err.Error())
		}
	}
}

// Deactivate relinquishes the task's active address space.
func (t *Task) Deactivate() {
	if mm := t.MemoryManager(); mm != nil {
		mm.Deactivate()
	}
}

// CopyInBytes is a fast version of CopyIn if the caller can serialize the
// data without reflection and pass in a byte slice.
//
// This Task's AddressSpace must be active.
func (t *Task) CopyInBytes(addr hostarch.Addr, dst []byte) (int, error) {
	return t.MemoryManager().CopyIn(t, addr, dst, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CopyOutBytes is a fast version of CopyOut if the caller can serialize the
// data without reflection and pass in a byte slice.
//
// This Task's AddressSpace must be active.
func (t *Task) CopyOutBytes(addr hostarch.Addr, src []byte) (int, error) {
	return t.MemoryManager().CopyOut(t, addr, src, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CopyInString copies a NUL-terminated string of length at most maxlen in from
// the task's memory. The copy will fail with syscall.EFAULT if it traverses
// user memory that is unmapped or not readable by the user.
//
// This Task's AddressSpace must be active.
func (t *Task) CopyInString(addr hostarch.Addr, maxlen int) (string, error) {
	return usermem.CopyStringIn(t, t.MemoryManager(), addr, maxlen, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CopyInVector copies a NULL-terminated vector of strings from the task's
// memory. The copy will fail with syscall.EFAULT if it traverses
// user memory that is unmapped or not readable by the user.
//
// maxElemSize is the maximum size of each individual element.
//
// maxTotalSize is the maximum total length of all elements plus the total
// number of elements. For example, the following strings correspond to
// the following set of sizes:
//
//	{ "a", "b", "c" } => 6 (3 for lengths, 3 for elements)
//	{ "abc" }         => 4 (3 for length, 1 for elements)
//
// This Task's AddressSpace must be active.
func (t *Task) CopyInVector(addr hostarch.Addr, maxElemSize, maxTotalSize int) ([]string, error) {
	var v []string
	for {
		argAddr := t.Arch().Native(0)
		if _, err := argAddr.CopyIn(t, addr); err != nil {
			return v, err
		}
		if t.Arch().Value(argAddr) == 0 {
			break
		}
		// Each string has a zero terminating byte counted, so copying out a string
		// requires at least one byte of space. Also, see the calculation below.
		if maxTotalSize <= 0 {
			return nil, linuxerr.ENOMEM
		}
		thisMax := maxElemSize
		if maxTotalSize < thisMax {
			thisMax = maxTotalSize
		}
		arg, err := t.CopyInString(hostarch.Addr(t.Arch().Value(argAddr)), thisMax)
		if err != nil {
			return v, err
		}
		v = append(v, arg)
		addr += hostarch.Addr(t.Arch().Width())
		maxTotalSize -= len(arg) + 1
	}
	return v, nil
}

// CopyOutIovecs converts src to an array of struct iovecs and copies it to the
// memory mapped at addr for Task.
//
// Preconditions: Same as usermem.IO.CopyOut, plus:
//   - The caller must be running on the task goroutine.
//   - t's AddressSpace must be active.
func (t *Task) CopyOutIovecs(addr hostarch.Addr, src hostarch.AddrRangeSeq) error {
	return copyOutIovecs(t, t, addr, src)
}

// copyOutIovecs converts src to an array of struct iovecs and copies it to the
// memory mapped at addr.
func copyOutIovecs(ctx marshal.CopyContext, t *Task, addr hostarch.Addr, src hostarch.AddrRangeSeq) error {
	switch t.Arch().Width() {
	case 8:
		if _, ok := addr.AddLength(uint64(src.NumRanges()) * iovecLength); !ok {
			return linuxerr.EFAULT
		}

		b := ctx.CopyScratchBuffer(iovecLength)
		for ; !src.IsEmpty(); src = src.Tail() {
			ar := src.Head()
			hostarch.ByteOrder.PutUint64(b[0:8], uint64(ar.Start))
			hostarch.ByteOrder.PutUint64(b[8:16], uint64(ar.Length()))
			if _, err := ctx.CopyOutBytes(addr, b); err != nil {
				return err
			}
			addr += iovecLength
		}

	default:
		return linuxerr.ENOSYS
	}

	return nil
}

// CopyInIovecs copies in IoVecs for Task.
//
// Preconditions: Same as usermem.IO.CopyIn, plus:
// * The caller must be running on the task goroutine.
// * t's AddressSpace must be active.
func (t *Task) CopyInIovecs(addr hostarch.Addr, numIovecs int) (hostarch.AddrRangeSeq, error) {
	// Special case to avoid allocating allocating a single hostaddr.AddrRange.
	if numIovecs == 1 {
		return copyInIovec(t, t, addr)
	}
	iovecs, err := copyInIovecs(t, t, addr, numIovecs)
	if err != nil {
		return hostarch.AddrRangeSeq{}, err
	}
	return hostarch.AddrRangeSeqFromSlice(iovecs), nil
}

func copyInIovec(ctx marshal.CopyContext, t *Task, addr hostarch.Addr) (hostarch.AddrRangeSeq, error) {
	if err := checkArch(t); err != nil {
		return hostarch.AddrRangeSeq{}, err
	}
	b := ctx.CopyScratchBuffer(iovecLength)
	ar, err := makeIovec(ctx, t, addr, b)
	if err != nil {
		return hostarch.AddrRangeSeq{}, err
	}
	return hostarch.AddrRangeSeqOf(ar).TakeFirst(MAX_RW_COUNT), nil
}

// copyInIovecs copies an array of numIovecs struct iovecs from the memory
// mapped at addr, converts them to hostarch.AddrRanges, and returns them as a
// hostarch.AddrRangeSeq.
//
// copyInIovecs shares the following properties with Linux's
// lib/iov_iter.c:import_iovec() => fs/read_write.c:rw_copy_check_uvector():
//
// - If the length of any AddrRange would exceed the range of an ssize_t,
// copyInIovecs returns EINVAL.
//
// - If the length of any AddrRange would cause its end to overflow,
// copyInIovecs returns EFAULT.
//
// - If any AddrRange would include addresses outside the application address
// range, copyInIovecs returns EFAULT.
//
//   - The combined length of all AddrRanges is limited to MAX_RW_COUNT. If the
//     combined length of all AddrRanges would otherwise exceed this amount, ranges
//     beyond MAX_RW_COUNT are silently truncated.
func copyInIovecs(ctx marshal.CopyContext, t *Task, addr hostarch.Addr, numIovecs int) ([]hostarch.AddrRange, error) {
	if err := checkArch(t); err != nil {
		return nil, err
	}
	if numIovecs == 0 {
		return nil, nil
	}

	var dst []hostarch.AddrRange
	if numIovecs > 1 {
		dst = make([]hostarch.AddrRange, 0, numIovecs)
	}

	if _, ok := addr.AddLength(uint64(numIovecs) * iovecLength); !ok {
		return nil, linuxerr.EFAULT
	}

	b := ctx.CopyScratchBuffer(iovecLength)
	for i := 0; i < numIovecs; i++ {
		ar, err := makeIovec(ctx, t, addr, b)
		if err != nil {
			return []hostarch.AddrRange{}, err
		}
		dst = append(dst, ar)

		addr += iovecLength
	}
	// Truncate to MAX_RW_COUNT.
	var total uint64
	for i := range dst {
		dstlen := uint64(dst[i].Length())
		if rem := uint64(MAX_RW_COUNT) - total; rem < dstlen {
			dst[i].End -= hostarch.Addr(dstlen - rem)
			dstlen = rem
		}
		total += dstlen
	}

	return dst, nil
}

func checkArch(t *Task) error {
	if t.Arch().Width() != 8 {
		return linuxerr.ENOSYS
	}
	return nil
}

func makeIovec(ctx marshal.CopyContext, t *Task, addr hostarch.Addr, b []byte) (hostarch.AddrRange, error) {
	if _, err := ctx.CopyInBytes(addr, b); err != nil {
		return hostarch.AddrRange{}, err
	}

	base := hostarch.Addr(hostarch.ByteOrder.Uint64(b[0:8]))
	length := hostarch.ByteOrder.Uint64(b[8:16])
	if length > math.MaxInt64 {
		return hostarch.AddrRange{}, linuxerr.EINVAL
	}
	ar, ok := t.MemoryManager().CheckIORange(base, int64(length))
	if !ok {
		return hostarch.AddrRange{}, linuxerr.EFAULT
	}
	return ar, nil
}

// SingleIOSequence returns a usermem.IOSequence representing [addr,
// addr+length) in t's address space. If this contains addresses outside the
// application address range, it returns EFAULT. If length exceeds
// MAX_RW_COUNT, the range is silently truncated.
//
// SingleIOSequence is analogous to Linux's
// lib/iov_iter.c:import_single_range(). (Note that the non-vectorized read and
// write syscalls in Linux do not use import_single_range(). However they check
// access_ok() in fs/read_write.c:vfs_read/vfs_write, and overflowing address
// ranges are truncated to MAX_RW_COUNT by fs/read_write.c:rw_verify_area().)
func (t *Task) SingleIOSequence(addr hostarch.Addr, length int, opts usermem.IOOpts) (usermem.IOSequence, error) {
	if length > MAX_RW_COUNT {
		length = MAX_RW_COUNT
	}
	ar, ok := t.MemoryManager().CheckIORange(addr, int64(length))
	if !ok {
		return usermem.IOSequence{}, linuxerr.EFAULT
	}
	return usermem.IOSequence{
		IO:    t.MemoryManager(),
		Addrs: hostarch.AddrRangeSeqOf(ar),
		Opts:  opts,
	}, nil
}

// IovecsIOSequence returns a usermem.IOSequence representing the array of
// iovcnt struct iovecs at addr in t's address space. opts applies to the
// returned IOSequence, not the reading of the struct iovec array.
//
// IovecsIOSequence is analogous to Linux's lib/iov_iter.c:import_iovec().
//
// Preconditions: Same as Task.CopyInIovecs.
func (t *Task) IovecsIOSequence(addr hostarch.Addr, iovcnt int, opts usermem.IOOpts) (usermem.IOSequence, error) {
	if iovcnt < 0 || iovcnt > linux.UIO_MAXIOV {
		return usermem.IOSequence{}, linuxerr.EINVAL
	}
	ars, err := t.CopyInIovecs(addr, iovcnt)
	if err != nil {
		return usermem.IOSequence{}, err
	}
	return usermem.IOSequence{
		IO:    t.MemoryManager(),
		Addrs: ars,
		Opts:  opts,
	}, nil
}

type taskCopyContext struct {
	ctx                context.Context
	t                  *Task
	opts               usermem.IOOpts
	allocateNewBuffers bool
}

// CopyContext returns a marshal.CopyContext that copies to/from t's address
// space using opts.
func (t *Task) CopyContext(ctx context.Context, opts usermem.IOOpts) *taskCopyContext {
	return &taskCopyContext{
		ctx:  ctx,
		t:    t,
		opts: opts,
	}
}

// CopyScratchBuffer implements marshal.CopyContext.CopyScratchBuffer.
func (cc *taskCopyContext) CopyScratchBuffer(size int) []byte {
	if ctxTask, ok := cc.ctx.(*Task); ok && !cc.allocateNewBuffers {
		return ctxTask.CopyScratchBuffer(size)
	}
	return make([]byte, size)
}

func (cc *taskCopyContext) getMemoryManager() (*mm.MemoryManager, error) {
	tmm := cc.t.MemoryManager()
	if tmm == nil {
		return nil, linuxerr.ESRCH
	}
	if !tmm.IncUsers() {
		return nil, linuxerr.EFAULT
	}
	return tmm, nil
}

// WithTaskMutexLocked runs the given function with the task's mutex locked.
func (cc *taskCopyContext) WithTaskMutexLocked(fn func() error) error {
	cc.t.mu.Lock()
	defer cc.t.mu.Unlock()
	return fn()
}

// CopyInBytes implements marshal.CopyContext.CopyInBytes.
//
// Preconditions: Same as usermem.IO.CopyIn, plus:
//   - The caller must be running on the task goroutine or hold the cc.t.mu
//   - t's AddressSpace must be active.
func (cc *taskCopyContext) CopyInBytes(addr hostarch.Addr, dst []byte) (int, error) {
	tmm, err := cc.getMemoryManager()
	if err != nil {
		return 0, err
	}
	defer tmm.DecUsers(cc.ctx)
	return tmm.CopyIn(cc.ctx, addr, dst, cc.opts)
}

// CopyOutBytes implements marshal.CopyContext.CopyOutBytes.
//
// Preconditions: Same as usermem.IO.CopyOut, plus:
//   - The caller must be running on the task goroutine or hold the cc.t.mu
//   - t's AddressSpace must be active.
func (cc *taskCopyContext) CopyOutBytes(addr hostarch.Addr, src []byte) (int, error) {
	tmm, err := cc.getMemoryManager()
	if err != nil {
		return 0, err
	}
	defer tmm.DecUsers(cc.ctx)
	return tmm.CopyOut(cc.ctx, addr, src, cc.opts)
}

// CopyOutIovecs converts src to an array of struct iovecs and copies it to the
// memory mapped at addr for Task.
//
// Preconditions: Same as usermem.IO.CopyOut, plus:
//   - The caller must be running on the task goroutine or hold the cc.t.mu
//   - t's AddressSpace must be active.
func (cc *taskCopyContext) CopyOutIovecs(addr hostarch.Addr, src hostarch.AddrRangeSeq) error {
	return copyOutIovecs(cc, cc.t, addr, src)
}

// CopyInIovecs copies in IoVecs for taskCopyContext.
//
// Preconditions: Same as usermem.IO.CopyIn, plus:
//   - The caller must be running on the task goroutine or hold the cc.t.mu
//   - t's AddressSpace must be active.
func (cc *taskCopyContext) CopyInIovecs(addr hostarch.Addr, numIovecs int) ([]hostarch.AddrRange, error) {
	return copyInIovecs(cc, cc.t, addr, numIovecs)
}

type ownTaskCopyContext struct {
	t    *Task
	opts usermem.IOOpts
}

// OwnCopyContext returns a marshal.CopyContext that copies to/from t's address
// space using opts. The returned CopyContext may only be used by t's task
// goroutine.
//
// Since t already implements marshal.CopyContext, this is only needed to
// override the usermem.IOOpts used for the copy.
func (t *Task) OwnCopyContext(opts usermem.IOOpts) *ownTaskCopyContext {
	return &ownTaskCopyContext{
		t:    t,
		opts: opts,
	}
}

// CopyScratchBuffer implements marshal.CopyContext.CopyScratchBuffer.
func (cc *ownTaskCopyContext) CopyScratchBuffer(size int) []byte {
	return cc.t.CopyScratchBuffer(size)
}

// CopyInBytes implements marshal.CopyContext.CopyInBytes.
func (cc *ownTaskCopyContext) CopyInBytes(addr hostarch.Addr, dst []byte) (int, error) {
	return cc.t.MemoryManager().CopyIn(cc.t, addr, dst, cc.opts)
}

// CopyOutBytes implements marshal.CopyContext.CopyOutBytes.
func (cc *ownTaskCopyContext) CopyOutBytes(addr hostarch.Addr, src []byte) (int, error) {
	return cc.t.MemoryManager().CopyOut(cc.t, addr, src, cc.opts)
}
