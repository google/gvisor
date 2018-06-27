// Copyright 2018 Google Inc.
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

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// _MAX_RW_COUNT is the maximum size in bytes of a single read or write.
// Reads and writes that exceed this size may be silently truncated.
// (Linux: include/linux/fs.h:MAX_RW_COUNT)
var _MAX_RW_COUNT = int(usermem.Addr(math.MaxInt32).RoundDown())

// Activate ensures that the task has an active address space.
func (t *Task) Activate() {
	if mm := t.MemoryManager(); mm != nil {
		if err := mm.Activate(); err != nil {
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

// CopyIn copies a fixed-size value or slice of fixed-size values in from the
// task's memory. The copy will fail with syscall.EFAULT if it traverses user
// memory that is unmapped or not readable by the user.
//
// This Task's AddressSpace must be active.
func (t *Task) CopyIn(addr usermem.Addr, dst interface{}) (int, error) {
	return usermem.CopyObjectIn(t, t.MemoryManager(), addr, dst, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CopyInBytes is a fast version of CopyIn if the caller can serialize the
// data without reflection and pass in a byte slice.
//
// This Task's AddressSpace must be active.
func (t *Task) CopyInBytes(addr usermem.Addr, dst []byte) (int, error) {
	return t.MemoryManager().CopyIn(t, addr, dst, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CopyOut copies a fixed-size value or slice of fixed-size values out to the
// task's memory. The copy will fail with syscall.EFAULT if it traverses user
// memory that is unmapped or not writeable by the user.
//
// This Task's AddressSpace must be active.
func (t *Task) CopyOut(addr usermem.Addr, src interface{}) (int, error) {
	return usermem.CopyObjectOut(t, t.MemoryManager(), addr, src, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CopyOutBytes is a fast version of CopyOut if the caller can serialize the
// data without reflection and pass in a byte slice.
//
// This Task's AddressSpace must be active.
func (t *Task) CopyOutBytes(addr usermem.Addr, src []byte) (int, error) {
	return t.MemoryManager().CopyOut(t, addr, src, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CopyInString copies a NUL-terminated string of length at most maxlen in from
// the task's memory. The copy will fail with syscall.EFAULT if it traverses
// user memory that is unmapped or not readable by the user.
//
// This Task's AddressSpace must be active.
func (t *Task) CopyInString(addr usermem.Addr, maxlen int) (string, error) {
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
//     { "a", "b", "c" } => 6 (3 for lengths, 3 for elements)
//     { "abc" }         => 4 (3 for length, 1 for elements)
//
// This Task's AddressSpace must be active.
func (t *Task) CopyInVector(addr usermem.Addr, maxElemSize, maxTotalSize int) ([]string, error) {
	var v []string
	for {
		argAddr := t.Arch().Native(0)
		if _, err := t.CopyIn(addr, argAddr); err != nil {
			return v, err
		}
		if t.Arch().Value(argAddr) == 0 {
			break
		}
		// Each string has a zero terminating byte counted, so copying out a string
		// requires at least one byte of space. Also, see the calculation below.
		if maxTotalSize <= 0 {
			return nil, syserror.ENOMEM
		}
		thisMax := maxElemSize
		if maxTotalSize < thisMax {
			thisMax = maxTotalSize
		}
		arg, err := t.CopyInString(usermem.Addr(t.Arch().Value(argAddr)), thisMax)
		if err != nil {
			return v, err
		}
		v = append(v, arg)
		addr += usermem.Addr(t.Arch().Width())
		maxTotalSize -= len(arg) + 1
	}
	return v, nil
}

// CopyOutIovecs converts src to an array of struct iovecs and copies it to the
// memory mapped at addr.
//
// Preconditions: As for usermem.IO.CopyOut. The caller must be running on the
// task goroutine. t's AddressSpace must be active.
func (t *Task) CopyOutIovecs(addr usermem.Addr, src usermem.AddrRangeSeq) error {
	switch t.Arch().Width() {
	case 8:
		const itemLen = 16
		if _, ok := addr.AddLength(uint64(src.NumRanges()) * itemLen); !ok {
			return syserror.EFAULT
		}

		b := t.CopyScratchBuffer(itemLen)
		for ; !src.IsEmpty(); src = src.Tail() {
			ar := src.Head()
			usermem.ByteOrder.PutUint64(b[0:8], uint64(ar.Start))
			usermem.ByteOrder.PutUint64(b[8:16], uint64(ar.Length()))
			if _, err := t.CopyOutBytes(addr, b); err != nil {
				return err
			}
			addr += itemLen
		}

	default:
		return syserror.ENOSYS
	}

	return nil
}

// CopyInIovecs copies an array of numIovecs struct iovecs from the memory
// mapped at addr, converts them to usermem.AddrRanges, and returns them as a
// usermem.AddrRangeSeq.
//
// CopyInIovecs shares the following properties with Linux's
// lib/iov_iter.c:import_iovec() => fs/read_write.c:rw_copy_check_uvector():
//
// - If the length of any AddrRange would exceed the range of an ssize_t,
// CopyInIovecs returns EINVAL.
//
// - If the length of any AddrRange would cause its end to overflow,
// CopyInIovecs returns EFAULT.
//
// - If any AddrRange would include addresses outside the application address
// range, CopyInIovecs returns EFAULT.
//
// - The combined length of all AddrRanges is limited to _MAX_RW_COUNT. If the
// combined length of all AddrRanges would otherwise exceed this amount, ranges
// beyond _MAX_RW_COUNT are silently truncated.
//
// Preconditions: As for usermem.IO.CopyIn. The caller must be running on the
// task goroutine. t's AddressSpace must be active.
func (t *Task) CopyInIovecs(addr usermem.Addr, numIovecs int) (usermem.AddrRangeSeq, error) {
	if numIovecs == 0 {
		return usermem.AddrRangeSeq{}, nil
	}

	var dst []usermem.AddrRange
	if numIovecs > 1 {
		dst = make([]usermem.AddrRange, 0, numIovecs)
	}

	switch t.Arch().Width() {
	case 8:
		const itemLen = 16
		if _, ok := addr.AddLength(uint64(numIovecs) * itemLen); !ok {
			return usermem.AddrRangeSeq{}, syserror.EFAULT
		}

		b := t.CopyScratchBuffer(itemLen)
		for i := 0; i < numIovecs; i++ {
			if _, err := t.CopyInBytes(addr, b); err != nil {
				return usermem.AddrRangeSeq{}, err
			}

			base := usermem.Addr(usermem.ByteOrder.Uint64(b[0:8]))
			length := usermem.ByteOrder.Uint64(b[8:16])
			if length > math.MaxInt64 {
				return usermem.AddrRangeSeq{}, syserror.EINVAL
			}
			ar, ok := t.MemoryManager().CheckIORange(base, int64(length))
			if !ok {
				return usermem.AddrRangeSeq{}, syserror.EFAULT
			}

			if numIovecs == 1 {
				// Special case to avoid allocating dst.
				return usermem.AddrRangeSeqOf(ar).TakeFirst(_MAX_RW_COUNT), nil
			}
			dst = append(dst, ar)

			addr += itemLen
		}

	default:
		return usermem.AddrRangeSeq{}, syserror.ENOSYS
	}

	// Truncate to _MAX_RW_COUNT.
	var total uint64
	for i := range dst {
		dstlen := uint64(dst[i].Length())
		if rem := uint64(_MAX_RW_COUNT) - total; rem < dstlen {
			dst[i].End -= usermem.Addr(dstlen - rem)
			dstlen = rem
		}
		total += dstlen
	}

	return usermem.AddrRangeSeqFromSlice(dst), nil
}

// SingleIOSequence returns a usermem.IOSequence representing [addr,
// addr+length) in t's address space. If this contains addresses outside the
// application address range, it returns EFAULT. If length exceeds
// _MAX_RW_COUNT, the range is silently truncated.
//
// SingleIOSequence is analogous to Linux's
// lib/iov_iter.c:import_single_range(). (Note that the non-vectorized read and
// write syscalls in Linux do not use import_single_range(). However they check
// access_ok() in fs/read_write.c:vfs_read/vfs_write, and overflowing address
// ranges are truncated to _MAX_RW_COUNT by fs/read_write.c:rw_verify_area().)
func (t *Task) SingleIOSequence(addr usermem.Addr, length int, opts usermem.IOOpts) (usermem.IOSequence, error) {
	if length > _MAX_RW_COUNT {
		length = _MAX_RW_COUNT
	}
	ar, ok := t.MemoryManager().CheckIORange(addr, int64(length))
	if !ok {
		return usermem.IOSequence{}, syserror.EFAULT
	}
	return usermem.IOSequence{
		IO:    t.MemoryManager(),
		Addrs: usermem.AddrRangeSeqOf(ar),
		Opts:  opts,
	}, nil
}

// IovecsIOSequence returns a usermem.IOSequence representing the array of
// iovcnt struct iovecs at addr in t's address space. opts applies to the
// returned IOSequence, not the reading of the struct iovec array.
//
// IovecsIOSequence is analogous to Linux's lib/iov_iter.c:import_iovec().
//
// Preconditions: As for Task.CopyInIovecs.
func (t *Task) IovecsIOSequence(addr usermem.Addr, iovcnt int, opts usermem.IOOpts) (usermem.IOSequence, error) {
	if iovcnt < 0 || iovcnt > linux.UIO_MAXIOV {
		return usermem.IOSequence{}, syserror.EINVAL
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
