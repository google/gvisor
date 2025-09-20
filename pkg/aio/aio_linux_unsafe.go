// Copyright 2025 The gVisor Authors.
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

//go:build linux
// +build linux

package aio

import (
	"fmt"
	"math"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// LinuxQueue implements Queue using Linux native AIO.
//
// In LinuxQueue, I/O requests (struct iocb) are submitted when Wait() =>
// io_submit(2) is called. In Linux, io_submit(2) sequentially invokes the
// usual *synchronous* entry point into file reads/writes
// (file_operations::read/write_iter), but provides a completion callback in
// the kernel I/O control block (struct kiocb); file read/write implementations
// may recognize this as indicating support for asynchronous I/O
// (!is_sync_kiocb()), start the request, and return -EIOCBQUEUED to indicate
// asynchronous completion. This means that submission of a read/write
// operation will block (without submitting later requests) until the operation
// completes, unless the implementation of that operation specifically supports
// asynchronous I/O. In practice, this seems to mean:
//
// - O_DIRECT reads, subject to the constraints described by the man page notes
// for open(2), will probably work.
//
// - O_DIRECT writes that do not extend a file's size, subject to the same
// constraints, will probably work.
type LinuxQueue struct {
	ctxID    uintptr
	iocbs    []linux.IOCallback
	iocbPtrs []*linux.IOCallback
	ioevs    []linux.IOEvent
}

// NewLinuxQueue returns a new LinuxQueue with the given capacity.
func NewLinuxQueue(cap int) (*LinuxQueue, error) {
	// io_setup(2) takes unsigned int nr_events.
	if cap > math.MaxUint32 {
		return nil, fmt.Errorf("capacity %d exceeds maximum %d", cap, math.MaxUint32)
	}
	var ctxID uintptr
	if _, _, e := unix.Syscall(unix.SYS_IO_SETUP, uintptr(cap), uintptr(unsafe.Pointer(&ctxID)), 0 /* unused */); e != 0 {
		return nil, e
	}
	q := &LinuxQueue{
		ctxID:    ctxID,
		iocbs:    make([]linux.IOCallback, cap),
		iocbPtrs: make([]*linux.IOCallback, cap),
		ioevs:    make([]linux.IOEvent, cap),
	}
	for i := range q.iocbPtrs {
		q.iocbPtrs[i] = &q.iocbs[i]
	}
	q.iocbs = q.iocbs[:0]
	return q, nil
}

// Destroy implements Queue.Destroy.
func (q *LinuxQueue) Destroy() {
	unix.Syscall(unix.SYS_IO_DESTROY, q.ctxID, 0 /* unused */, 0 /* unused */)
}

// Cap implements Queue.Cap.
func (q *LinuxQueue) Cap() int {
	return len(q.ioevs)
}

// Add implements Queue.Add.
func (q *LinuxQueue) Add(r Request) {
	iocb := linux.IOCallback{
		Data:   r.ID,
		FD:     r.FD,
		Buf:    uint64(uintptr(r.Buf)),
		Bytes:  uint64(r.Len),
		Offset: r.Off,
	}
	switch r.Op {
	case OpRead:
		iocb.OpCode = linux.IOCB_CMD_PREAD
	case OpWrite:
		iocb.OpCode = linux.IOCB_CMD_PWRITE
	case OpReadv:
		iocb.OpCode = linux.IOCB_CMD_PREADV
	case OpWritev:
		iocb.OpCode = linux.IOCB_CMD_PWRITEV
	default:
		panic(fmt.Sprintf("unknown op %v", r.Op))
	}
	q.iocbs = append(q.iocbs, iocb)
}

// Wait implements Queue.Wait.
func (q *LinuxQueue) Wait(cs []Completion, minCompletions int) ([]Completion, error) {
	if len(q.iocbs) != 0 {
		_, _, e := unix.Syscall(unix.SYS_IO_SUBMIT, q.ctxID, uintptr(len(q.iocbs)), uintptr(unsafe.Pointer(unsafe.SliceData(q.iocbPtrs))))
		q.iocbs = q.iocbs[:0]
		if e != 0 {
			return cs, e
		}
	}
	for {
		if ring := q.ring(); ring.Magic == linux.AIO_RING_MAGIC {
			nr := ring.Nr
			head := ring.Head
			if head >= nr {
				panic(fmt.Sprintf("aio_ring::head (%d) >= aio_ring::nr (%d)", head, nr))
			}
			origHead := head
			tail := atomic.LoadUint32(&ring.Tail)
			for head != tail {
				ioev := q.ringAt(head)
				cs = append(cs, Completion{
					ID:     ioev.Data,
					Result: ioev.Result,
				})
				head++
				if head >= nr {
					head = 0
				}
				minCompletions--
			}
			if head != origHead {
				atomic.StoreUint32(&ring.Head, head)
				if minCompletions <= 0 {
					return cs, nil
				}
			}
		}
		n, _, e := unix.Syscall6(unix.SYS_IO_GETEVENTS, q.ctxID, uintptr(minCompletions), uintptr(len(q.ioevs)), uintptr(unsafe.Pointer(unsafe.SliceData(q.ioevs))), 0 /* timeout */, 0 /* unused */)
		if e != 0 {
			if e == unix.EINTR {
				continue
			}
			return cs, e
		}
		for i := range q.ioevs[:n] {
			ioev := &q.ioevs[i]
			cs = append(cs, Completion{
				ID:     ioev.Data,
				Result: ioev.Result,
			})
		}
		return cs, nil
	}
}

func (q *LinuxQueue) ring() *linux.AIORing {
	return (*linux.AIORing)(unsafe.Pointer(q.ctxID))
}

// Preconditions: idx < q.ring().Nr.
func (q *LinuxQueue) ringAt(idx uint32) *linux.IOEvent {
	return (*linux.IOEvent)(unsafe.Pointer(q.ctxID + uintptr(q.ring().HeaderLength) + uintptr(idx)*unsafe.Sizeof(linux.IOEvent{})))
}
