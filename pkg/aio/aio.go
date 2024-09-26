// Copyright 2024 The gVisor Authors.
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

// Package aio provides asynchronous I/O on host file descriptors.
package aio

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
)

// A Queue provides the ability to concurrently execute multiple read/write
// operations on host file descriptors.
//
// Queues are not safe to use concurrently in multiple goroutines.
type Queue interface {
	// Destroy cancels all inflight operations and releases resources owned by
	// the Queue. Destroy waits for cancelation, so the Queue will not access
	// memory corresponding to inflight operations after Destroy returns.
	Destroy()

	// Cap returns the Queue's capacity, which is the maximum number of
	// concurrent operations supported by the Queue.
	Cap() int

	// Add enqueues an inflight operation.
	//
	// Note that some Queue implementations may not begin execution of new
	// Requests until the following call to Wait.
	//
	// Preconditions:
	// - The current number of inflight operations < Cap().
	Add(req Request)

	// Wait blocks until at least minCompletions inflight operations have
	// completed, then appends all completed inflight operations to cs and
	// returns the updated slice.
	//
	// If Wait returns a non-nil error, no Queue methods may be subsequently
	// called except Destroy.
	//
	// Preconditions:
	// - 0 <= minCompletions <= Cap().
	Wait(cs []Completion, minCompletions int) ([]Completion, error)
}

// Request is defined in aio_unsafe.go.

// Op selects an asynchronous I/O operation.
type Op uint8

// Possible values for Request.Op.
const (
	// OpRead represents a read into addresses [Buf, Buf+Len).
	OpRead Op = iota

	// OpWrite represents a write from addresses [Buf, Buf+Len).
	OpWrite

	// OpReadv represents a read, where the destination addresses are given by
	// the struct iovec array at address Buf of length Len.
	OpReadv

	// OpWritev represents a write, where the source addresses are given by the
	// struct iovec array at address Buf of length Len.
	OpWritev
)

// Completion provides outputs from an asynchronous I/O operation.
type Completion struct {
	ID     uint64 // copied from Request.ID in the corresponding Request
	Result int64  // number of bytes or negative errno
}

// Err returns an error representing the Completion. If Err returns nil,
// c.Result is the number of bytes completed by the operation.
func (c Completion) Err() error {
	if c.Result >= 0 {
		return nil
	}
	return unix.Errno(-c.Result)
}

// GoQueue implements Queue using a pool of worker goroutines.
type GoQueue struct {
	requests    chan Request
	completions chan Completion
	shutdown    chan struct{}
	workers     sync.WaitGroup
}

// NewGoQueue returns a new GoQueue with the given capacity.
func NewGoQueue(cap int) *GoQueue {
	q := &GoQueue{
		requests:    make(chan Request, cap),
		completions: make(chan Completion, cap),
		shutdown:    make(chan struct{}),
	}
	q.workers.Add(cap)
	for range cap {
		go q.workerMain()
	}
	return q
}

func (q *GoQueue) workerMain() {
	defer q.workers.Done()
	for {
		select {
		case <-q.shutdown:
			return
		case r := <-q.requests:
			var sysno uintptr
			switch r.Op {
			case OpRead:
				sysno = unix.SYS_PREAD64
			case OpWrite:
				sysno = unix.SYS_PWRITE64
			case OpReadv:
				sysno = unix.SYS_PREADV2
			case OpWritev:
				sysno = unix.SYS_PWRITEV2
			default:
				panic(fmt.Sprintf("unknown op %v", r.Op))
			}
			n, _, e := unix.Syscall6(sysno, uintptr(r.FD), uintptr(r.Buf), uintptr(r.Len), uintptr(r.Off), 0 /* pos_h */, 0 /* flags/unused */)
			c := Completion{
				ID:     r.ID,
				Result: int64(n),
			}
			if e != 0 {
				c.Result = -int64(e)
			}
			q.completions <- c
		}
	}
}

// Destroy implements Queue.Destroy.
func (q *GoQueue) Destroy() {
	close(q.shutdown)
	q.workers.Wait()
}

// Cap implements Queue.Cap.
func (q *GoQueue) Cap() int {
	return cap(q.requests)
}

// Add implements Queue.Add.
func (q *GoQueue) Add(r Request) {
	q.requests <- r
}

// Wait implements Queue.Wait.
func (q *GoQueue) Wait(cs []Completion, minCompletions int) ([]Completion, error) {
	i := 0
	for {
		if i < minCompletions {
			cs = append(cs, <-q.completions)
			i++
		} else {
			select {
			case c := <-q.completions:
				cs = append(cs, c)
				i++
			default:
				return cs, nil
			}
		}
	}
}
