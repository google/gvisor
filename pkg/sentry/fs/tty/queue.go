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

package tty

import (
	"bytes"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// queue represents one of the input or output queues between a pty master and
// slave. Bytes written to a queue are added to the read buffer until it is
// full, at which point they are written to the wait buffer. Bytes are
// processed (i.e. undergo termios transformations) as they are added to the
// read buffer. The read buffer is readable when its length is nonzero and
// readable is true.
type queue struct {
	// mu protects everything in queue.
	mu sync.Mutex `state:"nosave"`

	waiter.Queue `state:"nosave"`

	// readBuf is buffer of data ready to be read when readable is true.
	// This data has been processed.
	readBuf bytes.Buffer `state:".([]byte)"`

	// waitBuf contains data that can't fit into readBuf. It is put here
	// until it can be loaded into the read buffer. waitBuf contains data
	// that hasn't been processed.
	waitBuf bytes.Buffer `state:".([]byte)"`

	// readable indicates whether the read buffer can be read from.  In
	// canonical mode, there can be an unterminated line in the read buffer,
	// so readable must be checked.
	readable bool

	// transform is the the queue's function for transforming bytes
	// entering the queue. For example, transform might convert all '\r's
	// entering the queue to '\n's.
	transformer
}

// saveReadBuf is invoked by stateify.
func (q *queue) saveReadBuf() []byte {
	return append([]byte(nil), q.readBuf.Bytes()...)
}

// loadReadBuf is invoked by stateify.
func (q *queue) loadReadBuf(b []byte) {
	q.readBuf.Write(b)
}

// saveWaitBuf is invoked by stateify.
func (q *queue) saveWaitBuf() []byte {
	return append([]byte(nil), q.waitBuf.Bytes()...)
}

// loadWaitBuf is invoked by stateify.
func (q *queue) loadWaitBuf(b []byte) {
	q.waitBuf.Write(b)
}

// readReadiness returns whether q is ready to be read from.
func (q *queue) readReadiness(t *linux.KernelTermios) waiter.EventMask {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.readBuf.Len() > 0 && q.readable {
		return waiter.EventIn
	}
	return waiter.EventMask(0)
}

// writeReadiness returns whether q is ready to be written to.
func (q *queue) writeReadiness(t *linux.KernelTermios) waiter.EventMask {
	// Like Linux, we don't impose a maximum size on what can be enqueued.
	return waiter.EventOut
}

// readableSize writes the number of readable bytes to userspace.
func (q *queue) readableSize(ctx context.Context, io usermem.IO, args arch.SyscallArguments) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	var size int32
	if q.readable {
		size = int32(q.readBuf.Len())
	}

	_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), size, usermem.IOOpts{
		AddressSpaceActive: true,
	})
	return err

}

// read reads from q to userspace.
//
// Preconditions:
// * l.termiosMu must be held for reading.
func (q *queue) read(ctx context.Context, dst usermem.IOSequence, l *lineDiscipline) (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.readable {
		return 0, syserror.ErrWouldBlock
	}

	// Read out from the read buffer.
	n := canonMaxBytes
	if n > int(dst.NumBytes()) {
		n = int(dst.NumBytes())
	}
	if n > q.readBuf.Len() {
		n = q.readBuf.Len()
	}
	n, err := dst.Writer(ctx).Write(q.readBuf.Bytes()[:n])
	if err != nil {
		return 0, err
	}
	// Discard bytes read out.
	q.readBuf.Next(n)

	// If we read everything, this queue is no longer readable.
	if q.readBuf.Len() == 0 {
		q.readable = false
	}

	// Move data from the queue's wait buffer to its read buffer.
	q.pushWaitBufLocked(l)

	// If state changed, notify any waiters. If nothing was available to
	// read, let the caller know we could block.
	if n > 0 {
		q.Notify(waiter.EventOut)
	} else {
		return 0, syserror.ErrWouldBlock
	}
	return int64(n), nil
}

// write writes to q from userspace.
//
// Preconditions:
// * l.termiosMu must be held for reading.
func (q *queue) write(ctx context.Context, src usermem.IOSequence, l *lineDiscipline) (int64, error) {
	// TODO: Use CopyInTo/safemem to avoid extra copying.
	// Copy in the bytes to write from user-space.
	b := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, b)
	if err != nil {
		return 0, err
	}
	b = b[:n]
	return q.writeBytes(b, l)
}

// writeBytes writes to q from b.
//
// Preconditions:
// * l.termiosMu must be held for reading.
func (q *queue) writeBytes(b []byte, l *lineDiscipline) (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	// Write as much as possible to the read buffer.
	n := q.transform(l, q, b)

	// Write remaining data to the wait buffer.
	nWaiting, _ := q.waitBuf.Write(b[n:])

	// If state changed, notify any waiters. If we were unable to write
	// anything, let the caller know we could block.
	if n > 0 {
		q.Notify(waiter.EventIn)
	} else if nWaiting == 0 {
		return 0, syserror.ErrWouldBlock
	}
	return int64(n + nWaiting), nil
}

// pushWaitBuf fills the queue's read buffer with data from the wait buffer.
//
// Preconditions:
// * l.termiosMu must be held for reading.
func (q *queue) pushWaitBuf(l *lineDiscipline) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pushWaitBufLocked(l)
}

// Preconditions:
// * l.termiosMu must be held for reading.
// * q.mu must be locked.
func (q *queue) pushWaitBufLocked(l *lineDiscipline) {
	// Remove bytes from the wait buffer and move them to the read buffer.
	n := q.transform(l, q, q.waitBuf.Bytes())
	q.waitBuf.Next(n)

	// If state changed, notify any waiters.
	if n > 0 {
		q.Notify(waiter.EventIn)
	}
}
