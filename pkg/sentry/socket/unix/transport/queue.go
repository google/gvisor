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

package transport

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/waiter"
)

// queue is a buffer queue.
//
// +stateify savable
type queue struct {
	queueRefs

	ReaderQueue *waiter.Queue
	WriterQueue *waiter.Queue

	mu       sync.Mutex `state:"nosave"`
	closed   bool
	unread   bool
	used     int64
	limit    int64
	dataList messageList
}

// Close closes q for reading and writing. It is immediately not writable and
// will become unreadable when no more data is pending.
//
// Both the read and write queues must be notified after closing:
// q.ReaderQueue.Notify(waiter.ReadableEvents)
// q.WriterQueue.Notify(waiter.WritableEvents)
func (q *queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
}

// Reset empties the queue and Releases all of the Entries.
//
// Both the read and write queues must be notified after resetting:
// q.ReaderQueue.Notify(waiter.ReadableEvents)
// q.WriterQueue.Notify(waiter.WritableEvents)
func (q *queue) Reset(ctx context.Context) {
	q.mu.Lock()
	dataList := q.dataList
	q.dataList.Reset()
	q.used = 0
	q.mu.Unlock()

	for cur := dataList.Front(); cur != nil; cur = cur.Next() {
		cur.Release(ctx)
	}
}

// DecRef implements RefCounter.DecRef.
func (q *queue) DecRef(ctx context.Context) {
	q.queueRefs.DecRef(func() {
		// We don't need to notify after resetting because no one cares about
		// this queue after all references have been dropped.
		q.Reset(ctx)
	})
}

// IsReadable determines if q is currently readable.
func (q *queue) IsReadable() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.closed || q.dataList.Front() != nil
}

// bufWritable returns true if there is space for writing.
//
// N.B. Linux only considers a unix socket "writable" if >75% of the buffer is
// free.
//
// See net/unix/af_unix.c:unix_writeable.
func (q *queue) bufWritable() bool {
	return 4*q.used < q.limit
}

// IsWritable determines if q is currently writable.
func (q *queue) IsWritable() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.closed || q.bufWritable()
}

// Enqueue adds an entry to the data queue if room is available.
//
// If discardEmpty is true and there are zero bytes of data, the packet is
// dropped.
//
// If truncate is true, Enqueue may truncate the message before enqueuing it.
// Otherwise, the entire message must fit. If l is less than the size of data,
// err indicates why.
//
// If notify is true, ReaderQueue.Notify must be called:
// q.ReaderQueue.Notify(waiter.ReadableEvents)
func (q *queue) Enqueue(ctx context.Context, data [][]byte, c ControlMessages, from tcpip.FullAddress, discardEmpty bool, truncate bool) (l int64, notify bool, err *syserr.Error) {
	q.mu.Lock()

	if q.closed {
		q.mu.Unlock()
		return 0, false, syserr.ErrClosedForSend
	}

	for _, d := range data {
		l += int64(len(d))
	}
	if discardEmpty && l == 0 {
		q.mu.Unlock()
		c.Release(ctx)
		return 0, false, nil
	}

	free := q.limit - q.used

	if l > free && truncate {
		if free <= 0 {
			// Message can't fit right now.
			q.mu.Unlock()
			return 0, false, syserr.ErrWouldBlock
		}

		l = free
		err = syserr.ErrWouldBlock
	}

	if l > q.limit {
		// Message is too big to ever fit.
		q.mu.Unlock()
		return 0, false, syserr.ErrMessageTooLong
	}

	if l > free {
		// Message can't fit right now, and could not be truncated.
		q.mu.Unlock()
		return 0, false, syserr.ErrWouldBlock
	}

	// Aggregate l bytes of data. This will truncate the data if l is less than
	// the total bytes held in data.
	v := make([]byte, l)
	for i, b := 0, v; i < len(data) && len(b) > 0; i++ {
		n := copy(b, data[i])
		b = b[n:]
	}

	notify = q.dataList.Front() == nil
	q.used += l
	q.dataList.PushBack(&message{
		Data:    buffer.View(v),
		Control: c,
		Address: from,
	})

	q.mu.Unlock()

	return l, notify, err
}

// Dequeue removes the first entry in the data queue, if one exists.
//
// If notify is true, WriterQueue.Notify must be called:
// q.WriterQueue.Notify(waiter.WritableEvents)
func (q *queue) Dequeue() (e *message, notify bool, err *syserr.Error) {
	q.mu.Lock()

	if q.dataList.Front() == nil {
		err := syserr.ErrWouldBlock
		if q.closed {
			err = syserr.ErrClosedForReceive
			if q.unread {
				err = syserr.ErrConnectionReset
			}
		}
		q.mu.Unlock()

		return nil, false, err
	}

	notify = !q.bufWritable()

	e = q.dataList.Front()
	q.dataList.Remove(e)
	q.used -= e.Length()

	notify = notify && q.bufWritable()

	q.mu.Unlock()

	return e, notify, nil
}

// Peek returns the first entry in the data queue, if one exists.
func (q *queue) Peek() (*message, *syserr.Error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.dataList.Front() == nil {
		err := syserr.ErrWouldBlock
		if q.closed {
			if err = syserr.ErrClosedForReceive; q.unread {
				err = syserr.ErrConnectionReset
			}
		}
		return nil, err
	}

	return q.dataList.Front().Peek(), nil
}

// QueuedSize returns the number of bytes currently in the queue, that is, the
// number of readable bytes.
func (q *queue) QueuedSize() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.used
}

// MaxQueueSize returns the maximum number of bytes storable in the queue.
func (q *queue) MaxQueueSize() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.limit
}

// SetMaxQueueSize sets the maximum number of bytes storable in the queue.
func (q *queue) SetMaxQueueSize(v int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.limit = v
}

// CloseUnread sets flag to indicate that the peer is closed (not shutdown)
// with unread data. So if read on this queue shall return ECONNRESET error.
func (q *queue) CloseUnread() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.unread = true
}
