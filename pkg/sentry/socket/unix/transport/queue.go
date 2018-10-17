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

package transport

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/ilist"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// queue is a buffer queue.
//
// +stateify savable
type queue struct {
	ReaderQueue *waiter.Queue
	WriterQueue *waiter.Queue

	mu       sync.Mutex `state:"nosave"`
	closed   bool
	used     int64
	limit    int64
	dataList ilist.List
}

// newQueue allocates and initializes a new queue.
func newQueue(ReaderQueue *waiter.Queue, WriterQueue *waiter.Queue, limit int64) *queue {
	return &queue{ReaderQueue: ReaderQueue, WriterQueue: WriterQueue, limit: limit}
}

// Close closes q for reading and writing. It is immediately not writable and
// will become unreadable when no more data is pending.
//
// Both the read and write queues must be notified after closing:
// q.ReaderQueue.Notify(waiter.EventIn)
// q.WriterQueue.Notify(waiter.EventOut)
func (q *queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
}

// Reset empties the queue and Releases all of the Entries.
//
// Both the read and write queues must be notified after resetting:
// q.ReaderQueue.Notify(waiter.EventIn)
// q.WriterQueue.Notify(waiter.EventOut)
func (q *queue) Reset() {
	q.mu.Lock()
	for cur := q.dataList.Front(); cur != nil; cur = cur.Next() {
		cur.(*message).Release()
	}
	q.dataList.Reset()
	q.used = 0
	q.mu.Unlock()
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
// If truncate is true, Enqueue may truncate the message beforing enqueuing it.
// Otherwise, the entire message must fit. If n < e.Length(), err indicates why.
//
// If notify is true, ReaderQueue.Notify must be called:
// q.ReaderQueue.Notify(waiter.EventIn)
func (q *queue) Enqueue(e *message, truncate bool) (l int64, notify bool, err *tcpip.Error) {
	q.mu.Lock()

	if q.closed {
		q.mu.Unlock()
		return 0, false, tcpip.ErrClosedForSend
	}

	free := q.limit - q.used

	l = e.Length()

	if l > free && truncate {
		if free == 0 {
			// Message can't fit right now.
			q.mu.Unlock()
			return 0, false, tcpip.ErrWouldBlock
		}

		e.Truncate(free)
		l = e.Length()
		err = tcpip.ErrWouldBlock
	}

	if l > q.limit {
		// Message is too big to ever fit.
		q.mu.Unlock()
		return 0, false, tcpip.ErrMessageTooLong
	}

	if l > free {
		// Message can't fit right now.
		q.mu.Unlock()
		return 0, false, tcpip.ErrWouldBlock
	}

	notify = q.dataList.Front() == nil
	q.used += l
	q.dataList.PushBack(e)

	q.mu.Unlock()

	return l, notify, err
}

// Dequeue removes the first entry in the data queue, if one exists.
//
// If notify is true, WriterQueue.Notify must be called:
// q.WriterQueue.Notify(waiter.EventOut)
func (q *queue) Dequeue() (e *message, notify bool, err *tcpip.Error) {
	q.mu.Lock()

	if q.dataList.Front() == nil {
		err := tcpip.ErrWouldBlock
		if q.closed {
			err = tcpip.ErrClosedForReceive
		}
		q.mu.Unlock()

		return nil, false, err
	}

	notify = !q.bufWritable()

	e = q.dataList.Front().(*message)
	q.dataList.Remove(e)
	q.used -= e.Length()

	notify = notify && q.bufWritable()

	q.mu.Unlock()

	return e, notify, nil
}

// Peek returns the first entry in the data queue, if one exists.
func (q *queue) Peek() (*message, *tcpip.Error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.dataList.Front() == nil {
		err := tcpip.ErrWouldBlock
		if q.closed {
			err = tcpip.ErrClosedForReceive
		}
		return nil, err
	}

	return q.dataList.Front().(*message).Peek(), nil
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
	return q.limit
}
