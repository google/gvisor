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

// Package queue provides the implementation of buffer queue
// and interface of queue entry with Length method.
package queue

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/ilist"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// Entry implements Linker interface and has both Length and Release methods.
type Entry interface {
	ilist.Linker
	Length() int64
	Release()
	Peek() Entry
}

// Queue is a buffer queue.
//
// +stateify savable
type Queue struct {
	ReaderQueue *waiter.Queue
	WriterQueue *waiter.Queue

	mu       sync.Mutex `state:"nosave"`
	closed   bool
	used     int64
	limit    int64
	dataList ilist.List
}

// New allocates and initializes a new queue.
func New(ReaderQueue *waiter.Queue, WriterQueue *waiter.Queue, limit int64) *Queue {
	return &Queue{ReaderQueue: ReaderQueue, WriterQueue: WriterQueue, limit: limit}
}

// Close closes q for reading and writing. It is immediately not writable and
// will become unreadble will no more data is pending.
//
// Both the read and write queues must be notified after closing:
// q.ReaderQueue.Notify(waiter.EventIn)
// q.WriterQueue.Notify(waiter.EventOut)
func (q *Queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
}

// Reset empties the queue and Releases all of the Entries.
//
// Both the read and write queues must be notified after resetting:
// q.ReaderQueue.Notify(waiter.EventIn)
// q.WriterQueue.Notify(waiter.EventOut)
func (q *Queue) Reset() {
	q.mu.Lock()
	for cur := q.dataList.Front(); cur != nil; cur = cur.Next() {
		cur.(Entry).Release()
	}
	q.dataList.Reset()
	q.used = 0
	q.mu.Unlock()
}

// IsReadable determines if q is currently readable.
func (q *Queue) IsReadable() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.closed || q.dataList.Front() != nil
}

// IsWritable determines if q is currently writable.
func (q *Queue) IsWritable() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.closed || q.used < q.limit
}

// Enqueue adds an entry to the data queue if room is available.
//
// If notify is true, ReaderQueue.Notify must be called:
// q.ReaderQueue.Notify(waiter.EventIn)
func (q *Queue) Enqueue(e Entry) (notify bool, err *tcpip.Error) {
	q.mu.Lock()

	if q.closed {
		q.mu.Unlock()
		return false, tcpip.ErrClosedForSend
	}

	if q.used >= q.limit {
		q.mu.Unlock()
		return false, tcpip.ErrWouldBlock
	}

	notify = q.dataList.Front() == nil
	q.used += e.Length()
	q.dataList.PushBack(e)

	q.mu.Unlock()

	return notify, nil
}

// Dequeue removes the first entry in the data queue, if one exists.
//
// If notify is true, WriterQueue.Notify must be called:
// q.WriterQueue.Notify(waiter.EventOut)
func (q *Queue) Dequeue() (e Entry, notify bool, err *tcpip.Error) {
	q.mu.Lock()

	if q.dataList.Front() == nil {
		err := tcpip.ErrWouldBlock
		if q.closed {
			err = tcpip.ErrClosedForReceive
		}
		q.mu.Unlock()

		return nil, false, err
	}

	notify = q.used >= q.limit

	e = q.dataList.Front().(Entry)
	q.dataList.Remove(e)
	q.used -= e.Length()

	notify = notify && q.used < q.limit

	q.mu.Unlock()

	return e, notify, nil
}

// Peek returns the first entry in the data queue, if one exists.
func (q *Queue) Peek() (Entry, *tcpip.Error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.dataList.Front() == nil {
		err := tcpip.ErrWouldBlock
		if q.closed {
			err = tcpip.ErrClosedForReceive
		}
		return nil, err
	}

	return q.dataList.Front().(Entry).Peek(), nil
}

// QueuedSize returns the number of bytes currently in the queue, that is, the
// number of readable bytes.
func (q *Queue) QueuedSize() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.used
}

// MaxQueueSize returns the maximum number of bytes storable in the queue.
func (q *Queue) MaxQueueSize() int64 {
	return q.limit
}
