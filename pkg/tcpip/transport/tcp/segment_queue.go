// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
)

// segmentQueue is a bounded, thread-safe queue of TCP segments.
type segmentQueue struct {
	mu    sync.Mutex
	list  segmentList
	limit int
	used  int
}

// empty determines if the queue is empty.
func (q *segmentQueue) empty() bool {
	q.mu.Lock()
	r := q.used == 0
	q.mu.Unlock()

	return r
}

// setLimit updates the limit. No segments are immediately dropped in case the
// queue becomes full due to the new limit.
func (q *segmentQueue) setLimit(limit int) {
	q.mu.Lock()
	q.limit = limit
	q.mu.Unlock()
}

// enqueue adds the given segment to the queue.
//
// Returns true when the segment is successfully added to the queue, in which
// case ownership of the reference is transferred to the queue. And returns
// false if the queue is full, in which case ownership is retained by the
// caller.
func (q *segmentQueue) enqueue(s *segment) bool {
	q.mu.Lock()
	r := q.used < q.limit
	if r {
		q.list.PushBack(s)
		q.used += s.data.Size() + header.TCPMinimumSize
	}
	q.mu.Unlock()

	return r
}

// dequeue removes and returns the next segment from queue, if one exists.
// Ownership is transferred to the caller, who is responsible for decrementing
// the ref count when done.
func (q *segmentQueue) dequeue() *segment {
	q.mu.Lock()
	s := q.list.Front()
	if s != nil {
		q.list.Remove(s)
		q.used -= s.data.Size() + header.TCPMinimumSize
	}
	q.mu.Unlock()

	return s
}
