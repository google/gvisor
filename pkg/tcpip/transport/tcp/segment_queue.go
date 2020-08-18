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

package tcp

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// segmentQueue is a bounded, thread-safe queue of TCP segments.
//
// +stateify savable
type segmentQueue struct {
	mu    sync.Mutex  `state:"nosave"`
	list  segmentList `state:"wait"`
	limit int
	used  int
}

// emptyLocked determines if the queue is empty.
// Preconditions: q.mu must be held.
func (q *segmentQueue) emptyLocked() bool {
	return q.used == 0
}

// empty determines if the queue is empty.
func (q *segmentQueue) empty() bool {
	q.mu.Lock()
	r := q.emptyLocked()
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
		q.used++
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
		q.used--
	}
	q.mu.Unlock()

	return s
}
