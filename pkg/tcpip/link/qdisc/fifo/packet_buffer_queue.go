// Copyright 2020 The gVisor Authors.
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

package fifo

import (
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// packetBufferQueue is a bounded, thread-safe queue of PacketBuffers.
//
type packetBufferQueue struct {
	mu    sync.Mutex
	list  stack.PacketBufferList
	limit int
	used  int
}

// emptyLocked determines if the queue is empty.
// Preconditions: q.mu must be held.
func (q *packetBufferQueue) emptyLocked() bool {
	return q.used == 0
}

// empty determines if the queue is empty.
func (q *packetBufferQueue) empty() bool {
	q.mu.Lock()
	r := q.emptyLocked()
	q.mu.Unlock()

	return r
}

// setLimit updates the limit. No PacketBuffers are immediately dropped in case
// the queue becomes full due to the new limit.
func (q *packetBufferQueue) setLimit(limit int) {
	q.mu.Lock()
	q.limit = limit
	q.mu.Unlock()
}

// enqueue adds the given packet to the queue.
//
// Returns true when the PacketBuffer is successfully added to the queue, in
// which case the queue acquires a reference to the PacketBuffer, and
// returns false if the queue is full.
func (q *packetBufferQueue) enqueue(s *stack.PacketBuffer) bool {
	q.mu.Lock()
	r := q.used < q.limit
	if r {
		s.IncRef()
		q.list.PushBack(s)
		q.used++
	}
	q.mu.Unlock()

	return r
}

// dequeue removes and returns the next PacketBuffer from queue, if one exists.
// Caller is responsible for calling DecRef on the PacketBuffer.
func (q *packetBufferQueue) dequeue() *stack.PacketBuffer {
	q.mu.Lock()
	s := q.list.Front()
	if s != nil {
		q.list.Remove(s)
		q.used--
	}
	q.mu.Unlock()

	return s
}
