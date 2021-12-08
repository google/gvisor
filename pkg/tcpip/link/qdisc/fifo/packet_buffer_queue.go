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
	list  []*stack.PacketBuffer
	front int
	back  int
	limit int
}

func newPacketBufferQueue(limit int) *packetBufferQueue {
	p := &packetBufferQueue{
		limit: limit,
		list:  make([]*stack.PacketBuffer, limit),
		front: -1,
		back:  -1,
	}
	return p
}

// emptyLocked determines if the queue is empty.
// Preconditions: q.mu must be held.
func (q *packetBufferQueue) emptyLocked() bool {
	return q.front == -1
}

// empty determines if the queue is empty.
func (q *packetBufferQueue) empty() bool {
	q.mu.Lock()
	r := q.emptyLocked()
	q.mu.Unlock()

	return r
}

// enqueue adds the given packet to the queue.
//
// Returns true when the PacketBuffer is successfully added to the queue, in
// which case the queue acquires a reference to the PacketBuffer, and
// returns false if the queue is full.
func (q *packetBufferQueue) enqueue(s *stack.PacketBuffer) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if (q.back+1)%q.limit == q.front {
		return false
	} else if q.front == -1 {
		q.front = 0
		q.back = 0
	} else {
		q.back = (q.back + 1) % q.limit
	}

	s.IncRef()
	q.list[q.back] = s
	return true
}

// dequeue removes and returns the next PacketBuffer from queue, if one exists.
// Caller is responsible for calling DecRef on the PacketBuffer.
func (q *packetBufferQueue) dequeue() *stack.PacketBuffer {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.front == -1 {
		return nil
	}
	s := q.list[q.front]
	q.list[q.front] = nil
	if q.front == q.back {
		q.front = -1
		q.back = -1
	} else {
		q.front = (q.front + 1) % q.limit
	}
	return s
}
