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

// segmentQueue is a bounded, thread-safe queue of TCP segments.
//
// +stateify savable
type segmentQueue struct {
	mu segmentQueueMutex `state:"nosave"`
	// +checklocks:mu
	list segmentList `state:"wait"`
	ep   *Endpoint
	// +checklocks:mu
	frozen bool
	// memUsed is the total memory, as given by segMemSize, of the segments
	// in list.
	//
	// +checklocks:mu
	memUsed int64
}

// emptyLocked is equivalent to empty with q.mu already held.
//
// +checklocks:q.mu
func (q *segmentQueue) emptyLocked() bool {
	return q.list.Empty()
}

// empty determines if the queue is empty.
//
// +checklocksexclude:q.mu
func (q *segmentQueue) empty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.emptyLocked()
}

// zeroPayloadHeadroom is the memory that queued segments may use beyond the
// receive and send buffer sizes before segments without payload are refused.
// Linux uses the same 64KB headroom in tcp_add_backlog().
const zeroPayloadHeadroom = 64 << 10

// enqueue adds the given segment to the queue.
//
// If enqueue succeeds, the queue acquires its own reference and returns true.
// Otherwise it returns false. The caller retains its reference in either case.
//
// +checklocksexclude:q.mu
func (q *segmentQueue) enqueue(s *segment) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.frozen {
		return false
	}
	rcvBufSize := q.ep.ops.GetReceiveBufferSize()
	if s.payloadSize() == 0 {
		// Accept segments without payload (ACK, FIN, RST, etc.) even if
		// the receive buffer is full, so the connection can make progress.
		// Bound only the memory of the segments in this queue: unread data
		// must not cause these segments to be refused.
		if q.memUsed > rcvBufSize+q.ep.ops.GetSendBufferSize()+zeroPayloadHeadroom {
			return false
		}
	} else if q.ep.receiveMemUsed() > rcvBufSize {
		return false
	}

	s.IncRef()
	q.list.PushBack(s)
	q.memUsed += int64(s.segMemSize())
	// Set the owner now that the endpoint owns the segment.
	s.setOwner(q.ep, recvQ)
	return true
}

// dequeue removes and returns the next segment from queue, if one exists.
// Ownership is transferred to the caller, who is responsible for decrementing
// the ref count when done.
//
// +checklocksexclude:q.mu
func (q *segmentQueue) dequeue() *segment {
	q.mu.Lock()
	defer q.mu.Unlock()

	s := q.list.Front()
	if s != nil {
		q.list.Remove(s)
		q.memUsed -= int64(s.segMemSize())
	}

	return s
}

// freeze prevents any more segments from being added to the queue. i.e all
// future segmentQueue.enqueue will return false and not add the segment to the
// queue till the queue is unfroze with a corresponding segmentQueue.thaw call.
//
// +checklocksexclude:q.mu
func (q *segmentQueue) freeze() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.frozen = true
}

// thaw unfreezes a previously frozen queue using segmentQueue.freeze() and
// allows new segments to be queued again.
//
// +checklocksexclude:q.mu
func (q *segmentQueue) thaw() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.frozen = false
}
