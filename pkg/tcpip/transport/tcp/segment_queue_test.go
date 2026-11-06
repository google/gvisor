// Copyright 2026 The gVisor Authors.
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
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	testRcvBufSize = 4096
	testSndBufSize = 8192
)

func newTestQueueEndpoint() *Endpoint {
	ep := &Endpoint{}
	ep.ops.SetReceiveBufferSize(testRcvBufSize, false /* notify */)
	ep.ops.SetSendBufferSize(testSndBufSize, false /* notify */)
	ep.segmentQueue.ep = ep
	return ep
}

func newTestSegment(payload int) *segment {
	var clock faketime.NullClock
	var buf buffer.Buffer
	if payload > 0 {
		buf = buffer.MakeWithView(buffer.NewViewSize(payload))
	}
	return newOutgoingSegment(stack.TransportEndpointID{}, &clock, buf, 0)
}

// testSegMemSize returns the segMemSize of a test segment with the given
// payload size.
func testSegMemSize(payload int) int {
	s := newTestSegment(payload)
	defer s.DecRef()
	return s.segMemSize()
}

// fillQueue enqueues segments with the given payload size until one is
// refused or max segments have been queued, and returns how many were queued.
func fillQueue(ep *Endpoint, payload, max int) int {
	for n := 0; n < max; n++ {
		s := newTestSegment(payload)
		ok := ep.segmentQueue.enqueue(s)
		s.DecRef()
		if !ok {
			return n
		}
	}
	return max
}

func drainQueue(ep *Endpoint) {
	for s := ep.segmentQueue.dequeue(); s != nil; s = ep.segmentQueue.dequeue() {
		s.DecRef()
	}
}

func TestSegmentQueueBoundsZeroPayloadSegments(t *testing.T) {
	ep := newTestQueueEndpoint()
	defer drainQueue(ep)

	// Nothing dequeues, so zero-payload segments must eventually be refused.
	const max = 1 << 20
	n := fillQueue(ep, 0, max)
	if n == max {
		t.Fatalf("queued %d zero-payload segments without refusing any", n)
	}

	limit := testRcvBufSize + testSndBufSize + zeroPayloadHeadroom
	segMemSize := testSegMemSize(0)
	if used := ep.receiveMemUsed(); used <= limit || used > limit+segMemSize {
		t.Errorf("receiveMemUsed() = %d after refusal, want in (%d, %d]", used, limit, limit+segMemSize)
	}
}

func TestSegmentQueueDequeueFreesZeroPayloadRoom(t *testing.T) {
	ep := newTestQueueEndpoint()
	defer drainQueue(ep)

	if n := fillQueue(ep, 0, 1<<20); n == 1<<20 {
		t.Fatalf("queued %d zero-payload segments without refusing any", n)
	}
	ep.segmentQueue.dequeue().DecRef()

	s := newTestSegment(0)
	defer s.DecRef()
	if !ep.segmentQueue.enqueue(s) {
		t.Errorf("zero-payload segment refused after a dequeue, want it queued")
	}
}

func TestSegmentQueueZeroPayloadIgnoresUnreadData(t *testing.T) {
	ep := newTestQueueEndpoint()
	defer drainQueue(ep)

	// Charge more receive memory than the zero-payload limit, as unread
	// data that the processor already moved out of the queue does.
	const unread = 1 << 20
	ep.updateReceiveMemUsed(unread)
	defer ep.updateReceiveMemUsed(-unread)

	s := newTestSegment(0)
	defer s.DecRef()
	if !ep.segmentQueue.enqueue(s) {
		t.Errorf("zero-payload segment refused with unread data and an empty queue, want it queued")
	}

	d := newTestSegment(1024)
	defer d.DecRef()
	if ep.segmentQueue.enqueue(d) {
		t.Errorf("data segment queued with a full receive buffer, want it refused")
	}
}

func TestSegmentQueueReenqueueReleasesPreviousOwner(t *testing.T) {
	listenEP := newTestQueueEndpoint()
	childEP := newTestQueueEndpoint()
	defer drainQueue(childEP)

	s := newTestSegment(0)
	if !listenEP.segmentQueue.enqueue(s) {
		t.Fatalf("listenEP.segmentQueue.enqueue() = false, want true")
	}
	s.DecRef()

	// Move the segment to another endpoint, as a listening endpoint does
	// with segments for an established child endpoint.
	s = listenEP.segmentQueue.dequeue()
	ok := childEP.segmentQueue.enqueue(s)
	s.DecRef()
	if !ok {
		t.Fatalf("childEP.segmentQueue.enqueue() = false, want true")
	}

	if got := listenEP.receiveMemUsed(); got != 0 {
		t.Errorf("listenEP.receiveMemUsed() = %d after the segment moved, want 0", got)
	}
	if got, want := childEP.receiveMemUsed(), testSegMemSize(0); got != want {
		t.Errorf("childEP.receiveMemUsed() = %d, want %d", got, want)
	}
	drainQueue(childEP)
	if got := childEP.receiveMemUsed(); got != 0 {
		t.Errorf("childEP.receiveMemUsed() = %d after drain, want 0", got)
	}
}

func TestSegmentQueueConcurrentEnqueueAtLimit(t *testing.T) {
	ep := newTestQueueEndpoint()
	defer drainQueue(ep)

	// Use exactly the receive buffer size, so that one more data segment is
	// allowed and the segment after it is refused.
	ep.updateReceiveMemUsed(testRcvBufSize)
	defer ep.updateReceiveMemUsed(-testRcvBufSize)

	const callers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted int
	)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := newTestSegment(1024)
			defer s.DecRef()
			if ep.segmentQueue.enqueue(s) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Errorf("%d concurrent data segments queued at the receive buffer size, want 1", accepted)
	}
}

func TestSegmentQueueAllowsZeroPayloadWhenBufferFull(t *testing.T) {
	ep := newTestQueueEndpoint()
	defer drainQueue(ep)

	// Fill the receive buffer with data until a data segment is refused.
	if n := fillQueue(ep, 1024, 1000); n == 0 || n == 1000 {
		t.Fatalf("fillQueue(data) queued %d segments, want the receive buffer to fill", n)
	}

	// Pure ACKs/FINs still get in, so the connection can make progress.
	s := newTestSegment(0)
	defer s.DecRef()
	if !ep.segmentQueue.enqueue(s) {
		t.Errorf("zero-payload segment refused with a full receive buffer, want it queued")
	}

	// More data is still refused.
	d := newTestSegment(1024)
	defer d.DecRef()
	if ep.segmentQueue.enqueue(d) {
		t.Errorf("data segment queued with a full receive buffer, want it refused")
	}
}

func TestSegmentQueueFrozen(t *testing.T) {
	ep := newTestQueueEndpoint()
	defer drainQueue(ep)

	ep.segmentQueue.freeze()
	s := newTestSegment(0)
	defer s.DecRef()
	if ep.segmentQueue.enqueue(s) {
		t.Errorf("segment queued while frozen, want it refused")
	}
	ep.segmentQueue.thaw()
	if !ep.segmentQueue.enqueue(s) {
		t.Errorf("segment refused after thaw, want it queued")
	}
}
