// Copyright 2021 The gVisor Authors.
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
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const trueSegSize = stack.PacketBufferStructSize + segSize

type segmentSizeWants struct {
	DataSize   int
	SegMemSize int
}

func checkSegmentSize(t *testing.T, name string, seg *segment, want segmentSizeWants) {
	t.Helper()
	got := segmentSizeWants{
		DataSize:   seg.payloadSize(),
		SegMemSize: seg.segMemSize(),
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%s differs (-want +got):\n%s", name, diff)
	}
}

func TestSegmentMerge(t *testing.T) {
	var clock faketime.NullClock
	id := stack.TransportEndpointID{}
	seg1 := newOutgoingSegment(id, &clock, buffer.MakeWithView(buffer.NewViewSize(10)), 0)
	defer seg1.DecRef()
	seg2 := newOutgoingSegment(id, &clock, buffer.MakeWithView(buffer.NewViewSize(20)), 0)
	defer seg2.DecRef()

	checkSegmentSize(t, "seg1", seg1, segmentSizeWants{
		DataSize:   10,
		SegMemSize: trueSegSize + 10,
	})
	checkSegmentSize(t, "seg2", seg2, segmentSizeWants{
		DataSize:   20,
		SegMemSize: trueSegSize + 20,
	})

	seg1.merge(seg2)

	checkSegmentSize(t, "seg1", seg1, segmentSizeWants{
		DataSize:   30,
		SegMemSize: trueSegSize + 30,
	})
	checkSegmentSize(t, "seg2", seg2, segmentSizeWants{
		DataSize:   0,
		SegMemSize: trueSegSize,
	})
}

func TestReceiveMemoryAtBufferLimit(t *testing.T) {
	const budget = math.MaxInt32 - 1
	var ep Endpoint
	ep.ops.SetReceiveBufferSize(budget, false)
	// Leave one byte for a segment. Charge the existing data directly to
	// avoid allocating a two-GiB socket buffer in the test.
	ep.updateReceiveMemUsed(budget - 1)
	q := segmentQueue{ep: &ep}
	defer func() {
		for s := q.dequeue(); s != nil; s = q.dequeue() {
			s.DecRef()
		}
	}()
	var clock faketime.NullClock
	enqueue := func() bool {
		s := newOutgoingSegment(stack.TransportEndpointID{}, &clock, buffer.MakeWithData([]byte{1}), 0)
		defer s.DecRef()
		return q.enqueue(s)
	}
	if !enqueue() {
		t.Fatal("segment with one byte of payload did not fit")
	}
	if got, want := ep.receiveBufferAvailable(), 0; got != want {
		t.Errorf("available after charging segment overhead: got %d, want %d", got, want)
	}
	if enqueue() {
		t.Fatal("accepted another data segment with a full receive buffer")
	}
	q.dequeue().DecRef()
	if got, want := ep.receiveBufferAvailable(), 1; got != want {
		t.Errorf("available after releasing the segment: got %d, want %d", got, want)
	}
}
