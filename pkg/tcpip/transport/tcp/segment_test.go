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
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type segmentSizeWants struct {
	DataSize   int
	SegMemSize int
}

func checkSegmentSize(t *testing.T, name string, seg *segment, want segmentSizeWants) {
	t.Helper()
	got := segmentSizeWants{
		DataSize:   seg.data.Size(),
		SegMemSize: seg.segMemSize(),
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("%s differs (-want +got):\n%s", name, diff)
	}
}

func TestSegmentMerge(t *testing.T) {
	var clock faketime.NullClock
	id := stack.TransportEndpointID{}
	seg1 := newOutgoingSegment(id, &clock, buffer.NewView(10))
	defer seg1.decRef()
	seg2 := newOutgoingSegment(id, &clock, buffer.NewView(20))
	defer seg2.decRef()

	checkSegmentSize(t, "seg1", seg1, segmentSizeWants{
		DataSize:   10,
		SegMemSize: SegSize + 10,
	})
	checkSegmentSize(t, "seg2", seg2, segmentSizeWants{
		DataSize:   20,
		SegMemSize: SegSize + 20,
	})

	seg1.merge(seg2)

	checkSegmentSize(t, "seg1", seg1, segmentSizeWants{
		DataSize:   30,
		SegMemSize: SegSize + 30,
	})
	checkSegmentSize(t, "seg2", seg2, segmentSizeWants{
		DataSize:   0,
		SegMemSize: SegSize,
	})
}
