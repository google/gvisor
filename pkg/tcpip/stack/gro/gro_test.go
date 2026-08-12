// Copyright 2022 The gVisor Authors.
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

package gro

import (
	"math/bits"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type countingDispatcher struct {
	delivered int
}

func (d *countingDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.delivered++
}

func (*countingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func TestNBuckets(t *testing.T) {
	// groNBuckets must be a power of 2 so that we can use groNBuckets-1 as
	// a mask when indexing into the list of buckets.
	if bits.OnesCount(groNBuckets) != 1 {
		t.Fatalf("groNBuckets is not a power of two")
	}
}

func TestFlushDrainsBucket(t *testing.T) {
	dispatcher := &countingDispatcher{}
	gd := GRO{Dispatcher: dispatcher}
	gd.Init(true)
	bucket := &gd.buckets[0]
	for i := 0; i < groBucketSize; i++ {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		bucket.insert(packet, nil, nil)
	}
	t.Cleanup(func() {
		for bucket.count != 0 {
			bucket.removeOldest().DecRef()
		}
	})

	gd.Flush()

	if got := dispatcher.delivered; got != groBucketSize {
		t.Errorf("Flush delivered %d packets, want %d", got, groBucketSize)
	}
	if got := bucket.count; got != 0 {
		t.Errorf("Flush left %d packets in bucket, want 0", got)
	}
}
