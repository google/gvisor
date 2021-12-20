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

package qdisc_test

import (
	"math/rand"
	"testing"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkWriter = (*discardWriter)(nil)

// discardWriter implements LinkWriter.
type discardWriter struct {
}

func (*discardWriter) WritePackets(_ stack.RouteInfo, pkts stack.PacketBufferList, _ tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	return pkts.Len(), nil
}

// In b/209690936, fast simultaneous writes on qdisc will cause panics. This test
// reproduces the behavior shown in that bug.
func TestFastSimultaneousWrites(t *testing.T) {
	lower := &discardWriter{}
	linkEP := fifo.New(lower, 16, 1000)

	v := make(buffer.View, 1)

	prot := tcpip.NetworkProtocolNumber(0)
	r := stack.RouteInfo{}

	// Simulate many simultaneous writes from various goroutines, similar to TCP's sendTCPBatch().
	nWriters := 100
	nWrites := 100
	var wg sync.WaitGroup
	defer wg.Done()
	for i := 0; i < nWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < nWrites; j++ {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: v.ToVectorisedView(),
				})
				pkt.Hash = rand.Uint32()
				linkEP.WritePacket(r, prot, pkt)
				pkt.DecRef()
			}
		}()
	}
}
