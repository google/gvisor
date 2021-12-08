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
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type testContext struct {
	linkEP stack.LinkEndpoint
}

type discardEndpoint struct {
	channel.Endpoint
}

func (e *discardEndpoint) WritePackets(_ stack.RouteInfo, _ stack.PacketBufferList, _ tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	return 0, nil
}

func makeTestContext(t *testing.T, eventDepth int, packetDepth int) testContext {
	t.Helper()

	tc := testContext{}
	// We don't care what the underlying link endpoint does. This just
	// throws the packets away.
	lower := &discardEndpoint{}
	tc.linkEP = fifo.New(lower, 16, 1000)
	return tc
}

func TestFastSimultaneousWrites(t *testing.T) {
	c := makeTestContext(t, 0, 0)

	v := make(buffer.View, 1)

	prot := tcpip.NetworkProtocolNumber(0)
	r := stack.RouteInfo{}

	// Simulate many simultantious writes from various goroutines, similar to TCP's sendTCPBatch().
	nWriters := 100
	pktListSize := 2
	nWrites := 100
	var wg sync.WaitGroup
	for i := 0; i < nWriters; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < nWrites; j++ {
				var pkts stack.PacketBufferList
				pktsToDecRef := make([]*stack.PacketBuffer, pktListSize)
				for k := 0; k < pktListSize; k++ {
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Data: v.ToVectorisedView(),
					})
					pkt.Hash = rand.Uint32()
					pkts.PushBack(pkt)
					pktsToDecRef[k] = pkt
				}
				c.linkEP.WritePackets(r, pkts, prot)
				for _, pkt := range pktsToDecRef {
					pkt.DecRef()
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
