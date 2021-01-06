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

package ethernet_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.NetworkDispatcher = (*testNetworkDispatcher)(nil)

type testNetworkDispatcher struct {
	networkPackets int
}

func (t *testNetworkDispatcher) DeliverNetworkPacket(_, _ tcpip.LinkAddress, _ tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	t.networkPackets++
}

func (*testNetworkDispatcher) DeliverOutboundPacket(_, _ tcpip.LinkAddress, _ tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
}

func TestDeliverNetworkPacket(t *testing.T) {
	const (
		linkAddr       = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		otherLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		otherLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
	)

	e := ethernet.New(channel.New(0, 0, linkAddr))
	var networkDispatcher testNetworkDispatcher
	e.Attach(&networkDispatcher)

	if networkDispatcher.networkPackets != 0 {
		t.Fatalf("got networkDispatcher.networkPackets = %d, want = 0", networkDispatcher.networkPackets)
	}

	// An ethernet frame with a destination link address that is not assigned to
	// our ethernet link endpoint should still be delivered to the network
	// dispatcher since the ethernet endpoint is not expected to filter frames.
	eth := buffer.NewView(header.EthernetMinimumSize)
	header.Ethernet(eth).Encode(&header.EthernetFields{
		SrcAddr: otherLinkAddr1,
		DstAddr: otherLinkAddr2,
		Type:    header.IPv4ProtocolNumber,
	})
	e.DeliverNetworkPacket("", "", 0, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: eth.ToVectorisedView(),
	}))
	if networkDispatcher.networkPackets != 1 {
		t.Fatalf("got networkDispatcher.networkPackets = %d, want = 1", networkDispatcher.networkPackets)
	}
}
