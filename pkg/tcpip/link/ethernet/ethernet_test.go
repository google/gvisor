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
	"fmt"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/refsvfs2"
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

func (t *testNetworkDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	t.networkPackets++
}

func (*testNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer, bool) {
	panic("not implemented")
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
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Data: eth.ToVectorisedView()})
	defer p.DecRef()
	e.DeliverNetworkPacket(0, p)
	if networkDispatcher.networkPackets != 1 {
		t.Fatalf("got networkDispatcher.networkPackets = %d, want = 1", networkDispatcher.networkPackets)
	}
}

type testLinkEndpoint struct {
	stack.LinkEndpoint

	mtu uint32
}

func (t *testLinkEndpoint) MTU() uint32 {
	return t.mtu
}

func TestMTU(t *testing.T) {
	const maxFrameSize = 1500

	tests := []struct {
		maxFrameSize uint32
		expectedMTU  uint32
	}{
		{
			maxFrameSize: 0,
			expectedMTU:  0,
		},
		{
			maxFrameSize: header.EthernetMinimumSize - 1,
			expectedMTU:  0,
		},
		{
			maxFrameSize: header.EthernetMinimumSize,
			expectedMTU:  0,
		},
		{
			maxFrameSize: header.EthernetMinimumSize + 1,
			expectedMTU:  1,
		},
		{
			maxFrameSize: maxFrameSize,
			expectedMTU:  maxFrameSize - header.EthernetMinimumSize,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("MaxFrameSize=%d", test.maxFrameSize), func(t *testing.T) {
			e := ethernet.New(&testLinkEndpoint{mtu: test.maxFrameSize})
			if got := e.MTU(); got != test.expectedMTU {
				t.Errorf("got e.MTU() = %d, want = %d", got, test.expectedMTU)
			}
		})
	}
}

func TestWritePacketToRemoteAddHeader(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")

		netProto = 55
		nicID    = 1
	)

	c := channel.New(1, header.EthernetMinimumSize, localLinkAddr)

	s := stack.New(stack.Options{})
	if err := s.CreateNIC(nicID, ethernet.New(c)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}

	if err := s.WritePacketToRemote(nicID, remoteLinkAddr, netProto, buffer.VectorisedView{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", nicID, remoteLinkAddr, err)
	}

	{
		pkt := c.Read()
		if pkt == nil {
			t.Fatal("expected to read a packet")
		}

		eth := header.Ethernet(pkt.LinkHeader().View())
		pkt.DecRef()
		if got := eth.SourceAddress(); got != localLinkAddr {
			t.Errorf("got eth.SourceAddress() = %s, want = %s", got, localLinkAddr)
		}
		if got := eth.DestinationAddress(); got != remoteLinkAddr {
			t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
		}
		if got := eth.Type(); got != netProto {
			t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
		}
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refsvfs2.DoLeakCheck()
	os.Exit(code)
}
