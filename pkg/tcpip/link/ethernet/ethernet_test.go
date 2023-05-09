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

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.NetworkDispatcher = (*testNetworkDispatcher)(nil)

type deliveredPacket struct {
	protocol tcpip.NetworkProtocolNumber
	packet   stack.PacketBufferPtr
}

type testNetworkDispatcher struct {
	networkPackets []deliveredPacket
}

func (t *testNetworkDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pb stack.PacketBufferPtr) {
	t.networkPackets = append(t.networkPackets, deliveredPacket{protocol: proto, packet: pb})
}

func (*testNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, stack.PacketBufferPtr) {
	panic("not implemented")
}

func TestDeliverNetworkPacket(t *testing.T) {

	const (
		linkAddr      = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		otherLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
	)

	for _, testCase := range []struct {
		name    string
		dstAddr tcpip.LinkAddress
		pktType tcpip.PacketType
	}{
		{
			name:    "unicast",
			dstAddr: linkAddr,
			pktType: tcpip.PacketHost,
		},
		{
			name:    "broadcast",
			dstAddr: header.EthernetBroadcastAddress,
			pktType: tcpip.PacketBroadcast,
		},
		{
			name:    "multicast",
			dstAddr: tcpip.LinkAddress("\xFF\x00\x00\x00\x05\x07"),
			pktType: tcpip.PacketMulticast,
		},
		{
			name:    "other host",
			dstAddr: tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08"),
			pktType: tcpip.PacketOtherHost,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {

			e := ethernet.New(channel.New(0, 0, linkAddr))
			var networkDispatcher testNetworkDispatcher
			e.Attach(&networkDispatcher)

			if got, want := len(networkDispatcher.networkPackets), 0; got != want {
				t.Fatalf("got networkDispatcher.networkPackets = %d, want = %d", got, want)
			}

			const networkProtocol = header.IPv4ProtocolNumber

			// An ethernet frame with a destination link address that is not assigned to
			// our ethernet link endpoint should still be delivered to the network
			// dispatcher since the ethernet endpoint is not expected to filter frames.
			eth := make([]byte, header.EthernetMinimumSize)
			header.Ethernet(eth).Encode(&header.EthernetFields{
				SrcAddr: otherLinkAddr,
				DstAddr: testCase.dstAddr,
				Type:    networkProtocol,
			})
			p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: bufferv2.MakeWithData(eth)})
			defer p.DecRef()
			e.DeliverNetworkPacket(0, p)
			if got, want := len(networkDispatcher.networkPackets), 1; got != want {
				t.Fatalf("got networkDispatcher.networkPackets = %d, want = %d", got, want)
			}
			delivered := networkDispatcher.networkPackets[0]
			if diff := cmp.Diff(delivered.packet.LinkHeader().Slice(), eth); diff != "" {
				t.Errorf("LinkHeader mismatch (-want +got):\n%s", diff)
			}
			if got, want := delivered.protocol, networkProtocol; got != want {
				t.Errorf("got delivered.protocol = %d, want = %d", got, want)
			}
			if got, want := delivered.packet.PktType, testCase.pktType; got != want {
				t.Errorf("got delivered.packet.PktType = %d, want = %d", got, want)
			}
		})
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

	if err := s.WritePacketToRemote(nicID, remoteLinkAddr, netProto, bufferv2.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", nicID, remoteLinkAddr, err)
	}

	{
		pkt := c.Read()
		if pkt.IsNil() {
			t.Fatal("expected to read a packet")
		}

		eth := header.Ethernet(pkt.LinkHeader().Slice())
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
	refs.DoLeakCheck()
	os.Exit(code)
}
