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

package bridge_test

import (
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestWritePacketFromBridge(t *testing.T) {
	const (
		channelLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x05")
		channelLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		bridgeLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")

		netProto = 55
		nicID1   = 5
		nicID2   = 6
		bridgeID = 7
	)

	// Create two channel-based endpoints as receivers, they are both
	// bound to the same bridge device and are both expected to receive the
	// packets that are written by the bridge.
	ch1 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr1)
	ch2 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr2)
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})

	if err := s.CreateNIC(nicID1, ethernet.New(ch1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID1, err)
	}
	if err := s.CreateNIC(nicID2, ethernet.New(ch2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID2, err)
	}
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.SetNICCoordinator(nicID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID1, bridgeID)
	}
	if err := s.SetNICCoordinator(nicID2, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID2, bridgeID)
	}
	// When writing packets, the bridge will try all available bridge ports.
	if err := s.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	for _, c := range []*channel.Endpoint{ch1, ch2} {
		pkt := c.Read()
		if pkt == nil {
			t.Fatal("expected to read a packet")
		}

		eth := header.Ethernet(pkt.LinkHeader().Slice())
		pkt.DecRef()
		if got := eth.SourceAddress(); got != bridgeLinkAddr {
			t.Errorf("got eth.SourceAddress() = %s, want = %s", got, bridgeLinkAddr)
		}
		if got := eth.DestinationAddress(); got != remoteLinkAddr {
			t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
		}
		if got := eth.Type(); got != netProto {
			t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
		}
	}
}

type testNotification struct {
	ch chan bool
}

func (n *testNotification) WriteNotify() {
	n.ch <- true
}

// The test verifies that packates that are forwarded by
// a bridge will flooded to all bridge ports.
func TestWritePacketBetweenDevices(t *testing.T) {
	const (
		channelLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x04")
		channelLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x05")
		vethLinkAddr1    = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		vethLinkAddr2    = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		remoteLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")

		netProto = 55
		nicID1   = 4
		nicID2   = 5
		vethID   = 6
		bridgeID = 9
	)
	// Creates a pair of veth devices which will be attached to different
	// network stacks.
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	veth1.SetLinkAddress(vethLinkAddr1)
	veth2.SetLinkAddress(vethLinkAddr2)
	ch1 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr1)
	ch2 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr2)

	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})
	secondStack := stack.New(stack.Options{})
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.CreateNIC(nicID1, ethernet.New(ch1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID1, err)
	}
	if err := s.SetNICCoordinator(nicID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID1, bridgeID)
	}
	if err := s.CreateNIC(nicID2, ethernet.New(ch2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID2, err)
	}
	if err := s.SetNICCoordinator(nicID2, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID2, bridgeID)
	}
	if err := s.CreateNIC(vethID, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID, err)
	}
	// Attach one veth device to stack s, and attach the other
	// veth to stack secondStack.
	if err := s.SetNICCoordinator(vethID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator")
	}
	if err := secondStack.CreateNIC(vethID, ethernet.New(veth2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID, err)
	}

	n1 := &testNotification{ch: make(chan bool, 1)}
	n2 := &testNotification{ch: make(chan bool, 1)}
	ch1.AddNotify(n1)
	ch2.AddNotify(n2)
	// Write a packet to the veth device at the stack secondStack, the packet
	// will be available at the veth device at the stack s.
	if err := secondStack.WritePacketToRemote(vethID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	<-n1.ch
	<-n2.ch
	// No FDB entry, a package floods all bridge ports except the port that
	// is attached to the veth device.
	for _, c := range []*channel.Endpoint{ch1, ch2} {
		pkt := c.Read()
		if pkt == nil {
			t.Fatal("expected to read a packet")
		}

		pkt.LinkHeader().Consume(header.EthernetMinimumSize)
		eth := header.Ethernet(pkt.LinkHeader().Slice())
		pkt.DecRef()
		if got := eth.SourceAddress(); got != vethLinkAddr2 {
			t.Errorf("got eth.SourceAddress() = %s, want = %s", got, vethLinkAddr2)
		}
		if got := eth.DestinationAddress(); got != remoteLinkAddr {
			t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
		}
		if got := eth.Type(); got != netProto {
			t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
		}
	}
}

func TestBridgeFDB(t *testing.T) {
	const (
		channelLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x03")
		remoteLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")

		netProto = 55
		nicID    = 4
		vethID1  = 7
		vethID2  = 8
		bridgeID = 9
	)
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	ch := channel.New(1, header.EthernetMinimumSize, channelLinkAddr)
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})
	secondStack := stack.New(stack.Options{})

	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.CreateNIC(nicID, ethernet.New(ch)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	if err := s.SetNICCoordinator(nicID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID, bridgeID)
	}
	if err := s.CreateNIC(vethID1, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID1, err)
	}
	if err := s.SetNICCoordinator(vethID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", vethID1, bridgeID)
	}
	if err := secondStack.CreateNIC(vethID2, ethernet.New(veth2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID2, err)
	}
	n := &testNotification{ch: make(chan bool, 1)}
	ch.AddNotify(n)
	// Write a packet to the veth device at secondStack, the
	// packet will be available at stack s via veth.
	if err := secondStack.WritePacketToRemote(vethID2, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	<-n.ch
	pkt := ch.Read()
	defer pkt.DecRef()
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}
	// When forwarding the packet via the bridge device, the packet's
	// source MAC address will be used as lookup key to the bridge
	// FDB.
	var e stack.BridgeFDBEntry
	start := time.Now()
	for {
		e = bridgeEndpoint.FindFDBEntry(veth2.LinkAddress())
		if len(e.PortLinkAddress()) != 0 {
			break
		}
		if time.Since(start) > 30*time.Second {
			t.Fatalf("failed to find FDB entry for %s after 30 seconds", veth2.LinkAddress())
		}
		time.Sleep(time.Second)
	}
	if e.PortLinkAddress() != veth1.LinkAddress() {
		t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want = %s", veth2.LinkAddress(), e.PortLinkAddress(), veth1.LinkAddress())
	}
	// No FDB entry is expected for devices other than veth1.
	if e := bridgeEndpoint.FindFDBEntry(channelLinkAddr); len(e.PortLinkAddress()) != 0 {
		t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want = \"\"", channelLinkAddr, e.PortLinkAddress())
	}
}

func TestSetCoordinator(t *testing.T) {
	const (
		bridgeLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeID       = 6
	)

	s := stack.New(stack.Options{})
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.SetNICCoordinator(bridgeID, bridgeID); err == nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d) = %s, want = %s", bridgeID, bridgeID, err, tcpip.ErrNoSuchFile{})
	}
}

func TestMTU(t *testing.T) {
	e := stack.NewBridgeEndpoint(1500)
	mtus := []uint32{1000, 2000}
	for _, mtu := range mtus {
		e.SetMTU(mtu)

		if want, v := mtu-header.EthernetMinimumSize, e.MTU(); want != v {
			t.Errorf("MTU() = %v, want %v", v, want)
		}
	}
}

func TestNicExitingStackExitsBridgeToo(t *testing.T) {
	const (
		netProto        = 55
		nicID           = 5
		bridgeID        = 7
		bridgeLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")
		channelLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x04")
		remoteLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
	)

	src := stack.New(stack.Options{})

	// Create a bridge in src.
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	if err := src.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}

	// Create a channel-endpoint-based nic in src.
	ch := channel.New(1, header.EthernetMinimumSize, channelLinkAddr)
	if err := src.CreateNIC(nicID, ethernet.New(ch)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	// And add it to the bridge.
	if err := src.SetNICCoordinator(nicID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID, bridgeID)
	}

	// The bridge should forward pkts to the nic.
	if err := src.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	pkt := ch.Read()
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}
	pkt.DecRef()

	// Now move the nic into dst.
	dst := stack.New(stack.Options{})
	if _, err := src.SetNICStack(nicID, dst); err != nil {
		t.Fatalf("s.SetNICStack(%d, %p) = %s, want nil", nicID, dst, err)
	}

	// The bridge should no longer forward pkts to the nic, lest it defeat the purpose of network
	// namespaces.
	if err := src.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	pkt = ch.Read()
	if pkt != nil {
		pkt.DecRef()
		t.Fatal("did not expect to read a packet")
	}
}

// makeEthernetFrame builds an inbound frame whose ethernet header is still in
// the payload, for injection into a channel endpoint wrapped by ethernet.New.
func makeEthernetFrame(src, dst tcpip.LinkAddress) *stack.PacketBuffer {
	hdr := make([]byte, header.EthernetMinimumSize)
	header.Ethernet(hdr).Encode(&header.EthernetFields{
		SrcAddr: src,
		DstAddr: dst,
		Type:    header.IPv4ProtocolNumber,
	})
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(hdr),
	})
}

// drainChannels releases every packet queued on the given endpoints.
func drainChannels(eps ...*channel.Endpoint) {
	for _, ep := range eps {
		for pkt := ep.Read(); pkt != nil; pkt = ep.Read() {
			pkt.DecRef()
		}
	}
}

// TestBridgeDispatchOnlyForLocalOrMulticast checks that only group frames and
// frames addressed to the bridge or to the receiving port are passed up; other
// frames are only forwarded.
func TestBridgeDispatchOnlyForLocalOrMulticast(t *testing.T) {
	const (
		channelLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x10")
		channelLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x11")
		bridgeLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x12")
		unknownLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x13")

		nicID1   = 11
		nicID2   = 12
		bridgeID = 13
	)

	tests := []struct {
		name       string
		dst        tcpip.LinkAddress
		wantUpcall bool
		// checkFwd checks that port 2 receives the frame. Frames for the bridge
		// or the receiving port are not checked because they are still flooded.
		checkFwd bool
	}{
		{name: "unicast to other port", dst: channelLinkAddr2, checkFwd: true},
		{name: "unknown unicast", dst: unknownLinkAddr, checkFwd: true},
		{name: "unicast to bridge", dst: bridgeLinkAddr, wantUpcall: true},
		{name: "unicast to receiving port", dst: channelLinkAddr1, wantUpcall: true},
		{name: "broadcast", dst: header.EthernetBroadcastAddress, wantUpcall: true, checkFwd: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ch1 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr1)
			ch2 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr2)
			bridgeEndpoint := stack.NewBridgeEndpoint(1500)
			bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)

			s := stack.New(stack.Options{})
			defer s.Destroy()
			if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
			}
			if err := s.CreateNIC(nicID1, ethernet.New(ch1)); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID1, err)
			}
			if err := s.CreateNIC(nicID2, ethernet.New(ch2)); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID2, err)
			}
			if err := s.SetNICCoordinator(nicID1, bridgeID); err != nil {
				t.Fatalf("s.SetNICCoordinator(%d, %d): %s", nicID1, bridgeID, err)
			}
			if err := s.SetNICCoordinator(nicID2, bridgeID); err != nil {
				t.Fatalf("s.SetNICCoordinator(%d, %d): %s", nicID2, bridgeID, err)
			}

			// Learn port 2 so that frames to it are forwarded, not flooded.
			learn := makeEthernetFrame(channelLinkAddr2, channelLinkAddr1)
			ch2.InjectInbound(header.IPv4ProtocolNumber, learn)
			learn.DecRef()
			drainChannels(ch1, ch2)

			rx := s.NICInfo()[bridgeID].Stats.Rx.Packets
			before := rx.Value()
			pkt := makeEthernetFrame(channelLinkAddr1, test.dst)
			ch1.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()

			var wantUpcalls uint64
			if test.wantUpcall {
				wantUpcalls = 1
			}
			if got := rx.Value() - before; got != wantUpcalls {
				t.Errorf("got %d frames passed up to the bridge, want %d", got, wantUpcalls)
			}
			if test.checkFwd {
				if fwd := ch2.Read(); fwd == nil {
					t.Error("frame was not forwarded to port 2")
				} else {
					fwd.LinkHeader().Consume(header.EthernetMinimumSize)
					if got := header.Ethernet(fwd.LinkHeader().Slice()).DestinationAddress(); got != test.dst {
						t.Errorf("got forwarded destination = %s, want = %s", got, test.dst)
					}
					fwd.DecRef()
				}
			}

			drainChannels(ch1, ch2)
			ch1.Close()
			ch2.Close()
		})
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
