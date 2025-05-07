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

package stack_test

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
	// Write a packte to the veth device at the stack secondStack, the packet
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
	for e = bridgeEndpoint.FindFDBEntry(veth2.LinkAddress()); len(e.PortLinkAddress()) == 0 && time.Since(start) < 30*time.Second; {
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

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
