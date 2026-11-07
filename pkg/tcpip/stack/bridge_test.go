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
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
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
func makeEthernetFrame(src, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, payload []byte) *stack.PacketBuffer {
	frame := make([]byte, header.EthernetMinimumSize+len(payload))
	header.Ethernet(frame).Encode(&header.EthernetFields{
		SrcAddr: src,
		DstAddr: dst,
		Type:    proto,
	})
	copy(frame[header.EthernetMinimumSize:], payload)
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
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

const (
	dispatchPort1Addr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x10")
	dispatchPort2Addr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x11")
	dispatchBridgeAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x12")
	dispatchUnknownAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x13")
	// dispatchRemoteAddr is a host the bridge learns behind port 2.
	dispatchRemoteAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x14")
	// dispatchSrcAddr is a host behind port 1 that sends the test frames.
	dispatchSrcAddr       = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x15")
	dispatchMulticastAddr = tcpip.LinkAddress("\x01\x00\x5e\x00\x00\x01")
	dispatchNewPort1Addr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x16")
	dispatchNewPort2Addr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x17")
	dispatchPort1ID       = 11
	dispatchPort2ID       = 12
	dispatchBridgeID      = 13
)

var (
	dispatchBridgeIP = tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	dispatchSrcIP    = tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
)

// dispatchTestContext is a bridge with two ports. It records the packet type
// of every frame the bridge passes up.
type dispatchTestContext struct {
	s        *stack.Stack
	bridge   *stack.BridgeEndpoint
	ch1, ch2 *channel.Endpoint
	// classifying is whether port 1 classifies frames itself, as the ethernet
	// wrapper does. Otherwise port 1 behaves like a tap, fdbased, xdp or
	// sharedmem port, which leave the packet type unset.
	classifying bool
	passedUp    []tcpip.PacketType
}

// HandlePacket implements stack.PacketEndpoint.
func (c *dispatchTestContext) HandlePacket(_ tcpip.NICID, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	c.passedUp = append(c.passedUp, pkt.PktType)
}

func newDispatchTestContext(t *testing.T, classifying bool) *dispatchTestContext {
	t.Helper()
	c := &dispatchTestContext{
		bridge:      stack.NewBridgeEndpoint(1500),
		ch1:         channel.New(1, 1500, dispatchPort1Addr),
		ch2:         channel.New(1, 1500, dispatchPort2Addr),
		classifying: classifying,
	}
	c.bridge.SetLinkAddress(dispatchBridgeAddr)
	c.s = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
	})
	t.Cleanup(func() {
		drainChannels(c.ch1, c.ch2)
		c.ch1.Close()
		c.ch2.Close()
		c.s.Destroy()
	})
	if err := c.s.CreateNICWithOptions(dispatchBridgeID, c.bridge, stack.NICOptions{DeliverLinkPackets: true}); err != nil {
		t.Fatalf("s.CreateNICWithOptions(%d, _, _): %s", dispatchBridgeID, err)
	}
	port1 := stack.LinkEndpoint(c.ch1)
	if classifying {
		port1 = ethernet.New(c.ch1)
	}
	if err := c.s.CreateNIC(dispatchPort1ID, port1); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", dispatchPort1ID, err)
	}
	if err := c.s.CreateNIC(dispatchPort2ID, ethernet.New(c.ch2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", dispatchPort2ID, err)
	}
	for _, id := range []tcpip.NICID{dispatchPort1ID, dispatchPort2ID} {
		if err := c.s.SetNICCoordinator(id, dispatchBridgeID); err != nil {
			t.Fatalf("s.SetNICCoordinator(%d, %d): %s", id, dispatchBridgeID, err)
		}
	}
	if err := c.s.RegisterPacketEndpoint(dispatchBridgeID, header.EthernetProtocolAll, c); err != nil {
		t.Fatalf("s.RegisterPacketEndpoint(%d, _, _): %s", dispatchBridgeID, err)
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: dispatchBridgeIP, PrefixLen: 24},
	}
	if err := c.s.AddProtocolAddress(dispatchBridgeID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", dispatchBridgeID, protocolAddr, err)
	}

	// Learn a host behind port 2 so that frames to it are forwarded, not
	// flooded.
	learn := makeEthernetFrame(dispatchRemoteAddr, dispatchUnknownAddr, header.IPv4ProtocolNumber, nil)
	c.ch2.InjectInbound(header.IPv4ProtocolNumber, learn)
	learn.DecRef()
	drainChannels(c.ch1, c.ch2)
	return c
}

// injectFromPort1 injects a frame into port 1. A port
// that doesn't classify frames delivers them with the ethernet header already
// in the link header, as a tap does.
func (c *dispatchTestContext) injectFromPort1(src, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, payload []byte) {
	pkt := makeEthernetFrame(src, dst, proto, payload)
	defer pkt.DecRef()
	if !c.classifying {
		pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	}
	c.ch1.InjectInbound(proto, pkt)
}

type dispatchTest struct {
	name string
	dst  tcpip.LinkAddress
	// wantUpcall is whether the bridge passes the frame up, and wantPktType
	// the packet type it is passed up with.
	wantUpcall  bool
	wantPktType tcpip.PacketType
	// wantIP is whether IPv4 counts the frame as received.
	wantIP bool
	// wantFwd is whether port 2 sends out the frame.
	wantFwd bool
}

// check injects an IPv4 frame for test.dst into port 1 and checks what the
// bridge does with it.
func (c *dispatchTestContext) check(t *testing.T, test dispatchTest) {
	t.Helper()
	c.passedUp = nil
	ipRx := c.s.Stats().IP.PacketsReceived
	ipBefore := ipRx.Value()
	c.injectFromPort1(dispatchSrcAddr, test.dst, header.IPv4ProtocolNumber, nil)

	switch {
	case !test.wantUpcall && len(c.passedUp) != 0:
		t.Errorf("got frames passed up with packet types %v, want none", c.passedUp)
	case test.wantUpcall && (len(c.passedUp) != 1 || c.passedUp[0] != test.wantPktType):
		t.Errorf("got frames passed up with packet types %v, want [%d]", c.passedUp, test.wantPktType)
	}
	var wantIP uint64
	if test.wantIP {
		wantIP = 1
	}
	if got := ipRx.Value() - ipBefore; got != wantIP {
		t.Errorf("got %d frames received by IPv4, want %d", got, wantIP)
	}
	if fwd := c.ch2.Read(); fwd == nil {
		if test.wantFwd {
			t.Error("frame was not forwarded to port 2")
		}
	} else {
		if !test.wantFwd {
			t.Error("frame was forwarded to port 2")
		}
		fwd.LinkHeader().Consume(header.EthernetMinimumSize)
		if got := header.Ethernet(fwd.LinkHeader().Slice()).DestinationAddress(); got != test.dst {
			t.Errorf("got forwarded destination = %s, want = %s", got, test.dst)
		}
		fwd.DecRef()
	}
	drainChannels(c.ch1, c.ch2)
}

// portKinds runs a test with port 1 wrapped by the ethernet endpoint, which
// classifies frames, and with a bare port, which doesn't.
var portKinds = []struct {
	name        string
	classifying bool
}{
	{name: "ethernet port", classifying: true},
	{name: "unclassified port", classifying: false},
}

// TestBridgeDispatchOnlyForLocalOrMulticast checks that only group frames and
// frames addressed to the bridge or to one of its ports are passed up; other
// frames are only forwarded. Frames for the bridge or a port are not
// forwarded. The bridge classifies every frame it passes up.
func TestBridgeDispatchOnlyForLocalOrMulticast(t *testing.T) {
	tests := []dispatchTest{
		{name: "unicast to host behind other port", dst: dispatchRemoteAddr, wantFwd: true},
		{name: "unknown unicast", dst: dispatchUnknownAddr, wantFwd: true},
		{name: "unicast to bridge", dst: dispatchBridgeAddr, wantUpcall: true, wantPktType: tcpip.PacketHost, wantIP: true},
		{name: "unicast to receiving port", dst: dispatchPort1Addr, wantUpcall: true, wantPktType: tcpip.PacketHost, wantIP: true},
		{name: "unicast to other port", dst: dispatchPort2Addr, wantUpcall: true, wantPktType: tcpip.PacketOtherHost},
		{name: "broadcast", dst: header.EthernetBroadcastAddress, wantUpcall: true, wantPktType: tcpip.PacketBroadcast, wantIP: true, wantFwd: true},
		{name: "multicast", dst: dispatchMulticastAddr, wantUpcall: true, wantPktType: tcpip.PacketMulticast, wantIP: true, wantFwd: true},
	}
	for _, kind := range portKinds {
		for _, test := range tests {
			t.Run(kind.name+"/"+test.name, func(t *testing.T) {
				newDispatchTestContext(t, kind.classifying).check(t, test)
			})
		}
	}
}

// TestBridgePortAddressChange checks that the bridge tracks changes to its
// ports' addresses after they are added, as br_fdb_changeaddr does.
func TestBridgePortAddressChange(t *testing.T) {
	tests := []dispatchTest{
		{name: "new receiving port address", dst: dispatchNewPort1Addr, wantUpcall: true, wantPktType: tcpip.PacketHost, wantIP: true},
		{name: "new other port address", dst: dispatchNewPort2Addr, wantUpcall: true, wantPktType: tcpip.PacketOtherHost},
		{name: "old receiving port address", dst: dispatchPort1Addr, wantFwd: true},
		{name: "old other port address", dst: dispatchPort2Addr, wantFwd: true},
	}
	for _, kind := range portKinds {
		for _, test := range tests {
			t.Run(kind.name+"/"+test.name, func(t *testing.T) {
				c := newDispatchTestContext(t, kind.classifying)
				if err := c.s.SetNICAddress(dispatchPort1ID, dispatchNewPort1Addr); err != nil {
					t.Fatalf("s.SetNICAddress(%d, %s): %s", dispatchPort1ID, dispatchNewPort1Addr, err)
				}
				if err := c.s.SetNICAddress(dispatchPort2ID, dispatchNewPort2Addr); err != nil {
					t.Fatalf("s.SetNICAddress(%d, %s): %s", dispatchPort2ID, dispatchNewPort2Addr, err)
				}
				c.check(t, test)
			})
		}
	}
}

// TestBridgeDoesNotLearnLocalAddresses checks that, as in br_fdb_update, the
// bridge doesn't learn its own or its ports' addresses as source addresses.
func TestBridgeDoesNotLearnLocalAddresses(t *testing.T) {
	tests := []struct {
		name        string
		src         tcpip.LinkAddress
		wantLearned bool
	}{
		{name: "remote host", src: dispatchSrcAddr, wantLearned: true},
		{name: "bridge", src: dispatchBridgeAddr},
		{name: "receiving port", src: dispatchPort1Addr},
		{name: "other port", src: dispatchPort2Addr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newDispatchTestContext(t, true /* classifying */)
			c.injectFromPort1(test.src, header.EthernetBroadcastAddress, header.IPv4ProtocolNumber, nil)
			var want tcpip.LinkAddress
			if test.wantLearned {
				want = dispatchPort1Addr
			}
			if got := c.bridge.FindFDBEntry(test.src).PortLinkAddress(); got != want {
				t.Errorf("got FDB entry for %s on port %q, want %q", test.src, got, want)
			}
		})
	}
}

// TestBridgeARPRequests checks that, as in arp_rcv, the bridge doesn't answer
// an ARP request in a frame addressed to another port.
func TestBridgeARPRequests(t *testing.T) {
	tests := []struct {
		name      string
		dst       tcpip.LinkAddress
		wantReply bool
	}{
		{name: "bridge", dst: dispatchBridgeAddr, wantReply: true},
		{name: "receiving port", dst: dispatchPort1Addr, wantReply: true},
		{name: "other port", dst: dispatchPort2Addr, wantReply: false},
		{name: "broadcast", dst: header.EthernetBroadcastAddress, wantReply: true},
	}
	for _, kind := range portKinds {
		for _, test := range tests {
			t.Run(kind.name+"/"+test.name, func(t *testing.T) {
				c := newDispatchTestContext(t, kind.classifying)
				request := make([]byte, header.ARPSize)
				h := header.ARP(request)
				h.SetIPv4OverEthernet()
				h.SetOp(header.ARPRequest)
				copy(h.HardwareAddressSender(), dispatchSrcAddr)
				copy(h.ProtocolAddressSender(), dispatchSrcIP.AsSlice())
				copy(h.ProtocolAddressTarget(), dispatchBridgeIP.AsSlice())
				replies := c.s.Stats().ARP.OutgoingRepliesSent
				before := replies.Value()
				c.injectFromPort1(dispatchSrcAddr, test.dst, header.ARPProtocolNumber, request)
				var want uint64
				if test.wantReply {
					want = 1
				}
				if got := replies.Value() - before; got != want {
					t.Errorf("got %d ARP replies, want %d", got, want)
				}
			})
		}
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
