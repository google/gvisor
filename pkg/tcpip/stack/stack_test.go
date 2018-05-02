// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stack_test contains tests for the stack. It is in its own package so
// that the tests can also validate that all definitions needed to implement
// transport and network protocols are properly exported by the stack package.
package stack_test

import (
	"math"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/channel"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

const (
	fakeNetNumber    tcpip.NetworkProtocolNumber = math.MaxUint32
	fakeNetHeaderLen                             = 12

	// fakeControlProtocol is used for control packets that represent
	// destination port unreachable.
	fakeControlProtocol tcpip.TransportProtocolNumber = 2

	// defaultMTU is the MTU, in bytes, used throughout the tests, except
	// where another value is explicitly used. It is chosen to match the MTU
	// of loopback interfaces on linux systems.
	defaultMTU = 65536
)

// fakeNetworkEndpoint is a network-layer protocol endpoint. It counts sent and
// received packets; the counts of all endpoints are aggregated in the protocol
// descriptor.
//
// Headers of this protocol are fakeNetHeaderLen bytes, but we currently only
// use the first three: destination address, source address, and transport
// protocol. They're all one byte fields to simplify parsing.
type fakeNetworkEndpoint struct {
	nicid      tcpip.NICID
	id         stack.NetworkEndpointID
	proto      *fakeNetworkProtocol
	dispatcher stack.TransportDispatcher
	linkEP     stack.LinkEndpoint
}

func (f *fakeNetworkEndpoint) MTU() uint32 {
	return f.linkEP.MTU() - uint32(f.MaxHeaderLength())
}

func (f *fakeNetworkEndpoint) NICID() tcpip.NICID {
	return f.nicid
}

func (f *fakeNetworkEndpoint) ID() *stack.NetworkEndpointID {
	return &f.id
}

func (f *fakeNetworkEndpoint) HandlePacket(r *stack.Route, vv *buffer.VectorisedView) {
	// Increment the received packet count in the protocol descriptor.
	f.proto.packetCount[int(f.id.LocalAddress[0])%len(f.proto.packetCount)]++

	// Consume the network header.
	b := vv.First()
	vv.TrimFront(fakeNetHeaderLen)

	// Handle control packets.
	if b[2] == uint8(fakeControlProtocol) {
		nb := vv.First()
		if len(nb) < fakeNetHeaderLen {
			return
		}

		vv.TrimFront(fakeNetHeaderLen)
		f.dispatcher.DeliverTransportControlPacket(tcpip.Address(nb[1:2]), tcpip.Address(nb[0:1]), fakeNetNumber, tcpip.TransportProtocolNumber(nb[2]), stack.ControlPortUnreachable, 0, vv)
		return
	}

	// Dispatch the packet to the transport protocol.
	f.dispatcher.DeliverTransportPacket(r, tcpip.TransportProtocolNumber(b[2]), vv)
}

func (f *fakeNetworkEndpoint) MaxHeaderLength() uint16 {
	return f.linkEP.MaxHeaderLength() + fakeNetHeaderLen
}

func (f *fakeNetworkEndpoint) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, dstAddr tcpip.Address) uint16 {
	return 0
}

func (f *fakeNetworkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return f.linkEP.Capabilities()
}

func (f *fakeNetworkEndpoint) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.TransportProtocolNumber) *tcpip.Error {
	// Increment the sent packet count in the protocol descriptor.
	f.proto.sendPacketCount[int(r.RemoteAddress[0])%len(f.proto.sendPacketCount)]++

	// Add the protocol's header to the packet and send it to the link
	// endpoint.
	b := hdr.Prepend(fakeNetHeaderLen)
	b[0] = r.RemoteAddress[0]
	b[1] = f.id.LocalAddress[0]
	b[2] = byte(protocol)
	return f.linkEP.WritePacket(r, hdr, payload, fakeNetNumber)
}

func (*fakeNetworkEndpoint) Close() {}

type fakeNetGoodOption bool

type fakeNetBadOption bool

type fakeNetInvalidValueOption int

type fakeNetOptions struct {
	good bool
}

// fakeNetworkProtocol is a network-layer protocol descriptor. It aggregates the
// number of packets sent and received via endpoints of this protocol. The index
// where packets are added is given by the packet's destination address MOD 10.
type fakeNetworkProtocol struct {
	packetCount     [10]int
	sendPacketCount [10]int
	opts            fakeNetOptions
}

func (f *fakeNetworkProtocol) Number() tcpip.NetworkProtocolNumber {
	return fakeNetNumber
}

func (f *fakeNetworkProtocol) MinimumPacketSize() int {
	return fakeNetHeaderLen
}

func (*fakeNetworkProtocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	return tcpip.Address(v[1:2]), tcpip.Address(v[0:1])
}

func (f *fakeNetworkProtocol) NewEndpoint(nicid tcpip.NICID, addr tcpip.Address, linkAddrCache stack.LinkAddressCache, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	return &fakeNetworkEndpoint{
		nicid:      nicid,
		id:         stack.NetworkEndpointID{addr},
		proto:      f,
		dispatcher: dispatcher,
		linkEP:     linkEP,
	}, nil
}

func (f *fakeNetworkProtocol) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case fakeNetGoodOption:
		f.opts.good = bool(v)
		return nil
	case fakeNetInvalidValueOption:
		return tcpip.ErrInvalidOptionValue
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func (f *fakeNetworkProtocol) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *fakeNetGoodOption:
		*v = fakeNetGoodOption(f.opts.good)
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func TestNetworkReceive(t *testing.T) {
	// Create a stack with the fake network protocol, one nic, and two
	// addresses attached to it: 1 & 2.
	id, linkEP := channel.New(10, defaultMTU, "")
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x02"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)
	var views [1]buffer.View
	// Allocate the buffer containing the packet that will be injected into
	// the stack.
	buf := buffer.NewView(30)

	// Make sure packet with wrong address is not delivered.
	buf[0] = 3
	vv := buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 0 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 0)
	}
	if fakeNet.packetCount[2] != 0 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 0)
	}

	// Make sure packet is delivered to first endpoint.
	buf[0] = 1
	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 0 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 0)
	}

	// Make sure packet is delivered to second endpoint.
	buf[0] = 2
	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}

	// Make sure packet is not delivered if protocol number is wrong.
	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber-1, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}

	// Make sure packet that is too small is dropped.
	buf.CapLength(2)
	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}
}

func sendTo(t *testing.T, s *stack.Stack, addr tcpip.Address) {
	r, err := s.FindRoute(0, "", addr, fakeNetNumber)
	if err != nil {
		t.Fatalf("FindRoute failed: %v", err)
	}
	defer r.Release()

	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()))
	err = r.WritePacket(&hdr, nil, fakeTransNumber)
	if err != nil {
		t.Errorf("WritePacket failed: %v", err)
		return
	}
}

func TestNetworkSend(t *testing.T) {
	// Create a stack with the fake network protocol, one nic, and one
	// address: 1. The route table sends all packets through the only
	// existing nic.
	id, linkEP := channel.New(10, defaultMTU, "")
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("NewNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{"\x00", "\x00", "\x00", 1}})

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	// Make sure that the link-layer endpoint received the outbound packet.
	sendTo(t, s, "\x03")
	if c := linkEP.Drain(); c != 1 {
		t.Errorf("packetCount = %d, want %d", c, 1)
	}
}

func TestNetworkSendMultiRoute(t *testing.T) {
	// Create a stack with the fake network protocol, two nics, and two
	// addresses per nic, the first nic has odd address, the second one has
	// even addresses.
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)

	id1, linkEP1 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id1); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x03"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	id2, linkEP2 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(2, id2); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x02"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x04"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	// Set a route table that sends all packets with odd destination
	// addresses through the first NIC, and all even destination address
	// through the second one.
	s.SetRouteTable([]tcpip.Route{
		{"\x01", "\x01", "\x00", 1},
		{"\x00", "\x01", "\x00", 2},
	})

	// Send a packet to an odd destination.
	sendTo(t, s, "\x05")

	if c := linkEP1.Drain(); c != 1 {
		t.Errorf("packetCount = %d, want %d", c, 1)
	}

	// Send a packet to an even destination.
	sendTo(t, s, "\x06")

	if c := linkEP2.Drain(); c != 1 {
		t.Errorf("packetCount = %d, want %d", c, 1)
	}
}

func testRoute(t *testing.T, s *stack.Stack, nic tcpip.NICID, srcAddr, dstAddr, expectedSrcAddr tcpip.Address) {
	r, err := s.FindRoute(nic, srcAddr, dstAddr, fakeNetNumber)
	if err != nil {
		t.Fatalf("FindRoute failed: %v", err)
	}

	defer r.Release()

	if r.LocalAddress != expectedSrcAddr {
		t.Fatalf("Bad source address: expected %v, got %v", expectedSrcAddr, r.LocalAddress)
	}

	if r.RemoteAddress != dstAddr {
		t.Fatalf("Bad destination address: expected %v, got %v", dstAddr, r.RemoteAddress)
	}
}

func testNoRoute(t *testing.T, s *stack.Stack, nic tcpip.NICID, srcAddr, dstAddr tcpip.Address) {
	_, err := s.FindRoute(nic, srcAddr, dstAddr, fakeNetNumber)
	if err != tcpip.ErrNoRoute {
		t.Fatalf("FindRoute returned unexpected error, expected tcpip.ErrNoRoute, got %v", err)
	}
}

func TestRoutes(t *testing.T) {
	// Create a stack with the fake network protocol, two nics, and two
	// addresses per nic, the first nic has odd address, the second one has
	// even addresses.
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)

	id1, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id1); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x03"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	id2, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(2, id2); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x02"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x04"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	// Set a route table that sends all packets with odd destination
	// addresses through the first NIC, and all even destination address
	// through the second one.
	s.SetRouteTable([]tcpip.Route{
		{"\x01", "\x01", "\x00", 1},
		{"\x00", "\x01", "\x00", 2},
	})

	// Test routes to odd address.
	testRoute(t, s, 0, "", "\x05", "\x01")
	testRoute(t, s, 0, "\x01", "\x05", "\x01")
	testRoute(t, s, 1, "\x01", "\x05", "\x01")
	testRoute(t, s, 0, "\x03", "\x05", "\x03")
	testRoute(t, s, 1, "\x03", "\x05", "\x03")

	// Test routes to even address.
	testRoute(t, s, 0, "", "\x06", "\x02")
	testRoute(t, s, 0, "\x02", "\x06", "\x02")
	testRoute(t, s, 2, "\x02", "\x06", "\x02")
	testRoute(t, s, 0, "\x04", "\x06", "\x04")
	testRoute(t, s, 2, "\x04", "\x06", "\x04")

	// Try to send to odd numbered address from even numbered ones, then
	// vice-versa.
	testNoRoute(t, s, 0, "\x02", "\x05")
	testNoRoute(t, s, 2, "\x02", "\x05")
	testNoRoute(t, s, 0, "\x04", "\x05")
	testNoRoute(t, s, 2, "\x04", "\x05")

	testNoRoute(t, s, 0, "\x01", "\x06")
	testNoRoute(t, s, 1, "\x01", "\x06")
	testNoRoute(t, s, 0, "\x03", "\x06")
	testNoRoute(t, s, 1, "\x03", "\x06")
}

func TestAddressRemoval(t *testing.T) {
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	var views [1]buffer.View
	buf := buffer.NewView(30)

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	// Write a packet, and check that it gets delivered.
	fakeNet.packetCount[1] = 0
	buf[0] = 1
	vv := buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}

	// Remove the address, then check that packet doesn't get delivered
	// anymore.
	if err := s.RemoveAddress(1, "\x01"); err != nil {
		t.Fatalf("RemoveAddress failed: %v", err)
	}

	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}

	// Check that removing the same address fails.
	if err := s.RemoveAddress(1, "\x01"); err != tcpip.ErrBadLocalAddress {
		t.Fatalf("RemoveAddress failed: %v", err)
	}
}

func TestDelayedRemovalDueToRoute(t *testing.T) {
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{"\x00", "\x00", "\x00", 1},
	})

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	var views [1]buffer.View
	buf := buffer.NewView(30)

	// Write a packet, and check that it gets delivered.
	fakeNet.packetCount[1] = 0
	buf[0] = 1
	vv := buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}

	// Get a route, check that packet is still deliverable.
	r, err := s.FindRoute(0, "", "\x02", fakeNetNumber)
	if err != nil {
		t.Fatalf("FindRoute failed: %v", err)
	}

	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 2 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 2)
	}

	// Remove the address, then check that packet is still deliverable
	// because the route is keeping the address alive.
	if err := s.RemoveAddress(1, "\x01"); err != nil {
		t.Fatalf("RemoveAddress failed: %v", err)
	}

	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 3 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 3)
	}

	// Check that removing the same address fails.
	if err := s.RemoveAddress(1, "\x01"); err != tcpip.ErrBadLocalAddress {
		t.Fatalf("RemoveAddress failed: %v", err)
	}

	// Release the route, then check that packet is not deliverable anymore.
	r.Release()
	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 3 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 3)
	}
}

func TestPromiscuousMode(t *testing.T) {
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{"\x00", "\x00", "\x00", 1},
	})

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	var views [1]buffer.View
	buf := buffer.NewView(30)

	// Write a packet, and check that it doesn't get delivered as we don't
	// have a matching endpoint.
	fakeNet.packetCount[1] = 0
	buf[0] = 1
	vv := buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 0 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 0)
	}

	// Set promiscuous mode, then check that packet is delivered.
	if err := s.SetPromiscuousMode(1, true); err != nil {
		t.Fatalf("SetPromiscuousMode failed: %v", err)
	}

	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}

	// Check that we can't get a route as there is no local address.
	_, err := s.FindRoute(0, "", "\x02", fakeNetNumber)
	if err != tcpip.ErrNoRoute {
		t.Fatalf("FindRoute returned unexpected status: expected %v, got %v", tcpip.ErrNoRoute, err)
	}

	// Set promiscuous mode to false, then check that packet can't be
	// delivered anymore.
	if err := s.SetPromiscuousMode(1, false); err != nil {
		t.Fatalf("SetPromiscuousMode failed: %v", err)
	}

	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
}

func TestAddressSpoofing(t *testing.T) {
	srcAddr := tcpip.Address("\x01")
	dstAddr := tcpip.Address("\x02")

	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)

	id, _ := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, dstAddr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{"\x00", "\x00", "\x00", 1},
	})

	// With address spoofing disabled, FindRoute does not permit an address
	// that was not added to the NIC to be used as the source.
	r, err := s.FindRoute(0, srcAddr, dstAddr, fakeNetNumber)
	if err == nil {
		t.Errorf("FindRoute succeeded with route %+v when it should have failed", r)
	}

	// With address spoofing enabled, FindRoute permits any address to be used
	// as the source.
	if err := s.SetSpoofing(1, true); err != nil {
		t.Fatalf("SetSpoofing failed: %v", err)
	}
	r, err = s.FindRoute(0, srcAddr, dstAddr, fakeNetNumber)
	if err != nil {
		t.Fatalf("FindRoute failed: %v", err)
	}
	if r.LocalAddress != srcAddr {
		t.Errorf("Route has wrong local address: got %v, wanted %v", r.LocalAddress, srcAddr)
	}
	if r.RemoteAddress != dstAddr {
		t.Errorf("Route has wrong remote address: got %v, wanted %v", r.RemoteAddress, dstAddr)
	}
}

// Set the subnet, then check that packet is delivered.
func TestSubnetAcceptsMatchingPacket(t *testing.T) {
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{"\x00", "\x00", "\x00", 1},
	})

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	var views [1]buffer.View
	buf := buffer.NewView(30)
	buf[0] = 1
	fakeNet.packetCount[1] = 0
	subnet, err := tcpip.NewSubnet(tcpip.Address("\x00"), tcpip.AddressMask("\xF0"))
	if err != nil {
		t.Fatalf("NewSubnet failed: %v", err)
	}
	if err := s.AddSubnet(1, fakeNetNumber, subnet); err != nil {
		t.Fatalf("AddSubnet failed: %v", err)
	}

	vv := buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
}

// Set destination outside the subnet, then check it doesn't get delivered.
func TestSubnetRejectsNonmatchingPacket(t *testing.T) {
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, nil)

	id, linkEP := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{"\x00", "\x00", "\x00", 1},
	})

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	var views [1]buffer.View
	buf := buffer.NewView(30)
	buf[0] = 1
	fakeNet.packetCount[1] = 0
	subnet, err := tcpip.NewSubnet(tcpip.Address("\x10"), tcpip.AddressMask("\xF0"))
	if err != nil {
		t.Fatalf("NewSubnet failed: %v", err)
	}
	if err := s.AddSubnet(1, fakeNetNumber, subnet); err != nil {
		t.Fatalf("AddSubnet failed: %v", err)
	}
	vv := buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeNet.packetCount[1] != 0 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 0)
	}
}

func TestNetworkOptions(t *testing.T) {
	s := stack.New(&tcpip.StdClock{}, []string{"fakeNet"}, []string{})

	// Try an unsupported network protocol.
	if err := s.SetNetworkProtocolOption(tcpip.NetworkProtocolNumber(99999), fakeNetGoodOption(false)); err != tcpip.ErrUnknownProtocol {
		t.Fatalf("SetNetworkProtocolOption(fakeNet2, blah, false) = %v, want = tcpip.ErrUnknownProtocol", err)
	}

	testCases := []struct {
		option   interface{}
		wantErr  *tcpip.Error
		verifier func(t *testing.T, p stack.NetworkProtocol)
	}{
		{fakeNetGoodOption(true), nil, func(t *testing.T, p stack.NetworkProtocol) {
			t.Helper()
			fakeNet := p.(*fakeNetworkProtocol)
			if fakeNet.opts.good != true {
				t.Fatalf("fakeNet.opts.good = false, want = true")
			}
			var v fakeNetGoodOption
			if err := s.NetworkProtocolOption(fakeNetNumber, &v); err != nil {
				t.Fatalf("s.NetworkProtocolOption(fakeNetNumber, &v) = %v, want = nil, where v is option %T", v, err)
			}
			if v != true {
				t.Fatalf("s.NetworkProtocolOption(fakeNetNumber, &v) returned v = %v, want = true", v)
			}
		}},
		{fakeNetBadOption(true), tcpip.ErrUnknownProtocolOption, nil},
		{fakeNetInvalidValueOption(1), tcpip.ErrInvalidOptionValue, nil},
	}
	for _, tc := range testCases {
		if got := s.SetNetworkProtocolOption(fakeNetNumber, tc.option); got != tc.wantErr {
			t.Errorf("s.SetNetworkProtocolOption(fakeNet, %v) = %v, want = %v", tc.option, got, tc.wantErr)
		}
		if tc.verifier != nil {
			tc.verifier(t, s.NetworkProtocolInstance(fakeNetNumber))
		}
	}
}

func init() {
	stack.RegisterNetworkProtocolFactory("fakeNet", func() stack.NetworkProtocol {
		return &fakeNetworkProtocol{}
	})
}
