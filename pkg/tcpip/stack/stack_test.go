// Copyright 2018 The gVisor Authors.
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

// Package stack_test contains tests for the stack. It is in its own package so
// that the tests can also validate that all definitions needed to implement
// transport and network protocols are properly exported by the stack package.
package stack_test

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	fakeNetNumber        tcpip.NetworkProtocolNumber = math.MaxUint32
	fakeNetHeaderLen                                 = 12
	fakeDefaultPrefixLen                             = 8

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
	prefixLen  int
	proto      *fakeNetworkProtocol
	dispatcher stack.TransportDispatcher
	ep         stack.LinkEndpoint
}

func (f *fakeNetworkEndpoint) MTU() uint32 {
	return f.ep.MTU() - uint32(f.MaxHeaderLength())
}

func (f *fakeNetworkEndpoint) NICID() tcpip.NICID {
	return f.nicid
}

func (f *fakeNetworkEndpoint) PrefixLen() int {
	return f.prefixLen
}

func (*fakeNetworkEndpoint) DefaultTTL() uint8 {
	return 123
}

func (f *fakeNetworkEndpoint) ID() *stack.NetworkEndpointID {
	return &f.id
}

func (f *fakeNetworkEndpoint) HandlePacket(r *stack.Route, vv buffer.VectorisedView) {
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
	f.dispatcher.DeliverTransportPacket(r, tcpip.TransportProtocolNumber(b[2]), buffer.View([]byte{}), vv)
}

func (f *fakeNetworkEndpoint) MaxHeaderLength() uint16 {
	return f.ep.MaxHeaderLength() + fakeNetHeaderLen
}

func (f *fakeNetworkEndpoint) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, dstAddr tcpip.Address) uint16 {
	return 0
}

func (f *fakeNetworkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return f.ep.Capabilities()
}

func (f *fakeNetworkEndpoint) WritePacket(r *stack.Route, gso *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.TransportProtocolNumber, _ uint8, loop stack.PacketLooping) *tcpip.Error {
	// Increment the sent packet count in the protocol descriptor.
	f.proto.sendPacketCount[int(r.RemoteAddress[0])%len(f.proto.sendPacketCount)]++

	// Add the protocol's header to the packet and send it to the link
	// endpoint.
	b := hdr.Prepend(fakeNetHeaderLen)
	b[0] = r.RemoteAddress[0]
	b[1] = f.id.LocalAddress[0]
	b[2] = byte(protocol)

	if loop&stack.PacketLoop != 0 {
		views := make([]buffer.View, 1, 1+len(payload.Views()))
		views[0] = hdr.View()
		views = append(views, payload.Views()...)
		vv := buffer.NewVectorisedView(len(views[0])+payload.Size(), views)
		f.HandlePacket(r, vv)
	}
	if loop&stack.PacketOut == 0 {
		return nil
	}

	return f.ep.WritePacket(r, gso, hdr, payload, fakeNetNumber)
}

func (*fakeNetworkEndpoint) WriteHeaderIncludedPacket(r *stack.Route, payload buffer.VectorisedView, loop stack.PacketLooping) *tcpip.Error {
	return tcpip.ErrNotSupported
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

func (f *fakeNetworkProtocol) DefaultPrefixLen() int {
	return fakeDefaultPrefixLen
}

func (f *fakeNetworkProtocol) PacketCount(intfAddr byte) int {
	return f.packetCount[int(intfAddr)%len(f.packetCount)]
}

func (*fakeNetworkProtocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	return tcpip.Address(v[1:2]), tcpip.Address(v[0:1])
}

func (f *fakeNetworkProtocol) NewEndpoint(nicid tcpip.NICID, addrWithPrefix tcpip.AddressWithPrefix, linkAddrCache stack.LinkAddressCache, dispatcher stack.TransportDispatcher, ep stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	return &fakeNetworkEndpoint{
		nicid:      nicid,
		id:         stack.NetworkEndpointID{LocalAddress: addrWithPrefix.Address},
		prefixLen:  addrWithPrefix.PrefixLen,
		proto:      f,
		dispatcher: dispatcher,
		ep:         ep,
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

func fakeNetFactory() stack.NetworkProtocol {
	return &fakeNetworkProtocol{}
}

func TestNetworkReceive(t *testing.T) {
	// Create a stack with the fake network protocol, one nic, and two
	// addresses attached to it: 1 & 2.
	ep := channel.New(10, defaultMTU, "")
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	// Make sure packet with wrong address is not delivered.
	buf[0] = 3
	ep.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 0 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 0)
	}
	if fakeNet.packetCount[2] != 0 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 0)
	}

	// Make sure packet is delivered to first endpoint.
	buf[0] = 1
	ep.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 0 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 0)
	}

	// Make sure packet is delivered to second endpoint.
	buf[0] = 2
	ep.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}

	// Make sure packet is not delivered if protocol number is wrong.
	ep.Inject(fakeNetNumber-1, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}

	// Make sure packet that is too small is dropped.
	buf.CapLength(2)
	ep.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}
}

func sendTo(s *stack.Stack, addr tcpip.Address, payload buffer.View) *tcpip.Error {
	r, err := s.FindRoute(0, "", addr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer r.Release()
	return send(r, payload)
}

func send(r stack.Route, payload buffer.View) *tcpip.Error {
	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()))
	return r.WritePacket(nil /* gso */, hdr, payload.ToVectorisedView(), fakeTransNumber, 123)
}

func testSendTo(t *testing.T, s *stack.Stack, addr tcpip.Address, ep *channel.Endpoint, payload buffer.View) {
	t.Helper()
	ep.Drain()
	if err := sendTo(s, addr, payload); err != nil {
		t.Error("sendTo failed:", err)
	}
	if got, want := ep.Drain(), 1; got != want {
		t.Errorf("sendTo packet count: got = %d, want %d", got, want)
	}
}

func testSend(t *testing.T, r stack.Route, ep *channel.Endpoint, payload buffer.View) {
	t.Helper()
	ep.Drain()
	if err := send(r, payload); err != nil {
		t.Error("send failed:", err)
	}
	if got, want := ep.Drain(), 1; got != want {
		t.Errorf("send packet count: got = %d, want %d", got, want)
	}
}

func testFailingSend(t *testing.T, r stack.Route, ep *channel.Endpoint, payload buffer.View, wantErr *tcpip.Error) {
	t.Helper()
	if gotErr := send(r, payload); gotErr != wantErr {
		t.Errorf("send failed: got = %s, want = %s ", gotErr, wantErr)
	}
}

func testFailingSendTo(t *testing.T, s *stack.Stack, addr tcpip.Address, ep *channel.Endpoint, payload buffer.View, wantErr *tcpip.Error) {
	t.Helper()
	if gotErr := sendTo(s, addr, payload); gotErr != wantErr {
		t.Errorf("sendto failed: got = %s, want = %s ", gotErr, wantErr)
	}
}

func testRecv(t *testing.T, fakeNet *fakeNetworkProtocol, localAddrByte byte, ep *channel.Endpoint, buf buffer.View) {
	t.Helper()
	// testRecvInternal injects one packet, and we expect to receive it.
	want := fakeNet.PacketCount(localAddrByte) + 1
	testRecvInternal(t, fakeNet, localAddrByte, ep, buf, want)
}

func testFailingRecv(t *testing.T, fakeNet *fakeNetworkProtocol, localAddrByte byte, ep *channel.Endpoint, buf buffer.View) {
	t.Helper()
	// testRecvInternal injects one packet, and we do NOT expect to receive it.
	want := fakeNet.PacketCount(localAddrByte)
	testRecvInternal(t, fakeNet, localAddrByte, ep, buf, want)
}

func testRecvInternal(t *testing.T, fakeNet *fakeNetworkProtocol, localAddrByte byte, ep *channel.Endpoint, buf buffer.View, want int) {
	t.Helper()
	ep.Inject(fakeNetNumber, buf.ToVectorisedView())
	if got := fakeNet.PacketCount(localAddrByte); got != want {
		t.Errorf("receive packet count: got = %d, want %d", got, want)
	}
}

func TestNetworkSend(t *testing.T) {
	// Create a stack with the fake network protocol, one nic, and one
	// address: 1. The route table sends all packets through the only
	// existing nic.
	ep := channel.New(10, defaultMTU, "")
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("NewNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	// Make sure that the link-layer endpoint received the outbound packet.
	testSendTo(t, s, "\x03", ep, nil)
}

func TestNetworkSendMultiRoute(t *testing.T) {
	// Create a stack with the fake network protocol, two nics, and two
	// addresses per nic, the first nic has odd address, the second one has
	// even addresses.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep1 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep1); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x03"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	ep2 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(2, ep2); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x04"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	// Set a route table that sends all packets with odd destination
	// addresses through the first NIC, and all even destination address
	// through the second one.
	{
		subnet0, err := tcpip.NewSubnet("\x00", "\x01")
		if err != nil {
			t.Fatal(err)
		}
		subnet1, err := tcpip.NewSubnet("\x01", "\x01")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{
			{Destination: subnet1, Gateway: "\x00", NIC: 1},
			{Destination: subnet0, Gateway: "\x00", NIC: 2},
		})
	}

	// Send a packet to an odd destination.
	testSendTo(t, s, "\x05", ep1, nil)

	// Send a packet to an even destination.
	testSendTo(t, s, "\x06", ep2, nil)
}

func testRoute(t *testing.T, s *stack.Stack, nic tcpip.NICID, srcAddr, dstAddr, expectedSrcAddr tcpip.Address) {
	r, err := s.FindRoute(nic, srcAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
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
	_, err := s.FindRoute(nic, srcAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err != tcpip.ErrNoRoute {
		t.Fatalf("FindRoute returned unexpected error, got = %v, want = %s", err, tcpip.ErrNoRoute)
	}
}

func TestRoutes(t *testing.T) {
	// Create a stack with the fake network protocol, two nics, and two
	// addresses per nic, the first nic has odd address, the second one has
	// even addresses.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep1 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep1); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x03"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	ep2 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(2, ep2); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	if err := s.AddAddress(2, fakeNetNumber, "\x04"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	// Set a route table that sends all packets with odd destination
	// addresses through the first NIC, and all even destination address
	// through the second one.
	{
		subnet0, err := tcpip.NewSubnet("\x00", "\x01")
		if err != nil {
			t.Fatal(err)
		}
		subnet1, err := tcpip.NewSubnet("\x01", "\x01")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{
			{Destination: subnet1, Gateway: "\x00", NIC: 1},
			{Destination: subnet0, Gateway: "\x00", NIC: 2},
		})
	}

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
	const localAddrByte byte = 0x01
	localAddr := tcpip.Address([]byte{localAddrByte})
	remoteAddr := tcpip.Address("\x02")

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, localAddr); err != nil {
		t.Fatal("AddAddress failed:", err)
	}
	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	// Send and receive packets, and verify they are received.
	buf[0] = localAddrByte
	testRecv(t, fakeNet, localAddrByte, ep, buf)
	testSendTo(t, s, remoteAddr, ep, nil)

	// Remove the address, then check that send/receive doesn't work anymore.
	if err := s.RemoveAddress(1, localAddr); err != nil {
		t.Fatal("RemoveAddress failed:", err)
	}
	testFailingRecv(t, fakeNet, localAddrByte, ep, buf)
	testFailingSendTo(t, s, remoteAddr, ep, nil, tcpip.ErrNoRoute)

	// Check that removing the same address fails.
	if err := s.RemoveAddress(1, localAddr); err != tcpip.ErrBadLocalAddress {
		t.Fatalf("RemoveAddress returned unexpected error, got = %v, want = %s", err, tcpip.ErrBadLocalAddress)
	}
}

func TestAddressRemovalWithRouteHeld(t *testing.T) {
	const localAddrByte byte = 0x01
	localAddr := tcpip.Address([]byte{localAddrByte})
	remoteAddr := tcpip.Address("\x02")

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}
	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)
	buf := buffer.NewView(30)

	if err := s.AddAddress(1, fakeNetNumber, localAddr); err != nil {
		t.Fatal("AddAddress failed:", err)
	}
	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	r, err := s.FindRoute(0, "", remoteAddr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
	}

	// Send and receive packets, and verify they are received.
	buf[0] = localAddrByte
	testRecv(t, fakeNet, localAddrByte, ep, buf)
	testSend(t, r, ep, nil)
	testSendTo(t, s, remoteAddr, ep, nil)

	// Remove the address, then check that send/receive doesn't work anymore.
	if err := s.RemoveAddress(1, localAddr); err != nil {
		t.Fatal("RemoveAddress failed:", err)
	}
	testFailingRecv(t, fakeNet, localAddrByte, ep, buf)
	testFailingSend(t, r, ep, nil, tcpip.ErrInvalidEndpointState)
	testFailingSendTo(t, s, remoteAddr, ep, nil, tcpip.ErrNoRoute)

	// Check that removing the same address fails.
	if err := s.RemoveAddress(1, localAddr); err != tcpip.ErrBadLocalAddress {
		t.Fatalf("RemoveAddress returned unexpected error, got = %v, want = %s", err, tcpip.ErrBadLocalAddress)
	}
}

func verifyAddress(t *testing.T, s *stack.Stack, nicid tcpip.NICID, addr tcpip.Address) {
	t.Helper()
	info, ok := s.NICInfo()[nicid]
	if !ok {
		t.Fatalf("NICInfo() failed to find nicid=%d", nicid)
	}
	if len(addr) == 0 {
		// No address given, verify that there is no address assigned to the NIC.
		for _, a := range info.ProtocolAddresses {
			if a.Protocol == fakeNetNumber && a.AddressWithPrefix != (tcpip.AddressWithPrefix{}) {
				t.Errorf("verify no-address: got = %s, want = %s", a.AddressWithPrefix, (tcpip.AddressWithPrefix{}))
			}
		}
		return
	}
	// Address given, verify the address is assigned to the NIC and no other
	// address is.
	found := false
	for _, a := range info.ProtocolAddresses {
		if a.Protocol == fakeNetNumber {
			if a.AddressWithPrefix.Address == addr {
				found = true
			} else {
				t.Errorf("verify address: got = %s, want = %s", a.AddressWithPrefix.Address, addr)
			}
		}
	}
	if !found {
		t.Errorf("verify address: couldn't find %s on the NIC", addr)
	}
}

func TestEndpointExpiration(t *testing.T) {
	const (
		localAddrByte byte          = 0x01
		remoteAddr    tcpip.Address = "\x03"
		noAddr        tcpip.Address = ""
		nicid         tcpip.NICID   = 1
	)
	localAddr := tcpip.Address([]byte{localAddrByte})

	for _, promiscuous := range []bool{true, false} {
		for _, spoofing := range []bool{true, false} {
			t.Run(fmt.Sprintf("promiscuous=%t spoofing=%t", promiscuous, spoofing), func(t *testing.T) {
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
				})

				ep := channel.New(10, defaultMTU, "")
				if err := s.CreateNIC(nicid, ep); err != nil {
					t.Fatal("CreateNIC failed:", err)
				}

				{
					subnet, err := tcpip.NewSubnet("\x00", "\x00")
					if err != nil {
						t.Fatal(err)
					}
					s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
				}

				fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)
				buf := buffer.NewView(30)
				buf[0] = localAddrByte

				if promiscuous {
					if err := s.SetPromiscuousMode(nicid, true); err != nil {
						t.Fatal("SetPromiscuousMode failed:", err)
					}
				}

				if spoofing {
					if err := s.SetSpoofing(nicid, true); err != nil {
						t.Fatal("SetSpoofing failed:", err)
					}
				}

				// 1. No Address yet, send should only work for spoofing, receive for
				// promiscuous mode.
				//-----------------------
				verifyAddress(t, s, nicid, noAddr)
				if promiscuous {
					testRecv(t, fakeNet, localAddrByte, ep, buf)
				} else {
					testFailingRecv(t, fakeNet, localAddrByte, ep, buf)
				}
				if spoofing {
					// FIXME(b/139841518):Spoofing doesn't work if there is no primary address.
					// testSendTo(t, s, remoteAddr, ep, nil)
				} else {
					testFailingSendTo(t, s, remoteAddr, ep, nil, tcpip.ErrNoRoute)
				}

				// 2. Add Address, everything should work.
				//-----------------------
				if err := s.AddAddress(nicid, fakeNetNumber, localAddr); err != nil {
					t.Fatal("AddAddress failed:", err)
				}
				verifyAddress(t, s, nicid, localAddr)
				testRecv(t, fakeNet, localAddrByte, ep, buf)
				testSendTo(t, s, remoteAddr, ep, nil)

				// 3. Remove the address, send should only work for spoofing, receive
				// for promiscuous mode.
				//-----------------------
				if err := s.RemoveAddress(nicid, localAddr); err != nil {
					t.Fatal("RemoveAddress failed:", err)
				}
				verifyAddress(t, s, nicid, noAddr)
				if promiscuous {
					testRecv(t, fakeNet, localAddrByte, ep, buf)
				} else {
					testFailingRecv(t, fakeNet, localAddrByte, ep, buf)
				}
				if spoofing {
					// FIXME(b/139841518):Spoofing doesn't work if there is no primary address.
					// testSendTo(t, s, remoteAddr, ep, nil)
				} else {
					testFailingSendTo(t, s, remoteAddr, ep, nil, tcpip.ErrNoRoute)
				}

				// 4. Add Address back, everything should work again.
				//-----------------------
				if err := s.AddAddress(nicid, fakeNetNumber, localAddr); err != nil {
					t.Fatal("AddAddress failed:", err)
				}
				verifyAddress(t, s, nicid, localAddr)
				testRecv(t, fakeNet, localAddrByte, ep, buf)
				testSendTo(t, s, remoteAddr, ep, nil)

				// 5. Take a reference to the endpoint by getting a route. Verify that
				// we can still send/receive, including sending using the route.
				//-----------------------
				r, err := s.FindRoute(0, "", remoteAddr, fakeNetNumber, false /* multicastLoop */)
				if err != nil {
					t.Fatal("FindRoute failed:", err)
				}
				testRecv(t, fakeNet, localAddrByte, ep, buf)
				testSendTo(t, s, remoteAddr, ep, nil)
				testSend(t, r, ep, nil)

				// 6. Remove the address. Send should only work for spoofing, receive
				// for promiscuous mode.
				//-----------------------
				if err := s.RemoveAddress(nicid, localAddr); err != nil {
					t.Fatal("RemoveAddress failed:", err)
				}
				verifyAddress(t, s, nicid, noAddr)
				if promiscuous {
					testRecv(t, fakeNet, localAddrByte, ep, buf)
				} else {
					testFailingRecv(t, fakeNet, localAddrByte, ep, buf)
				}
				if spoofing {
					testSend(t, r, ep, nil)
					testSendTo(t, s, remoteAddr, ep, nil)
				} else {
					testFailingSend(t, r, ep, nil, tcpip.ErrInvalidEndpointState)
					testFailingSendTo(t, s, remoteAddr, ep, nil, tcpip.ErrNoRoute)
				}

				// 7. Add Address back, everything should work again.
				//-----------------------
				if err := s.AddAddress(nicid, fakeNetNumber, localAddr); err != nil {
					t.Fatal("AddAddress failed:", err)
				}
				verifyAddress(t, s, nicid, localAddr)
				testRecv(t, fakeNet, localAddrByte, ep, buf)
				testSendTo(t, s, remoteAddr, ep, nil)
				testSend(t, r, ep, nil)

				// 8. Remove the route, sendTo/recv should still work.
				//-----------------------
				r.Release()
				verifyAddress(t, s, nicid, localAddr)
				testRecv(t, fakeNet, localAddrByte, ep, buf)
				testSendTo(t, s, remoteAddr, ep, nil)

				// 9. Remove the address. Send should only work for spoofing, receive
				// for promiscuous mode.
				//-----------------------
				if err := s.RemoveAddress(nicid, localAddr); err != nil {
					t.Fatal("RemoveAddress failed:", err)
				}
				verifyAddress(t, s, nicid, noAddr)
				if promiscuous {
					testRecv(t, fakeNet, localAddrByte, ep, buf)
				} else {
					testFailingRecv(t, fakeNet, localAddrByte, ep, buf)
				}
				if spoofing {
					// FIXME(b/139841518):Spoofing doesn't work if there is no primary address.
					// testSendTo(t, s, remoteAddr, ep, nil)
				} else {
					testFailingSendTo(t, s, remoteAddr, ep, nil, tcpip.ErrNoRoute)
				}
			})
		}
	}
}

func TestPromiscuousMode(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	// Write a packet, and check that it doesn't get delivered as we don't
	// have a matching endpoint.
	const localAddrByte byte = 0x01
	buf[0] = localAddrByte
	testFailingRecv(t, fakeNet, localAddrByte, ep, buf)

	// Set promiscuous mode, then check that packet is delivered.
	if err := s.SetPromiscuousMode(1, true); err != nil {
		t.Fatal("SetPromiscuousMode failed:", err)
	}
	testRecv(t, fakeNet, localAddrByte, ep, buf)

	// Check that we can't get a route as there is no local address.
	_, err := s.FindRoute(0, "", "\x02", fakeNetNumber, false /* multicastLoop */)
	if err != tcpip.ErrNoRoute {
		t.Fatalf("FindRoute returned unexpected error: got = %v, want = %s", err, tcpip.ErrNoRoute)
	}

	// Set promiscuous mode to false, then check that packet can't be
	// delivered anymore.
	if err := s.SetPromiscuousMode(1, false); err != nil {
		t.Fatal("SetPromiscuousMode failed:", err)
	}
	testFailingRecv(t, fakeNet, localAddrByte, ep, buf)
}

func TestSpoofingWithAddress(t *testing.T) {
	localAddr := tcpip.Address("\x01")
	nonExistentLocalAddr := tcpip.Address("\x02")
	dstAddr := tcpip.Address("\x03")

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, localAddr); err != nil {
		t.Fatal("AddAddress failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	// With address spoofing disabled, FindRoute does not permit an address
	// that was not added to the NIC to be used as the source.
	r, err := s.FindRoute(0, nonExistentLocalAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err == nil {
		t.Errorf("FindRoute succeeded with route %+v when it should have failed", r)
	}

	// With address spoofing enabled, FindRoute permits any address to be used
	// as the source.
	if err := s.SetSpoofing(1, true); err != nil {
		t.Fatal("SetSpoofing failed:", err)
	}
	r, err = s.FindRoute(0, nonExistentLocalAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
	}
	if r.LocalAddress != nonExistentLocalAddr {
		t.Errorf("got Route.LocalAddress = %s, want = %s", r.LocalAddress, nonExistentLocalAddr)
	}
	if r.RemoteAddress != dstAddr {
		t.Errorf("got Route.RemoteAddress = %s, want = %s", r.RemoteAddress, dstAddr)
	}
	// Sending a packet works.
	testSendTo(t, s, dstAddr, ep, nil)
	testSend(t, r, ep, nil)

	// FindRoute should also work with a local address that exists on the NIC.
	r, err = s.FindRoute(0, localAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
	}
	if r.LocalAddress != localAddr {
		t.Errorf("got Route.LocalAddress = %s, want = %s", r.LocalAddress, nonExistentLocalAddr)
	}
	if r.RemoteAddress != dstAddr {
		t.Errorf("got Route.RemoteAddress = %s, want = %s", r.RemoteAddress, dstAddr)
	}
	// Sending a packet using the route works.
	testSend(t, r, ep, nil)
}

func TestSpoofingNoAddress(t *testing.T) {
	nonExistentLocalAddr := tcpip.Address("\x01")
	dstAddr := tcpip.Address("\x02")

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	// With address spoofing disabled, FindRoute does not permit an address
	// that was not added to the NIC to be used as the source.
	r, err := s.FindRoute(0, nonExistentLocalAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err == nil {
		t.Errorf("FindRoute succeeded with route %+v when it should have failed", r)
	}
	// Sending a packet fails.
	testFailingSendTo(t, s, dstAddr, ep, nil, tcpip.ErrNoRoute)

	// With address spoofing enabled, FindRoute permits any address to be used
	// as the source.
	if err := s.SetSpoofing(1, true); err != nil {
		t.Fatal("SetSpoofing failed:", err)
	}
	r, err = s.FindRoute(0, nonExistentLocalAddr, dstAddr, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatal("FindRoute failed:", err)
	}
	if r.LocalAddress != nonExistentLocalAddr {
		t.Errorf("got Route.LocalAddress = %s, want = %s", r.LocalAddress, nonExistentLocalAddr)
	}
	if r.RemoteAddress != dstAddr {
		t.Errorf("got Route.RemoteAddress = %s, want = %s", r.RemoteAddress, dstAddr)
	}
	// Sending a packet works.
	// FIXME(b/139841518):Spoofing doesn't work if there is no primary address.
	// testSendTo(t, s, remoteAddr, ep, nil)
}

func verifyRoute(gotRoute, wantRoute stack.Route) error {
	if gotRoute.LocalAddress != wantRoute.LocalAddress {
		return fmt.Errorf("bad local address: got %s, want = %s", gotRoute.LocalAddress, wantRoute.LocalAddress)
	}
	if gotRoute.RemoteAddress != wantRoute.RemoteAddress {
		return fmt.Errorf("bad remote address: got %s, want = %s", gotRoute.RemoteAddress, wantRoute.RemoteAddress)
	}
	if gotRoute.RemoteLinkAddress != wantRoute.RemoteLinkAddress {
		return fmt.Errorf("bad remote link address: got %s, want = %s", gotRoute.RemoteLinkAddress, wantRoute.RemoteLinkAddress)
	}
	if gotRoute.NextHop != wantRoute.NextHop {
		return fmt.Errorf("bad next-hop address: got %s, want = %s", gotRoute.NextHop, wantRoute.NextHop)
	}
	return nil
}

func TestOutgoingBroadcastWithEmptyRouteTable(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}
	s.SetRouteTable([]tcpip.Route{})

	// If there is no endpoint, it won't work.
	if _, err := s.FindRoute(1, header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */); err != tcpip.ErrNetworkUnreachable {
		t.Fatalf("got FindRoute(1, %s, %s, %d) = %s, want = %s", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err, tcpip.ErrNetworkUnreachable)
	}

	protoAddr := tcpip.ProtocolAddress{Protocol: fakeNetNumber, AddressWithPrefix: tcpip.AddressWithPrefix{header.IPv4Any, 0}}
	if err := s.AddProtocolAddress(1, protoAddr); err != nil {
		t.Fatalf("AddProtocolAddress(1, %s) failed: %s", protoAddr, err)
	}
	r, err := s.FindRoute(1, header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(1, %s, %s, %d) failed: %s", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err)
	}
	if err := verifyRoute(r, stack.Route{LocalAddress: header.IPv4Any, RemoteAddress: header.IPv4Broadcast}); err != nil {
		t.Errorf("FindRoute(1, %s, %s, %d) returned unexpected Route: %s)", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err)
	}

	// If the NIC doesn't exist, it won't work.
	if _, err := s.FindRoute(2, header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */); err != tcpip.ErrNetworkUnreachable {
		t.Fatalf("got FindRoute(2, %s, %s, %d) = %s want = %s", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err, tcpip.ErrNetworkUnreachable)
	}
}

func TestOutgoingBroadcastWithRouteTable(t *testing.T) {
	defaultAddr := tcpip.AddressWithPrefix{header.IPv4Any, 0}
	// Local subnet on NIC1: 192.168.1.58/24, gateway 192.168.1.1.
	nic1Addr := tcpip.AddressWithPrefix{"\xc0\xa8\x01\x3a", 24}
	nic1Gateway := tcpip.Address("\xc0\xa8\x01\x01")
	// Local subnet on NIC2: 10.10.10.5/24, gateway 10.10.10.1.
	nic2Addr := tcpip.AddressWithPrefix{"\x0a\x0a\x0a\x05", 24}
	nic2Gateway := tcpip.Address("\x0a\x0a\x0a\x01")

	// Create a new stack with two NICs.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC failed: %s", err)
	}
	if err := s.CreateNIC(2, ep); err != nil {
		t.Fatalf("CreateNIC failed: %s", err)
	}
	nic1ProtoAddr := tcpip.ProtocolAddress{fakeNetNumber, nic1Addr}
	if err := s.AddProtocolAddress(1, nic1ProtoAddr); err != nil {
		t.Fatalf("AddProtocolAddress(1, %s) failed: %s", nic1ProtoAddr, err)
	}

	nic2ProtoAddr := tcpip.ProtocolAddress{fakeNetNumber, nic2Addr}
	if err := s.AddProtocolAddress(2, nic2ProtoAddr); err != nil {
		t.Fatalf("AddAddress(2, %s) failed: %s", nic2ProtoAddr, err)
	}

	// Set the initial route table.
	rt := []tcpip.Route{
		{Destination: nic1Addr.Subnet(), NIC: 1},
		{Destination: nic2Addr.Subnet(), NIC: 2},
		{Destination: defaultAddr.Subnet(), Gateway: nic2Gateway, NIC: 2},
		{Destination: defaultAddr.Subnet(), Gateway: nic1Gateway, NIC: 1},
	}
	s.SetRouteTable(rt)

	// When an interface is given, the route for a broadcast goes through it.
	r, err := s.FindRoute(1, nic1Addr.Address, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(1, %s, %s, %d) failed: %s", nic1Addr.Address, header.IPv4Broadcast, fakeNetNumber, err)
	}
	if err := verifyRoute(r, stack.Route{LocalAddress: nic1Addr.Address, RemoteAddress: header.IPv4Broadcast}); err != nil {
		t.Errorf("FindRoute(1, %s, %s, %d) returned unexpected Route: %s)", nic1Addr.Address, header.IPv4Broadcast, fakeNetNumber, err)
	}

	// When an interface is not given, it consults the route table.
	// 1. Case: Using the default route.
	r, err = s.FindRoute(0, "", header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(0, \"\", %s, %d) failed: %s", header.IPv4Broadcast, fakeNetNumber, err)
	}
	if err := verifyRoute(r, stack.Route{LocalAddress: nic2Addr.Address, RemoteAddress: header.IPv4Broadcast}); err != nil {
		t.Errorf("FindRoute(0, \"\", %s, %d) returned unexpected Route: %s)", header.IPv4Broadcast, fakeNetNumber, err)
	}

	// 2. Case: Having an explicit route for broadcast will select that one.
	rt = append(
		[]tcpip.Route{
			{Destination: tcpip.AddressWithPrefix{header.IPv4Broadcast, 8 * header.IPv4AddressSize}.Subnet(), NIC: 1},
		},
		rt...,
	)
	s.SetRouteTable(rt)
	r, err = s.FindRoute(0, "", header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(0, \"\", %s, %d) failed: %s", header.IPv4Broadcast, fakeNetNumber, err)
	}
	if err := verifyRoute(r, stack.Route{LocalAddress: nic1Addr.Address, RemoteAddress: header.IPv4Broadcast}); err != nil {
		t.Errorf("FindRoute(0, \"\", %s, %d) returned unexpected Route: %s)", header.IPv4Broadcast, fakeNetNumber, err)
	}
}

func TestMulticastOrIPv6LinkLocalNeedsNoRoute(t *testing.T) {
	for _, tc := range []struct {
		name        string
		routeNeeded bool
		address     tcpip.Address
	}{
		// IPv4 multicast address range: 224.0.0.0 - 239.255.255.255
		//                <=>  0xe0.0x00.0x00.0x00 - 0xef.0xff.0xff.0xff
		{"IPv4 Multicast 1", false, "\xe0\x00\x00\x00"},
		{"IPv4 Multicast 2", false, "\xef\xff\xff\xff"},
		{"IPv4 Unicast 1", true, "\xdf\xff\xff\xff"},
		{"IPv4 Unicast 2", true, "\xf0\x00\x00\x00"},
		{"IPv4 Unicast 3", true, "\x00\x00\x00\x00"},

		// IPv6 multicast address is 0xff[8] + flags[4] + scope[4] + groupId[112]
		{"IPv6 Multicast 1", false, "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Multicast 2", false, "\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Multicast 3", false, "\xff\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"},

		// IPv6 link-local address starts with fe80::/10.
		{"IPv6 Unicast Link-Local 1", false, "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Link-Local 2", false, "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
		{"IPv6 Unicast Link-Local 3", false, "\xfe\x80\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff"},
		{"IPv6 Unicast Link-Local 4", false, "\xfe\xbf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Link-Local 5", false, "\xfe\xbf\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"},

		// IPv6 addresses that are neither multicast nor link-local.
		{"IPv6 Unicast Not Link-Local 1", true, "\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 2", true, "\xf0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"},
		{"IPv6 Unicast Not Link-local 3", true, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 4", true, "\xfe\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 5", true, "\xfe\xdf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 6", true, "\xfd\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"IPv6 Unicast Not Link-Local 7", true, "\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
			})

			ep := channel.New(10, defaultMTU, "")
			if err := s.CreateNIC(1, ep); err != nil {
				t.Fatal("CreateNIC failed:", err)
			}

			s.SetRouteTable([]tcpip.Route{})

			var anyAddr tcpip.Address
			if len(tc.address) == header.IPv4AddressSize {
				anyAddr = header.IPv4Any
			} else {
				anyAddr = header.IPv6Any
			}

			want := tcpip.ErrNetworkUnreachable
			if tc.routeNeeded {
				want = tcpip.ErrNoRoute
			}

			// If there is no endpoint, it won't work.
			if _, err := s.FindRoute(1, anyAddr, tc.address, fakeNetNumber, false /* multicastLoop */); err != want {
				t.Fatalf("got FindRoute(1, %v, %v, %v) = %v, want = %v", anyAddr, tc.address, fakeNetNumber, err, want)
			}

			if err := s.AddAddress(1, fakeNetNumber, anyAddr); err != nil {
				t.Fatalf("AddAddress(%v, %v) failed: %v", fakeNetNumber, anyAddr, err)
			}

			if r, err := s.FindRoute(1, anyAddr, tc.address, fakeNetNumber, false /* multicastLoop */); tc.routeNeeded {
				// Route table is empty but we need a route, this should cause an error.
				if err != tcpip.ErrNoRoute {
					t.Fatalf("got FindRoute(1, %v, %v, %v) = %v, want = %v", anyAddr, tc.address, fakeNetNumber, err, tcpip.ErrNoRoute)
				}
			} else {
				if err != nil {
					t.Fatalf("FindRoute(1, %v, %v, %v) failed: %v", anyAddr, tc.address, fakeNetNumber, err)
				}
				if r.LocalAddress != anyAddr {
					t.Errorf("Bad local address: got %v, want = %v", r.LocalAddress, anyAddr)
				}
				if r.RemoteAddress != tc.address {
					t.Errorf("Bad remote address: got %v, want = %v", r.RemoteAddress, tc.address)
				}
			}
			// If the NIC doesn't exist, it won't work.
			if _, err := s.FindRoute(2, anyAddr, tc.address, fakeNetNumber, false /* multicastLoop */); err != want {
				t.Fatalf("got FindRoute(2, %v, %v, %v) = %v want = %v", anyAddr, tc.address, fakeNetNumber, err, want)
			}
		})
	}
}

// Add a range of addresses, then check that a packet is delivered.
func TestAddressRangeAcceptsMatchingPacket(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	const localAddrByte byte = 0x01
	buf[0] = localAddrByte
	subnet, err := tcpip.NewSubnet(tcpip.Address("\x00"), tcpip.AddressMask("\xF0"))
	if err != nil {
		t.Fatal("NewSubnet failed:", err)
	}
	if err := s.AddAddressRange(1, fakeNetNumber, subnet); err != nil {
		t.Fatal("AddAddressRange failed:", err)
	}

	testRecv(t, fakeNet, localAddrByte, ep, buf)
}

func testNicForAddressRange(t *testing.T, nicID tcpip.NICID, s *stack.Stack, subnet tcpip.Subnet, rangeExists bool) {
	t.Helper()

	// Loop over all addresses and check them.
	numOfAddresses := 1 << uint(8-subnet.Prefix())
	if numOfAddresses < 1 || numOfAddresses > 255 {
		t.Fatalf("got numOfAddresses = %d, want = [1 .. 255] (subnet=%s)", numOfAddresses, subnet)
	}

	addrBytes := []byte(subnet.ID())
	for i := 0; i < numOfAddresses; i++ {
		addr := tcpip.Address(addrBytes)
		wantNicID := nicID
		// The subnet and broadcast addresses are skipped.
		if !rangeExists || addr == subnet.ID() || addr == subnet.Broadcast() {
			wantNicID = 0
		}
		if gotNicID := s.CheckLocalAddress(0, fakeNetNumber, addr); gotNicID != wantNicID {
			t.Errorf("got CheckLocalAddress(0, %d, %s) = %d, want = %d", fakeNetNumber, addr, gotNicID, wantNicID)
		}
		addrBytes[0]++
	}

	// Trying the next address should always fail since it is outside the range.
	if gotNicID := s.CheckLocalAddress(0, fakeNetNumber, tcpip.Address(addrBytes)); gotNicID != 0 {
		t.Errorf("got CheckLocalAddress(0, %d, %s) = %d, want = %d", fakeNetNumber, tcpip.Address(addrBytes), gotNicID, 0)
	}
}

// Set a range of addresses, then remove it again, and check at each step that
// CheckLocalAddress returns the correct NIC for each address or zero if not
// existent.
func TestCheckLocalAddressForSubnet(t *testing.T) {
	const nicID tcpip.NICID = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: nicID}})
	}

	subnet, err := tcpip.NewSubnet(tcpip.Address("\xa0"), tcpip.AddressMask("\xf0"))
	if err != nil {
		t.Fatal("NewSubnet failed:", err)
	}

	testNicForAddressRange(t, nicID, s, subnet, false /* rangeExists */)

	if err := s.AddAddressRange(nicID, fakeNetNumber, subnet); err != nil {
		t.Fatal("AddAddressRange failed:", err)
	}

	testNicForAddressRange(t, nicID, s, subnet, true /* rangeExists */)

	if err := s.RemoveAddressRange(nicID, subnet); err != nil {
		t.Fatal("RemoveAddressRange failed:", err)
	}

	testNicForAddressRange(t, nicID, s, subnet, false /* rangeExists */)
}

// Set a range of addresses, then send a packet to a destination outside the
// range and then check it doesn't get delivered.
func TestAddressRangeRejectsNonmatchingPacket(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	buf := buffer.NewView(30)

	const localAddrByte byte = 0x01
	buf[0] = localAddrByte
	subnet, err := tcpip.NewSubnet(tcpip.Address("\x10"), tcpip.AddressMask("\xF0"))
	if err != nil {
		t.Fatal("NewSubnet failed:", err)
	}
	if err := s.AddAddressRange(1, fakeNetNumber, subnet); err != nil {
		t.Fatal("AddAddressRange failed:", err)
	}
	testFailingRecv(t, fakeNet, localAddrByte, ep, buf)
}

func TestNetworkOptions(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{fakeNetFactory()},
		TransportProtocols: []stack.TransportProtocol{},
	})

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

func stackContainsAddressRange(s *stack.Stack, id tcpip.NICID, addrRange tcpip.Subnet) bool {
	ranges, ok := s.NICAddressRanges()[id]
	if !ok {
		return false
	}
	for _, r := range ranges {
		if r == addrRange {
			return true
		}
	}
	return false
}

func TestAddresRangeAddRemove(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	addr := tcpip.Address("\x01\x01\x01\x01")
	mask := tcpip.AddressMask(strings.Repeat("\xff", len(addr)))
	addrRange, err := tcpip.NewSubnet(addr, mask)
	if err != nil {
		t.Fatal("NewSubnet failed:", err)
	}

	if got, want := stackContainsAddressRange(s, 1, addrRange), false; got != want {
		t.Fatalf("got stackContainsAddressRange(...) = %t, want = %t", got, want)
	}

	if err := s.AddAddressRange(1, fakeNetNumber, addrRange); err != nil {
		t.Fatal("AddAddressRange failed:", err)
	}

	if got, want := stackContainsAddressRange(s, 1, addrRange), true; got != want {
		t.Fatalf("got stackContainsAddressRange(...) = %t, want = %t", got, want)
	}

	if err := s.RemoveAddressRange(1, addrRange); err != nil {
		t.Fatal("RemoveAddressRange failed:", err)
	}

	if got, want := stackContainsAddressRange(s, 1, addrRange), false; got != want {
		t.Fatalf("got stackContainsAddressRange(...) = %t, want = %t", got, want)
	}
}

func TestGetMainNICAddressAddPrimaryNonPrimary(t *testing.T) {
	for _, addrLen := range []int{4, 16} {
		t.Run(fmt.Sprintf("addrLen=%d", addrLen), func(t *testing.T) {
			for canBe := 0; canBe < 3; canBe++ {
				t.Run(fmt.Sprintf("canBe=%d", canBe), func(t *testing.T) {
					for never := 0; never < 3; never++ {
						t.Run(fmt.Sprintf("never=%d", never), func(t *testing.T) {
							s := stack.New(stack.Options{
								NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
							})
							ep := channel.New(10, defaultMTU, "")
							if err := s.CreateNIC(1, ep); err != nil {
								t.Fatal("CreateNIC failed:", err)
							}
							// Insert <canBe> primary and <never> never-primary addresses.
							// Each one will add a network endpoint to the NIC.
							primaryAddrAdded := make(map[tcpip.AddressWithPrefix]struct{})
							for i := 0; i < canBe+never; i++ {
								var behavior stack.PrimaryEndpointBehavior
								if i < canBe {
									behavior = stack.CanBePrimaryEndpoint
								} else {
									behavior = stack.NeverPrimaryEndpoint
								}
								// Add an address and in case of a primary one include a
								// prefixLen.
								address := tcpip.Address(bytes.Repeat([]byte{byte(i)}, addrLen))
								if behavior == stack.CanBePrimaryEndpoint {
									protocolAddress := tcpip.ProtocolAddress{
										Protocol: fakeNetNumber,
										AddressWithPrefix: tcpip.AddressWithPrefix{
											Address:   address,
											PrefixLen: addrLen * 8,
										},
									}
									if err := s.AddProtocolAddressWithOptions(1, protocolAddress, behavior); err != nil {
										t.Fatal("AddProtocolAddressWithOptions failed:", err)
									}
									// Remember the address/prefix.
									primaryAddrAdded[protocolAddress.AddressWithPrefix] = struct{}{}
								} else {
									if err := s.AddAddressWithOptions(1, fakeNetNumber, address, behavior); err != nil {
										t.Fatal("AddAddressWithOptions failed:", err)
									}
								}
							}
							// Check that GetMainNICAddress returns an address if at least
							// one primary address was added. In that case make sure the
							// address/prefixLen matches what we added.
							gotAddr, err := s.GetMainNICAddress(1, fakeNetNumber)
							if err != nil {
								t.Fatal("GetMainNICAddress failed:", err)
							}
							if len(primaryAddrAdded) == 0 {
								// No primary addresses present.
								if wantAddr := (tcpip.AddressWithPrefix{}); gotAddr != wantAddr {
									t.Fatalf("GetMainNICAddress: got addr = %s, want = %s", gotAddr, wantAddr)
								}
							} else {
								// At least one primary address was added, verify the returned
								// address is in the list of primary addresses we added.
								if _, ok := primaryAddrAdded[gotAddr]; !ok {
									t.Fatalf("GetMainNICAddress: got = %s, want any in {%v}", gotAddr, primaryAddrAdded)
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestGetMainNICAddressAddRemove(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	for _, tc := range []struct {
		name      string
		address   tcpip.Address
		prefixLen int
	}{
		{"IPv4", "\x01\x01\x01\x01", 24},
		{"IPv6", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 116},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protocolAddress := tcpip.ProtocolAddress{
				Protocol: fakeNetNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   tc.address,
					PrefixLen: tc.prefixLen,
				},
			}
			if err := s.AddProtocolAddress(1, protocolAddress); err != nil {
				t.Fatal("AddProtocolAddress failed:", err)
			}

			// Check that we get the right initial address and prefix length.
			gotAddr, err := s.GetMainNICAddress(1, fakeNetNumber)
			if err != nil {
				t.Fatal("GetMainNICAddress failed:", err)
			}
			if wantAddr := protocolAddress.AddressWithPrefix; gotAddr != wantAddr {
				t.Fatalf("got s.GetMainNICAddress(...) = %s, want = %s", gotAddr, wantAddr)
			}

			if err := s.RemoveAddress(1, protocolAddress.AddressWithPrefix.Address); err != nil {
				t.Fatal("RemoveAddress failed:", err)
			}

			// Check that we get no address after removal.
			gotAddr, err = s.GetMainNICAddress(1, fakeNetNumber)
			if err != nil {
				t.Fatal("GetMainNICAddress failed:", err)
			}
			if wantAddr := (tcpip.AddressWithPrefix{}); gotAddr != wantAddr {
				t.Fatalf("got GetMainNICAddress(...) = %s, want = %s", gotAddr, wantAddr)
			}
		})
	}
}

// Simple network address generator. Good for 255 addresses.
type addressGenerator struct{ cnt byte }

func (g *addressGenerator) next(addrLen int) tcpip.Address {
	g.cnt++
	return tcpip.Address(bytes.Repeat([]byte{g.cnt}, addrLen))
}

func verifyAddresses(t *testing.T, expectedAddresses, gotAddresses []tcpip.ProtocolAddress) {
	t.Helper()

	if len(gotAddresses) != len(expectedAddresses) {
		t.Fatalf("got len(addresses) = %d, want = %d", len(gotAddresses), len(expectedAddresses))
	}

	sort.Slice(gotAddresses, func(i, j int) bool {
		return gotAddresses[i].AddressWithPrefix.Address < gotAddresses[j].AddressWithPrefix.Address
	})
	sort.Slice(expectedAddresses, func(i, j int) bool {
		return expectedAddresses[i].AddressWithPrefix.Address < expectedAddresses[j].AddressWithPrefix.Address
	})

	for i, gotAddr := range gotAddresses {
		expectedAddr := expectedAddresses[i]
		if gotAddr != expectedAddr {
			t.Errorf("got address = %+v, wanted = %+v", gotAddr, expectedAddr)
		}
	}
}

func TestAddAddress(t *testing.T) {
	const nicid = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicid, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	var addrGen addressGenerator
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, 2)
	for _, addrLen := range []int{4, 16} {
		address := addrGen.next(addrLen)
		if err := s.AddAddress(nicid, fakeNetNumber, address); err != nil {
			t.Fatalf("AddAddress(address=%s) failed: %s", address, err)
		}
		expectedAddresses = append(expectedAddresses, tcpip.ProtocolAddress{
			Protocol:          fakeNetNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{address, fakeDefaultPrefixLen},
		})
	}

	gotAddresses := s.AllAddresses()[nicid]
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddProtocolAddress(t *testing.T) {
	const nicid = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicid, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	var addrGen addressGenerator
	addrLenRange := []int{4, 16}
	prefixLenRange := []int{8, 13, 20, 32}
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, len(addrLenRange)*len(prefixLenRange))
	for _, addrLen := range addrLenRange {
		for _, prefixLen := range prefixLenRange {
			protocolAddress := tcpip.ProtocolAddress{
				Protocol: fakeNetNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   addrGen.next(addrLen),
					PrefixLen: prefixLen,
				},
			}
			if err := s.AddProtocolAddress(nicid, protocolAddress); err != nil {
				t.Errorf("AddProtocolAddress(%+v) failed: %s", protocolAddress, err)
			}
			expectedAddresses = append(expectedAddresses, protocolAddress)
		}
	}

	gotAddresses := s.AllAddresses()[nicid]
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddAddressWithOptions(t *testing.T) {
	const nicid = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicid, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	addrLenRange := []int{4, 16}
	behaviorRange := []stack.PrimaryEndpointBehavior{stack.CanBePrimaryEndpoint, stack.FirstPrimaryEndpoint, stack.NeverPrimaryEndpoint}
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, len(addrLenRange)*len(behaviorRange))
	var addrGen addressGenerator
	for _, addrLen := range addrLenRange {
		for _, behavior := range behaviorRange {
			address := addrGen.next(addrLen)
			if err := s.AddAddressWithOptions(nicid, fakeNetNumber, address, behavior); err != nil {
				t.Fatalf("AddAddressWithOptions(address=%s, behavior=%d) failed: %s", address, behavior, err)
			}
			expectedAddresses = append(expectedAddresses, tcpip.ProtocolAddress{
				Protocol:          fakeNetNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{address, fakeDefaultPrefixLen},
			})
		}
	}

	gotAddresses := s.AllAddresses()[nicid]
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddProtocolAddressWithOptions(t *testing.T) {
	const nicid = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicid, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	addrLenRange := []int{4, 16}
	prefixLenRange := []int{8, 13, 20, 32}
	behaviorRange := []stack.PrimaryEndpointBehavior{stack.CanBePrimaryEndpoint, stack.FirstPrimaryEndpoint, stack.NeverPrimaryEndpoint}
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, len(addrLenRange)*len(prefixLenRange)*len(behaviorRange))
	var addrGen addressGenerator
	for _, addrLen := range addrLenRange {
		for _, prefixLen := range prefixLenRange {
			for _, behavior := range behaviorRange {
				protocolAddress := tcpip.ProtocolAddress{
					Protocol: fakeNetNumber,
					AddressWithPrefix: tcpip.AddressWithPrefix{
						Address:   addrGen.next(addrLen),
						PrefixLen: prefixLen,
					},
				}
				if err := s.AddProtocolAddressWithOptions(nicid, protocolAddress, behavior); err != nil {
					t.Fatalf("AddProtocolAddressWithOptions(%+v, %d) failed: %s", protocolAddress, behavior, err)
				}
				expectedAddresses = append(expectedAddresses, protocolAddress)
			}
		}
	}

	gotAddresses := s.AllAddresses()[nicid]
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestNICStats(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep1 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep1); err != nil {
		t.Fatal("CreateNIC failed: ", err)
	}
	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress failed:", err)
	}
	// Route all packets for address \x01 to NIC 1.
	{
		subnet, err := tcpip.NewSubnet("\x01", "\xff")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
	}

	// Send a packet to address 1.
	buf := buffer.NewView(30)
	ep1.Inject(fakeNetNumber, buf.ToVectorisedView())
	if got, want := s.NICInfo()[1].Stats.Rx.Packets.Value(), uint64(1); got != want {
		t.Errorf("got Rx.Packets.Value() = %d, want = %d", got, want)
	}

	if got, want := s.NICInfo()[1].Stats.Rx.Bytes.Value(), uint64(len(buf)); got != want {
		t.Errorf("got Rx.Bytes.Value() = %d, want = %d", got, want)
	}

	payload := buffer.NewView(10)
	// Write a packet out via the address for NIC 1
	if err := sendTo(s, "\x01", payload); err != nil {
		t.Fatal("sendTo failed: ", err)
	}
	want := uint64(ep1.Drain())
	if got := s.NICInfo()[1].Stats.Tx.Packets.Value(); got != want {
		t.Errorf("got Tx.Packets.Value() = %d, ep1.Drain() = %d", got, want)
	}

	if got, want := s.NICInfo()[1].Stats.Tx.Bytes.Value(), uint64(len(payload)); got != want {
		t.Errorf("got Tx.Bytes.Value() = %d, want = %d", got, want)
	}
}

func TestNICForwarding(t *testing.T) {
	// Create a stack with the fake network protocol, two NICs, each with
	// an address.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	s.SetForwarding(true)

	ep1 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(1, ep1); err != nil {
		t.Fatal("CreateNIC #1 failed:", err)
	}
	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress #1 failed:", err)
	}

	ep2 := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(2, ep2); err != nil {
		t.Fatal("CreateNIC #2 failed:", err)
	}
	if err := s.AddAddress(2, fakeNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress #2 failed:", err)
	}

	// Route all packets to address 3 to NIC 2.
	{
		subnet, err := tcpip.NewSubnet("\x03", "\xff")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 2}})
	}

	// Send a packet to address 3.
	buf := buffer.NewView(30)
	buf[0] = 3
	ep1.Inject(fakeNetNumber, buf.ToVectorisedView())

	select {
	case <-ep2.C:
	default:
		t.Fatal("Packet not forwarded")
	}

	// Test that forwarding increments Tx stats correctly.
	if got, want := s.NICInfo()[2].Stats.Tx.Packets.Value(), uint64(1); got != want {
		t.Errorf("got Tx.Packets.Value() = %d, want = %d", got, want)
	}

	if got, want := s.NICInfo()[2].Stats.Tx.Bytes.Value(), uint64(len(buf)); got != want {
		t.Errorf("got Tx.Bytes.Value() = %d, want = %d", got, want)
	}
}
