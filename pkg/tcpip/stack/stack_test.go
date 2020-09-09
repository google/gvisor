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
	"net"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
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

	dstAddrOffset        = 0
	srcAddrOffset        = 1
	protocolNumberOffset = 2
)

// fakeNetworkEndpoint is a network-layer protocol endpoint. It counts sent and
// received packets; the counts of all endpoints are aggregated in the protocol
// descriptor.
//
// Headers of this protocol are fakeNetHeaderLen bytes, but we currently only
// use the first three: destination address, source address, and transport
// protocol. They're all one byte fields to simplify parsing.
type fakeNetworkEndpoint struct {
	nicID      tcpip.NICID
	proto      *fakeNetworkProtocol
	dispatcher stack.TransportDispatcher
	ep         stack.LinkEndpoint
}

func (f *fakeNetworkEndpoint) MTU() uint32 {
	return f.ep.MTU() - uint32(f.MaxHeaderLength())
}

func (f *fakeNetworkEndpoint) NICID() tcpip.NICID {
	return f.nicID
}

func (*fakeNetworkEndpoint) DefaultTTL() uint8 {
	return 123
}

func (f *fakeNetworkEndpoint) HandlePacket(r *stack.Route, pkt *stack.PacketBuffer) {
	// Increment the received packet count in the protocol descriptor.
	f.proto.packetCount[int(r.LocalAddress[0])%len(f.proto.packetCount)]++

	// Handle control packets.
	if pkt.NetworkHeader().View()[protocolNumberOffset] == uint8(fakeControlProtocol) {
		nb, ok := pkt.Data.PullUp(fakeNetHeaderLen)
		if !ok {
			return
		}
		pkt.Data.TrimFront(fakeNetHeaderLen)
		f.dispatcher.DeliverTransportControlPacket(
			tcpip.Address(nb[srcAddrOffset:srcAddrOffset+1]),
			tcpip.Address(nb[dstAddrOffset:dstAddrOffset+1]),
			fakeNetNumber,
			tcpip.TransportProtocolNumber(nb[protocolNumberOffset]),
			stack.ControlPortUnreachable, 0, pkt)
		return
	}

	// Dispatch the packet to the transport protocol.
	f.dispatcher.DeliverTransportPacket(r, tcpip.TransportProtocolNumber(pkt.NetworkHeader().View()[protocolNumberOffset]), pkt)
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

func (f *fakeNetworkEndpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return f.proto.Number()
}

func (f *fakeNetworkEndpoint) WritePacket(r *stack.Route, gso *stack.GSO, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) *tcpip.Error {
	// Increment the sent packet count in the protocol descriptor.
	f.proto.sendPacketCount[int(r.RemoteAddress[0])%len(f.proto.sendPacketCount)]++

	// Add the protocol's header to the packet and send it to the link
	// endpoint.
	hdr := pkt.NetworkHeader().Push(fakeNetHeaderLen)
	hdr[dstAddrOffset] = r.RemoteAddress[0]
	hdr[srcAddrOffset] = r.LocalAddress[0]
	hdr[protocolNumberOffset] = byte(params.Protocol)

	if r.Loop&stack.PacketLoop != 0 {
		f.HandlePacket(r, pkt)
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}

	return f.ep.WritePacket(r, gso, fakeNetNumber, pkt)
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (f *fakeNetworkEndpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, params stack.NetworkHeaderParams) (int, *tcpip.Error) {
	panic("not implemented")
}

func (*fakeNetworkEndpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) *tcpip.Error {
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
	return tcpip.Address(v[srcAddrOffset : srcAddrOffset+1]), tcpip.Address(v[dstAddrOffset : dstAddrOffset+1])
}

func (f *fakeNetworkProtocol) NewEndpoint(nicID tcpip.NICID, _ stack.LinkAddressCache, _ stack.NUDHandler, dispatcher stack.TransportDispatcher, ep stack.LinkEndpoint, _ *stack.Stack) stack.NetworkEndpoint {
	return &fakeNetworkEndpoint{
		nicID:      nicID,
		proto:      f,
		dispatcher: dispatcher,
		ep:         ep,
	}
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

// Close implements TransportProtocol.Close.
func (*fakeNetworkProtocol) Close() {}

// Wait implements TransportProtocol.Wait.
func (*fakeNetworkProtocol) Wait() {}

// Parse implements TransportProtocol.Parse.
func (*fakeNetworkProtocol) Parse(pkt *stack.PacketBuffer) (tcpip.TransportProtocolNumber, bool, bool) {
	hdr, ok := pkt.NetworkHeader().Consume(fakeNetHeaderLen)
	if !ok {
		return 0, false, false
	}
	return tcpip.TransportProtocolNumber(hdr[protocolNumberOffset]), true, true
}

func fakeNetFactory() stack.NetworkProtocol {
	return &fakeNetworkProtocol{}
}

// linkEPWithMockedAttach is a stack.LinkEndpoint that tests can use to verify
// that LinkEndpoint.Attach was called.
type linkEPWithMockedAttach struct {
	stack.LinkEndpoint
	attached bool
}

// Attach implements stack.LinkEndpoint.Attach.
func (l *linkEPWithMockedAttach) Attach(d stack.NetworkDispatcher) {
	l.LinkEndpoint.Attach(d)
	l.attached = d != nil
}

func (l *linkEPWithMockedAttach) isAttached() bool {
	return l.attached
}

// Checks to see if list contains an address.
func containsAddr(list []tcpip.ProtocolAddress, item tcpip.ProtocolAddress) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}

	return false
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
	buf[dstAddrOffset] = 3
	ep.InjectInbound(fakeNetNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
	if fakeNet.packetCount[1] != 0 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 0)
	}
	if fakeNet.packetCount[2] != 0 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 0)
	}

	// Make sure packet is delivered to first endpoint.
	buf[dstAddrOffset] = 1
	ep.InjectInbound(fakeNetNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 0 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 0)
	}

	// Make sure packet is delivered to second endpoint.
	buf[dstAddrOffset] = 2
	ep.InjectInbound(fakeNetNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}

	// Make sure packet is not delivered if protocol number is wrong.
	ep.InjectInbound(fakeNetNumber-1, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
	if fakeNet.packetCount[1] != 1 {
		t.Errorf("packetCount[1] = %d, want %d", fakeNet.packetCount[1], 1)
	}
	if fakeNet.packetCount[2] != 1 {
		t.Errorf("packetCount[2] = %d, want %d", fakeNet.packetCount[2], 1)
	}

	// Make sure packet that is too small is dropped.
	buf.CapLength(2)
	ep.InjectInbound(fakeNetNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
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
	return r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: fakeTransNumber, TTL: 123, TOS: stack.DefaultTOS}, stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Data:               payload.ToVectorisedView(),
	}))
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
	ep.InjectInbound(fakeNetNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
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

// TestAttachToLinkEndpointImmediately tests that a LinkEndpoint is attached to
// a NetworkDispatcher when the NIC is created.
func TestAttachToLinkEndpointImmediately(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name    string
		nicOpts stack.NICOptions
	}{
		{
			name:    "Create enabled NIC",
			nicOpts: stack.NICOptions{Disabled: false},
		},
		{
			name:    "Create disabled NIC",
			nicOpts: stack.NICOptions{Disabled: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
			})

			e := linkEPWithMockedAttach{
				LinkEndpoint: loopback.New(),
			}

			if err := s.CreateNICWithOptions(nicID, &e, test.nicOpts); err != nil {
				t.Fatalf("CreateNICWithOptions(%d, _, %+v) = %s", nicID, test.nicOpts, err)
			}
			if !e.isAttached() {
				t.Fatal("link endpoint not attached to a network dispatcher")
			}
		})
	}
}

func TestDisableUnknownNIC(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	if err := s.DisableNIC(1); err != tcpip.ErrUnknownNICID {
		t.Fatalf("got s.DisableNIC(1) = %v, want = %s", err, tcpip.ErrUnknownNICID)
	}
}

func TestDisabledNICsNICInfoAndCheckNIC(t *testing.T) {
	const nicID = 1

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	e := loopback.New()
	nicOpts := stack.NICOptions{Disabled: true}
	if err := s.CreateNICWithOptions(nicID, e, nicOpts); err != nil {
		t.Fatalf("CreateNICWithOptions(%d, _, %+v) = %s", nicID, nicOpts, err)
	}

	checkNIC := func(enabled bool) {
		t.Helper()

		allNICInfo := s.NICInfo()
		nicInfo, ok := allNICInfo[nicID]
		if !ok {
			t.Errorf("entry for %d missing from allNICInfo = %+v", nicID, allNICInfo)
		} else if nicInfo.Flags.Running != enabled {
			t.Errorf("got nicInfo.Flags.Running = %t, want = %t", nicInfo.Flags.Running, enabled)
		}

		if got := s.CheckNIC(nicID); got != enabled {
			t.Errorf("got s.CheckNIC(%d) = %t, want = %t", nicID, got, enabled)
		}
	}

	// NIC should initially report itself as disabled.
	checkNIC(false)

	if err := s.EnableNIC(nicID); err != nil {
		t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
	}
	checkNIC(true)

	// If the NIC is not reporting a correct enabled status, we cannot trust the
	// next check so end the test here.
	if t.Failed() {
		t.FailNow()
	}

	if err := s.DisableNIC(nicID); err != nil {
		t.Fatalf("s.DisableNIC(%d): %s", nicID, err)
	}
	checkNIC(false)
}

func TestRemoveUnknownNIC(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	if err := s.RemoveNIC(1); err != tcpip.ErrUnknownNICID {
		t.Fatalf("got s.RemoveNIC(1) = %v, want = %s", err, tcpip.ErrUnknownNICID)
	}
}

func TestRemoveNIC(t *testing.T) {
	const nicID = 1

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})

	e := linkEPWithMockedAttach{
		LinkEndpoint: loopback.New(),
	}
	if err := s.CreateNIC(nicID, &e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	// NIC should be present in NICInfo and attached to a NetworkDispatcher.
	allNICInfo := s.NICInfo()
	if _, ok := allNICInfo[nicID]; !ok {
		t.Errorf("entry for %d missing from allNICInfo = %+v", nicID, allNICInfo)
	}
	if !e.isAttached() {
		t.Fatal("link endpoint not attached to a network dispatcher")
	}

	// Removing a NIC should remove it from NICInfo and e should be detached from
	// the NetworkDispatcher.
	if err := s.RemoveNIC(nicID); err != nil {
		t.Fatalf("s.RemoveNIC(%d): %s", nicID, err)
	}
	if nicInfo, ok := s.NICInfo()[nicID]; ok {
		t.Errorf("got unexpected NICInfo entry for deleted NIC %d = %+v", nicID, nicInfo)
	}
	if e.isAttached() {
		t.Error("link endpoint for removed NIC still attached to a network dispatcher")
	}
}

func TestRouteWithDownNIC(t *testing.T) {
	tests := []struct {
		name   string
		downFn func(s *stack.Stack, nicID tcpip.NICID) *tcpip.Error
		upFn   func(s *stack.Stack, nicID tcpip.NICID) *tcpip.Error
	}{
		{
			name:   "Disabled NIC",
			downFn: (*stack.Stack).DisableNIC,
			upFn:   (*stack.Stack).EnableNIC,
		},

		// Once a NIC is removed, it cannot be brought up.
		{
			name:   "Removed NIC",
			downFn: (*stack.Stack).RemoveNIC,
		},
	}

	const unspecifiedNIC = 0
	const nicID1 = 1
	const nicID2 = 2
	const addr1 = tcpip.Address("\x01")
	const addr2 = tcpip.Address("\x02")
	const nic1Dst = tcpip.Address("\x05")
	const nic2Dst = tcpip.Address("\x06")

	setup := func(t *testing.T) (*stack.Stack, *channel.Endpoint, *channel.Endpoint) {
		s := stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
		})

		ep1 := channel.New(1, defaultMTU, "")
		if err := s.CreateNIC(nicID1, ep1); err != nil {
			t.Fatalf("CreateNIC(%d, _): %s", nicID1, err)
		}

		if err := s.AddAddress(nicID1, fakeNetNumber, addr1); err != nil {
			t.Fatalf("AddAddress(%d, %d, %s): %s", nicID1, fakeNetNumber, addr1, err)
		}

		ep2 := channel.New(1, defaultMTU, "")
		if err := s.CreateNIC(nicID2, ep2); err != nil {
			t.Fatalf("CreateNIC(%d, _): %s", nicID2, err)
		}

		if err := s.AddAddress(nicID2, fakeNetNumber, addr2); err != nil {
			t.Fatalf("AddAddress(%d, %d, %s): %s", nicID2, fakeNetNumber, addr2, err)
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
				{Destination: subnet1, Gateway: "\x00", NIC: nicID1},
				{Destination: subnet0, Gateway: "\x00", NIC: nicID2},
			})
		}

		return s, ep1, ep2
	}

	// Tests that routes through a down NIC are not used when looking up a route
	// for a destination.
	t.Run("Find", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				s, _, _ := setup(t)

				// Test routes to odd address.
				testRoute(t, s, unspecifiedNIC, "", "\x05", addr1)
				testRoute(t, s, unspecifiedNIC, addr1, "\x05", addr1)
				testRoute(t, s, nicID1, addr1, "\x05", addr1)

				// Test routes to even address.
				testRoute(t, s, unspecifiedNIC, "", "\x06", addr2)
				testRoute(t, s, unspecifiedNIC, addr2, "\x06", addr2)
				testRoute(t, s, nicID2, addr2, "\x06", addr2)

				// Bringing NIC1 down should result in no routes to odd addresses. Routes to
				// even addresses should continue to be available as NIC2 is still up.
				if err := test.downFn(s, nicID1); err != nil {
					t.Fatalf("test.downFn(_, %d): %s", nicID1, err)
				}
				testNoRoute(t, s, unspecifiedNIC, "", nic1Dst)
				testNoRoute(t, s, unspecifiedNIC, addr1, nic1Dst)
				testNoRoute(t, s, nicID1, addr1, nic1Dst)
				testRoute(t, s, unspecifiedNIC, "", nic2Dst, addr2)
				testRoute(t, s, unspecifiedNIC, addr2, nic2Dst, addr2)
				testRoute(t, s, nicID2, addr2, nic2Dst, addr2)

				// Bringing NIC2 down should result in no routes to even addresses. No
				// route should be available to any address as routes to odd addresses
				// were made unavailable by bringing NIC1 down above.
				if err := test.downFn(s, nicID2); err != nil {
					t.Fatalf("test.downFn(_, %d): %s", nicID2, err)
				}
				testNoRoute(t, s, unspecifiedNIC, "", nic1Dst)
				testNoRoute(t, s, unspecifiedNIC, addr1, nic1Dst)
				testNoRoute(t, s, nicID1, addr1, nic1Dst)
				testNoRoute(t, s, unspecifiedNIC, "", nic2Dst)
				testNoRoute(t, s, unspecifiedNIC, addr2, nic2Dst)
				testNoRoute(t, s, nicID2, addr2, nic2Dst)

				if upFn := test.upFn; upFn != nil {
					// Bringing NIC1 up should make routes to odd addresses available
					// again. Routes to even addresses should continue to be unavailable
					// as NIC2 is still down.
					if err := upFn(s, nicID1); err != nil {
						t.Fatalf("test.upFn(_, %d): %s", nicID1, err)
					}
					testRoute(t, s, unspecifiedNIC, "", nic1Dst, addr1)
					testRoute(t, s, unspecifiedNIC, addr1, nic1Dst, addr1)
					testRoute(t, s, nicID1, addr1, nic1Dst, addr1)
					testNoRoute(t, s, unspecifiedNIC, "", nic2Dst)
					testNoRoute(t, s, unspecifiedNIC, addr2, nic2Dst)
					testNoRoute(t, s, nicID2, addr2, nic2Dst)
				}
			})
		}
	})

	// Tests that writing a packet using a Route through a down NIC fails.
	t.Run("WritePacket", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				s, ep1, ep2 := setup(t)

				r1, err := s.FindRoute(nicID1, addr1, nic1Dst, fakeNetNumber, false /* multicastLoop */)
				if err != nil {
					t.Errorf("FindRoute(%d, %s, %s, %d, false): %s", nicID1, addr1, nic1Dst, fakeNetNumber, err)
				}
				defer r1.Release()

				r2, err := s.FindRoute(nicID2, addr2, nic2Dst, fakeNetNumber, false /* multicastLoop */)
				if err != nil {
					t.Errorf("FindRoute(%d, %s, %s, %d, false): %s", nicID2, addr2, nic2Dst, fakeNetNumber, err)
				}
				defer r2.Release()

				// If we failed to get routes r1 or r2, we cannot proceed with the test.
				if t.Failed() {
					t.FailNow()
				}

				buf := buffer.View([]byte{1})
				testSend(t, r1, ep1, buf)
				testSend(t, r2, ep2, buf)

				// Writes with Routes that use NIC1 after being brought down should fail.
				if err := test.downFn(s, nicID1); err != nil {
					t.Fatalf("test.downFn(_, %d): %s", nicID1, err)
				}
				testFailingSend(t, r1, ep1, buf, tcpip.ErrInvalidEndpointState)
				testSend(t, r2, ep2, buf)

				// Writes with Routes that use NIC2 after being brought down should fail.
				if err := test.downFn(s, nicID2); err != nil {
					t.Fatalf("test.downFn(_, %d): %s", nicID2, err)
				}
				testFailingSend(t, r1, ep1, buf, tcpip.ErrInvalidEndpointState)
				testFailingSend(t, r2, ep2, buf, tcpip.ErrInvalidEndpointState)

				if upFn := test.upFn; upFn != nil {
					// Writes with Routes that use NIC1 after being brought up should
					// succeed.
					//
					// TODO(gvisor.dev/issue/1491): Should we instead completely
					// invalidate all Routes that were bound to a NIC that was brought
					// down at some point?
					if err := upFn(s, nicID1); err != nil {
						t.Fatalf("test.upFn(_, %d): %s", nicID1, err)
					}
					testSend(t, r1, ep1, buf)
					testFailingSend(t, r2, ep2, buf, tcpip.ErrInvalidEndpointState)
				}
			})
		}
	})
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
	buf[dstAddrOffset] = localAddrByte
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
	buf[dstAddrOffset] = localAddrByte
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

func verifyAddress(t *testing.T, s *stack.Stack, nicID tcpip.NICID, addr tcpip.Address) {
	t.Helper()
	info, ok := s.NICInfo()[nicID]
	if !ok {
		t.Fatalf("NICInfo() failed to find nicID=%d", nicID)
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
		nicID         tcpip.NICID   = 1
	)
	localAddr := tcpip.Address([]byte{localAddrByte})

	for _, promiscuous := range []bool{true, false} {
		for _, spoofing := range []bool{true, false} {
			t.Run(fmt.Sprintf("promiscuous=%t spoofing=%t", promiscuous, spoofing), func(t *testing.T) {
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
					s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
				}

				fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)
				buf := buffer.NewView(30)
				buf[dstAddrOffset] = localAddrByte

				if promiscuous {
					if err := s.SetPromiscuousMode(nicID, true); err != nil {
						t.Fatal("SetPromiscuousMode failed:", err)
					}
				}

				if spoofing {
					if err := s.SetSpoofing(nicID, true); err != nil {
						t.Fatal("SetSpoofing failed:", err)
					}
				}

				// 1. No Address yet, send should only work for spoofing, receive for
				// promiscuous mode.
				//-----------------------
				verifyAddress(t, s, nicID, noAddr)
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
				if err := s.AddAddress(nicID, fakeNetNumber, localAddr); err != nil {
					t.Fatal("AddAddress failed:", err)
				}
				verifyAddress(t, s, nicID, localAddr)
				testRecv(t, fakeNet, localAddrByte, ep, buf)
				testSendTo(t, s, remoteAddr, ep, nil)

				// 3. Remove the address, send should only work for spoofing, receive
				// for promiscuous mode.
				//-----------------------
				if err := s.RemoveAddress(nicID, localAddr); err != nil {
					t.Fatal("RemoveAddress failed:", err)
				}
				verifyAddress(t, s, nicID, noAddr)
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
				if err := s.AddAddress(nicID, fakeNetNumber, localAddr); err != nil {
					t.Fatal("AddAddress failed:", err)
				}
				verifyAddress(t, s, nicID, localAddr)
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
				if err := s.RemoveAddress(nicID, localAddr); err != nil {
					t.Fatal("RemoveAddress failed:", err)
				}
				verifyAddress(t, s, nicID, noAddr)
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
				if err := s.AddAddress(nicID, fakeNetNumber, localAddr); err != nil {
					t.Fatal("AddAddress failed:", err)
				}
				verifyAddress(t, s, nicID, localAddr)
				testRecv(t, fakeNet, localAddrByte, ep, buf)
				testSendTo(t, s, remoteAddr, ep, nil)
				testSend(t, r, ep, nil)

				// 8. Remove the route, sendTo/recv should still work.
				//-----------------------
				r.Release()
				verifyAddress(t, s, nicID, localAddr)
				testRecv(t, fakeNet, localAddrByte, ep, buf)
				testSendTo(t, s, remoteAddr, ep, nil)

				// 9. Remove the address. Send should only work for spoofing, receive
				// for promiscuous mode.
				//-----------------------
				if err := s.RemoveAddress(nicID, localAddr); err != nil {
					t.Fatal("RemoveAddress failed:", err)
				}
				verifyAddress(t, s, nicID, noAddr)
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
	buf[dstAddrOffset] = localAddrByte
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
		t.Fatalf("AddProtocolAddress(1, %v) failed: %v", protoAddr, err)
	}
	r, err := s.FindRoute(1, header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(1, %v, %v, %d) failed: %v", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err)
	}
	if err := verifyRoute(r, stack.Route{LocalAddress: header.IPv4Any, RemoteAddress: header.IPv4Broadcast}); err != nil {
		t.Errorf("FindRoute(1, %v, %v, %d) returned unexpected Route: %v", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err)
	}

	// If the NIC doesn't exist, it won't work.
	if _, err := s.FindRoute(2, header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, false /* multicastLoop */); err != tcpip.ErrNetworkUnreachable {
		t.Fatalf("got FindRoute(2, %v, %v, %d) = %v want = %v", header.IPv4Any, header.IPv4Broadcast, fakeNetNumber, err, tcpip.ErrNetworkUnreachable)
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
		t.Fatalf("AddProtocolAddress(1, %v) failed: %v", nic1ProtoAddr, err)
	}

	nic2ProtoAddr := tcpip.ProtocolAddress{fakeNetNumber, nic2Addr}
	if err := s.AddProtocolAddress(2, nic2ProtoAddr); err != nil {
		t.Fatalf("AddAddress(2, %v) failed: %v", nic2ProtoAddr, err)
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
		t.Fatalf("FindRoute(1, %v, %v, %d) failed: %v", nic1Addr.Address, header.IPv4Broadcast, fakeNetNumber, err)
	}
	if err := verifyRoute(r, stack.Route{LocalAddress: nic1Addr.Address, RemoteAddress: header.IPv4Broadcast}); err != nil {
		t.Errorf("FindRoute(1, %v, %v, %d) returned unexpected Route: %v", nic1Addr.Address, header.IPv4Broadcast, fakeNetNumber, err)
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
	const nicID = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	var addrGen addressGenerator
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, 2)
	for _, addrLen := range []int{4, 16} {
		address := addrGen.next(addrLen)
		if err := s.AddAddress(nicID, fakeNetNumber, address); err != nil {
			t.Fatalf("AddAddress(address=%s) failed: %s", address, err)
		}
		expectedAddresses = append(expectedAddresses, tcpip.ProtocolAddress{
			Protocol:          fakeNetNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{address, fakeDefaultPrefixLen},
		})
	}

	gotAddresses := s.AllAddresses()[nicID]
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddProtocolAddress(t *testing.T) {
	const nicID = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
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
			if err := s.AddProtocolAddress(nicID, protocolAddress); err != nil {
				t.Errorf("AddProtocolAddress(%+v) failed: %s", protocolAddress, err)
			}
			expectedAddresses = append(expectedAddresses, protocolAddress)
		}
	}

	gotAddresses := s.AllAddresses()[nicID]
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddAddressWithOptions(t *testing.T) {
	const nicID = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatal("CreateNIC failed:", err)
	}

	addrLenRange := []int{4, 16}
	behaviorRange := []stack.PrimaryEndpointBehavior{stack.CanBePrimaryEndpoint, stack.FirstPrimaryEndpoint, stack.NeverPrimaryEndpoint}
	expectedAddresses := make([]tcpip.ProtocolAddress, 0, len(addrLenRange)*len(behaviorRange))
	var addrGen addressGenerator
	for _, addrLen := range addrLenRange {
		for _, behavior := range behaviorRange {
			address := addrGen.next(addrLen)
			if err := s.AddAddressWithOptions(nicID, fakeNetNumber, address, behavior); err != nil {
				t.Fatalf("AddAddressWithOptions(address=%s, behavior=%d) failed: %s", address, behavior, err)
			}
			expectedAddresses = append(expectedAddresses, tcpip.ProtocolAddress{
				Protocol:          fakeNetNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{address, fakeDefaultPrefixLen},
			})
		}
	}

	gotAddresses := s.AllAddresses()[nicID]
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestAddProtocolAddressWithOptions(t *testing.T) {
	const nicID = 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
	})
	ep := channel.New(10, defaultMTU, "")
	if err := s.CreateNIC(nicID, ep); err != nil {
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
				if err := s.AddProtocolAddressWithOptions(nicID, protocolAddress, behavior); err != nil {
					t.Fatalf("AddProtocolAddressWithOptions(%+v, %d) failed: %s", protocolAddress, behavior, err)
				}
				expectedAddresses = append(expectedAddresses, protocolAddress)
			}
		}
	}

	gotAddresses := s.AllAddresses()[nicID]
	verifyAddresses(t, expectedAddresses, gotAddresses)
}

func TestCreateNICWithOptions(t *testing.T) {
	type callArgsAndExpect struct {
		nicID tcpip.NICID
		opts  stack.NICOptions
		err   *tcpip.Error
	}

	tests := []struct {
		desc  string
		calls []callArgsAndExpect
	}{
		{
			desc: "DuplicateNICID",
			calls: []callArgsAndExpect{
				{
					nicID: tcpip.NICID(1),
					opts:  stack.NICOptions{Name: "eth1"},
					err:   nil,
				},
				{
					nicID: tcpip.NICID(1),
					opts:  stack.NICOptions{Name: "eth2"},
					err:   tcpip.ErrDuplicateNICID,
				},
			},
		},
		{
			desc: "DuplicateName",
			calls: []callArgsAndExpect{
				{
					nicID: tcpip.NICID(1),
					opts:  stack.NICOptions{Name: "lo"},
					err:   nil,
				},
				{
					nicID: tcpip.NICID(2),
					opts:  stack.NICOptions{Name: "lo"},
					err:   tcpip.ErrDuplicateNICID,
				},
			},
		},
		{
			desc: "Unnamed",
			calls: []callArgsAndExpect{
				{
					nicID: tcpip.NICID(1),
					opts:  stack.NICOptions{},
					err:   nil,
				},
				{
					nicID: tcpip.NICID(2),
					opts:  stack.NICOptions{},
					err:   nil,
				},
			},
		},
		{
			desc: "UnnamedDuplicateNICID",
			calls: []callArgsAndExpect{
				{
					nicID: tcpip.NICID(1),
					opts:  stack.NICOptions{},
					err:   nil,
				},
				{
					nicID: tcpip.NICID(1),
					opts:  stack.NICOptions{},
					err:   tcpip.ErrDuplicateNICID,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			s := stack.New(stack.Options{})
			ep := channel.New(0, 0, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00"))
			for _, call := range test.calls {
				if got, want := s.CreateNICWithOptions(call.nicID, ep, call.opts), call.err; got != want {
					t.Fatalf("CreateNICWithOptions(%v, _, %+v) = %v, want %v", call.nicID, call.opts, got, want)
				}
			}
		})
	}
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
	ep1.InjectInbound(fakeNetNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
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
	const nicID1 = 1
	const nicID2 = 2
	const dstAddr = tcpip.Address("\x03")

	tests := []struct {
		name      string
		headerLen uint16
	}{
		{
			name: "Zero header length",
		},
		{
			name:      "Non-zero header length",
			headerLen: 16,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
			})
			s.SetForwarding(true)

			ep1 := channel.New(10, defaultMTU, "")
			if err := s.CreateNIC(nicID1, ep1); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID1, err)
			}
			if err := s.AddAddress(nicID1, fakeNetNumber, "\x01"); err != nil {
				t.Fatalf("AddAddress(%d, %d, 0x01): %s", nicID1, fakeNetNumber, err)
			}

			ep2 := channelLinkWithHeaderLength{
				Endpoint:     channel.New(10, defaultMTU, ""),
				headerLength: test.headerLen,
			}
			if err := s.CreateNIC(nicID2, &ep2); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID2, err)
			}
			if err := s.AddAddress(nicID2, fakeNetNumber, "\x02"); err != nil {
				t.Fatalf("AddAddress(%d, %d, 0x02): %s", nicID2, fakeNetNumber, err)
			}

			// Route all packets to dstAddr to NIC 2.
			{
				subnet, err := tcpip.NewSubnet(dstAddr, "\xff")
				if err != nil {
					t.Fatal(err)
				}
				s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: nicID2}})
			}

			// Send a packet to dstAddr.
			buf := buffer.NewView(30)
			buf[dstAddrOffset] = dstAddr[0]
			ep1.InjectInbound(fakeNetNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: buf.ToVectorisedView(),
			}))

			pkt, ok := ep2.Read()
			if !ok {
				t.Fatal("packet not forwarded")
			}

			// Test that the link's MaxHeaderLength is honoured.
			if capacity, want := pkt.Pkt.AvailableHeaderBytes(), int(test.headerLen); capacity != want {
				t.Errorf("got LinkHeader.AvailableLength() = %d, want = %d", capacity, want)
			}

			// Test that forwarding increments Tx stats correctly.
			if got, want := s.NICInfo()[nicID2].Stats.Tx.Packets.Value(), uint64(1); got != want {
				t.Errorf("got Tx.Packets.Value() = %d, want = %d", got, want)
			}

			if got, want := s.NICInfo()[nicID2].Stats.Tx.Bytes.Value(), uint64(len(buf)); got != want {
				t.Errorf("got Tx.Bytes.Value() = %d, want = %d", got, want)
			}
		})
	}
}

// TestNICContextPreservation tests that you can read out via stack.NICInfo the
// Context data you pass via NICContext.Context in stack.CreateNICWithOptions.
func TestNICContextPreservation(t *testing.T) {
	var ctx *int
	tests := []struct {
		name string
		opts stack.NICOptions
		want stack.NICContext
	}{
		{
			"context_set",
			stack.NICOptions{Context: ctx},
			ctx,
		},
		{
			"context_not_set",
			stack.NICOptions{},
			nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{})
			id := tcpip.NICID(1)
			ep := channel.New(0, 0, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x00"))
			if err := s.CreateNICWithOptions(id, ep, test.opts); err != nil {
				t.Fatalf("got stack.CreateNICWithOptions(%d, %+v, %+v) = %s, want nil", id, ep, test.opts, err)
			}
			nicinfos := s.NICInfo()
			nicinfo, ok := nicinfos[id]
			if !ok {
				t.Fatalf("got nicinfos[%d] = _, %t, want _, true; nicinfos = %+v", id, ok, nicinfos)
			}
			if got, want := nicinfo.Context == test.want, true; got != want {
				t.Fatalf("got nicinfo.Context == ctx = %t, want %t; nicinfo.Context = %p, ctx = %p", got, want, nicinfo.Context, test.want)
			}
		})
	}
}

// TestNICAutoGenLinkLocalAddr tests the auto-generation of IPv6 link-local
// addresses.
func TestNICAutoGenLinkLocalAddr(t *testing.T) {
	const nicID = 1

	var secretKey [header.OpaqueIIDSecretKeyMinBytes]byte
	n, err := rand.Read(secretKey[:])
	if err != nil {
		t.Fatalf("rand.Read(_): %s", err)
	}
	if n != header.OpaqueIIDSecretKeyMinBytes {
		t.Fatalf("expected rand.Read to read %d bytes, read %d bytes", header.OpaqueIIDSecretKeyMinBytes, n)
	}

	nicNameFunc := func(_ tcpip.NICID, name string) string {
		return name
	}

	tests := []struct {
		name         string
		nicName      string
		autoGen      bool
		linkAddr     tcpip.LinkAddress
		iidOpts      stack.OpaqueInterfaceIdentifierOptions
		shouldGen    bool
		expectedAddr tcpip.Address
	}{
		{
			name:      "Disabled",
			nicName:   "nic1",
			autoGen:   false,
			linkAddr:  linkAddr1,
			shouldGen: false,
		},
		{
			name:     "Disabled without OIID options",
			nicName:  "nic1",
			autoGen:  false,
			linkAddr: linkAddr1,
			iidOpts: stack.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: nicNameFunc,
				SecretKey:     secretKey[:],
			},
			shouldGen: false,
		},

		// Tests for EUI64 based addresses.
		{
			name:         "EUI64 Enabled",
			autoGen:      true,
			linkAddr:     linkAddr1,
			shouldGen:    true,
			expectedAddr: header.LinkLocalAddr(linkAddr1),
		},
		{
			name:      "EUI64 Empty MAC",
			autoGen:   true,
			shouldGen: false,
		},
		{
			name:      "EUI64 Invalid MAC",
			autoGen:   true,
			linkAddr:  "\x01\x02\x03",
			shouldGen: false,
		},
		{
			name:      "EUI64 Multicast MAC",
			autoGen:   true,
			linkAddr:  "\x01\x02\x03\x04\x05\x06",
			shouldGen: false,
		},
		{
			name:      "EUI64 Unspecified MAC",
			autoGen:   true,
			linkAddr:  "\x00\x00\x00\x00\x00\x00",
			shouldGen: false,
		},

		// Tests for Opaque IID based addresses.
		{
			name:     "OIID Enabled",
			nicName:  "nic1",
			autoGen:  true,
			linkAddr: linkAddr1,
			iidOpts: stack.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: nicNameFunc,
				SecretKey:     secretKey[:],
			},
			shouldGen:    true,
			expectedAddr: header.LinkLocalAddrWithOpaqueIID("nic1", 0, secretKey[:]),
		},
		// These are all cases where we would not have generated a
		// link-local address if opaque IIDs were disabled.
		{
			name:    "OIID Empty MAC and empty nicName",
			autoGen: true,
			iidOpts: stack.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: nicNameFunc,
				SecretKey:     secretKey[:1],
			},
			shouldGen:    true,
			expectedAddr: header.LinkLocalAddrWithOpaqueIID("", 0, secretKey[:1]),
		},
		{
			name:     "OIID Invalid MAC",
			nicName:  "test",
			autoGen:  true,
			linkAddr: "\x01\x02\x03",
			iidOpts: stack.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: nicNameFunc,
				SecretKey:     secretKey[:2],
			},
			shouldGen:    true,
			expectedAddr: header.LinkLocalAddrWithOpaqueIID("test", 0, secretKey[:2]),
		},
		{
			name:     "OIID Multicast MAC",
			nicName:  "test2",
			autoGen:  true,
			linkAddr: "\x01\x02\x03\x04\x05\x06",
			iidOpts: stack.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: nicNameFunc,
				SecretKey:     secretKey[:3],
			},
			shouldGen:    true,
			expectedAddr: header.LinkLocalAddrWithOpaqueIID("test2", 0, secretKey[:3]),
		},
		{
			name:     "OIID Unspecified MAC and nil SecretKey",
			nicName:  "test3",
			autoGen:  true,
			linkAddr: "\x00\x00\x00\x00\x00\x00",
			iidOpts: stack.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: nicNameFunc,
			},
			shouldGen:    true,
			expectedAddr: header.LinkLocalAddrWithOpaqueIID("test3", 0, nil),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				autoGenAddrC: make(chan ndpAutoGenAddrEvent, 1),
			}
			opts := stack.Options{
				NetworkProtocols:     []stack.NetworkProtocol{ipv6.NewProtocol()},
				AutoGenIPv6LinkLocal: test.autoGen,
				NDPDisp:              &ndpDisp,
				OpaqueIIDOpts:        test.iidOpts,
			}

			e := channel.New(0, 1280, test.linkAddr)
			s := stack.New(opts)
			nicOpts := stack.NICOptions{Name: test.nicName, Disabled: true}
			if err := s.CreateNICWithOptions(nicID, e, nicOpts); err != nil {
				t.Fatalf("CreateNICWithOptions(%d, _, %+v) = %s", nicID, opts, err)
			}

			// A new disabled NIC should not have any address, even if auto generation
			// was enabled.
			allStackAddrs := s.AllAddresses()
			allNICAddrs, ok := allStackAddrs[nicID]
			if !ok {
				t.Fatalf("entry for %d missing from allStackAddrs = %+v", nicID, allStackAddrs)
			}
			if l := len(allNICAddrs); l != 0 {
				t.Fatalf("got len(allNICAddrs) = %d, want = 0", l)
			}

			// Enabling the NIC should attempt auto-generation of a link-local
			// address.
			if err := s.EnableNIC(nicID); err != nil {
				t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
			}

			var expectedMainAddr tcpip.AddressWithPrefix
			if test.shouldGen {
				expectedMainAddr = tcpip.AddressWithPrefix{
					Address:   test.expectedAddr,
					PrefixLen: header.IPv6LinkLocalPrefix.PrefixLen,
				}

				// Should have auto-generated an address and resolved immediately (DAD
				// is disabled).
				select {
				case e := <-ndpDisp.autoGenAddrC:
					if diff := checkAutoGenAddrEvent(e, expectedMainAddr, newAddr); diff != "" {
						t.Errorf("auto-gen addr event mismatch (-want +got):\n%s", diff)
					}
				default:
					t.Fatal("expected addr auto gen event")
				}
			} else {
				// Should not have auto-generated an address.
				select {
				case <-ndpDisp.autoGenAddrC:
					t.Fatal("unexpectedly auto-generated an address")
				default:
				}
			}

			gotMainAddr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
			}
			if gotMainAddr != expectedMainAddr {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", gotMainAddr, expectedMainAddr)
			}
		})
	}
}

// TestNoLinkLocalAutoGenForLoopbackNIC tests that IPv6 link-local addresses are
// not auto-generated for loopback NICs.
func TestNoLinkLocalAutoGenForLoopbackNIC(t *testing.T) {
	const nicID = 1
	const nicName = "nicName"

	tests := []struct {
		name          string
		opaqueIIDOpts stack.OpaqueInterfaceIdentifierOptions
	}{
		{
			name:          "IID From MAC",
			opaqueIIDOpts: stack.OpaqueInterfaceIdentifierOptions{},
		},
		{
			name: "Opaque IID",
			opaqueIIDOpts: stack.OpaqueInterfaceIdentifierOptions{
				NICNameFromID: func(_ tcpip.NICID, nicName string) string {
					return nicName
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := stack.Options{
				NetworkProtocols:     []stack.NetworkProtocol{ipv6.NewProtocol()},
				AutoGenIPv6LinkLocal: true,
				OpaqueIIDOpts:        test.opaqueIIDOpts,
			}

			e := loopback.New()
			s := stack.New(opts)
			nicOpts := stack.NICOptions{Name: nicName}
			if err := s.CreateNICWithOptions(nicID, e, nicOpts); err != nil {
				t.Fatalf("CreateNICWithOptions(%d, _, %+v) = %s", nicID, nicOpts, err)
			}

			addr, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(%d, _) err = %s", nicID, err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Errorf("got stack.GetMainNICAddress(%d, _) = %s, want = %s", nicID, addr, want)
			}
		})
	}
}

// TestNICAutoGenAddrDoesDAD tests that the successful auto-generation of IPv6
// link-local addresses will only be assigned after the DAD process resolves.
func TestNICAutoGenAddrDoesDAD(t *testing.T) {
	const nicID = 1

	ndpDisp := ndpDispatcher{
		dadC: make(chan ndpDADEvent),
	}
	ndpConfigs := stack.DefaultNDPConfigurations()
	opts := stack.Options{
		NetworkProtocols:     []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs:           ndpConfigs,
		AutoGenIPv6LinkLocal: true,
		NDPDisp:              &ndpDisp,
	}

	e := channel.New(int(ndpConfigs.DupAddrDetectTransmits), 1280, linkAddr1)
	s := stack.New(opts)
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	// Address should not be considered bound to the
	// NIC yet (DAD ongoing).
	addr, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
	}
	if want := (tcpip.AddressWithPrefix{}); addr != want {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, addr, want)
	}

	linkLocalAddr := header.LinkLocalAddr(linkAddr1)

	// Wait for DAD to resolve.
	select {
	case <-time.After(time.Duration(ndpConfigs.DupAddrDetectTransmits)*ndpConfigs.RetransmitTimer + time.Second):
		// We should get a resolution event after 1s (default time to
		// resolve as per default NDP configurations). Waiting for that
		// resolution time + an extra 1s without a resolution event
		// means something is wrong.
		t.Fatal("timed out waiting for DAD resolution")
	case e := <-ndpDisp.dadC:
		if diff := checkDADEvent(e, nicID, linkLocalAddr, true, nil); diff != "" {
			t.Errorf("dad event mismatch (-want +got):\n%s", diff)
		}
	}
	addr, err = s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
	}
	if want := (tcpip.AddressWithPrefix{Address: linkLocalAddr, PrefixLen: header.IPv6LinkLocalPrefix.PrefixLen}); addr != want {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, addr, want)
	}
}

// TestNewPEB tests that a new PrimaryEndpointBehavior value (peb) is respected
// when an address's kind gets "promoted" to permanent from permanentExpired.
func TestNewPEBOnPromotionToPermanent(t *testing.T) {
	pebs := []stack.PrimaryEndpointBehavior{
		stack.NeverPrimaryEndpoint,
		stack.CanBePrimaryEndpoint,
		stack.FirstPrimaryEndpoint,
	}

	for _, pi := range pebs {
		for _, ps := range pebs {
			t.Run(fmt.Sprintf("%d-to-%d", pi, ps), func(t *testing.T) {
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocol{fakeNetFactory()},
				})
				ep1 := channel.New(10, defaultMTU, "")
				if err := s.CreateNIC(1, ep1); err != nil {
					t.Fatal("CreateNIC failed:", err)
				}

				// Add a permanent address with initial
				// PrimaryEndpointBehavior (peb), pi. If pi is
				// NeverPrimaryEndpoint, the address should not
				// be returned by a call to GetMainNICAddress;
				// else, it should.
				if err := s.AddAddressWithOptions(1, fakeNetNumber, "\x01", pi); err != nil {
					t.Fatal("AddAddressWithOptions failed:", err)
				}
				addr, err := s.GetMainNICAddress(1, fakeNetNumber)
				if err != nil {
					t.Fatal("s.GetMainNICAddress failed:", err)
				}
				if pi == stack.NeverPrimaryEndpoint {
					if want := (tcpip.AddressWithPrefix{}); addr != want {
						t.Fatalf("got GetMainNICAddress = %s, want = %s", addr, want)

					}
				} else if addr.Address != "\x01" {
					t.Fatalf("got GetMainNICAddress = %s, want = 1", addr.Address)
				}

				{
					subnet, err := tcpip.NewSubnet("\x00", "\x00")
					if err != nil {
						t.Fatalf("NewSubnet failed: %v", err)
					}
					s.SetRouteTable([]tcpip.Route{{Destination: subnet, Gateway: "\x00", NIC: 1}})
				}

				// Take a route through the address so its ref
				// count gets incremented and does not actually
				// get deleted when RemoveAddress is called
				// below. This is because we want to test that a
				// new peb is respected when an address gets
				// "promoted" to permanent from a
				// permanentExpired kind.
				r, err := s.FindRoute(1, "\x01", "\x02", fakeNetNumber, false)
				if err != nil {
					t.Fatalf("FindRoute failed: %v", err)
				}
				defer r.Release()
				if err := s.RemoveAddress(1, "\x01"); err != nil {
					t.Fatalf("RemoveAddress failed: %v", err)
				}

				//
				// At this point, the address should still be
				// known by the NIC, but have its
				// kind = permanentExpired.
				//

				// Add some other address with peb set to
				// FirstPrimaryEndpoint.
				if err := s.AddAddressWithOptions(1, fakeNetNumber, "\x03", stack.FirstPrimaryEndpoint); err != nil {
					t.Fatalf("AddAddressWithOptions failed: %v", err)

				}

				// Add back the address we removed earlier and
				// make sure the new peb was respected.
				// (The address should just be promoted now).
				if err := s.AddAddressWithOptions(1, fakeNetNumber, "\x01", ps); err != nil {
					t.Fatalf("AddAddressWithOptions failed: %v", err)
				}
				var primaryAddrs []tcpip.Address
				for _, pa := range s.NICInfo()[1].ProtocolAddresses {
					primaryAddrs = append(primaryAddrs, pa.AddressWithPrefix.Address)
				}
				var expectedList []tcpip.Address
				switch ps {
				case stack.FirstPrimaryEndpoint:
					expectedList = []tcpip.Address{
						"\x01",
						"\x03",
					}
				case stack.CanBePrimaryEndpoint:
					expectedList = []tcpip.Address{
						"\x03",
						"\x01",
					}
				case stack.NeverPrimaryEndpoint:
					expectedList = []tcpip.Address{
						"\x03",
					}
				}
				if !cmp.Equal(primaryAddrs, expectedList) {
					t.Fatalf("got NIC's primary addresses = %v, want = %v", primaryAddrs, expectedList)
				}

				// Once we remove the other address, if the new
				// peb, ps, was NeverPrimaryEndpoint, no address
				// should be returned by a call to
				// GetMainNICAddress; else, our original address
				// should be returned.
				if err := s.RemoveAddress(1, "\x03"); err != nil {
					t.Fatalf("RemoveAddress failed: %v", err)
				}
				addr, err = s.GetMainNICAddress(1, fakeNetNumber)
				if err != nil {
					t.Fatalf("s.GetMainNICAddress failed: %v", err)
				}
				if ps == stack.NeverPrimaryEndpoint {
					if want := (tcpip.AddressWithPrefix{}); addr != want {
						t.Fatalf("got GetMainNICAddress = %s, want = %s", addr, want)

					}
				} else {
					if addr.Address != "\x01" {
						t.Fatalf("got GetMainNICAddress = %s, want = 1", addr.Address)
					}
				}
			})
		}
	}
}

func TestIPv6SourceAddressSelectionScopeAndSameAddress(t *testing.T) {
	const (
		linkLocalAddr1         = tcpip.Address("\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
		linkLocalAddr2         = tcpip.Address("\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")
		linkLocalMulticastAddr = tcpip.Address("\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
		uniqueLocalAddr1       = tcpip.Address("\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
		uniqueLocalAddr2       = tcpip.Address("\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")
		globalAddr1            = tcpip.Address("\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
		globalAddr2            = tcpip.Address("\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")
		nicID                  = 1
		lifetimeSeconds        = 9999
	)

	prefix1, _, stableGlobalAddr1 := prefixSubnetAddr(0, linkAddr1)
	prefix2, _, stableGlobalAddr2 := prefixSubnetAddr(1, linkAddr1)

	var tempIIDHistory [header.IIDSize]byte
	header.InitialTempIID(tempIIDHistory[:], nil, nicID)
	tempGlobalAddr1 := header.GenerateTempIPv6SLAACAddr(tempIIDHistory[:], stableGlobalAddr1.Address).Address
	tempGlobalAddr2 := header.GenerateTempIPv6SLAACAddr(tempIIDHistory[:], stableGlobalAddr2.Address).Address

	// Rule 3 is not tested here, and is instead tested by NDP's AutoGenAddr test.
	tests := []struct {
		name                                   string
		slaacPrefixForTempAddrBeforeNICAddrAdd tcpip.AddressWithPrefix
		nicAddrs                               []tcpip.Address
		slaacPrefixForTempAddrAfterNICAddrAdd  tcpip.AddressWithPrefix
		connectAddr                            tcpip.Address
		expectedLocalAddr                      tcpip.Address
	}{
		// Test Rule 1 of RFC 6724 section 5.
		{
			name:              "Same Global most preferred (last address)",
			nicAddrs:          []tcpip.Address{linkLocalAddr1, uniqueLocalAddr1, globalAddr1},
			connectAddr:       globalAddr1,
			expectedLocalAddr: globalAddr1,
		},
		{
			name:              "Same Global most preferred (first address)",
			nicAddrs:          []tcpip.Address{globalAddr1, linkLocalAddr1, uniqueLocalAddr1},
			connectAddr:       globalAddr1,
			expectedLocalAddr: globalAddr1,
		},
		{
			name:              "Same Link Local most preferred (last address)",
			nicAddrs:          []tcpip.Address{globalAddr1, uniqueLocalAddr1, linkLocalAddr1},
			connectAddr:       linkLocalAddr1,
			expectedLocalAddr: linkLocalAddr1,
		},
		{
			name:              "Same Link Local most preferred (first address)",
			nicAddrs:          []tcpip.Address{linkLocalAddr1, uniqueLocalAddr1, globalAddr1},
			connectAddr:       linkLocalAddr1,
			expectedLocalAddr: linkLocalAddr1,
		},
		{
			name:              "Same Unique Local most preferred (last address)",
			nicAddrs:          []tcpip.Address{uniqueLocalAddr1, globalAddr1, linkLocalAddr1},
			connectAddr:       uniqueLocalAddr1,
			expectedLocalAddr: uniqueLocalAddr1,
		},
		{
			name:              "Same Unique Local most preferred (first address)",
			nicAddrs:          []tcpip.Address{globalAddr1, linkLocalAddr1, uniqueLocalAddr1},
			connectAddr:       uniqueLocalAddr1,
			expectedLocalAddr: uniqueLocalAddr1,
		},

		// Test Rule 2 of RFC 6724 section 5.
		{
			name:              "Global most preferred (last address)",
			nicAddrs:          []tcpip.Address{linkLocalAddr1, uniqueLocalAddr1, globalAddr1},
			connectAddr:       globalAddr2,
			expectedLocalAddr: globalAddr1,
		},
		{
			name:              "Global most preferred (first address)",
			nicAddrs:          []tcpip.Address{globalAddr1, linkLocalAddr1, uniqueLocalAddr1},
			connectAddr:       globalAddr2,
			expectedLocalAddr: globalAddr1,
		},
		{
			name:              "Link Local most preferred (last address)",
			nicAddrs:          []tcpip.Address{globalAddr1, uniqueLocalAddr1, linkLocalAddr1},
			connectAddr:       linkLocalAddr2,
			expectedLocalAddr: linkLocalAddr1,
		},
		{
			name:              "Link Local most preferred (first address)",
			nicAddrs:          []tcpip.Address{linkLocalAddr1, uniqueLocalAddr1, globalAddr1},
			connectAddr:       linkLocalAddr2,
			expectedLocalAddr: linkLocalAddr1,
		},
		{
			name:              "Link Local most preferred for link local multicast (last address)",
			nicAddrs:          []tcpip.Address{globalAddr1, uniqueLocalAddr1, linkLocalAddr1},
			connectAddr:       linkLocalMulticastAddr,
			expectedLocalAddr: linkLocalAddr1,
		},
		{
			name:              "Link Local most preferred for link local multicast (first address)",
			nicAddrs:          []tcpip.Address{linkLocalAddr1, uniqueLocalAddr1, globalAddr1},
			connectAddr:       linkLocalMulticastAddr,
			expectedLocalAddr: linkLocalAddr1,
		},
		{
			name:              "Unique Local most preferred (last address)",
			nicAddrs:          []tcpip.Address{uniqueLocalAddr1, globalAddr1, linkLocalAddr1},
			connectAddr:       uniqueLocalAddr2,
			expectedLocalAddr: uniqueLocalAddr1,
		},
		{
			name:              "Unique Local most preferred (first address)",
			nicAddrs:          []tcpip.Address{globalAddr1, linkLocalAddr1, uniqueLocalAddr1},
			connectAddr:       uniqueLocalAddr2,
			expectedLocalAddr: uniqueLocalAddr1,
		},

		// Test Rule 7 of RFC 6724 section 5.
		{
			name:                                   "Temp Global most preferred (last address)",
			slaacPrefixForTempAddrBeforeNICAddrAdd: prefix1,
			nicAddrs:                               []tcpip.Address{linkLocalAddr1, uniqueLocalAddr1, globalAddr1},
			connectAddr:                            globalAddr2,
			expectedLocalAddr:                      tempGlobalAddr1,
		},
		{
			name:                                  "Temp Global most preferred (first address)",
			nicAddrs:                              []tcpip.Address{linkLocalAddr1, uniqueLocalAddr1, globalAddr1},
			slaacPrefixForTempAddrAfterNICAddrAdd: prefix1,
			connectAddr:                           globalAddr2,
			expectedLocalAddr:                     tempGlobalAddr1,
		},

		// Test returning the endpoint that is closest to the front when
		// candidate addresses are "equal" from the perspective of RFC 6724
		// section 5.
		{
			name:              "Unique Local for Global",
			nicAddrs:          []tcpip.Address{linkLocalAddr1, uniqueLocalAddr1, uniqueLocalAddr2},
			connectAddr:       globalAddr2,
			expectedLocalAddr: uniqueLocalAddr1,
		},
		{
			name:              "Link Local for Global",
			nicAddrs:          []tcpip.Address{linkLocalAddr1, linkLocalAddr2},
			connectAddr:       globalAddr2,
			expectedLocalAddr: linkLocalAddr1,
		},
		{
			name:              "Link Local for Unique Local",
			nicAddrs:          []tcpip.Address{linkLocalAddr1, linkLocalAddr2},
			connectAddr:       uniqueLocalAddr2,
			expectedLocalAddr: linkLocalAddr1,
		},
		{
			name:                                   "Temp Global for Global",
			slaacPrefixForTempAddrBeforeNICAddrAdd: prefix1,
			slaacPrefixForTempAddrAfterNICAddrAdd:  prefix2,
			connectAddr:                            globalAddr1,
			expectedLocalAddr:                      tempGlobalAddr2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := channel.New(0, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{ipv6.NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:                  true,
					AutoGenGlobalAddresses:     true,
					AutoGenTempGlobalAddresses: true,
				},
				NDPDisp: &ndpDispatcher{},
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			s.SetRouteTable([]tcpip.Route{{
				Destination: header.IPv6EmptySubnet,
				Gateway:     llAddr3,
				NIC:         nicID,
			}})
			s.AddLinkAddress(nicID, llAddr3, linkAddr3)

			if test.slaacPrefixForTempAddrBeforeNICAddrAdd != (tcpip.AddressWithPrefix{}) {
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, test.slaacPrefixForTempAddrBeforeNICAddrAdd, true, true, lifetimeSeconds, lifetimeSeconds))
			}

			for _, a := range test.nicAddrs {
				if err := s.AddAddress(nicID, ipv6.ProtocolNumber, a); err != nil {
					t.Errorf("s.AddAddress(%d, %d, %s): %s", nicID, ipv6.ProtocolNumber, a, err)
				}
			}

			if test.slaacPrefixForTempAddrAfterNICAddrAdd != (tcpip.AddressWithPrefix{}) {
				e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr3, 0, test.slaacPrefixForTempAddrAfterNICAddrAdd, true, true, lifetimeSeconds, lifetimeSeconds))
			}

			if t.Failed() {
				t.FailNow()
			}

			if got := addrForNewConnectionTo(t, s, tcpip.FullAddress{Addr: test.connectAddr, NIC: nicID, Port: 1234}); got != test.expectedLocalAddr {
				t.Errorf("got local address = %s, want = %s", got, test.expectedLocalAddr)
			}
		})
	}
}

func TestAddRemoveIPv4BroadcastAddressOnNICEnableDisable(t *testing.T) {
	const nicID = 1
	broadcastAddr := tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   header.IPv4Broadcast,
			PrefixLen: 32,
		},
	}

	e := loopback.New()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv4.NewProtocol()},
	})
	nicOpts := stack.NICOptions{Disabled: true}
	if err := s.CreateNICWithOptions(nicID, e, nicOpts); err != nil {
		t.Fatalf("CreateNIC(%d, _, %+v) = %s", nicID, nicOpts, err)
	}

	{
		allStackAddrs := s.AllAddresses()
		if allNICAddrs, ok := allStackAddrs[nicID]; !ok {
			t.Fatalf("entry for %d missing from allStackAddrs = %+v", nicID, allStackAddrs)
		} else if containsAddr(allNICAddrs, broadcastAddr) {
			t.Fatalf("got allNICAddrs = %+v, don't want = %+v", allNICAddrs, broadcastAddr)
		}
	}

	// Enabling the NIC should add the IPv4 broadcast address.
	if err := s.EnableNIC(nicID); err != nil {
		t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
	}

	{
		allStackAddrs := s.AllAddresses()
		if allNICAddrs, ok := allStackAddrs[nicID]; !ok {
			t.Fatalf("entry for %d missing from allStackAddrs = %+v", nicID, allStackAddrs)
		} else if !containsAddr(allNICAddrs, broadcastAddr) {
			t.Fatalf("got allNICAddrs = %+v, want = %+v", allNICAddrs, broadcastAddr)
		}
	}

	// Disabling the NIC should remove the IPv4 broadcast address.
	if err := s.DisableNIC(nicID); err != nil {
		t.Fatalf("s.DisableNIC(%d): %s", nicID, err)
	}

	{
		allStackAddrs := s.AllAddresses()
		if allNICAddrs, ok := allStackAddrs[nicID]; !ok {
			t.Fatalf("entry for %d missing from allStackAddrs = %+v", nicID, allStackAddrs)
		} else if containsAddr(allNICAddrs, broadcastAddr) {
			t.Fatalf("got allNICAddrs = %+v, don't want = %+v", allNICAddrs, broadcastAddr)
		}
	}
}

// TestLeaveIPv6SolicitedNodeAddrBeforeAddrRemoval tests that removing an IPv6
// address after leaving its solicited node multicast address does not result in
// an error.
func TestLeaveIPv6SolicitedNodeAddrBeforeAddrRemoval(t *testing.T) {
	const nicID = 1

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
	})
	e := channel.New(10, 1280, linkAddr1)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
	}

	if err := s.AddAddress(nicID, ipv6.ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s): %s", nicID, ipv6.ProtocolNumber, addr1, err)
	}

	// The NIC should have joined addr1's solicited node multicast address.
	snmc := header.SolicitedNodeAddr(addr1)
	in, err := s.IsInGroup(nicID, snmc)
	if err != nil {
		t.Fatalf("IsInGroup(%d, %s): %s", nicID, snmc, err)
	}
	if !in {
		t.Fatalf("got IsInGroup(%d, %s) = false, want = true", nicID, snmc)
	}

	if err := s.LeaveGroup(ipv6.ProtocolNumber, nicID, snmc); err != nil {
		t.Fatalf("LeaveGroup(%d, %d, %s): %s", ipv6.ProtocolNumber, nicID, snmc, err)
	}
	in, err = s.IsInGroup(nicID, snmc)
	if err != nil {
		t.Fatalf("IsInGroup(%d, %s): %s", nicID, snmc, err)
	}
	if in {
		t.Fatalf("got IsInGroup(%d, %s) = true, want = false", nicID, snmc)
	}

	if err := s.RemoveAddress(nicID, addr1); err != nil {
		t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, addr1, err)
	}
}

func TestJoinLeaveMulticastOnNICEnableDisable(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name  string
		proto tcpip.NetworkProtocolNumber
		addr  tcpip.Address
	}{
		{
			name:  "IPv6 All-Nodes",
			proto: header.IPv6ProtocolNumber,
			addr:  header.IPv6AllNodesMulticastAddress,
		},
		{
			name:  "IPv4 All-Systems",
			proto: header.IPv4ProtocolNumber,
			addr:  header.IPv4AllSystems,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := loopback.New()
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol()},
			})
			nicOpts := stack.NICOptions{Disabled: true}
			if err := s.CreateNICWithOptions(nicID, e, nicOpts); err != nil {
				t.Fatalf("CreateNIC(%d, _, %+v) = %s", nicID, nicOpts, err)
			}

			// Should not be in the multicast group yet because the NIC has not been
			// enabled yet.
			if isInGroup, err := s.IsInGroup(nicID, test.addr); err != nil {
				t.Fatalf("IsInGroup(%d, %s): %s", nicID, test.addr, err)
			} else if isInGroup {
				t.Fatalf("got IsInGroup(%d, %s) = true, want = false", nicID, test.addr)
			}

			// The all-nodes multicast group should be joined when the NIC is enabled.
			if err := s.EnableNIC(nicID); err != nil {
				t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
			}

			if isInGroup, err := s.IsInGroup(nicID, test.addr); err != nil {
				t.Fatalf("IsInGroup(%d, %s): %s", nicID, test.addr, err)
			} else if !isInGroup {
				t.Fatalf("got IsInGroup(%d, %s) = false, want = true", nicID, test.addr)
			}

			// The multicast group should be left when the NIC is disabled.
			if err := s.DisableNIC(nicID); err != nil {
				t.Fatalf("s.DisableNIC(%d): %s", nicID, err)
			}

			if isInGroup, err := s.IsInGroup(nicID, test.addr); err != nil {
				t.Fatalf("IsInGroup(%d, %s): %s", nicID, test.addr, err)
			} else if isInGroup {
				t.Fatalf("got IsInGroup(%d, %s) = true, want = false", nicID, test.addr)
			}

			// The all-nodes multicast group should be joined when the NIC is enabled.
			if err := s.EnableNIC(nicID); err != nil {
				t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
			}

			if isInGroup, err := s.IsInGroup(nicID, test.addr); err != nil {
				t.Fatalf("IsInGroup(%d, %s): %s", nicID, test.addr, err)
			} else if !isInGroup {
				t.Fatalf("got IsInGroup(%d, %s) = false, want = true", nicID, test.addr)
			}

			// Leaving the group before disabling the NIC should not cause an error.
			if err := s.LeaveGroup(test.proto, nicID, test.addr); err != nil {
				t.Fatalf("s.LeaveGroup(%d, %d, %s): %s", test.proto, nicID, test.addr, err)
			}

			if err := s.DisableNIC(nicID); err != nil {
				t.Fatalf("s.DisableNIC(%d): %s", nicID, err)
			}

			if isInGroup, err := s.IsInGroup(nicID, test.addr); err != nil {
				t.Fatalf("IsInGroup(%d, %s): %s", nicID, test.addr, err)
			} else if isInGroup {
				t.Fatalf("got IsInGroup(%d, %s) = true, want = false", nicID, test.addr)
			}
		})
	}
}

// TestDoDADWhenNICEnabled tests that IPv6 endpoints that were added while a NIC
// was disabled have DAD performed on them when the NIC is enabled.
func TestDoDADWhenNICEnabled(t *testing.T) {
	const dadTransmits = 1
	const retransmitTimer = time.Second
	const nicID = 1

	ndpDisp := ndpDispatcher{
		dadC: make(chan ndpDADEvent),
	}
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			DupAddrDetectTransmits: dadTransmits,
			RetransmitTimer:        retransmitTimer,
		},
		NDPDisp: &ndpDisp,
	}

	e := channel.New(dadTransmits, 1280, linkAddr1)
	s := stack.New(opts)
	nicOpts := stack.NICOptions{Disabled: true}
	if err := s.CreateNICWithOptions(nicID, e, nicOpts); err != nil {
		t.Fatalf("CreateNIC(%d, _, %+v) = %s", nicID, nicOpts, err)
	}

	addr := tcpip.ProtocolAddress{
		Protocol: header.IPv6ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   llAddr1,
			PrefixLen: 128,
		},
	}
	if err := s.AddProtocolAddress(nicID, addr); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v): %s", nicID, addr, err)
	}

	// Address should be in the list of all addresses.
	if addrs := s.AllAddresses()[nicID]; !containsV6Addr(addrs, addr.AddressWithPrefix) {
		t.Fatalf("got s.AllAddresses()[%d] = %+v, want = %+v", nicID, addrs, addr)
	}

	// Address should be tentative so it should not be a main address.
	got, err := s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
	}
	if want := (tcpip.AddressWithPrefix{}); got != want {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, got, want)
	}

	// Enabling the NIC should start DAD for the address.
	if err := s.EnableNIC(nicID); err != nil {
		t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
	}
	if addrs := s.AllAddresses()[nicID]; !containsV6Addr(addrs, addr.AddressWithPrefix) {
		t.Fatalf("got s.AllAddresses()[%d] = %+v, want = %+v", nicID, addrs, addr)
	}

	// Address should not be considered bound to the NIC yet (DAD ongoing).
	got, err = s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
	}
	if want := (tcpip.AddressWithPrefix{}); got != want {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, got, want)
	}

	// Wait for DAD to resolve.
	select {
	case <-time.After(dadTransmits*retransmitTimer + defaultAsyncPositiveEventTimeout):
		t.Fatal("timed out waiting for DAD resolution")
	case e := <-ndpDisp.dadC:
		if diff := checkDADEvent(e, nicID, addr.AddressWithPrefix.Address, true, nil); diff != "" {
			t.Errorf("dad event mismatch (-want +got):\n%s", diff)
		}
	}
	if addrs := s.AllAddresses()[nicID]; !containsV6Addr(addrs, addr.AddressWithPrefix) {
		t.Fatalf("got s.AllAddresses()[%d] = %+v, want = %+v", nicID, addrs, addr)
	}
	got, err = s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
	}
	if got != addr.AddressWithPrefix {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = %s, want = %s", nicID, header.IPv6ProtocolNumber, got, addr.AddressWithPrefix)
	}

	// Enabling the NIC again should be a no-op.
	if err := s.EnableNIC(nicID); err != nil {
		t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
	}
	if addrs := s.AllAddresses()[nicID]; !containsV6Addr(addrs, addr.AddressWithPrefix) {
		t.Fatalf("got s.AllAddresses()[%d] = %+v, want = %+v", nicID, addrs, addr)
	}
	got, err = s.GetMainNICAddress(nicID, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (_, %v), want = (_, nil)", nicID, header.IPv6ProtocolNumber, err)
	}
	if got != addr.AddressWithPrefix {
		t.Fatalf("got stack.GetMainNICAddress(%d, %d) = (%s, nil), want = (%s, nil)", nicID, header.IPv6ProtocolNumber, got, addr.AddressWithPrefix)
	}
}

func TestStackReceiveBufferSizeOption(t *testing.T) {
	const sMin = stack.MinBufferSize
	testCases := []struct {
		name string
		rs   stack.ReceiveBufferSizeOption
		err  *tcpip.Error
	}{
		// Invalid configurations.
		{"min_below_zero", stack.ReceiveBufferSizeOption{Min: -1, Default: sMin, Max: sMin}, tcpip.ErrInvalidOptionValue},
		{"min_zero", stack.ReceiveBufferSizeOption{Min: 0, Default: sMin, Max: sMin}, tcpip.ErrInvalidOptionValue},
		{"default_below_min", stack.ReceiveBufferSizeOption{Min: sMin, Default: sMin - 1, Max: sMin - 1}, tcpip.ErrInvalidOptionValue},
		{"default_above_max", stack.ReceiveBufferSizeOption{Min: sMin, Default: sMin + 1, Max: sMin}, tcpip.ErrInvalidOptionValue},
		{"max_below_min", stack.ReceiveBufferSizeOption{Min: sMin, Default: sMin + 1, Max: sMin - 1}, tcpip.ErrInvalidOptionValue},

		// Valid Configurations
		{"in_ascending_order", stack.ReceiveBufferSizeOption{Min: sMin, Default: sMin + 1, Max: sMin + 2}, nil},
		{"all_equal", stack.ReceiveBufferSizeOption{Min: sMin, Default: sMin, Max: sMin}, nil},
		{"min_default_equal", stack.ReceiveBufferSizeOption{Min: sMin, Default: sMin, Max: sMin + 1}, nil},
		{"default_max_equal", stack.ReceiveBufferSizeOption{Min: sMin, Default: sMin + 1, Max: sMin + 1}, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := stack.New(stack.Options{})
			defer s.Close()
			if err := s.SetOption(tc.rs); err != tc.err {
				t.Fatalf("s.SetOption(%#v) = %v, want: %v", tc.rs, err, tc.err)
			}
			var rs stack.ReceiveBufferSizeOption
			if tc.err == nil {
				if err := s.Option(&rs); err != nil {
					t.Fatalf("s.Option(%#v) = %v, want: nil", rs, err)
				}
				if got, want := rs, tc.rs; got != want {
					t.Fatalf("s.Option(..) returned unexpected value got: %#v, want: %#v", got, want)
				}
			}
		})
	}
}

func TestStackSendBufferSizeOption(t *testing.T) {
	const sMin = stack.MinBufferSize
	testCases := []struct {
		name string
		ss   stack.SendBufferSizeOption
		err  *tcpip.Error
	}{
		// Invalid configurations.
		{"min_below_zero", stack.SendBufferSizeOption{Min: -1, Default: sMin, Max: sMin}, tcpip.ErrInvalidOptionValue},
		{"min_zero", stack.SendBufferSizeOption{Min: 0, Default: sMin, Max: sMin}, tcpip.ErrInvalidOptionValue},
		{"default_below_min", stack.SendBufferSizeOption{Min: 0, Default: sMin - 1, Max: sMin - 1}, tcpip.ErrInvalidOptionValue},
		{"default_above_max", stack.SendBufferSizeOption{Min: 0, Default: sMin + 1, Max: sMin}, tcpip.ErrInvalidOptionValue},
		{"max_below_min", stack.SendBufferSizeOption{Min: sMin, Default: sMin + 1, Max: sMin - 1}, tcpip.ErrInvalidOptionValue},

		// Valid Configurations
		{"in_ascending_order", stack.SendBufferSizeOption{Min: sMin, Default: sMin + 1, Max: sMin + 2}, nil},
		{"all_equal", stack.SendBufferSizeOption{Min: sMin, Default: sMin, Max: sMin}, nil},
		{"min_default_equal", stack.SendBufferSizeOption{Min: sMin, Default: sMin, Max: sMin + 1}, nil},
		{"default_max_equal", stack.SendBufferSizeOption{Min: sMin, Default: sMin + 1, Max: sMin + 1}, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := stack.New(stack.Options{})
			defer s.Close()
			if err := s.SetOption(tc.ss); err != tc.err {
				t.Fatalf("s.SetOption(%+v) = %v, want: %v", tc.ss, err, tc.err)
			}
			var ss stack.SendBufferSizeOption
			if tc.err == nil {
				if err := s.Option(&ss); err != nil {
					t.Fatalf("s.Option(%+v) = %v, want: nil", ss, err)
				}
				if got, want := ss, tc.ss; got != want {
					t.Fatalf("s.Option(..) returned unexpected value got: %#v, want: %#v", got, want)
				}
			}
		})
	}
}

func TestOutgoingSubnetBroadcast(t *testing.T) {
	const (
		unspecifiedNICID = 0
		nicID1           = 1
	)

	defaultAddr := tcpip.AddressWithPrefix{
		Address:   header.IPv4Any,
		PrefixLen: 0,
	}
	defaultSubnet := defaultAddr.Subnet()
	ipv4Addr := tcpip.AddressWithPrefix{
		Address:   "\xc0\xa8\x01\x3a",
		PrefixLen: 24,
	}
	ipv4Subnet := ipv4Addr.Subnet()
	ipv4SubnetBcast := ipv4Subnet.Broadcast()
	ipv4Gateway := tcpip.Address("\xc0\xa8\x01\x01")
	ipv4AddrPrefix31 := tcpip.AddressWithPrefix{
		Address:   "\xc0\xa8\x01\x3a",
		PrefixLen: 31,
	}
	ipv4Subnet31 := ipv4AddrPrefix31.Subnet()
	ipv4Subnet31Bcast := ipv4Subnet31.Broadcast()
	ipv4AddrPrefix32 := tcpip.AddressWithPrefix{
		Address:   "\xc0\xa8\x01\x3a",
		PrefixLen: 32,
	}
	ipv4Subnet32 := ipv4AddrPrefix32.Subnet()
	ipv4Subnet32Bcast := ipv4Subnet32.Broadcast()
	ipv6Addr := tcpip.AddressWithPrefix{
		Address:   "\x20\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
		PrefixLen: 64,
	}
	ipv6Subnet := ipv6Addr.Subnet()
	ipv6SubnetBcast := ipv6Subnet.Broadcast()
	remNetAddr := tcpip.AddressWithPrefix{
		Address:   "\x64\x0a\x7b\x18",
		PrefixLen: 24,
	}
	remNetSubnet := remNetAddr.Subnet()
	remNetSubnetBcast := remNetSubnet.Broadcast()

	tests := []struct {
		name          string
		nicAddr       tcpip.ProtocolAddress
		routes        []tcpip.Route
		remoteAddr    tcpip.Address
		expectedRoute stack.Route
	}{
		// Broadcast to a locally attached subnet populates the broadcast MAC.
		{
			name: "IPv4 Broadcast to local subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4Addr,
			},
			routes: []tcpip.Route{
				{
					Destination: ipv4Subnet,
					NIC:         nicID1,
				},
			},
			remoteAddr: ipv4SubnetBcast,
			expectedRoute: stack.Route{
				LocalAddress:      ipv4Addr.Address,
				RemoteAddress:     ipv4SubnetBcast,
				RemoteLinkAddress: header.EthernetBroadcastAddress,
				NetProto:          header.IPv4ProtocolNumber,
				Loop:              stack.PacketOut,
			},
		},
		// Broadcast to a locally attached /31 subnet does not populate the
		// broadcast MAC.
		{
			name: "IPv4 Broadcast to local /31 subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4AddrPrefix31,
			},
			routes: []tcpip.Route{
				{
					Destination: ipv4Subnet31,
					NIC:         nicID1,
				},
			},
			remoteAddr: ipv4Subnet31Bcast,
			expectedRoute: stack.Route{
				LocalAddress:  ipv4AddrPrefix31.Address,
				RemoteAddress: ipv4Subnet31Bcast,
				NetProto:      header.IPv4ProtocolNumber,
				Loop:          stack.PacketOut,
			},
		},
		// Broadcast to a locally attached /32 subnet does not populate the
		// broadcast MAC.
		{
			name: "IPv4 Broadcast to local /32 subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4AddrPrefix32,
			},
			routes: []tcpip.Route{
				{
					Destination: ipv4Subnet32,
					NIC:         nicID1,
				},
			},
			remoteAddr: ipv4Subnet32Bcast,
			expectedRoute: stack.Route{
				LocalAddress:  ipv4AddrPrefix32.Address,
				RemoteAddress: ipv4Subnet32Bcast,
				NetProto:      header.IPv4ProtocolNumber,
				Loop:          stack.PacketOut,
			},
		},
		// IPv6 has no notion of a broadcast.
		{
			name: "IPv6 'Broadcast' to local subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: ipv6Addr,
			},
			routes: []tcpip.Route{
				{
					Destination: ipv6Subnet,
					NIC:         nicID1,
				},
			},
			remoteAddr: ipv6SubnetBcast,
			expectedRoute: stack.Route{
				LocalAddress:  ipv6Addr.Address,
				RemoteAddress: ipv6SubnetBcast,
				NetProto:      header.IPv6ProtocolNumber,
				Loop:          stack.PacketOut,
			},
		},
		// Broadcast to a remote subnet in the route table is send to the next-hop
		// gateway.
		{
			name: "IPv4 Broadcast to remote subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4Addr,
			},
			routes: []tcpip.Route{
				{
					Destination: remNetSubnet,
					Gateway:     ipv4Gateway,
					NIC:         nicID1,
				},
			},
			remoteAddr: remNetSubnetBcast,
			expectedRoute: stack.Route{
				LocalAddress:  ipv4Addr.Address,
				RemoteAddress: remNetSubnetBcast,
				NextHop:       ipv4Gateway,
				NetProto:      header.IPv4ProtocolNumber,
				Loop:          stack.PacketOut,
			},
		},
		// Broadcast to an unknown subnet follows the default route. Note that this
		// is essentially just routing an unknown destination IP, because w/o any
		// subnet prefix information a subnet broadcast address is just a normal IP.
		{
			name: "IPv4 Broadcast to unknown subnet",
			nicAddr: tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: ipv4Addr,
			},
			routes: []tcpip.Route{
				{
					Destination: defaultSubnet,
					Gateway:     ipv4Gateway,
					NIC:         nicID1,
				},
			},
			remoteAddr: remNetSubnetBcast,
			expectedRoute: stack.Route{
				LocalAddress:  ipv4Addr.Address,
				RemoteAddress: remNetSubnetBcast,
				NextHop:       ipv4Gateway,
				NetProto:      header.IPv4ProtocolNumber,
				Loop:          stack.PacketOut,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol()},
			})
			ep := channel.New(0, defaultMTU, "")
			if err := s.CreateNIC(nicID1, ep); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID1, err)
			}
			if err := s.AddProtocolAddress(nicID1, test.nicAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v): %s", nicID1, test.nicAddr, err)
			}

			s.SetRouteTable(test.routes)

			var netProto tcpip.NetworkProtocolNumber
			switch l := len(test.remoteAddr); l {
			case header.IPv4AddressSize:
				netProto = header.IPv4ProtocolNumber
			case header.IPv6AddressSize:
				netProto = header.IPv6ProtocolNumber
			default:
				t.Fatalf("got unexpected address length = %d bytes", l)
			}

			if r, err := s.FindRoute(unspecifiedNICID, "" /* localAddr */, test.remoteAddr, netProto, false /* multicastLoop */); err != nil {
				t.Fatalf("FindRoute(%d, '', %s, %d): %s", unspecifiedNICID, test.remoteAddr, netProto, err)
			} else if diff := cmp.Diff(r, test.expectedRoute, cmpopts.IgnoreUnexported(r)); diff != "" {
				t.Errorf("route mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveWith(t *testing.T) {
	const (
		unspecifiedNICID = 0
		nicID            = 1
	)

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv4.NewProtocol(), arp.NewProtocol()},
	})
	ep := channel.New(0, defaultMTU, "")
	ep.LinkEPCapabilities |= stack.CapabilityResolutionRequired
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
	}
	addr := tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.1.58").To4()),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(nicID, addr); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v): %s", nicID, addr, err)
	}

	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	remoteAddr := tcpip.Address(net.ParseIP("192.168.1.59").To4())
	r, err := s.FindRoute(unspecifiedNICID, "" /* localAddr */, remoteAddr, header.IPv4ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(%d, '', %s, %d): %s", unspecifiedNICID, remoteAddr, header.IPv4ProtocolNumber, err)
	}
	defer r.Release()

	// Should initially require resolution.
	if !r.IsResolutionRequired() {
		t.Fatal("got r.IsResolutionRequired() = false, want = true")
	}

	// Manually resolving the route should no longer require resolution.
	r.ResolveWith("\x01")
	if r.IsResolutionRequired() {
		t.Fatal("got r.IsResolutionRequired() = true, want = false")
	}
}
