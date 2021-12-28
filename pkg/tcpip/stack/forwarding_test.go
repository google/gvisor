// Copyright 2020 The gVisor Authors.
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

package stack

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	fwdTestNetNumber           tcpip.NetworkProtocolNumber = math.MaxUint32
	fwdTestNetHeaderLen                                    = 12
	fwdTestNetDefaultPrefixLen                             = 8

	// fwdTestNetDefaultMTU is the MTU, in bytes, used throughout the tests,
	// except where another value is explicitly used. It is chosen to match
	// the MTU of loopback interfaces on linux systems.
	fwdTestNetDefaultMTU = 65536

	dstAddrOffset        = 0
	srcAddrOffset        = 1
	protocolNumberOffset = 2
)

var _ LinkAddressResolver = (*fwdTestNetworkEndpoint)(nil)
var _ NetworkEndpoint = (*fwdTestNetworkEndpoint)(nil)

// fwdTestNetworkEndpoint is a network-layer protocol endpoint.
// Headers of this protocol are fwdTestNetHeaderLen bytes, but we currently only
// use the first three: destination address, source address, and transport
// protocol. They're all one byte fields to simplify parsing.
type fwdTestNetworkEndpoint struct {
	AddressableEndpointState

	nic        NetworkInterface
	proto      *fwdTestNetworkProtocol
	dispatcher TransportDispatcher

	mu struct {
		sync.RWMutex
		forwarding bool
	}
}

func (*fwdTestNetworkEndpoint) Enable() tcpip.Error {
	return nil
}

func (*fwdTestNetworkEndpoint) Enabled() bool {
	return true
}

func (*fwdTestNetworkEndpoint) Disable() {}

func (f *fwdTestNetworkEndpoint) MTU() uint32 {
	return f.nic.MTU() - uint32(f.MaxHeaderLength())
}

func (*fwdTestNetworkEndpoint) DefaultTTL() uint8 {
	return 123
}

func (f *fwdTestNetworkEndpoint) HandlePacket(pkt *PacketBuffer) {
	if _, _, ok := f.proto.Parse(pkt); !ok {
		return
	}

	netHdr := pkt.NetworkHeader().View()
	_, dst := f.proto.ParseAddresses(netHdr)

	addressEndpoint := f.AcquireAssignedAddress(dst, f.nic.Promiscuous(), CanBePrimaryEndpoint)
	if addressEndpoint != nil {
		addressEndpoint.DecRef()
		// Dispatch the packet to the transport protocol.
		f.dispatcher.DeliverTransportPacket(tcpip.TransportProtocolNumber(netHdr[protocolNumberOffset]), pkt)
		return
	}

	r, err := f.proto.stack.FindRoute(0, "", dst, fwdTestNetNumber, false /* multicastLoop */)
	if err != nil {
		return
	}
	defer r.Release()

	vv := buffer.NewVectorisedView(pkt.Size(), pkt.Views())
	pkt = NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Data:               vv.ToView().ToVectorisedView(),
	})
	// TODO(gvisor.dev/issue/1085) Decrease the TTL field in forwarded packets.
	_ = r.WriteHeaderIncludedPacket(pkt)
}

func (f *fwdTestNetworkEndpoint) MaxHeaderLength() uint16 {
	return f.nic.MaxHeaderLength() + fwdTestNetHeaderLen
}

func (f *fwdTestNetworkEndpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return f.proto.Number()
}

func (f *fwdTestNetworkEndpoint) WritePacket(r *Route, params NetworkHeaderParams, pkt *PacketBuffer) tcpip.Error {
	// Add the protocol's header to the packet and send it to the link
	// endpoint.
	b := pkt.NetworkHeader().Push(fwdTestNetHeaderLen)
	b[dstAddrOffset] = r.RemoteAddress()[0]
	b[srcAddrOffset] = r.LocalAddress()[0]
	b[protocolNumberOffset] = byte(params.Protocol)

	return f.nic.WritePacket(r, fwdTestNetNumber, pkt)
}

// WritePackets implements LinkEndpoint.WritePackets.
func (*fwdTestNetworkEndpoint) WritePackets(*Route, PacketBufferList, NetworkHeaderParams) (int, tcpip.Error) {
	panic("not implemented")
}

func (f *fwdTestNetworkEndpoint) WriteHeaderIncludedPacket(r *Route, pkt *PacketBuffer) tcpip.Error {
	// The network header should not already be populated.
	if _, ok := pkt.NetworkHeader().Consume(fwdTestNetHeaderLen); !ok {
		return &tcpip.ErrMalformedHeader{}
	}

	return f.nic.WritePacket(r, fwdTestNetNumber, pkt)
}

func (f *fwdTestNetworkEndpoint) Close() {
	f.AddressableEndpointState.Cleanup()
}

// Stats implements stack.NetworkEndpoint.
func (*fwdTestNetworkEndpoint) Stats() NetworkEndpointStats {
	return &fwdTestNetworkEndpointStats{}
}

var _ NetworkEndpointStats = (*fwdTestNetworkEndpointStats)(nil)

type fwdTestNetworkEndpointStats struct{}

// IsNetworkEndpointStats implements stack.NetworkEndpointStats.
func (*fwdTestNetworkEndpointStats) IsNetworkEndpointStats() {}

var _ NetworkProtocol = (*fwdTestNetworkProtocol)(nil)

// fwdTestNetworkProtocol is a network-layer protocol that implements Address
// resolution.
type fwdTestNetworkProtocol struct {
	stack *Stack

	neigh                  *neighborCache
	addrResolveDelay       time.Duration
	onLinkAddressResolved  func(*neighborCache, tcpip.Address, tcpip.LinkAddress)
	onResolveStaticAddress func(tcpip.Address) (tcpip.LinkAddress, bool)
}

func (*fwdTestNetworkProtocol) Number() tcpip.NetworkProtocolNumber {
	return fwdTestNetNumber
}

func (*fwdTestNetworkProtocol) MinimumPacketSize() int {
	return fwdTestNetHeaderLen
}

func (*fwdTestNetworkProtocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	return tcpip.Address(v[srcAddrOffset : srcAddrOffset+1]), tcpip.Address(v[dstAddrOffset : dstAddrOffset+1])
}

func (*fwdTestNetworkProtocol) Parse(pkt *PacketBuffer) (tcpip.TransportProtocolNumber, bool, bool) {
	netHeader, ok := pkt.NetworkHeader().Consume(fwdTestNetHeaderLen)
	if !ok {
		return 0, false, false
	}
	return tcpip.TransportProtocolNumber(netHeader[protocolNumberOffset]), true, true
}

func (f *fwdTestNetworkProtocol) NewEndpoint(nic NetworkInterface, dispatcher TransportDispatcher) NetworkEndpoint {
	e := &fwdTestNetworkEndpoint{
		nic:        nic,
		proto:      f,
		dispatcher: dispatcher,
	}
	e.AddressableEndpointState.Init(e)
	return e
}

func (*fwdTestNetworkProtocol) SetOption(tcpip.SettableNetworkProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*fwdTestNetworkProtocol) Option(tcpip.GettableNetworkProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*fwdTestNetworkProtocol) Close() {}

func (*fwdTestNetworkProtocol) Wait() {}

func (f *fwdTestNetworkEndpoint) LinkAddressRequest(addr, _ tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error {
	if fn := f.proto.onLinkAddressResolved; fn != nil {
		f.proto.stack.clock.AfterFunc(f.proto.addrResolveDelay, func() {
			fn(f.proto.neigh, addr, remoteLinkAddr)
		})
	}
	return nil
}

func (f *fwdTestNetworkEndpoint) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if fn := f.proto.onResolveStaticAddress; fn != nil {
		return fn(addr)
	}
	return "", false
}

func (*fwdTestNetworkEndpoint) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return fwdTestNetNumber
}

// Forwarding implements stack.ForwardingNetworkEndpoint.
func (f *fwdTestNetworkEndpoint) Forwarding() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mu.forwarding

}

// SetForwarding implements stack.ForwardingNetworkEndpoint.
func (f *fwdTestNetworkEndpoint) SetForwarding(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mu.forwarding = v
}

// fwdTestPacketInfo holds all the information about an outbound packet.
type fwdTestPacketInfo struct {
	RemoteLinkAddress tcpip.LinkAddress
	LocalLinkAddress  tcpip.LinkAddress
	Pkt               *PacketBuffer
}

var _ LinkEndpoint = (*fwdTestLinkEndpoint)(nil)

type fwdTestLinkEndpoint struct {
	dispatcher NetworkDispatcher
	mtu        uint32
	linkAddr   tcpip.LinkAddress

	// C is where outbound packets are queued.
	C chan fwdTestPacketInfo
}

// InjectInbound injects an inbound packet.
func (e *fwdTestLinkEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	e.InjectLinkAddr(protocol, "", pkt)
}

// InjectLinkAddr injects an inbound packet with a remote link address.
func (e *fwdTestLinkEndpoint) InjectLinkAddr(protocol tcpip.NetworkProtocolNumber, remote tcpip.LinkAddress, pkt *PacketBuffer) {
	e.dispatcher.DeliverNetworkPacket(remote, "" /* local */, protocol, pkt)
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *fwdTestLinkEndpoint) Attach(dispatcher NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *fwdTestLinkEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *fwdTestLinkEndpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e fwdTestLinkEndpoint) Capabilities() LinkEndpointCapabilities {
	caps := LinkEndpointCapabilities(0)
	return caps | CapabilityResolutionRequired
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*fwdTestLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (e *fwdTestLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// WritePackets stores outbound packets into the channel.
func (e *fwdTestLinkEndpoint) WritePackets(r RouteInfo, pkts PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		p := fwdTestPacketInfo{
			RemoteLinkAddress: r.RemoteLinkAddress,
			LocalLinkAddress:  r.LocalLinkAddress,
			Pkt:               pkt,
		}

		select {
		case e.C <- p:
		default:
		}

		n++
	}

	return n, nil
}

func (*fwdTestLinkEndpoint) WriteRawPacket(*PacketBuffer) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Wait implements stack.LinkEndpoint.Wait.
func (*fwdTestLinkEndpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*fwdTestLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	panic("not implemented")
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *fwdTestLinkEndpoint) AddHeader(tcpip.LinkAddress, tcpip.LinkAddress, tcpip.NetworkProtocolNumber, *PacketBuffer) {
	panic("not implemented")
}

func fwdTestNetFactory(t *testing.T, proto *fwdTestNetworkProtocol) (*faketime.ManualClock, *fwdTestLinkEndpoint, *fwdTestLinkEndpoint) {
	clock := faketime.NewManualClock()
	// Create a stack with the network protocol and two NICs.
	s := New(Options{
		NetworkProtocols: []NetworkProtocolFactory{func(s *Stack) NetworkProtocol {
			proto.stack = s
			return proto
		}},
		Clock: clock,
	})

	protoNum := proto.Number()
	if err := s.SetForwardingDefaultAndAllNICs(protoNum, true); err != nil {
		t.Fatalf("SetForwardingDefaultAndAllNICs(%d, true): %s", protoNum, err)
	}

	// NIC 1 has the link address "a", and added the network address 1.
	ep1 := &fwdTestLinkEndpoint{
		C:        make(chan fwdTestPacketInfo, 300),
		mtu:      fwdTestNetDefaultMTU,
		linkAddr: "a",
	}
	if err := s.CreateNIC(1, ep1); err != nil {
		t.Fatal("CreateNIC #1 failed:", err)
	}
	protocolAddr1 := tcpip.ProtocolAddress{
		Protocol: fwdTestNetNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   "\x01",
			PrefixLen: fwdTestNetDefaultPrefixLen,
		},
	}
	if err := s.AddProtocolAddress(1, protocolAddr1, AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", 1, protocolAddr1, err)
	}

	// NIC 2 has the link address "b", and added the network address 2.
	ep2 := &fwdTestLinkEndpoint{
		C:        make(chan fwdTestPacketInfo, 300),
		mtu:      fwdTestNetDefaultMTU,
		linkAddr: "b",
	}
	if err := s.CreateNIC(2, ep2); err != nil {
		t.Fatal("CreateNIC #2 failed:", err)
	}
	protocolAddr2 := tcpip.ProtocolAddress{
		Protocol: fwdTestNetNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   "\x02",
			PrefixLen: fwdTestNetDefaultPrefixLen,
		},
	}
	if err := s.AddProtocolAddress(2, protocolAddr2, AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", 2, protocolAddr2, err)
	}

	nic, ok := s.nics[2]
	if !ok {
		t.Fatal("NIC 2 does not exist")
	}

	if l, ok := nic.linkAddrResolvers[fwdTestNetNumber]; ok {
		proto.neigh = &l.neigh
	}

	// Route all packets to NIC 2.
	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 2}})
	}

	return clock, ep1, ep2
}

func TestForwardingWithStaticResolver(t *testing.T) {
	// Create a network protocol with a static resolver.
	proto := &fwdTestNetworkProtocol{
		onResolveStaticAddress:
		// The network address 3 is resolved to the link address "c".
		func(addr tcpip.Address) (tcpip.LinkAddress, bool) {
			if addr == "\x03" {
				return "c", true
			}
			return "", false
		},
	}

	clock, ep1, ep2 := fwdTestNetFactory(t, proto)

	// Inject an inbound packet to address 3 on NIC 1, and see if it is
	// forwarded to NIC 2.
	buf := buffer.NewView(30)
	buf[dstAddrOffset] = 3
	ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))

	var p fwdTestPacketInfo

	clock.Advance(proto.addrResolveDelay)
	select {
	case p = <-ep2.C:
	default:
		t.Fatal("packet not forwarded")
	}

	// Test that the static address resolution happened correctly.
	if p.RemoteLinkAddress != "c" {
		t.Fatalf("got p.RemoteLinkAddress = %s, want = c", p.RemoteLinkAddress)
	}
	if p.LocalLinkAddress != "b" {
		t.Fatalf("got p.LocalLinkAddress = %s, want = b", p.LocalLinkAddress)
	}
}

func TestForwardingWithFakeResolver(t *testing.T) {
	proto := fwdTestNetworkProtocol{
		addrResolveDelay: 500 * time.Millisecond,
		onLinkAddressResolved: func(neigh *neighborCache, addr tcpip.Address, linkAddr tcpip.LinkAddress) {
			t.Helper()
			if len(linkAddr) != 0 {
				t.Fatalf("got linkAddr=%q, want unspecified", linkAddr)
			}
			// Any address will be resolved to the link address "c".
			neigh.handleConfirmation(addr, "c", ReachabilityConfirmationFlags{
				Solicited: true,
				Override:  false,
				IsRouter:  false,
			})
		},
	}
	clock, ep1, ep2 := fwdTestNetFactory(t, &proto)

	// Inject an inbound packet to address 3 on NIC 1, and see if it is
	// forwarded to NIC 2.
	buf := buffer.NewView(30)
	buf[dstAddrOffset] = 3
	ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))

	var p fwdTestPacketInfo

	clock.Advance(proto.addrResolveDelay)
	select {
	case p = <-ep2.C:
	default:
		t.Fatal("packet not forwarded")
	}

	// Test that the address resolution happened correctly.
	if p.RemoteLinkAddress != "c" {
		t.Fatalf("got p.RemoteLinkAddress = %s, want = c", p.RemoteLinkAddress)
	}
	if p.LocalLinkAddress != "b" {
		t.Fatalf("got p.LocalLinkAddress = %s, want = b", p.LocalLinkAddress)
	}
}

func TestForwardingWithNoResolver(t *testing.T) {
	// Create a network protocol without a resolver.
	proto := &fwdTestNetworkProtocol{}

	// Whether or not we use the neighbor cache here does not matter since
	// neither linkAddrCache nor neighborCache will be used.
	clock, ep1, ep2 := fwdTestNetFactory(t, proto)

	// inject an inbound packet to address 3 on NIC 1, and see if it is
	// forwarded to NIC 2.
	buf := buffer.NewView(30)
	buf[dstAddrOffset] = 3
	ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))

	clock.Advance(proto.addrResolveDelay)
	select {
	case <-ep2.C:
		t.Fatal("Packet should not be forwarded")
	default:
	}
}

func TestForwardingResolutionFailsForQueuedPackets(t *testing.T) {
	proto := &fwdTestNetworkProtocol{
		addrResolveDelay: 50 * time.Millisecond,
		onLinkAddressResolved: func(*neighborCache, tcpip.Address, tcpip.LinkAddress) {
			// Don't resolve the link address.
		},
	}

	clock, ep1, ep2 := fwdTestNetFactory(t, proto)

	const numPackets int = 5
	// These packets will all be enqueued in the packet queue to wait for link
	// address resolution.
	for i := 0; i < numPackets; i++ {
		buf := buffer.NewView(30)
		buf[dstAddrOffset] = 3
		ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
			Data: buf.ToVectorisedView(),
		}))
	}

	// All packets should fail resolution.
	for i := 0; i < numPackets; i++ {
		clock.Advance(proto.addrResolveDelay)
		select {
		case got := <-ep2.C:
			t.Fatalf("got %#v; packets should have failed resolution and not been forwarded", got)
		default:
		}
	}
}

func TestForwardingWithFakeResolverPartialTimeout(t *testing.T) {
	proto := fwdTestNetworkProtocol{
		addrResolveDelay: 500 * time.Millisecond,
		onLinkAddressResolved: func(neigh *neighborCache, addr tcpip.Address, linkAddr tcpip.LinkAddress) {
			t.Helper()
			if len(linkAddr) != 0 {
				t.Fatalf("got linkAddr=%q, want unspecified", linkAddr)
			}
			// Only packets to address 3 will be resolved to the
			// link address "c".
			if addr == "\x03" {
				neigh.handleConfirmation(addr, "c", ReachabilityConfirmationFlags{
					Solicited: true,
					Override:  false,
					IsRouter:  false,
				})
			}
		},
	}
	clock, ep1, ep2 := fwdTestNetFactory(t, &proto)

	// Inject an inbound packet to address 4 on NIC 1. This packet should
	// not be forwarded.
	buf := buffer.NewView(30)
	buf[dstAddrOffset] = 4
	ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))

	// Inject an inbound packet to address 3 on NIC 1, and see if it is
	// forwarded to NIC 2.
	buf = buffer.NewView(30)
	buf[dstAddrOffset] = 3
	ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))

	var p fwdTestPacketInfo

	clock.Advance(proto.addrResolveDelay)
	select {
	case p = <-ep2.C:
	default:
		t.Fatal("packet not forwarded")
	}

	if nh := PayloadSince(p.Pkt.NetworkHeader()); nh[dstAddrOffset] != 3 {
		t.Fatalf("got p.Pkt.NetworkHeader[dstAddrOffset] = %d, want = 3", nh[dstAddrOffset])
	}

	// Test that the address resolution happened correctly.
	if p.RemoteLinkAddress != "c" {
		t.Fatalf("got p.RemoteLinkAddress = %s, want = c", p.RemoteLinkAddress)
	}
	if p.LocalLinkAddress != "b" {
		t.Fatalf("got p.LocalLinkAddress = %s, want = b", p.LocalLinkAddress)
	}
}

func TestForwardingWithFakeResolverTwoPackets(t *testing.T) {
	proto := fwdTestNetworkProtocol{
		addrResolveDelay: 500 * time.Millisecond,
		onLinkAddressResolved: func(neigh *neighborCache, addr tcpip.Address, linkAddr tcpip.LinkAddress) {
			t.Helper()
			if len(linkAddr) != 0 {
				t.Fatalf("got linkAddr=%q, want unspecified", linkAddr)
			}
			// Any packets will be resolved to the link address "c".
			neigh.handleConfirmation(addr, "c", ReachabilityConfirmationFlags{
				Solicited: true,
				Override:  false,
				IsRouter:  false,
			})
		},
	}
	clock, ep1, ep2 := fwdTestNetFactory(t, &proto)

	// Inject two inbound packets to address 3 on NIC 1.
	for i := 0; i < 2; i++ {
		buf := buffer.NewView(30)
		buf[dstAddrOffset] = 3
		ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
			Data: buf.ToVectorisedView(),
		}))
	}

	for i := 0; i < 2; i++ {
		var p fwdTestPacketInfo

		clock.Advance(proto.addrResolveDelay)
		select {
		case p = <-ep2.C:
		default:
			t.Fatal("packet not forwarded")
		}

		if nh := PayloadSince(p.Pkt.NetworkHeader()); nh[dstAddrOffset] != 3 {
			t.Fatalf("got p.Pkt.NetworkHeader[dstAddrOffset] = %d, want = 3", nh[dstAddrOffset])
		}

		// Test that the address resolution happened correctly.
		if p.RemoteLinkAddress != "c" {
			t.Fatalf("got p.RemoteLinkAddress = %s, want = c", p.RemoteLinkAddress)
		}
		if p.LocalLinkAddress != "b" {
			t.Fatalf("got p.LocalLinkAddress = %s, want = b", p.LocalLinkAddress)
		}
	}
}

func TestForwardingWithFakeResolverManyPackets(t *testing.T) {
	proto := fwdTestNetworkProtocol{
		addrResolveDelay: 500 * time.Millisecond,
		onLinkAddressResolved: func(neigh *neighborCache, addr tcpip.Address, linkAddr tcpip.LinkAddress) {
			t.Helper()
			if len(linkAddr) != 0 {
				t.Fatalf("got linkAddr=%q, want unspecified", linkAddr)
			}
			// Any packets will be resolved to the link address "c".
			neigh.handleConfirmation(addr, "c", ReachabilityConfirmationFlags{
				Solicited: true,
				Override:  false,
				IsRouter:  false,
			})
		},
	}
	clock, ep1, ep2 := fwdTestNetFactory(t, &proto)

	for i := 0; i < maxPendingPacketsPerResolution+5; i++ {
		// Inject inbound 'maxPendingPacketsPerResolution + 5' packets on NIC 1.
		buf := buffer.NewView(30)
		buf[dstAddrOffset] = 3
		// Set the packet sequence number.
		binary.BigEndian.PutUint16(buf[fwdTestNetHeaderLen:], uint16(i))
		ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
			Data: buf.ToVectorisedView(),
		}))
	}

	for i := 0; i < maxPendingPacketsPerResolution; i++ {
		var p fwdTestPacketInfo

		clock.Advance(proto.addrResolveDelay)
		select {
		case p = <-ep2.C:
		default:
			t.Fatal("packet not forwarded")
		}

		b := PayloadSince(p.Pkt.NetworkHeader())
		if b[dstAddrOffset] != 3 {
			t.Fatalf("got b[dstAddrOffset] = %d, want = 3", b[dstAddrOffset])
		}
		if len(b) < fwdTestNetHeaderLen+2 {
			t.Fatalf("packet is too short to hold a sequence number: len(b) = %d", b)
		}
		seqNumBuf := b[fwdTestNetHeaderLen:]

		// The first 5 packets should not be forwarded so the sequence number should
		// start with 5.
		want := uint16(i + 5)
		if n := binary.BigEndian.Uint16(seqNumBuf); n != want {
			t.Fatalf("got the packet #%d, want = #%d", n, want)
		}

		// Test that the address resolution happened correctly.
		if p.RemoteLinkAddress != "c" {
			t.Fatalf("got p.RemoteLinkAddress = %s, want = c", p.RemoteLinkAddress)
		}
		if p.LocalLinkAddress != "b" {
			t.Fatalf("got p.LocalLinkAddress = %s, want = b", p.LocalLinkAddress)
		}
	}
}

func TestForwardingWithFakeResolverManyResolutions(t *testing.T) {
	proto := fwdTestNetworkProtocol{
		addrResolveDelay: 500 * time.Millisecond,
		onLinkAddressResolved: func(neigh *neighborCache, addr tcpip.Address, linkAddr tcpip.LinkAddress) {
			t.Helper()
			if len(linkAddr) != 0 {
				t.Fatalf("got linkAddr=%q, want unspecified", linkAddr)
			}
			// Any packets will be resolved to the link address "c".
			neigh.handleConfirmation(addr, "c", ReachabilityConfirmationFlags{
				Solicited: true,
				Override:  false,
				IsRouter:  false,
			})
		},
	}
	clock, ep1, ep2 := fwdTestNetFactory(t, &proto)

	for i := 0; i < maxPendingResolutions+5; i++ {
		// Inject inbound 'maxPendingResolutions + 5' packets on NIC 1.
		// Each packet has a different destination address (3 to
		// maxPendingResolutions + 7).
		buf := buffer.NewView(30)
		buf[dstAddrOffset] = byte(3 + i)
		ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
			Data: buf.ToVectorisedView(),
		}))
	}

	for i := 0; i < maxPendingResolutions; i++ {
		var p fwdTestPacketInfo

		clock.Advance(proto.addrResolveDelay)
		select {
		case p = <-ep2.C:
		default:
			t.Fatal("packet not forwarded")
		}

		// The first 5 packets (address 3 to 7) should not be forwarded
		// because their address resolutions are interrupted.
		if nh := PayloadSince(p.Pkt.NetworkHeader()); nh[dstAddrOffset] < 8 {
			t.Fatalf("got p.Pkt.NetworkHeader[dstAddrOffset] = %d, want p.Pkt.NetworkHeader[dstAddrOffset] >= 8", nh[dstAddrOffset])
		}

		// Test that the address resolution happened correctly.
		if p.RemoteLinkAddress != "c" {
			t.Fatalf("got p.RemoteLinkAddress = %s, want = c", p.RemoteLinkAddress)
		}
		if p.LocalLinkAddress != "b" {
			t.Fatalf("got p.LocalLinkAddress = %s, want = b", p.LocalLinkAddress)
		}
	}
}
