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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
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

// fwdTestNetworkEndpoint is a network-layer protocol endpoint.
// Headers of this protocol are fwdTestNetHeaderLen bytes, but we currently only
// use the first three: destination address, source address, and transport
// protocol. They're all one byte fields to simplify parsing.
type fwdTestNetworkEndpoint struct {
	nicID      tcpip.NICID
	proto      *fwdTestNetworkProtocol
	dispatcher TransportDispatcher
	ep         LinkEndpoint
}

var _ NetworkEndpoint = (*fwdTestNetworkEndpoint)(nil)

func (f *fwdTestNetworkEndpoint) MTU() uint32 {
	return f.ep.MTU() - uint32(f.MaxHeaderLength())
}

func (f *fwdTestNetworkEndpoint) NICID() tcpip.NICID {
	return f.nicID
}

func (*fwdTestNetworkEndpoint) DefaultTTL() uint8 {
	return 123
}

func (f *fwdTestNetworkEndpoint) HandlePacket(r *Route, pkt *PacketBuffer) {
	// Dispatch the packet to the transport protocol.
	f.dispatcher.DeliverTransportPacket(r, tcpip.TransportProtocolNumber(pkt.NetworkHeader().View()[protocolNumberOffset]), pkt)
}

func (f *fwdTestNetworkEndpoint) MaxHeaderLength() uint16 {
	return f.ep.MaxHeaderLength() + fwdTestNetHeaderLen
}

func (f *fwdTestNetworkEndpoint) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, dstAddr tcpip.Address) uint16 {
	return 0
}

func (f *fwdTestNetworkEndpoint) Capabilities() LinkEndpointCapabilities {
	return f.ep.Capabilities()
}

func (f *fwdTestNetworkEndpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return f.proto.Number()
}

func (f *fwdTestNetworkEndpoint) WritePacket(r *Route, gso *GSO, params NetworkHeaderParams, pkt *PacketBuffer) *tcpip.Error {
	// Add the protocol's header to the packet and send it to the link
	// endpoint.
	b := pkt.NetworkHeader().Push(fwdTestNetHeaderLen)
	b[dstAddrOffset] = r.RemoteAddress[0]
	b[srcAddrOffset] = r.LocalAddress[0]
	b[protocolNumberOffset] = byte(params.Protocol)

	return f.ep.WritePacket(r, gso, fwdTestNetNumber, pkt)
}

// WritePackets implements LinkEndpoint.WritePackets.
func (f *fwdTestNetworkEndpoint) WritePackets(r *Route, gso *GSO, pkts PacketBufferList, params NetworkHeaderParams) (int, *tcpip.Error) {
	panic("not implemented")
}

func (*fwdTestNetworkEndpoint) WriteHeaderIncludedPacket(r *Route, pkt *PacketBuffer) *tcpip.Error {
	return tcpip.ErrNotSupported
}

func (*fwdTestNetworkEndpoint) Close() {}

// fwdTestNetworkProtocol is a network-layer protocol that implements Address
// resolution.
type fwdTestNetworkProtocol struct {
	addrCache              *linkAddrCache
	neigh                  *neighborCache
	addrResolveDelay       time.Duration
	onLinkAddressResolved  func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, _ tcpip.LinkAddress)
	onResolveStaticAddress func(tcpip.Address) (tcpip.LinkAddress, bool)
}

var _ NetworkProtocol = (*fwdTestNetworkProtocol)(nil)
var _ LinkAddressResolver = (*fwdTestNetworkProtocol)(nil)

func (f *fwdTestNetworkProtocol) Number() tcpip.NetworkProtocolNumber {
	return fwdTestNetNumber
}

func (f *fwdTestNetworkProtocol) MinimumPacketSize() int {
	return fwdTestNetHeaderLen
}

func (f *fwdTestNetworkProtocol) DefaultPrefixLen() int {
	return fwdTestNetDefaultPrefixLen
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

func (f *fwdTestNetworkProtocol) NewEndpoint(nicID tcpip.NICID, _ LinkAddressCache, _ NUDHandler, dispatcher TransportDispatcher, ep LinkEndpoint, _ *Stack) NetworkEndpoint {
	return &fwdTestNetworkEndpoint{
		nicID:      nicID,
		proto:      f,
		dispatcher: dispatcher,
		ep:         ep,
	}
}

func (f *fwdTestNetworkProtocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

func (f *fwdTestNetworkProtocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

func (f *fwdTestNetworkProtocol) Close() {}

func (f *fwdTestNetworkProtocol) Wait() {}

func (f *fwdTestNetworkProtocol) LinkAddressRequest(addr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress, linkEP LinkEndpoint) *tcpip.Error {
	if f.onLinkAddressResolved != nil {
		time.AfterFunc(f.addrResolveDelay, func() {
			f.onLinkAddressResolved(f.addrCache, f.neigh, addr, remoteLinkAddr)
		})
	}
	return nil
}

func (f *fwdTestNetworkProtocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if f.onResolveStaticAddress != nil {
		return f.onResolveStaticAddress(addr)
	}
	return "", false
}

func (f *fwdTestNetworkProtocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return fwdTestNetNumber
}

// fwdTestPacketInfo holds all the information about an outbound packet.
type fwdTestPacketInfo struct {
	RemoteLinkAddress tcpip.LinkAddress
	LocalLinkAddress  tcpip.LinkAddress
	Pkt               *PacketBuffer
}

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

// GSOMaxSize returns the maximum GSO packet size.
func (*fwdTestLinkEndpoint) GSOMaxSize() uint32 {
	return 1 << 15
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

func (e fwdTestLinkEndpoint) WritePacket(r *Route, gso *GSO, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) *tcpip.Error {
	p := fwdTestPacketInfo{
		RemoteLinkAddress: r.RemoteLinkAddress,
		LocalLinkAddress:  r.LocalLinkAddress,
		Pkt:               pkt,
	}

	select {
	case e.C <- p:
	default:
	}

	return nil
}

// WritePackets stores outbound packets into the channel.
func (e *fwdTestLinkEndpoint) WritePackets(r *Route, gso *GSO, pkts PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		e.WritePacket(r, gso, protocol, pkt)
		n++
	}

	return n, nil
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *fwdTestLinkEndpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	p := fwdTestPacketInfo{
		Pkt: NewPacketBuffer(PacketBufferOptions{Data: vv}),
	}

	select {
	case e.C <- p:
	default:
	}

	return nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (*fwdTestLinkEndpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*fwdTestLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	panic("not implemented")
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *fwdTestLinkEndpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	panic("not implemented")
}

func fwdTestNetFactory(t *testing.T, proto *fwdTestNetworkProtocol, useNeighborCache bool) (ep1, ep2 *fwdTestLinkEndpoint) {
	// Create a stack with the network protocol and two NICs.
	s := New(Options{
		NetworkProtocols: []NetworkProtocol{proto},
		UseNeighborCache: useNeighborCache,
	})

	if !useNeighborCache {
		proto.addrCache = s.linkAddrCache
	}

	// Enable forwarding.
	s.SetForwarding(true)

	// NIC 1 has the link address "a", and added the network address 1.
	ep1 = &fwdTestLinkEndpoint{
		C:        make(chan fwdTestPacketInfo, 300),
		mtu:      fwdTestNetDefaultMTU,
		linkAddr: "a",
	}
	if err := s.CreateNIC(1, ep1); err != nil {
		t.Fatal("CreateNIC #1 failed:", err)
	}
	if err := s.AddAddress(1, fwdTestNetNumber, "\x01"); err != nil {
		t.Fatal("AddAddress #1 failed:", err)
	}

	// NIC 2 has the link address "b", and added the network address 2.
	ep2 = &fwdTestLinkEndpoint{
		C:        make(chan fwdTestPacketInfo, 300),
		mtu:      fwdTestNetDefaultMTU,
		linkAddr: "b",
	}
	if err := s.CreateNIC(2, ep2); err != nil {
		t.Fatal("CreateNIC #2 failed:", err)
	}
	if err := s.AddAddress(2, fwdTestNetNumber, "\x02"); err != nil {
		t.Fatal("AddAddress #2 failed:", err)
	}

	if useNeighborCache {
		// Control the neighbor cache for NIC 2.
		nic, ok := s.nics[2]
		if !ok {
			t.Fatal("failed to get the neighbor cache for NIC 2")
		}
		proto.neigh = nic.neigh
	}

	// Route all packets to NIC 2.
	{
		subnet, err := tcpip.NewSubnet("\x00", "\x00")
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 2}})
	}

	return ep1, ep2
}

func TestForwardingWithStaticResolver(t *testing.T) {
	tests := []struct {
		name             string
		useNeighborCache bool
	}{
		{
			name:             "linkAddrCache",
			useNeighborCache: false,
		},
		{
			name:             "neighborCache",
			useNeighborCache: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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

			ep1, ep2 := fwdTestNetFactory(t, proto, test.useNeighborCache)

			// Inject an inbound packet to address 3 on NIC 1, and see if it is
			// forwarded to NIC 2.
			buf := buffer.NewView(30)
			buf[dstAddrOffset] = 3
			ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
				Data: buf.ToVectorisedView(),
			}))

			var p fwdTestPacketInfo

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
		})
	}
}

func TestForwardingWithFakeResolver(t *testing.T) {
	tests := []struct {
		name             string
		useNeighborCache bool
		proto            *fwdTestNetworkProtocol
	}{
		{
			name:             "linkAddrCache",
			useNeighborCache: false,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, _ tcpip.LinkAddress) {
					// Any address will be resolved to the link address "c".
					cache.add(tcpip.FullAddress{NIC: 2, Addr: addr}, "c")
				},
			},
		},
		{
			name:             "neighborCache",
			useNeighborCache: true,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) {
					t.Helper()
					if len(remoteLinkAddr) != 0 {
						t.Fatalf("got remoteLinkAddr=%q, want unspecified", remoteLinkAddr)
					}
					// Any address will be resolved to the link address "c".
					neigh.HandleConfirmation(addr, "c", ReachabilityConfirmationFlags{
						Solicited: true,
						Override:  false,
						IsRouter:  false,
					})
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ep1, ep2 := fwdTestNetFactory(t, test.proto, test.useNeighborCache)

			// Inject an inbound packet to address 3 on NIC 1, and see if it is
			// forwarded to NIC 2.
			buf := buffer.NewView(30)
			buf[dstAddrOffset] = 3
			ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
				Data: buf.ToVectorisedView(),
			}))

			var p fwdTestPacketInfo

			select {
			case p = <-ep2.C:
			case <-time.After(time.Second):
				t.Fatal("packet not forwarded")
			}

			// Test that the address resolution happened correctly.
			if p.RemoteLinkAddress != "c" {
				t.Fatalf("got p.RemoteLinkAddress = %s, want = c", p.RemoteLinkAddress)
			}
			if p.LocalLinkAddress != "b" {
				t.Fatalf("got p.LocalLinkAddress = %s, want = b", p.LocalLinkAddress)
			}
		})
	}
}

func TestForwardingWithNoResolver(t *testing.T) {
	// Create a network protocol without a resolver.
	proto := &fwdTestNetworkProtocol{}

	// Whether or not we use the neighbor cache here does not matter since
	// neither linkAddrCache nor neighborCache will be used.
	ep1, ep2 := fwdTestNetFactory(t, proto, false /* useNeighborCache */)

	// inject an inbound packet to address 3 on NIC 1, and see if it is
	// forwarded to NIC 2.
	buf := buffer.NewView(30)
	buf[dstAddrOffset] = 3
	ep1.InjectInbound(fwdTestNetNumber, NewPacketBuffer(PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))

	select {
	case <-ep2.C:
		t.Fatal("Packet should not be forwarded")
	case <-time.After(time.Second):
	}
}

func TestForwardingWithFakeResolverPartialTimeout(t *testing.T) {
	tests := []struct {
		name             string
		useNeighborCache bool
		proto            *fwdTestNetworkProtocol
	}{
		{
			name:             "linkAddrCache",
			useNeighborCache: false,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, _ tcpip.LinkAddress) {
					// Only packets to address 3 will be resolved to the
					// link address "c".
					if addr == "\x03" {
						cache.add(tcpip.FullAddress{NIC: 2, Addr: addr}, "c")
					}
				},
			},
		},
		{
			name:             "neighborCache",
			useNeighborCache: true,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) {
					t.Helper()
					if len(remoteLinkAddr) != 0 {
						t.Fatalf("got remoteLinkAddr=%q, want unspecified", remoteLinkAddr)
					}
					// Only packets to address 3 will be resolved to the
					// link address "c".
					if addr == "\x03" {
						neigh.HandleConfirmation(addr, "c", ReachabilityConfirmationFlags{
							Solicited: true,
							Override:  false,
							IsRouter:  false,
						})
					}
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ep1, ep2 := fwdTestNetFactory(t, test.proto, test.useNeighborCache)

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

			select {
			case p = <-ep2.C:
			case <-time.After(time.Second):
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
		})
	}
}

func TestForwardingWithFakeResolverTwoPackets(t *testing.T) {
	tests := []struct {
		name             string
		useNeighborCache bool
		proto            *fwdTestNetworkProtocol
	}{
		{
			name:             "linkAddrCache",
			useNeighborCache: false,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, _ tcpip.LinkAddress) {
					// Any packets will be resolved to the link address "c".
					cache.add(tcpip.FullAddress{NIC: 2, Addr: addr}, "c")
				},
			},
		},
		{
			name:             "neighborCache",
			useNeighborCache: true,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) {
					t.Helper()
					if len(remoteLinkAddr) != 0 {
						t.Fatalf("got remoteLinkAddr=%q, want unspecified", remoteLinkAddr)
					}
					// Any packets will be resolved to the link address "c".
					neigh.HandleConfirmation(addr, "c", ReachabilityConfirmationFlags{
						Solicited: true,
						Override:  false,
						IsRouter:  false,
					})
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ep1, ep2 := fwdTestNetFactory(t, test.proto, test.useNeighborCache)

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

				select {
				case p = <-ep2.C:
				case <-time.After(time.Second):
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
		})
	}
}

func TestForwardingWithFakeResolverManyPackets(t *testing.T) {
	tests := []struct {
		name             string
		useNeighborCache bool
		proto            *fwdTestNetworkProtocol
	}{
		{
			name:             "linkAddrCache",
			useNeighborCache: false,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, _ tcpip.LinkAddress) {
					// Any packets will be resolved to the link address "c".
					cache.add(tcpip.FullAddress{NIC: 2, Addr: addr}, "c")
				},
			},
		},
		{
			name:             "neighborCache",
			useNeighborCache: true,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) {
					t.Helper()
					if len(remoteLinkAddr) != 0 {
						t.Fatalf("got remoteLinkAddr=%q, want unspecified", remoteLinkAddr)
					}
					// Any packets will be resolved to the link address "c".
					neigh.HandleConfirmation(addr, "c", ReachabilityConfirmationFlags{
						Solicited: true,
						Override:  false,
						IsRouter:  false,
					})
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ep1, ep2 := fwdTestNetFactory(t, test.proto, test.useNeighborCache)

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

				select {
				case p = <-ep2.C:
				case <-time.After(time.Second):
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
		})
	}
}

func TestForwardingWithFakeResolverManyResolutions(t *testing.T) {
	tests := []struct {
		name             string
		useNeighborCache bool
		proto            *fwdTestNetworkProtocol
	}{
		{
			name:             "linkAddrCache",
			useNeighborCache: false,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, _ tcpip.LinkAddress) {
					// Any packets will be resolved to the link address "c".
					cache.add(tcpip.FullAddress{NIC: 2, Addr: addr}, "c")
				},
			},
		},
		{
			name:             "neighborCache",
			useNeighborCache: true,
			proto: &fwdTestNetworkProtocol{
				addrResolveDelay: 500 * time.Millisecond,
				onLinkAddressResolved: func(cache *linkAddrCache, neigh *neighborCache, addr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) {
					t.Helper()
					if len(remoteLinkAddr) != 0 {
						t.Fatalf("got remoteLinkAddr=%q, want unspecified", remoteLinkAddr)
					}
					// Any packets will be resolved to the link address "c".
					neigh.HandleConfirmation(addr, "c", ReachabilityConfirmationFlags{
						Solicited: true,
						Override:  false,
						IsRouter:  false,
					})
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ep1, ep2 := fwdTestNetFactory(t, test.proto, test.useNeighborCache)

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

				select {
				case p = <-ep2.C:
				case <-time.After(time.Second):
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
		})
	}
}
