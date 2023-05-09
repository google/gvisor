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

// Package utils holds common testing utilities for tcpip.
package utils

import (
	"testing"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

// Common NIC IDs used by tests.
const (
	Host1NICID   = 1
	RouterNICID1 = 2
	RouterNICID2 = 3
	Host2NICID   = 4
)

// Common NIC names used by tests.
const (
	Host1NICName   = "host1NIC"
	RouterNIC1Name = "routerNIC1"
	RouterNIC2Name = "routerNIC2"
	Host2NICName   = "host2NIC"
)

// Common link addresses used by tests.
const (
	LinkAddr1 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
	LinkAddr2 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x07")
	LinkAddr3 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x08")
	LinkAddr4 = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")
)

// Common IP addresses used by tests.
var (
	Ipv4Addr = tcpip.AddressWithPrefix{
		Address:   testutil.MustParse4("192.168.1.58"),
		PrefixLen: 24,
	}
	Ipv4Subnet      = Ipv4Addr.Subnet()
	Ipv4SubnetBcast = Ipv4Subnet.Broadcast()

	Ipv6Addr = tcpip.AddressWithPrefix{
		Address:   testutil.MustParse6("200a::1"),
		PrefixLen: 64,
	}
	Ipv6Subnet      = Ipv6Addr.Subnet()
	Ipv6SubnetBcast = Ipv6Subnet.Broadcast()

	Ipv4Addr1 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse4("192.168.0.1"),
			PrefixLen: 24,
		},
	}
	Ipv4Addr2 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse4("192.168.0.2"),
			PrefixLen: 8,
		},
	}
	Ipv4Addr3 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse4("192.168.0.3"),
			PrefixLen: 8,
		},
	}
	Ipv6Addr1 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse6("a::1"),
			PrefixLen: 64,
		},
	}
	Ipv6Addr2 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse6("a::2"),
			PrefixLen: 64,
		},
	}
	Ipv6Addr3 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse6("a::3"),
			PrefixLen: 64,
		},
	}

	// Remote addrs.
	RemoteIPv4Addr = testutil.MustParse4("10.0.0.1")
	RemoteIPv6Addr = testutil.MustParse6("200b::1")
)

// Common ports for testing.
const (
	RemotePort = 5555
	LocalPort  = 80
)

// Common IP addresses used for testing.
var (
	Host1IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse4("192.168.0.2"),
			PrefixLen: 24,
		},
	}
	RouterNIC1IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse4("192.168.0.1"),
			PrefixLen: 24,
		},
	}
	RouterNIC2IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse4("10.0.0.3"),
			PrefixLen: 8,
		},
	}
	Host2IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse4("10.0.0.2"),
			PrefixLen: 8,
		},
	}
	Host1IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse6("a::2"),
			PrefixLen: 64,
		},
	}
	RouterNIC1IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse6("a::1"),
			PrefixLen: 64,
		},
	}
	RouterNIC2IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse6("b::1"),
			PrefixLen: 64,
		},
	}
	Host2IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   testutil.MustParse6("b::2"),
			PrefixLen: 64,
		},
	}
)

// NewEthernetEndpoint returns an ethernet link endpoint that wraps an inner
// link endpoint and checks the destination link address before delivering
// network packets to the network dispatcher.
//
// See ethernet.Endpoint for more details.
func NewEthernetEndpoint(ep stack.LinkEndpoint) *EndpointWithDestinationCheck {
	var e EndpointWithDestinationCheck
	e.Endpoint.Init(ethernet.New(ep), &e)
	return &e
}

// EndpointWithDestinationCheck is a link endpoint that checks the destination
// link address before delivering network packets to the network dispatcher.
type EndpointWithDestinationCheck struct {
	nested.Endpoint
}

var _ stack.NetworkDispatcher = (*EndpointWithDestinationCheck)(nil)
var _ stack.LinkEndpoint = (*EndpointWithDestinationCheck)(nil)

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (e *EndpointWithDestinationCheck) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
	if dst := header.Ethernet(pkt.LinkHeader().Slice()).DestinationAddress(); dst == e.Endpoint.LinkAddress() || dst == header.EthernetBroadcastAddress || header.IsMulticastEthernetAddress(dst) {
		e.Endpoint.DeliverNetworkPacket(proto, pkt)
	}
}

// SetupRouterStack creates the NICs, sets forwarding, adds addresses and sets
// the route table for a stack that should operate as a router.
func SetupRouterStack(t *testing.T, s *stack.Stack, ep1, ep2 stack.LinkEndpoint) {

	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d): %s", ipv4.ProtocolNumber, err)
	}
	if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d): %s", ipv6.ProtocolNumber, err)
	}

	for _, setup := range []struct {
		nicID   tcpip.NICID
		nicName string
		ep      stack.LinkEndpoint

		addresses [2]tcpip.ProtocolAddress
	}{
		{
			nicID:     RouterNICID1,
			nicName:   RouterNIC1Name,
			ep:        ep1,
			addresses: [2]tcpip.ProtocolAddress{RouterNIC1IPv4Addr, RouterNIC1IPv6Addr},
		},
		{
			nicID:     RouterNICID2,
			nicName:   RouterNIC2Name,
			ep:        ep2,
			addresses: [2]tcpip.ProtocolAddress{RouterNIC2IPv4Addr, RouterNIC2IPv6Addr},
		},
	} {
		opts := stack.NICOptions{Name: setup.nicName}
		if err := s.CreateNICWithOptions(setup.nicID, setup.ep, opts); err != nil {
			t.Fatalf("s.CreateNICWithOptions(%d, _, %#v): %s", setup.nicID, opts, err)
		}

		for _, addr := range setup.addresses {
			if err := s.AddProtocolAddress(setup.nicID, addr, stack.AddressProperties{}); err != nil {
				t.Fatalf("s.AddProtocolAddress(%d, %#v, {}): %s", setup.nicID, addr, err)
			}
		}
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: RouterNIC1IPv4Addr.AddressWithPrefix.Subnet(),
			NIC:         RouterNICID1,
		},
		{
			Destination: RouterNIC1IPv6Addr.AddressWithPrefix.Subnet(),
			NIC:         RouterNICID1,
		},
		{
			Destination: RouterNIC2IPv4Addr.AddressWithPrefix.Subnet(),
			NIC:         RouterNICID2,
		},
		{
			Destination: RouterNIC2IPv6Addr.AddressWithPrefix.Subnet(),
			NIC:         RouterNICID2,
		},
	})
}

// SetupRoutedStacks creates the NICs, sets forwarding, adds addresses and sets
// the route tables for the passed stacks.
func SetupRoutedStacks(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack) {
	const maxFrameSize = header.IPv6MinimumMTU + header.EthernetMinimumSize
	host1NIC, routerNIC1 := pipe.New(LinkAddr1, LinkAddr2, maxFrameSize)
	routerNIC2, host2NIC := pipe.New(LinkAddr3, LinkAddr4, maxFrameSize)

	SetupRouterStack(t, routerStack, NewEthernetEndpoint(routerNIC1), NewEthernetEndpoint(routerNIC2))

	{
		opts := stack.NICOptions{Name: Host1NICName}
		if err := host1Stack.CreateNICWithOptions(Host1NICID, NewEthernetEndpoint(host1NIC), opts); err != nil {
			t.Fatalf("host1Stack.CreateNICWithOptions(%d, _, %#v): %s", Host1NICID, opts, err)
		}
	}
	{
		opts := stack.NICOptions{Name: Host2NICName}
		if err := host2Stack.CreateNICWithOptions(Host2NICID, NewEthernetEndpoint(host2NIC), opts); err != nil {
			t.Fatalf("host2Stack.CreateNICWithOptions(%d, _, %#v): %s", Host2NICID, opts, err)
		}
	}

	if err := host1Stack.AddProtocolAddress(Host1NICID, Host1IPv4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %+v, {}): %s", Host1NICID, Host1IPv4Addr, err)
	}
	if err := host2Stack.AddProtocolAddress(Host2NICID, Host2IPv4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %+v, {}): %s", Host2NICID, Host2IPv4Addr, err)
	}
	if err := host1Stack.AddProtocolAddress(Host1NICID, Host1IPv6Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %+v, {}): %s", Host1NICID, Host1IPv6Addr, err)
	}
	if err := host2Stack.AddProtocolAddress(Host2NICID, Host2IPv6Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %+v, {}): %s", Host2NICID, Host2IPv6Addr, err)
	}

	host1Stack.SetRouteTable([]tcpip.Route{
		{
			Destination: Host1IPv4Addr.AddressWithPrefix.Subnet(),
			NIC:         Host1NICID,
		},
		{
			Destination: Host1IPv6Addr.AddressWithPrefix.Subnet(),
			NIC:         Host1NICID,
		},
		{
			Destination: Host2IPv4Addr.AddressWithPrefix.Subnet(),
			Gateway:     RouterNIC1IPv4Addr.AddressWithPrefix.Address,
			NIC:         Host1NICID,
		},
		{
			Destination: Host2IPv6Addr.AddressWithPrefix.Subnet(),
			Gateway:     RouterNIC1IPv6Addr.AddressWithPrefix.Address,
			NIC:         Host1NICID,
		},
	})
	host2Stack.SetRouteTable([]tcpip.Route{
		{
			Destination: Host2IPv4Addr.AddressWithPrefix.Subnet(),
			NIC:         Host2NICID,
		},
		{
			Destination: Host2IPv6Addr.AddressWithPrefix.Subnet(),
			NIC:         Host2NICID,
		},
		{
			Destination: Host1IPv4Addr.AddressWithPrefix.Subnet(),
			Gateway:     RouterNIC2IPv4Addr.AddressWithPrefix.Address,
			NIC:         Host2NICID,
		},
		{
			Destination: Host1IPv6Addr.AddressWithPrefix.Subnet(),
			Gateway:     RouterNIC2IPv6Addr.AddressWithPrefix.Address,
			NIC:         Host2NICID,
		},
	})
}

// ICMPv4Echo returns an ICMPv4 echo packet.
func ICMPv4Echo(src, dst tcpip.Address, ttl uint8, ty header.ICMPv4Type) []byte {
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
	hdr := prependable.New(totalLen)
	pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
	pkt.SetType(ty)
	pkt.SetCode(header.ICMPv4UnusedCode)
	pkt.SetChecksum(0)
	pkt.SetChecksum(^checksum.Checksum(pkt, 0))
	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		Protocol:    uint8(icmp.ProtocolNumber4),
		TTL:         ttl,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return hdr.View()
}

// RxICMPv4EchoRequest constructs and injects an ICMPv4 echo request packet on
// the provided endpoint.
func RxICMPv4EchoRequest(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8) {
	newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(ICMPv4Echo(src, dst, ttl, header.ICMPv4Echo)),
	})
	defer newPkt.DecRef()
	e.InjectInbound(header.IPv4ProtocolNumber, newPkt)
}

// RxICMPv4EchoReply constructs and injects an ICMPv4 echo reply packet on
// the provided endpoint.
func RxICMPv4EchoReply(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8) {
	newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(ICMPv4Echo(src, dst, ttl, header.ICMPv4EchoReply)),
	})
	defer newPkt.DecRef()
	e.InjectInbound(header.IPv4ProtocolNumber, newPkt)
}

// ICMPv6Echo returns an ICMPv6 echo packet.
func ICMPv6Echo(src, dst tcpip.Address, ttl uint8, ty header.ICMPv6Type) []byte {
	totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
	hdr := prependable.New(totalLen)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))
	pkt.SetType(ty)
	pkt.SetCode(header.ICMPv6UnusedCode)
	pkt.SetChecksum(0)
	pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: pkt,
		Src:    src,
		Dst:    dst,
	}))
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6MinimumSize,
		TransportProtocol: icmp.ProtocolNumber6,
		HopLimit:          ttl,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	return hdr.View()
}

// RxICMPv6EchoRequest constructs and injects an ICMPv6 echo request packet on
// the provided endpoint.
func RxICMPv6EchoRequest(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8) {
	newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(ICMPv6Echo(src, dst, ttl, header.ICMPv6EchoRequest)),
	})
	defer newPkt.DecRef()
	e.InjectInbound(header.IPv6ProtocolNumber, newPkt)
}

// RxICMPv6EchoReply constructs and injects an ICMPv6 echo reply packet on
// the provided endpoint.
func RxICMPv6EchoReply(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8) {
	newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(ICMPv6Echo(src, dst, ttl, header.ICMPv6EchoReply)),
	})
	defer newPkt.DecRef()
	e.InjectInbound(header.IPv6ProtocolNumber, newPkt)
}
