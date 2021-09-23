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
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
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
		Address:   tcpip.Address(net.ParseIP("192.168.1.58").To4()),
		PrefixLen: 24,
	}
	Ipv4Subnet      = Ipv4Addr.Subnet()
	Ipv4SubnetBcast = Ipv4Subnet.Broadcast()

	Ipv6Addr = tcpip.AddressWithPrefix{
		Address:   tcpip.Address(net.ParseIP("200a::1").To16()),
		PrefixLen: 64,
	}
	Ipv6Subnet      = Ipv6Addr.Subnet()
	Ipv6SubnetBcast = Ipv6Subnet.Broadcast()

	Ipv4Addr1 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.1").To4()),
			PrefixLen: 24,
		},
	}
	Ipv4Addr2 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.2").To4()),
			PrefixLen: 8,
		},
	}
	Ipv4Addr3 = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.3").To4()),
			PrefixLen: 8,
		},
	}
	Ipv6Addr1 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::1").To16()),
			PrefixLen: 64,
		},
	}
	Ipv6Addr2 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::2").To16()),
			PrefixLen: 64,
		},
	}
	Ipv6Addr3 = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::3").To16()),
			PrefixLen: 64,
		},
	}

	// Remote addrs.
	RemoteIPv4Addr = tcpip.Address(net.ParseIP("10.0.0.1").To4())
	RemoteIPv6Addr = tcpip.Address(net.ParseIP("200b::1").To16())
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
			Address:   tcpip.Address(net.ParseIP("192.168.0.2").To4()),
			PrefixLen: 24,
		},
	}
	RouterNIC1IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.0.1").To4()),
			PrefixLen: 24,
		},
	}
	RouterNIC2IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("10.0.0.1").To4()),
			PrefixLen: 8,
		},
	}
	Host2IPv4Addr = tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("10.0.0.2").To4()),
			PrefixLen: 8,
		},
	}
	Host1IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::2").To16()),
			PrefixLen: 64,
		},
	}
	RouterNIC1IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("a::1").To16()),
			PrefixLen: 64,
		},
	}
	RouterNIC2IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("b::1").To16()),
			PrefixLen: 64,
		},
	}
	Host2IPv6Addr = tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("b::2").To16()),
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
func (e *EndpointWithDestinationCheck) DeliverNetworkPacket(src, dst tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if dst == e.Endpoint.LinkAddress() || dst == header.EthernetBroadcastAddress || header.IsMulticastEthernetAddress(dst) {
		e.Endpoint.DeliverNetworkPacket(src, dst, proto, pkt)
	}
}

// SetupRoutedStacks creates the NICs, sets forwarding, adds addresses and sets
// the route tables for the passed stacks.
func SetupRoutedStacks(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack) {
	host1NIC, routerNIC1 := pipe.New(LinkAddr1, LinkAddr2)
	routerNIC2, host2NIC := pipe.New(LinkAddr3, LinkAddr4)

	{
		opts := stack.NICOptions{Name: Host1NICName}
		if err := host1Stack.CreateNICWithOptions(Host1NICID, NewEthernetEndpoint(host1NIC), opts); err != nil {
			t.Fatalf("host1Stack.CreateNICWithOptions(%d, _, %#v): %s", Host1NICID, opts, err)
		}
	}
	{
		opts := stack.NICOptions{Name: RouterNIC1Name}
		if err := routerStack.CreateNICWithOptions(RouterNICID1, NewEthernetEndpoint(routerNIC1), opts); err != nil {
			t.Fatalf("routerStack.CreateNICWithOptions(%d, _, %#v): %s", RouterNICID1, opts, err)
		}
	}
	{
		opts := stack.NICOptions{Name: RouterNIC2Name}
		if err := routerStack.CreateNICWithOptions(RouterNICID2, NewEthernetEndpoint(routerNIC2), opts); err != nil {
			t.Fatalf("routerStack.CreateNICWithOptions(%d, _, %#v): %s", RouterNICID2, opts, err)
		}
	}
	{
		opts := stack.NICOptions{Name: Host2NICName}
		if err := host2Stack.CreateNICWithOptions(Host2NICID, NewEthernetEndpoint(host2NIC), opts); err != nil {
			t.Fatalf("host2Stack.CreateNICWithOptions(%d, _, %#v): %s", Host2NICID, opts, err)
		}
	}

	if err := routerStack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("routerStack.SetForwardingDefaultAndAllNICs(%d): %s", ipv4.ProtocolNumber, err)
	}
	if err := routerStack.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		t.Fatalf("routerStack.SetForwardingDefaultAndAllNICs(%d): %s", ipv6.ProtocolNumber, err)
	}

	if err := host1Stack.AddProtocolAddress(Host1NICID, Host1IPv4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %+v, {}): %s", Host1NICID, Host1IPv4Addr, err)
	}
	if err := routerStack.AddProtocolAddress(RouterNICID1, RouterNIC1IPv4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("routerStack.AddProtocolAddress(%d, %+v, {}): %s", RouterNICID1, RouterNIC1IPv4Addr, err)
	}
	if err := routerStack.AddProtocolAddress(RouterNICID2, RouterNIC2IPv4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("routerStack.AddProtocolAddress(%d, %+v, {}): %s", RouterNICID2, RouterNIC2IPv4Addr, err)
	}
	if err := host2Stack.AddProtocolAddress(Host2NICID, Host2IPv4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("host2Stack.AddProtocolAddress(%d, %+v, {}): %s", Host2NICID, Host2IPv4Addr, err)
	}
	if err := host1Stack.AddProtocolAddress(Host1NICID, Host1IPv6Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("host1Stack.AddProtocolAddress(%d, %+v, {}): %s", Host1NICID, Host1IPv6Addr, err)
	}
	if err := routerStack.AddProtocolAddress(RouterNICID1, RouterNIC1IPv6Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("routerStack.AddProtocolAddress(%d, %+v, {}): %s", RouterNICID1, RouterNIC1IPv6Addr, err)
	}
	if err := routerStack.AddProtocolAddress(RouterNICID2, RouterNIC2IPv6Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("routerStack.AddProtocolAddress(%d, %+v, {}): %s", RouterNICID2, RouterNIC2IPv6Addr, err)
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
	routerStack.SetRouteTable([]tcpip.Route{
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

func rxICMPv4Echo(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8, ty header.ICMPv4Type) {
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
	hdr := buffer.NewPrependable(totalLen)
	pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
	pkt.SetType(ty)
	pkt.SetCode(header.ICMPv4UnusedCode)
	pkt.SetChecksum(0)
	pkt.SetChecksum(^header.Checksum(pkt, 0))
	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		Protocol:    uint8(icmp.ProtocolNumber4),
		TTL:         ttl,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: hdr.View().ToVectorisedView(),
	}))
}

// RxICMPv4EchoRequest constructs and injects an ICMPv4 echo request packet on
// the provided endpoint.
func RxICMPv4EchoRequest(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8) {
	rxICMPv4Echo(e, src, dst, ttl, header.ICMPv4Echo)
}

// RxICMPv4EchoReply constructs and injects an ICMPv4 echo reply packet on
// the provided endpoint.
func RxICMPv4EchoReply(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8) {
	rxICMPv4Echo(e, src, dst, ttl, header.ICMPv4EchoReply)
}

func rxICMPv6Echo(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8, ty header.ICMPv6Type) {
	totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
	hdr := buffer.NewPrependable(totalLen)
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

	e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: hdr.View().ToVectorisedView(),
	}))
}

// RxICMPv6EchoRequest constructs and injects an ICMPv6 echo request packet on
// the provided endpoint.
func RxICMPv6EchoRequest(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8) {
	rxICMPv6Echo(e, src, dst, ttl, header.ICMPv6EchoRequest)
}

// RxICMPv6EchoReply constructs and injects an ICMPv6 echo reply packet on
// the provided endpoint.
func RxICMPv6EchoReply(e *channel.Endpoint, src, dst tcpip.Address, ttl uint8) {
	rxICMPv6Echo(e, src, dst, ttl, header.ICMPv6EchoReply)
}
