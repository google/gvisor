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

package integration_test

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	defaultMTU = 1280
	ttl        = 255
)

var (
	ipv4Addr = tcpip.AddressWithPrefix{
		Address:   tcpip.Address(net.ParseIP("192.168.1.58").To4()),
		PrefixLen: 24,
	}
	ipv4Subnet      = ipv4Addr.Subnet()
	ipv4SubnetBcast = ipv4Subnet.Broadcast()

	ipv6Addr = tcpip.AddressWithPrefix{
		Address:   tcpip.Address(net.ParseIP("200a::1").To16()),
		PrefixLen: 64,
	}
	ipv6Subnet      = ipv6Addr.Subnet()
	ipv6SubnetBcast = ipv6Subnet.Broadcast()

	// Remote addrs.
	remoteIPv4Addr = tcpip.Address(net.ParseIP("10.0.0.1").To4())
	remoteIPv6Addr = tcpip.Address(net.ParseIP("200b::1").To16())
)

// TestPingMulticastBroadcast tests that responding to an Echo Request destined
// to a multicast or broadcast address uses a unicast source address for the
// reply.
func TestPingMulticastBroadcast(t *testing.T) {
	const nicID = 1

	rxIPv4ICMP := func(e *channel.Endpoint, dst tcpip.Address) {
		totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
		hdr := buffer.NewPrependable(totalLen)
		pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
		pkt.SetType(header.ICMPv4Echo)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(^header.Checksum(pkt, 0))
		ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			IHL:         header.IPv4MinimumSize,
			TotalLength: uint16(totalLen),
			Protocol:    uint8(icmp.ProtocolNumber4),
			TTL:         ttl,
			SrcAddr:     remoteIPv4Addr,
			DstAddr:     dst,
		})

		e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	rxIPv6ICMP := func(e *channel.Endpoint, dst tcpip.Address) {
		totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
		hdr := buffer.NewPrependable(totalLen)
		pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))
		pkt.SetType(header.ICMPv6EchoRequest)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(header.ICMPv6Checksum(pkt, remoteIPv6Addr, dst, buffer.VectorisedView{}))
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength: header.ICMPv6MinimumSize,
			NextHeader:    uint8(icmp.ProtocolNumber6),
			HopLimit:      ttl,
			SrcAddr:       remoteIPv6Addr,
			DstAddr:       dst,
		})

		e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	tests := []struct {
		name    string
		dstAddr tcpip.Address
	}{
		{
			name:    "IPv4 unicast",
			dstAddr: ipv4Addr.Address,
		},
		{
			name:    "IPv4 directed broadcast",
			dstAddr: ipv4SubnetBcast,
		},
		{
			name:    "IPv4 broadcast",
			dstAddr: header.IPv4Broadcast,
		},
		{
			name:    "IPv4 all-systems multicast",
			dstAddr: header.IPv4AllSystems,
		},
		{
			name:    "IPv6 unicast",
			dstAddr: ipv6Addr.Address,
		},
		{
			name:    "IPv6 all-nodes multicast",
			dstAddr: header.IPv6AllNodesMulticastAddress,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ipv4Proto := ipv4.NewProtocol()
			ipv6Proto := ipv6.NewProtocol()
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{ipv4Proto, ipv6Proto},
				TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol4(), icmp.NewProtocol6()},
			})
			// We only expect a single packet in response to our ICMP Echo Request.
			e := channel.New(1, defaultMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			ipv4ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: ipv4Addr}
			if err := s.AddProtocolAddress(nicID, ipv4ProtoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v): %s", nicID, ipv4ProtoAddr, err)
			}
			ipv6ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: ipv6Addr}
			if err := s.AddProtocolAddress(nicID, ipv6ProtoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v): %s", nicID, ipv6ProtoAddr, err)
			}

			// Default routes for IPv4 and IPv6 so ICMP can find a route to the remote
			// node when attempting to send the ICMP Echo Reply.
			s.SetRouteTable([]tcpip.Route{
				tcpip.Route{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
				tcpip.Route{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
			})

			var rxICMP func(*channel.Endpoint, tcpip.Address)
			var expectedSrc tcpip.Address
			var expectedDst tcpip.Address
			var proto stack.NetworkProtocol
			switch l := len(test.dstAddr); l {
			case header.IPv4AddressSize:
				rxICMP = rxIPv4ICMP
				expectedSrc = ipv4Addr.Address
				expectedDst = remoteIPv4Addr
				proto = ipv4Proto
			case header.IPv6AddressSize:
				rxICMP = rxIPv6ICMP
				expectedSrc = ipv6Addr.Address
				expectedDst = remoteIPv6Addr
				proto = ipv6Proto
			default:
				t.Fatalf("got unexpected address length = %d bytes", l)
			}

			rxICMP(e, test.dstAddr)
			pkt, ok := e.Read()
			if !ok {
				t.Fatal("expected ICMP response")
			}

			if pkt.Route.LocalAddress != expectedSrc {
				t.Errorf("got pkt.Route.LocalAddress = %s, want = %s", pkt.Route.LocalAddress, expectedSrc)
			}
			if pkt.Route.RemoteAddress != expectedDst {
				t.Errorf("got pkt.Route.RemoteAddress = %s, want = %s", pkt.Route.RemoteAddress, expectedDst)
			}

			src, dst := proto.ParseAddresses(pkt.Pkt.NetworkHeader().View())
			if src != expectedSrc {
				t.Errorf("got pkt source = %s, want = %s", src, expectedSrc)
			}
			if dst != expectedDst {
				t.Errorf("got pkt destination = %s, want = %s", dst, expectedDst)
			}
		})
	}

}

// TestIncomingMulticastAndBroadcast tests receiving a packet destined to some
// multicast or broadcast address.
func TestIncomingMulticastAndBroadcast(t *testing.T) {
	const (
		nicID      = 1
		remotePort = 5555
		localPort  = 80
	)

	data := []byte{1, 2, 3, 4}

	rxIPv4UDP := func(e *channel.Endpoint, dst tcpip.Address) {
		payloadLen := header.UDPMinimumSize + len(data)
		totalLen := header.IPv4MinimumSize + payloadLen
		hdr := buffer.NewPrependable(totalLen)
		u := header.UDP(hdr.Prepend(payloadLen))
		u.Encode(&header.UDPFields{
			SrcPort: remotePort,
			DstPort: localPort,
			Length:  uint16(payloadLen),
		})
		copy(u.Payload(), data)
		sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, remoteIPv4Addr, dst, uint16(payloadLen))
		sum = header.Checksum(data, sum)
		u.SetChecksum(^u.CalculateChecksum(sum))

		ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			IHL:         header.IPv4MinimumSize,
			TotalLength: uint16(totalLen),
			Protocol:    uint8(udp.ProtocolNumber),
			TTL:         ttl,
			SrcAddr:     remoteIPv4Addr,
			DstAddr:     dst,
		})

		e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	rxIPv6UDP := func(e *channel.Endpoint, dst tcpip.Address) {
		payloadLen := header.UDPMinimumSize + len(data)
		hdr := buffer.NewPrependable(header.IPv6MinimumSize + payloadLen)
		u := header.UDP(hdr.Prepend(payloadLen))
		u.Encode(&header.UDPFields{
			SrcPort: remotePort,
			DstPort: localPort,
			Length:  uint16(payloadLen),
		})
		copy(u.Payload(), data)
		sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, remoteIPv6Addr, dst, uint16(payloadLen))
		sum = header.Checksum(data, sum)
		u.SetChecksum(^u.CalculateChecksum(sum))

		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength: uint16(payloadLen),
			NextHeader:    uint8(udp.ProtocolNumber),
			HopLimit:      ttl,
			SrcAddr:       remoteIPv6Addr,
			DstAddr:       dst,
		})

		e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	tests := []struct {
		name     string
		bindAddr tcpip.Address
		dstAddr  tcpip.Address
		expectRx bool
	}{
		{
			name:     "IPv4 unicast binding to unicast",
			bindAddr: ipv4Addr.Address,
			dstAddr:  ipv4Addr.Address,
			expectRx: true,
		},
		{
			name:     "IPv4 unicast binding to broadcast",
			bindAddr: header.IPv4Broadcast,
			dstAddr:  ipv4Addr.Address,
			expectRx: false,
		},
		{
			name:     "IPv4 unicast binding to wildcard",
			dstAddr:  ipv4Addr.Address,
			expectRx: true,
		},

		{
			name:     "IPv4 directed broadcast binding to subnet broadcast",
			bindAddr: ipv4SubnetBcast,
			dstAddr:  ipv4SubnetBcast,
			expectRx: true,
		},
		{
			name:     "IPv4 directed broadcast binding to broadcast",
			bindAddr: header.IPv4Broadcast,
			dstAddr:  ipv4SubnetBcast,
			expectRx: false,
		},
		{
			name:     "IPv4 directed broadcast binding to wildcard",
			dstAddr:  ipv4SubnetBcast,
			expectRx: true,
		},

		{
			name:     "IPv4 broadcast binding to broadcast",
			bindAddr: header.IPv4Broadcast,
			dstAddr:  header.IPv4Broadcast,
			expectRx: true,
		},
		{
			name:     "IPv4 broadcast binding to subnet broadcast",
			bindAddr: ipv4SubnetBcast,
			dstAddr:  header.IPv4Broadcast,
			expectRx: false,
		},
		{
			name:     "IPv4 broadcast binding to wildcard",
			dstAddr:  ipv4SubnetBcast,
			expectRx: true,
		},

		{
			name:     "IPv4 all-systems multicast binding to all-systems multicast",
			bindAddr: header.IPv4AllSystems,
			dstAddr:  header.IPv4AllSystems,
			expectRx: true,
		},
		{
			name:     "IPv4 all-systems multicast binding to wildcard",
			dstAddr:  header.IPv4AllSystems,
			expectRx: true,
		},
		{
			name:     "IPv4 all-systems multicast binding to unicast",
			bindAddr: ipv4Addr.Address,
			dstAddr:  header.IPv4AllSystems,
			expectRx: false,
		},

		// IPv6 has no notion of a broadcast.
		{
			name:     "IPv6 unicast binding to wildcard",
			dstAddr:  ipv6Addr.Address,
			expectRx: true,
		},
		{
			name:     "IPv6 broadcast-like address binding to wildcard",
			dstAddr:  ipv6SubnetBcast,
			expectRx: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
			})
			e := channel.New(0, defaultMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			ipv4ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: ipv4Addr}
			if err := s.AddProtocolAddress(nicID, ipv4ProtoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v): %s", nicID, ipv4ProtoAddr, err)
			}
			ipv6ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: ipv6Addr}
			if err := s.AddProtocolAddress(nicID, ipv6ProtoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v): %s", nicID, ipv6ProtoAddr, err)
			}

			var netproto tcpip.NetworkProtocolNumber
			var rxUDP func(*channel.Endpoint, tcpip.Address)
			switch l := len(test.dstAddr); l {
			case header.IPv4AddressSize:
				netproto = header.IPv4ProtocolNumber
				rxUDP = rxIPv4UDP
			case header.IPv6AddressSize:
				netproto = header.IPv6ProtocolNumber
				rxUDP = rxIPv6UDP
			default:
				t.Fatalf("got unexpected address length = %d bytes", l)
			}

			wq := waiter.Queue{}
			ep, err := s.NewEndpoint(udp.ProtocolNumber, netproto, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, netproto, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: test.bindAddr, Port: localPort}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("ep.Bind(%+v): %s", bindAddr, err)
			}

			rxUDP(e, test.dstAddr)
			if gotPayload, _, err := ep.Read(nil); test.expectRx {
				if err != nil {
					t.Fatalf("Read(nil): %s", err)
				}
				if diff := cmp.Diff(buffer.View(data), gotPayload); diff != "" {
					t.Errorf("got UDP payload mismatch (-want +got):\n%s", diff)
				}
			} else {
				if err != tcpip.ErrWouldBlock {
					t.Fatalf("got Read(nil) = (%x, _, %s), want = (_, _, %s)", gotPayload, err, tcpip.ErrWouldBlock)
				}
			}
		})
	}
}
