// Copyright 2019 The gVisor Authors.
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

package ipv6

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

// setupStackAndEndpoint creates a stack with a single NIC with a link-local
// address llladdr and an IPv6 endpoint to a remote with link-local address
// rlladdr
func setupStackAndEndpoint(t *testing.T, llladdr, rlladdr tcpip.Address) (*stack.Stack, stack.NetworkEndpoint) {
	t.Helper()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol6()},
	})

	if err := s.CreateNIC(1, &stubLinkEndpoint{}); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}
	if err := s.AddAddress(1, ProtocolNumber, llladdr); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", ProtocolNumber, llladdr, err)
	}

	{
		subnet, err := tcpip.NewSubnet(rlladdr, tcpip.AddressMask(strings.Repeat("\xff", len(rlladdr))))
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable(
			[]tcpip.Route{{
				Destination: subnet,
				NIC:         1,
			}},
		)
	}

	netProto := s.NetworkProtocolInstance(ProtocolNumber)
	if netProto == nil {
		t.Fatalf("cannot find protocol instance for network protocol %d", ProtocolNumber)
	}

	ep, err := netProto.NewEndpoint(0, tcpip.AddressWithPrefix{rlladdr, netProto.DefaultPrefixLen()}, &stubLinkAddressCache{}, &stubDispatcher{}, nil)
	if err != nil {
		t.Fatalf("NewEndpoint(_) = _, %s, want = _, nil", err)
	}

	return s, ep
}

// TestHopLimitValidation is a test that makes sure that NDP packets are only
// received if their IP header's hop limit is set to 255.
func TestHopLimitValidation(t *testing.T) {
	setup := func(t *testing.T) (*stack.Stack, stack.NetworkEndpoint, stack.Route) {
		t.Helper()

		// Create a stack with the assigned link-local address lladdr0
		// and an endpoint to lladdr1.
		s, ep := setupStackAndEndpoint(t, lladdr0, lladdr1)

		r, err := s.FindRoute(1, lladdr0, lladdr1, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			t.Fatalf("FindRoute(_) = _, %s, want = _, nil", err)
		}

		return s, ep, r
	}

	handleIPv6Payload := func(hdr buffer.Prependable, hopLimit uint8, ep stack.NetworkEndpoint, r *stack.Route) {
		payloadLength := hdr.UsedLength()
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength: uint16(payloadLength),
			NextHeader:    uint8(header.ICMPv6ProtocolNumber),
			HopLimit:      hopLimit,
			SrcAddr:       r.LocalAddress,
			DstAddr:       r.RemoteAddress,
		})
		ep.HandlePacket(r, tcpip.PacketBuffer{
			Data: hdr.View().ToVectorisedView(),
		})
	}

	types := []struct {
		name        string
		typ         header.ICMPv6Type
		size        int
		statCounter func(tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
	}{
		{"RouterSolicit", header.ICMPv6RouterSolicit, header.ICMPv6MinimumSize, func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
			return stats.RouterSolicit
		}},
		{"RouterAdvert", header.ICMPv6RouterAdvert, header.ICMPv6HeaderSize + header.NDPRAMinimumSize, func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
			return stats.RouterAdvert
		}},
		{"NeighborSolicit", header.ICMPv6NeighborSolicit, header.ICMPv6NeighborSolicitMinimumSize, func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
			return stats.NeighborSolicit
		}},
		{"NeighborAdvert", header.ICMPv6NeighborAdvert, header.ICMPv6NeighborAdvertSize, func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
			return stats.NeighborAdvert
		}},
		{"RedirectMsg", header.ICMPv6RedirectMsg, header.ICMPv6MinimumSize, func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
			return stats.RedirectMsg
		}},
	}

	for _, typ := range types {
		t.Run(typ.name, func(t *testing.T) {
			s, ep, r := setup(t)
			defer r.Release()

			stats := s.Stats().ICMP.V6PacketsReceived
			invalid := stats.Invalid
			typStat := typ.statCounter(stats)

			hdr := buffer.NewPrependable(header.IPv6MinimumSize + typ.size)
			pkt := header.ICMPv6(hdr.Prepend(typ.size))
			pkt.SetType(typ.typ)
			pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

			// Invalid count should initially be 0.
			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}

			// Should not have received any ICMPv6 packets with
			// type = typ.typ.
			if got := typStat.Value(); got != 0 {
				t.Fatalf("got %s = %d, want = 0", typ.name, got)
			}

			// Receive the NDP packet with an invalid hop limit
			// value.
			handleIPv6Payload(hdr, header.NDPHopLimit-1, ep, &r)

			// Invalid count should have increased.
			if got := invalid.Value(); got != 1 {
				t.Fatalf("got invalid = %d, want = 1", got)
			}

			// Rx count of NDP packet of type typ.typ should not
			// have increased.
			if got := typStat.Value(); got != 0 {
				t.Fatalf("got %s = %d, want = 0", typ.name, got)
			}

			// Receive the NDP packet with a valid hop limit value.
			handleIPv6Payload(hdr, header.NDPHopLimit, ep, &r)

			// Rx count of NDP packet of type typ.typ should have
			// increased.
			if got := typStat.Value(); got != 1 {
				t.Fatalf("got %s = %d, want = 1", typ.name, got)
			}

			// Invalid count should not have increased again.
			if got := invalid.Value(); got != 1 {
				t.Fatalf("got invalid = %d, want = 1", got)
			}
		})
	}
}

// TestRouterAdvertValidation tests that when the NIC is configured to handle
// NDP Router Advertisement packets, it validates the Router Advertisement
// properly before handling them.
func TestRouterAdvertValidation(t *testing.T) {
	tests := []struct {
		name            string
		src             tcpip.Address
		hopLimit        uint8
		code            uint8
		ndpPayload      []byte
		expectedSuccess bool
	}{
		{
			"OK",
			lladdr0,
			255,
			0,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			true,
		},
		{
			"NonLinkLocalSourceAddr",
			addr1,
			255,
			0,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			false,
		},
		{
			"HopLimitNot255",
			lladdr0,
			254,
			0,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			false,
		},
		{
			"NonZeroCode",
			lladdr0,
			255,
			1,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
			false,
		},
		{
			"NDPPayloadTooSmall",
			lladdr0,
			255,
			0,
			[]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0,
			},
			false,
		},
		{
			"OKWithOptions",
			lladdr0,
			255,
			0,
			[]byte{
				// RA payload
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,

				// Option #1 (TargetLinkLayerAddress)
				2, 1, 0, 0, 0, 0, 0, 0,

				// Option #2 (unrecognized)
				255, 1, 0, 0, 0, 0, 0, 0,

				// Option #3 (PrefixInformation)
				3, 4, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			true,
		},
		{
			"OptionWithZeroLength",
			lladdr0,
			255,
			0,
			[]byte{
				// RA payload
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,

				// Option #1 (TargetLinkLayerAddress)
				// Invalid as it has 0 length.
				2, 0, 0, 0, 0, 0, 0, 0,

				// Option #2 (unrecognized)
				255, 1, 0, 0, 0, 0, 0, 0,

				// Option #3 (PrefixInformation)
				3, 4, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := channel.New(10, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{NewProtocol()},
			})

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			icmpSize := header.ICMPv6HeaderSize + len(test.ndpPayload)
			hdr := buffer.NewPrependable(header.IPv6MinimumSize + icmpSize)
			pkt := header.ICMPv6(hdr.Prepend(icmpSize))
			pkt.SetType(header.ICMPv6RouterAdvert)
			pkt.SetCode(test.code)
			copy(pkt.NDPPayload(), test.ndpPayload)
			payloadLength := hdr.UsedLength()
			pkt.SetChecksum(header.ICMPv6Checksum(pkt, test.src, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength: uint16(payloadLength),
				NextHeader:    uint8(icmp.ProtocolNumber6),
				HopLimit:      test.hopLimit,
				SrcAddr:       test.src,
				DstAddr:       header.IPv6AllNodesMulticastAddress,
			})

			stats := s.Stats().ICMP.V6PacketsReceived
			invalid := stats.Invalid
			rxRA := stats.RouterAdvert

			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}
			if got := rxRA.Value(); got != 0 {
				t.Fatalf("got rxRA = %d, want = 0", got)
			}

			e.InjectInbound(header.IPv6ProtocolNumber, tcpip.PacketBuffer{
				Data: hdr.View().ToVectorisedView(),
			})

			if test.expectedSuccess {
				if got := invalid.Value(); got != 0 {
					t.Fatalf("got invalid = %d, want = 0", got)
				}
				if got := rxRA.Value(); got != 1 {
					t.Fatalf("got rxRA = %d, want = 1", got)
				}

			} else {
				if got := invalid.Value(); got != 1 {
					t.Fatalf("got invalid = %d, want = 1", got)
				}
				if got := rxRA.Value(); got != 0 {
					t.Fatalf("got rxRA = %d, want = 0", got)
				}
			}
		})
	}
}
