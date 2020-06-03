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
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	addr1 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	addr2 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	// The least significant 3 bytes are the same as addr2 so both addr2 and
	// addr3 will have the same solicited-node address.
	addr3 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x02"
	addr4 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x03"

	// Tests use the extension header identifier values as uint8 instead of
	// header.IPv6ExtensionHeaderIdentifier.
	hopByHopExtHdrID    = uint8(header.IPv6HopByHopOptionsExtHdrIdentifier)
	routingExtHdrID     = uint8(header.IPv6RoutingExtHdrIdentifier)
	fragmentExtHdrID    = uint8(header.IPv6FragmentExtHdrIdentifier)
	destinationExtHdrID = uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
	noNextHdrID         = uint8(header.IPv6NoNextHeaderIdentifier)
)

// testReceiveICMP tests receiving an ICMP packet from src to dst. want is the
// expected Neighbor Advertisement received count after receiving the packet.
func testReceiveICMP(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64) {
	t.Helper()

	// Receive ICMP packet.
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
	pkt.SetType(header.ICMPv6NeighborAdvert)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, src, dst, buffer.VectorisedView{}))
	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(header.ICMPv6ProtocolNumber),
		HopLimit:      255,
		SrcAddr:       src,
		DstAddr:       dst,
	})

	e.InjectInbound(ProtocolNumber, &stack.PacketBuffer{
		Data: hdr.View().ToVectorisedView(),
	})

	stats := s.Stats().ICMP.V6PacketsReceived

	if got := stats.NeighborAdvert.Value(); got != want {
		t.Fatalf("got NeighborAdvert = %d, want = %d", got, want)
	}
}

// testReceiveUDP tests receiving a UDP packet from src to dst. want is the
// expected UDP received count after receiving the packet.
func testReceiveUDP(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64) {
	t.Helper()

	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)
	defer close(ch)

	ep, err := s.NewEndpoint(udp.ProtocolNumber, ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Addr: dst, Port: 80}); err != nil {
		t.Fatalf("ep.Bind(...) failed: %v", err)
	}

	// Receive UDP Packet.
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.UDPMinimumSize)
	u := header.UDP(hdr.Prepend(header.UDPMinimumSize))
	u.Encode(&header.UDPFields{
		SrcPort: 5555,
		DstPort: 80,
		Length:  header.UDPMinimumSize,
	})

	// UDP pseudo-header checksum.
	sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, header.UDPMinimumSize)

	// UDP checksum
	sum = header.Checksum(header.UDP([]byte{}), sum)
	u.SetChecksum(^u.CalculateChecksum(sum))

	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(udp.ProtocolNumber),
		HopLimit:      255,
		SrcAddr:       src,
		DstAddr:       dst,
	})

	e.InjectInbound(ProtocolNumber, &stack.PacketBuffer{
		Data: hdr.View().ToVectorisedView(),
	})

	stat := s.Stats().UDP.PacketsReceived

	if got := stat.Value(); got != want {
		t.Fatalf("got UDPPacketsReceived = %d, want = %d", got, want)
	}
}

// TestReceiveOnAllNodesMulticastAddr tests that IPv6 endpoints receive ICMP and
// UDP packets destined to the IPv6 link-local all-nodes multicast address.
func TestReceiveOnAllNodesMulticastAddr(t *testing.T) {
	tests := []struct {
		name            string
		protocolFactory stack.TransportProtocol
		rxf             func(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64)
	}{
		{"ICMP", icmp.NewProtocol6(), testReceiveICMP},
		{"UDP", udp.NewProtocol(), testReceiveUDP},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{test.protocolFactory},
			})
			e := channel.New(10, 1280, linkAddr1)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			// Should receive a packet destined to the all-nodes
			// multicast address.
			test.rxf(t, s, e, addr1, header.IPv6AllNodesMulticastAddress, 1)
		})
	}
}

// TestReceiveOnSolicitedNodeAddr tests that IPv6 endpoints receive ICMP and UDP
// packets destined to the IPv6 solicited-node address of an assigned IPv6
// address.
func TestReceiveOnSolicitedNodeAddr(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name            string
		protocolFactory stack.TransportProtocol
		rxf             func(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64)
	}{
		{"ICMP", icmp.NewProtocol6(), testReceiveICMP},
		{"UDP", udp.NewProtocol(), testReceiveUDP},
	}

	snmc := header.SolicitedNodeAddr(addr2)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{test.protocolFactory},
			})
			e := channel.New(1, 1280, linkAddr1)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			s.SetRouteTable([]tcpip.Route{
				tcpip.Route{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			// Should not receive a packet destined to the solicited node address of
			// addr2/addr3 yet as we haven't added those addresses.
			test.rxf(t, s, e, addr1, snmc, 0)

			if err := s.AddAddress(nicID, ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr2, err)
			}

			// Should receive a packet destined to the solicited node address of
			// addr2/addr3 now that we have added added addr2.
			test.rxf(t, s, e, addr1, snmc, 1)

			if err := s.AddAddress(nicID, ProtocolNumber, addr3); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr3, err)
			}

			// Should still receive a packet destined to the solicited node address of
			// addr2/addr3 now that we have added addr3.
			test.rxf(t, s, e, addr1, snmc, 2)

			if err := s.RemoveAddress(nicID, addr2); err != nil {
				t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, addr2, err)
			}

			// Should still receive a packet destined to the solicited node address of
			// addr2/addr3 now that we have removed addr2.
			test.rxf(t, s, e, addr1, snmc, 3)

			// Make sure addr3's endpoint does not get removed from the NIC by
			// incrementing its reference count with a route.
			r, err := s.FindRoute(nicID, addr3, addr4, ProtocolNumber, false)
			if err != nil {
				t.Fatalf("FindRoute(%d, %s, %s, %d, false): %s", nicID, addr3, addr4, ProtocolNumber, err)
			}
			defer r.Release()

			if err := s.RemoveAddress(nicID, addr3); err != nil {
				t.Fatalf("RemoveAddress(%d, %s) = %s", nicID, addr3, err)
			}

			// Should not receive a packet destined to the solicited node address of
			// addr2/addr3 yet as both of them got removed, even though a route using
			// addr3 exists.
			test.rxf(t, s, e, addr1, snmc, 3)
		})
	}
}

// TestAddIpv6Address tests adding IPv6 addresses.
func TestAddIpv6Address(t *testing.T) {
	tests := []struct {
		name string
		addr tcpip.Address
	}{
		// This test is in response to b/140943433.
		{
			"Nil",
			tcpip.Address([]byte(nil)),
		},
		{
			"ValidUnicast",
			addr1,
		},
		{
			"ValidLinkLocalUnicast",
			lladdr0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{NewProtocol()},
			})
			if err := s.CreateNIC(1, &stubLinkEndpoint{}); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, ProtocolNumber, test.addr); err != nil {
				t.Fatalf("AddAddress(_, %d, nil) = %s", ProtocolNumber, err)
			}

			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
			}
			if addr.Address != test.addr {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", addr.Address, test.addr)
			}
		})
	}
}

func TestReceiveIPv6ExtHdrs(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name         string
		extHdr       func(nextHdr uint8) ([]byte, uint8)
		shouldAccept bool
	}{
		{
			name:         "None",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{}, nextHdr },
			shouldAccept: true,
		},
		{
			name: "hopbyhop with unknown option skippable action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Skippable unknown.
					62, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "hopbyhop with unknown option discard action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard unknown.
					127, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "hopbyhop with unknown option discard and send icmp action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "hopbyhop with unknown option discard and send icmp action unless multicast dest",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
		{
			name:         "routing with zero segments left",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 1, 0, 2, 3, 4, 5}, routingExtHdrID },
			shouldAccept: true,
		},
		{
			name:         "routing with non-zero segments left",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 1, 1, 2, 3, 4, 5}, routingExtHdrID },
			shouldAccept: false,
		},
		{
			name:         "atomic fragment with zero ID",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 0, 0, 0, 0, 0, 0}, fragmentExtHdrID },
			shouldAccept: true,
		},
		{
			name:         "atomic fragment with non-zero ID",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 0, 0, 1, 2, 3, 4}, fragmentExtHdrID },
			shouldAccept: true,
		},
		{
			name:         "fragment",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{nextHdr, 0, 1, 0, 1, 2, 3, 4}, fragmentExtHdrID },
			shouldAccept: false,
		},
		{
			name:         "No next header",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{}, noNextHdrID },
			shouldAccept: false,
		},
		{
			name: "destination with unknown option skippable action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Skippable unknown.
					62, 6, 1, 2, 3, 4, 5, 6,
				}, destinationExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "destination with unknown option discard action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard unknown.
					127, 6, 1, 2, 3, 4, 5, 6,
				}, destinationExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "destination with unknown option discard and send icmp action",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
				}, destinationExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "destination with unknown option discard and send icmp action unless multicast dest",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
				}, destinationExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "routing - atomic fragment",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Routing extension header.
					fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Fragment extension header.
					nextHdr, 0, 0, 0, 1, 2, 3, 4,
				}, routingExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "atomic fragment - routing",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Fragment extension header.
					routingExtHdrID, 0, 0, 0, 1, 2, 3, 4,

					// Routing extension header.
					nextHdr, 0, 1, 0, 2, 3, 4, 5,
				}, fragmentExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "hop by hop (with skippable unknown) - routing",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Hop By Hop extension header with skippable unknown option.
					routingExtHdrID, 0, 62, 4, 1, 2, 3, 4,

					// Routing extension header.
					nextHdr, 0, 1, 0, 2, 3, 4, 5,
				}, hopByHopExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "routing - hop by hop (with skippable unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Routing extension header.
					hopByHopExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Hop By Hop extension header with skippable unknown option.
					nextHdr, 0, 62, 4, 1, 2, 3, 4,
				}, routingExtHdrID
			},
			shouldAccept: false,
		},
		{
			name:         "No next header",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return []byte{}, noNextHdrID },
			shouldAccept: false,
		},
		{
			name: "hopbyhop (with skippable unknown) - routing - atomic fragment - destination (with skippable unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Hop By Hop extension header with skippable unknown option.
					routingExtHdrID, 0, 62, 4, 1, 2, 3, 4,

					// Routing extension header.
					fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Fragment extension header.
					destinationExtHdrID, 0, 0, 0, 1, 2, 3, 4,

					// Destination extension header with skippable unknown option.
					nextHdr, 0, 63, 4, 1, 2, 3, 4,
				}, hopByHopExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "hopbyhop (with discard unknown) - routing - atomic fragment - destination (with skippable unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Hop By Hop extension header with discard action for unknown option.
					routingExtHdrID, 0, 65, 4, 1, 2, 3, 4,

					// Routing extension header.
					fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Fragment extension header.
					destinationExtHdrID, 0, 0, 0, 1, 2, 3, 4,

					// Destination extension header with skippable unknown option.
					nextHdr, 0, 63, 4, 1, 2, 3, 4,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
		{
			name: "hopbyhop (with skippable unknown) - routing - atomic fragment - destination (with discard unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Hop By Hop extension header with skippable unknown option.
					routingExtHdrID, 0, 62, 4, 1, 2, 3, 4,

					// Routing extension header.
					fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5,

					// Fragment extension header.
					destinationExtHdrID, 0, 0, 0, 1, 2, 3, 4,

					// Destination extension header with discard action for unknown
					// option.
					nextHdr, 0, 65, 4, 1, 2, 3, 4,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
			})
			e := channel.New(0, 1280, linkAddr1)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr2, err)
			}

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			defer wq.EventUnregister(&we)
			defer close(ch)
			ep, err := s.NewEndpoint(udp.ProtocolNumber, ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, ProtocolNumber, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: addr2, Port: 80}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("Bind(%+v): %s", bindAddr, err)
			}

			udpPayload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			udpLength := header.UDPMinimumSize + len(udpPayload)
			extHdrBytes, ipv6NextHdr := test.extHdr(uint8(header.UDPProtocolNumber))
			extHdrLen := len(extHdrBytes)
			hdr := buffer.NewPrependable(header.IPv6MinimumSize + extHdrLen + udpLength)

			// Serialize UDP message.
			u := header.UDP(hdr.Prepend(udpLength))
			u.Encode(&header.UDPFields{
				SrcPort: 5555,
				DstPort: 80,
				Length:  uint16(udpLength),
			})
			copy(u.Payload(), udpPayload)
			sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, addr1, addr2, uint16(udpLength))
			sum = header.Checksum(udpPayload, sum)
			u.SetChecksum(^u.CalculateChecksum(sum))

			// Copy extension header bytes between the UDP message and the IPv6
			// fixed header.
			copy(hdr.Prepend(extHdrLen), extHdrBytes)

			// Serialize IPv6 fixed header.
			payloadLength := hdr.UsedLength()
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength: uint16(payloadLength),
				NextHeader:    ipv6NextHdr,
				HopLimit:      255,
				SrcAddr:       addr1,
				DstAddr:       addr2,
			})

			e.InjectInbound(ProtocolNumber, &stack.PacketBuffer{
				Data: hdr.View().ToVectorisedView(),
			})

			stats := s.Stats().UDP.PacketsReceived

			if !test.shouldAccept {
				if got := stats.Value(); got != 0 {
					t.Errorf("got UDP Rx Packets = %d, want = 0", got)
				}

				return
			}

			// Expect a UDP packet.
			if got := stats.Value(); got != 1 {
				t.Errorf("got UDP Rx Packets = %d, want = 1", got)
			}
			gotPayload, _, err := ep.Read(nil)
			if err != nil {
				t.Fatalf("Read(nil): %s", err)
			}
			if diff := cmp.Diff(buffer.View(udpPayload), gotPayload); diff != "" {
				t.Errorf("got UDP payload mismatch (-want +got):\n%s", diff)
			}

			// Should not have any more UDP packets.
			if gotPayload, _, err := ep.Read(nil); err != tcpip.ErrWouldBlock {
				t.Fatalf("got Read(nil) = (%x, _, %v), want = (_, _, %s)", gotPayload, err, tcpip.ErrWouldBlock)
			}
		})
	}
}

// fragmentData holds the IPv6 payload for a fragmented IPv6 packet.
type fragmentData struct {
	nextHdr uint8
	data    buffer.VectorisedView
}

func TestReceiveIPv6Fragments(t *testing.T) {
	const nicID = 1
	const udpPayload1Length = 256
	const udpPayload2Length = 128
	const fragmentExtHdrLen = 8
	// Note, not all routing extension headers will be 8 bytes but this test
	// uses 8 byte routing extension headers for most sub tests.
	const routingExtHdrLen = 8

	udpGen := func(payload []byte, multiplier uint8) buffer.View {
		payloadLen := len(payload)
		for i := 0; i < payloadLen; i++ {
			payload[i] = uint8(i) * multiplier
		}

		udpLength := header.UDPMinimumSize + payloadLen

		hdr := buffer.NewPrependable(udpLength)
		u := header.UDP(hdr.Prepend(udpLength))
		u.Encode(&header.UDPFields{
			SrcPort: 5555,
			DstPort: 80,
			Length:  uint16(udpLength),
		})
		copy(u.Payload(), payload)
		sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, addr1, addr2, uint16(udpLength))
		sum = header.Checksum(payload, sum)
		u.SetChecksum(^u.CalculateChecksum(sum))
		return hdr.View()
	}

	var udpPayload1Buf [udpPayload1Length]byte
	udpPayload1 := udpPayload1Buf[:]
	ipv6Payload1 := udpGen(udpPayload1, 1)

	var udpPayload2Buf [udpPayload2Length]byte
	udpPayload2 := udpPayload2Buf[:]
	ipv6Payload2 := udpGen(udpPayload2, 2)

	tests := []struct {
		name             string
		expectedPayload  []byte
		fragments        []fragmentData
		expectedPayloads [][]byte
	}{
		{
			name: "No fragmentation",
			fragments: []fragmentData{
				{
					nextHdr: uint8(header.UDPProtocolNumber),
					data:    ipv6Payload1.ToVectorisedView(),
				},
			},
			expectedPayloads: [][]byte{udpPayload1},
		},
		{
			name: "Atomic fragment",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1),
						[]buffer.View{
							// Fragment extension header.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 0, 0, 0, 0, 0}),

							ipv6Payload1,
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1},
		},
		{
			name: "Two fragments",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1[:64],
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1},
		},
		{
			name: "Two fragments with different IDs",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1[:64],
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 2
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 2}),

							ipv6Payload1[64:],
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with per-fragment routing header with zero segments left",
			fragments: []fragmentData{
				{
					nextHdr: routingExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+64,
						[]buffer.View{
							// Routing extension header.
							//
							// Segments left = 0.
							buffer.View([]byte{fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5}),

							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1[:64],
						},
					),
				},
				{
					nextHdr: routingExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+len(ipv6Payload1)-64,
						[]buffer.View{
							// Routing extension header.
							//
							// Segments left = 0.
							buffer.View([]byte{fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5}),

							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1},
		},
		{
			name: "Two fragments with per-fragment routing header with non-zero segments left",
			fragments: []fragmentData{
				{
					nextHdr: routingExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+64,
						[]buffer.View{
							// Routing extension header.
							//
							// Segments left = 1.
							buffer.View([]byte{fragmentExtHdrID, 0, 1, 1, 2, 3, 4, 5}),

							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1[:64],
						},
					),
				},
				{
					nextHdr: routingExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+len(ipv6Payload1)-64,
						[]buffer.View{
							// Routing extension header.
							//
							// Segments left = 1.
							buffer.View([]byte{fragmentExtHdrID, 0, 1, 1, 2, 3, 4, 5}),

							// Fragment extension header.
							//
							// Fragment offset = 9, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 72, 0, 0, 0, 1}),

							ipv6Payload1[64:],
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with zero segments left",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1}),

							// Routing extension header.
							//
							// Segments left = 0.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 1, 0, 2, 3, 4, 5}),

							ipv6Payload1[:64],
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 9, More = false, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 72, 0, 0, 0, 1}),

							ipv6Payload1[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1},
		},
		{
			name: "Two fragments with routing header with non-zero segments left",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						routingExtHdrLen+fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1}),

							// Routing extension header.
							//
							// Segments left = 1.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 1, 1, 2, 3, 4, 5}),

							ipv6Payload1[:64],
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 9, More = false, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 72, 0, 0, 0, 1}),

							ipv6Payload1[64:],
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with zero segments left across fragments",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						// The length of this payload is fragmentExtHdrLen+8 because the
						// first 8 bytes of the 16 byte routing extension header is in
						// this fragment.
						fragmentExtHdrLen+8,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1}),

							// Routing extension header (part 1)
							//
							// Segments left = 0.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 1, 1, 0, 2, 3, 4, 5}),
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						// The length of this payload is
						// fragmentExtHdrLen+8+len(ipv6Payload1) because the last 8 bytes of
						// the 16 byte routing extension header is in this fagment.
						fragmentExtHdrLen+8+len(ipv6Payload1),
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 1, More = false, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 8, 0, 0, 0, 1}),

							// Routing extension header (part 2)
							buffer.View([]byte{6, 7, 8, 9, 10, 11, 12, 13}),

							ipv6Payload1,
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with non-zero segments left across fragments",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						// The length of this payload is fragmentExtHdrLen+8 because the
						// first 8 bytes of the 16 byte routing extension header is in
						// this fragment.
						fragmentExtHdrLen+8,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1}),

							// Routing extension header (part 1)
							//
							// Segments left = 1.
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 1, 1, 1, 2, 3, 4, 5}),
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						// The length of this payload is
						// fragmentExtHdrLen+8+len(ipv6Payload1) because the last 8 bytes of
						// the 16 byte routing extension header is in this fagment.
						fragmentExtHdrLen+8+len(ipv6Payload1),
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 1, More = false, ID = 1
							buffer.View([]byte{routingExtHdrID, 0, 0, 8, 0, 0, 0, 1}),

							// Routing extension header (part 2)
							buffer.View([]byte{6, 7, 8, 9, 10, 11, 12, 13}),

							ipv6Payload1,
						},
					),
				},
			},
			expectedPayloads: nil,
		},
		// As per RFC 6946, IPv6 atomic fragments MUST NOT interfere with "normal"
		// fragmented traffic.
		{
			name: "Two fragments with atomic",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1[:64],
						},
					),
				},
				// This fragment has the same ID as the other fragments but is an atomic
				// fragment. It should not interfere with the other fragments.
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload2),
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 0, 0, 0, 0, 1}),

							ipv6Payload2,
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1[64:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload2, udpPayload1},
		},
		{
			name: "Two interleaved fragmented packets",
			fragments: []fragmentData{
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1}),

							ipv6Payload1[:64],
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+32,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 2
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 2}),

							ipv6Payload2[:32],
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload1)-64,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1}),

							ipv6Payload1[64:],
						},
					),
				},
				{
					nextHdr: fragmentExtHdrID,
					data: buffer.NewVectorisedView(
						fragmentExtHdrLen+len(ipv6Payload2)-32,
						[]buffer.View{
							// Fragment extension header.
							//
							// Fragment offset = 4, More = false, ID = 2
							buffer.View([]byte{uint8(header.UDPProtocolNumber), 0, 0, 32, 0, 0, 0, 2}),

							ipv6Payload2[32:],
						},
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1, udpPayload2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
			})
			e := channel.New(0, 1280, linkAddr1)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, addr2, err)
			}

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			defer wq.EventUnregister(&we)
			defer close(ch)
			ep, err := s.NewEndpoint(udp.ProtocolNumber, ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, ProtocolNumber, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: addr2, Port: 80}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("Bind(%+v): %s", bindAddr, err)
			}

			for _, f := range test.fragments {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize)

				// Serialize IPv6 fixed header.
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(f.data.Size()),
					NextHeader:    f.nextHdr,
					HopLimit:      255,
					SrcAddr:       addr1,
					DstAddr:       addr2,
				})

				vv := hdr.View().ToVectorisedView()
				vv.Append(f.data)

				e.InjectInbound(ProtocolNumber, &stack.PacketBuffer{
					Data: vv,
				})
			}

			if got, want := s.Stats().UDP.PacketsReceived.Value(), uint64(len(test.expectedPayloads)); got != want {
				t.Errorf("got UDP Rx Packets = %d, want = %d", got, want)
			}

			for i, p := range test.expectedPayloads {
				gotPayload, _, err := ep.Read(nil)
				if err != nil {
					t.Fatalf("(i=%d) Read(nil): %s", i, err)
				}
				if diff := cmp.Diff(buffer.View(p), gotPayload); diff != "" {
					t.Errorf("(i=%d) got UDP payload mismatch (-want +got):\n%s", i, diff)
				}
			}

			if gotPayload, _, err := ep.Read(nil); err != tcpip.ErrWouldBlock {
				t.Fatalf("(last) got Read(nil) = (%x, _, %v), want = (_, _, %s)", gotPayload, err, tcpip.ErrWouldBlock)
			}
		})
	}
}
