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
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	iptestutil "gvisor.dev/gvisor/pkg/tcpip/network/internal/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	addr1 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"))
	addr2 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"))
	// The least significant 3 bytes are the same as addr2 so both addr2 and
	// addr3 will have the same solicited-node address.
	addr3 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x02"))
	addr4 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x03"))
)

const (
	// Tests use the extension header identifier values as uint8 instead of
	// header.IPv6ExtensionHeaderIdentifier.
	hopByHopExtHdrID    = uint8(header.IPv6HopByHopOptionsExtHdrIdentifier)
	routingExtHdrID     = uint8(header.IPv6RoutingExtHdrIdentifier)
	fragmentExtHdrID    = uint8(header.IPv6FragmentExtHdrIdentifier)
	destinationExtHdrID = uint8(header.IPv6DestinationOptionsExtHdrIdentifier)
	noNextHdrID         = uint8(header.IPv6NoNextHeaderIdentifier)
	unknownHdrID        = uint8(header.IPv6UnknownExtHdrIdentifier)

	extraHeaderReserve = 50
)

var _ stack.MulticastForwardingEventDispatcher = (*fakeMulticastEventDispatcher)(nil)

type fakeMulticastEventDispatcher struct{}

func (m *fakeMulticastEventDispatcher) OnMissingRoute(context stack.MulticastPacketContext) {}

func (m *fakeMulticastEventDispatcher) OnUnexpectedInputInterface(context stack.MulticastPacketContext, expectedInputInterface tcpip.NICID) {
}

// testReceiveICMP tests receiving an ICMP packet from src to dst. want is the
// expected Neighbor Advertisement received count after receiving the packet.
func testReceiveICMP(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64) {
	t.Helper()

	// Receive ICMP packet.
	hdr := prependable.New(header.IPv6MinimumSize + header.ICMPv6NeighborAdvertMinimumSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertMinimumSize))
	pkt.SetType(header.ICMPv6NeighborAdvert)
	pkt.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: pkt,
		Src:    src,
		Dst:    dst,
	}))
	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           src,
		DstAddr:           dst,
	})

	pktBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(hdr.View()),
	})
	e.InjectInbound(ProtocolNumber, pktBuf)
	pktBuf.DecRef()

	stats := s.Stats().ICMP.V6.PacketsReceived

	if got := stats.NeighborAdvert.Value(); got != want {
		t.Fatalf("got NeighborAdvert = %d, want = %d", got, want)
	}
}

// testReceiveUDP tests receiving a UDP packet from src to dst. want is the
// expected UDP received count after receiving the packet.
func testReceiveUDP(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64) {
	t.Helper()

	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
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
	hdr := prependable.New(header.IPv6MinimumSize + header.UDPMinimumSize)
	u := header.UDP(hdr.Prepend(header.UDPMinimumSize))
	u.Encode(&header.UDPFields{
		SrcPort: 5555,
		DstPort: 80,
		Length:  header.UDPMinimumSize,
	})

	// UDP pseudo-header checksum.
	sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, header.UDPMinimumSize)

	// UDP checksum
	sum = checksum.Checksum(nil, sum)
	u.SetChecksum(^u.CalculateChecksum(sum))

	payloadLength := hdr.UsedLength()
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		TransportProtocol: udp.ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           src,
		DstAddr:           dst,
	})

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(hdr.View()),
	})
	e.InjectInbound(ProtocolNumber, pkt)
	pkt.DecRef()

	stat := s.Stats().UDP.PacketsReceived

	if got := stat.Value(); got != want {
		t.Fatalf("got UDPPacketsReceived = %d, want = %d", got, want)
	}
}

func compareFragments(packets []stack.PacketBufferPtr, sourcePacket stack.PacketBufferPtr, mtu uint32, wantFragments []fragmentInfo, proto tcpip.TransportProtocolNumber) error {
	// sourcePacket does not have its IP Header populated. Let's copy the one
	// from the first fragment.
	source := header.IPv6(packets[0].NetworkHeader().Slice())
	sourceIPHeadersLen := len(source)
	view := sourcePacket.ToView()
	defer view.Release()
	source = append(source, view.AsSlice()...)

	var reassembledPayload buffer.Buffer
	defer reassembledPayload.Release()
	for i, fragment := range packets {
		// Confirm that the packet is valid.
		allBytes := fragment.ToBuffer()
		defer allBytes.Release()
		fragmentIPHeaders := header.IPv6(allBytes.Flatten())
		if !fragmentIPHeaders.IsValid(len(fragmentIPHeaders)) {
			return fmt.Errorf("fragment #%d: IP packet is invalid:\n%s", i, hex.Dump(fragmentIPHeaders))
		}

		fragmentIPHeadersLength := len(fragment.NetworkHeader().Slice())
		if fragmentIPHeadersLength != sourceIPHeadersLen {
			return fmt.Errorf("fragment #%d: got fragmentIPHeadersLength = %d, want = %d", i, fragmentIPHeadersLength, sourceIPHeadersLen)
		}

		if got := len(fragmentIPHeaders); got > int(mtu) {
			return fmt.Errorf("fragment #%d: got len(fragmentIPHeaders) = %d, want <= %d", i, got, mtu)
		}

		sourceIPHeader := source[:header.IPv6MinimumSize]
		fragmentIPHeader := fragmentIPHeaders[:header.IPv6MinimumSize]

		if got := fragmentIPHeaders.PayloadLength(); got != wantFragments[i].payloadSize {
			return fmt.Errorf("fragment #%d: got fragmentIPHeaders.PayloadLength() = %d, want = %d", i, got, wantFragments[i].payloadSize)
		}

		// We expect the IPv6 Header to be similar across each fragment, besides the
		// payload length.
		sourceIPHeader.SetPayloadLength(0)
		fragmentIPHeader.SetPayloadLength(0)
		if diff := cmp.Diff(fragmentIPHeader, sourceIPHeader); diff != "" {
			return fmt.Errorf("fragment #%d: fragmentIPHeader mismatch (-want +got):\n%s", i, diff)
		}

		if got := fragment.AvailableHeaderBytes(); got != extraHeaderReserve {
			return fmt.Errorf("fragment #%d: got packet.AvailableHeaderBytes() = %d, want = %d", i, got, extraHeaderReserve)
		}
		if fragment.NetworkProtocolNumber != sourcePacket.NetworkProtocolNumber {
			return fmt.Errorf("fragment #%d: got fragment.NetworkProtocolNumber = %d, want = %d", i, fragment.NetworkProtocolNumber, sourcePacket.NetworkProtocolNumber)
		}

		if len(packets) > 1 {
			// If the source packet was big enough that it needed fragmentation, let's
			// inspect the fragment header. Because no other extension headers are
			// supported, it will always be the last extension header.
			fragmentHeader := header.IPv6Fragment(fragmentIPHeaders[fragmentIPHeadersLength-header.IPv6FragmentHeaderSize : fragmentIPHeadersLength])

			if got := fragmentHeader.More(); got != wantFragments[i].more {
				return fmt.Errorf("fragment #%d: got fragmentHeader.More() = %t, want = %t", i, got, wantFragments[i].more)
			}
			if got := fragmentHeader.FragmentOffset(); got != wantFragments[i].offset {
				return fmt.Errorf("fragment #%d: got fragmentHeader.FragmentOffset() = %d, want = %d", i, got, wantFragments[i].offset)
			}
			if got := fragmentHeader.NextHeader(); got != uint8(proto) {
				return fmt.Errorf("fragment #%d: got fragmentHeader.NextHeader() = %d, want = %d", i, got, uint8(proto))
			}
		}

		// Store the reassembled payload as we parse each fragment. The payload
		// includes the Transport header and everything after.
		reassembledPayload.Append(fragment.TransportHeader().View())
		reassembledPayload.Append(fragment.Data().AsRange().ToView())
	}

	if diff := cmp.Diff([]byte(source[sourceIPHeadersLen:]), reassembledPayload.Flatten()); diff != "" {
		return fmt.Errorf("reassembledPayload mismatch (-want +got):\n%s", diff)
	}

	return nil
}

// TestReceiveOnAllNodesMulticastAddr tests that IPv6 endpoints receive ICMP and
// UDP packets destined to the IPv6 link-local all-nodes multicast address.
func TestReceiveOnAllNodesMulticastAddr(t *testing.T) {
	tests := []struct {
		name string
		rxf  func(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64)
	}{
		{"ICMP", testReceiveICMP},
		{"UDP", testReceiveUDP},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			e := channel.New(10, header.IPv6MinimumMTU, linkAddr1)
			defer e.Close()
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
	tests := []struct {
		name string
		rxf  func(t *testing.T, s *stack.Stack, e *channel.Endpoint, src, dst tcpip.Address, want uint64)
	}{
		{"ICMP", testReceiveICMP},
		{"UDP", testReceiveUDP},
	}

	snmc := header.SolicitedNodeAddr(addr2)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			e := channel.New(1, header.IPv6MinimumMTU, linkAddr1)
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			// Should not receive a packet destined to the solicited node address of
			// addr2/addr3 yet as we haven't added those addresses.
			test.rxf(t, s, e, addr1, snmc, 0)

			protocolAddr2 := tcpip.ProtocolAddress{
				Protocol:          ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr2, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr2, err)
			}

			// Should receive a packet destined to the solicited node address of
			// addr2/addr3 now that we have added added addr2.
			test.rxf(t, s, e, addr1, snmc, 1)

			protocolAddr3 := tcpip.ProtocolAddress{
				Protocol:          ProtocolNumber,
				AddressWithPrefix: addr3.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr3, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr3, err)
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
	const nicID = 1

	tests := []struct {
		name string
		addr tcpip.Address
	}{
		// This test is in response to b/140943433.
		{
			"Nil",
			tcpip.Address{},
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
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			if err := s.CreateNIC(nicID, &stubLinkEndpoint{}); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ProtocolNumber,
				AddressWithPrefix: test.addr.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}

			if addr, err := s.GetMainNICAddress(nicID, ProtocolNumber); err != nil {
				t.Fatalf("stack.GetMainNICAddress(%d, %d): %s", nicID, ProtocolNumber, err)
			} else if addr.Address != test.addr {
				t.Fatalf("got stack.GetMainNICAddress(%d, %d) = %s, want = %s", nicID, ProtocolNumber, addr.Address, test.addr)
			}
		})
	}
}

func TestReceiveIPv6ExtHdrs(t *testing.T) {
	tests := []struct {
		name                    string
		extHdr                  func(nextHdr uint8) ([]byte, uint8)
		shouldAccept            bool
		countersToBeIncremented func(*tcpip.Stats) []*tcpip.StatCounter
		// Should we expect an ICMP response and if so, with what contents?
		expectICMP bool
		ICMPType   header.ICMPv6Type
		ICMPCode   header.ICMPv6Code
		pointer    uint32
		multicast  bool
	}{
		{
			name:         "None",
			extHdr:       func(nextHdr uint8) ([]byte, uint8) { return nil, nextHdr },
			shouldAccept: true,
			expectICMP:   false,
		},
		{
			name: "hopbyhop with router alert option",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 0,

					// Router Alert option.
					5, 2, 0, 0, 0, 0,
				}, hopByHopExtHdrID
			},
			shouldAccept: true,
			countersToBeIncremented: func(stats *tcpip.Stats) []*tcpip.StatCounter {
				return []*tcpip.StatCounter{stats.IP.OptionRouterAlertReceived}
			},
		},
		{
			name: "hopbyhop with two router alert options",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Router Alert option.
					5, 2, 0, 0, 0, 0,

					// Router Alert option.
					5, 2, 0, 0, 0, 0, 0, 0,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
			countersToBeIncremented: func(stats *tcpip.Stats) []*tcpip.StatCounter {
				return []*tcpip.StatCounter{
					stats.IP.OptionRouterAlertReceived,
					stats.IP.MalformedPacketsReceived,
				}
			},
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
			expectICMP:   false,
		},
		{
			name: "hopbyhop with unknown option discard and send icmp action (unicast)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
					//^ Unknown option.
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownOption,
			pointer:      header.IPv6FixedHeaderSize + 8,
		},
		{
			name: "hopbyhop with unknown option discard and send icmp action (multicast)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
					//^ Unknown option.
				}, hopByHopExtHdrID
			},
			multicast:    true,
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownOption,
			pointer:      header.IPv6FixedHeaderSize + 8,
		},
		{
			name: "hopbyhop with unknown option discard and send icmp action unless multicast dest (unicast)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
					//^ Unknown option.
				}, hopByHopExtHdrID
			},
			expectICMP: true,
			ICMPType:   header.ICMPv6ParamProblem,
			ICMPCode:   header.ICMPv6UnknownOption,
			pointer:    header.IPv6FixedHeaderSize + 8,
		},
		{
			name: "hopbyhop with unknown option discard and send icmp action unless multicast dest (multicast)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
					//^ Unknown option.
				}, hopByHopExtHdrID
			},
			multicast:    true,
			shouldAccept: false,
			expectICMP:   false,
		},
		{
			name: "routing with zero segments left",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 0,
					1, 0, 2, 3, 4, 5,
				}, routingExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "routing with non-zero segments left",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 0,
					1, 1, 2, 3, 4, 5,
				}, routingExtHdrID
			},
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6ErroneousHeader,
			pointer:      header.IPv6FixedHeaderSize + 2,
		},
		{
			name: "atomic fragment with zero ID",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 0,
					0, 0, 0, 0, 0, 0,
				}, fragmentExtHdrID
			},
			shouldAccept: true,
		},
		{
			name: "atomic fragment with non-zero ID",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 0,
					0, 0, 1, 2, 3, 4,
				}, fragmentExtHdrID
			},
			shouldAccept: true,
			expectICMP:   false,
		},
		{
			name: "fragment",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 0,
					1, 0, 1, 2, 3, 4,
				}, fragmentExtHdrID
			},
			shouldAccept: false,
			expectICMP:   false,
		},
		{
			name: "No next header",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return nil, noNextHdrID
			},
			shouldAccept: false,
			expectICMP:   false,
		},
		{
			name: "unknown next header (first)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 0, 63, 4, 1, 2, 3, 4,
				}, unknownHdrID
			},
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownHeader,
			pointer:      header.IPv6NextHeaderOffset,
		},
		{
			name: "unknown next header (not first)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					unknownHdrID, 0,
					63, 4, 1, 2, 3, 4,
				}, hopByHopExtHdrID
			},
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownHeader,
			pointer:      header.IPv6FixedHeaderSize,
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
			expectICMP:   false,
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
			expectICMP:   false,
		},
		{
			name: "destination with unknown option discard and send icmp action (unicast)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
					//^  191 is an unknown option.
				}, destinationExtHdrID
			},
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownOption,
			pointer:      header.IPv6FixedHeaderSize + 8,
		},
		{
			name: "destination with unknown option discard and send icmp action (muilticast)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
					//^  191 is an unknown option.
				}, destinationExtHdrID
			},
			multicast:    true,
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownOption,
			pointer:      header.IPv6FixedHeaderSize + 8,
		},
		{
			name: "destination with unknown option discard and send icmp action unless multicast dest (unicast)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
					//^ 255 is unknown.
				}, destinationExtHdrID
			},
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownOption,
			pointer:      header.IPv6FixedHeaderSize + 8,
		},
		{
			name: "destination with unknown option discard and send icmp action unless multicast dest (multicast)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
					//^ 255 is unknown.
				}, destinationExtHdrID
			},
			shouldAccept: false,
			expectICMP:   false,
			multicast:    true,
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
					// ^^^   The HopByHop extension header may not appear after the first
					// extension header.

					// Hop By Hop extension header with skippable unknown option.
					nextHdr, 0, 62, 4, 1, 2, 3, 4,
				}, routingExtHdrID
			},
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownHeader,
			pointer:      header.IPv6FixedHeaderSize,
		},
		{
			name: "routing - hop by hop (with send icmp unknown)",
			extHdr: func(nextHdr uint8) ([]byte, uint8) {
				return []byte{
					// Routing extension header.
					hopByHopExtHdrID, 0, 1, 0, 2, 3, 4, 5,
					// ^^^   The HopByHop extension header may not appear after the first
					// extension header.

					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Skippable unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
				}, routingExtHdrID
			},
			shouldAccept: false,
			expectICMP:   true,
			ICMPType:     header.ICMPv6ParamProblem,
			ICMPCode:     header.ICMPv6UnknownHeader,
			pointer:      header.IPv6FixedHeaderSize,
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
			expectICMP:   false,
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
			expectICMP:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			e := channel.New(1, header.IPv6MinimumMTU, linkAddr1)
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}

			// Add a default route so that a return packet knows where to go.
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
			wq.EventRegister(&we)
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
			hdr := prependable.New(header.IPv6MinimumSize + extHdrLen + udpLength)

			// Serialize UDP message.
			u := header.UDP(hdr.Prepend(udpLength))
			u.Encode(&header.UDPFields{
				SrcPort: 5555,
				DstPort: 80,
				Length:  uint16(udpLength),
			})
			copy(u.Payload(), udpPayload)

			dstAddr := tcpip.Address(addr2)
			if test.multicast {
				dstAddr = header.IPv6AllNodesMulticastAddress
			}

			sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, addr1, dstAddr, uint16(udpLength))
			sum = checksum.Checksum(udpPayload, sum)
			u.SetChecksum(^u.CalculateChecksum(sum))

			// Copy extension header bytes between the UDP message and the IPv6
			// fixed header.
			copy(hdr.Prepend(extHdrLen), extHdrBytes)

			// Serialize IPv6 fixed header.
			payloadLength := hdr.UsedLength()
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength: uint16(payloadLength),
				// We're lying about transport protocol here to be able to generate
				// raw extension headers from the test definitions.
				TransportProtocol: tcpip.TransportProtocolNumber(ipv6NextHdr),
				HopLimit:          255,
				SrcAddr:           addr1,
				DstAddr:           dstAddr,
			})

			stats := s.Stats()
			var counters []*tcpip.StatCounter
			// Make sure that the counters we expect to be incremented are initially
			// set to zero.
			if fn := test.countersToBeIncremented; fn != nil {
				counters = fn(&stats)
			}
			for i := range counters {
				if got := counters[i].Value(); got != 0 {
					t.Errorf("before writing packet: got test.countersToBeIncremented(&stats)[%d].Value() = %d, want = 0", i, got)
				}
			}

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(hdr.View()),
			})
			e.InjectInbound(ProtocolNumber, pkt)
			pkt.DecRef()
			for i := range counters {
				if got := counters[i].Value(); got != 1 {
					t.Errorf("after writing packet: got test.countersToBeIncremented(&stats)[%d].Value() = %d, want = 1", i, got)
				}
			}

			udpReceiveStat := stats.UDP.PacketsReceived
			if !test.shouldAccept {
				if got := udpReceiveStat.Value(); got != 0 {
					t.Errorf("got UDP Rx Packets = %d, want = 0", got)
				}

				if !test.expectICMP {
					if p := e.Read(); !p.IsNil() {
						t.Fatalf("unexpected packet received: %#v", p)
					}
					return
				}

				// ICMP required.
				p := e.Read()
				if p.IsNil() {
					t.Fatalf("expected packet wasn't written out")
				}
				defer p.DecRef()

				// Pack the output packet into a single buffer.View as the checkers
				// assume that.
				v := p.ToView()
				defer v.Release()
				pkt := v.AsSlice()
				if got, want := len(pkt), header.IPv6FixedHeaderSize+header.ICMPv6MinimumSize+hdr.UsedLength(); got != want {
					t.Fatalf("got an ICMP packet of size = %d, want = %d", got, want)
				}

				checker.IPv6(t, v, checker.ICMPv6(
					checker.ICMPv6Type(test.ICMPType),
					checker.ICMPv6Code(test.ICMPCode)))

				// We know we are looking at no extension headers in the error ICMP
				// packets.
				icm := header.ICMPv6(header.IPv6(pkt).Payload())
				// We know we sent small packets that won't be truncated when reflected
				// back to us.
				originalPacket := icm.Payload()
				if got, want := icm.TypeSpecific(), test.pointer; got != want {
					t.Errorf("unexpected ICMPv6 pointer, got = %d, want = %d\n", got, want)
				}
				if diff := cmp.Diff([]byte(hdr.View()), originalPacket); diff != "" {
					t.Errorf("ICMPv6 payload mismatch (-want +got):\n%s", diff)
				}
				return
			}

			// Expect a UDP packet.
			if got := udpReceiveStat.Value(); got != 1 {
				t.Errorf("got UDP Rx Packets = %d, want = 1", got)
			}
			var buf bytes.Buffer
			result, err := ep.Read(&buf, tcpip.ReadOptions{})
			if err != nil {
				t.Fatalf("Read: %s", err)
			}
			if diff := cmp.Diff(tcpip.ReadResult{
				Count: len(udpPayload),
				Total: len(udpPayload),
			}, result, checker.IgnoreCmpPath("ControlMessages")); diff != "" {
				t.Errorf("Read: unexpected result (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(udpPayload, buf.Bytes()); diff != "" {
				t.Errorf("got UDP payload mismatch (-want +got):\n%s", diff)
			}

			// Should not have any more UDP packets.
			res, err := ep.Read(ioutil.Discard, tcpip.ReadOptions{})
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				t.Fatalf("got Read = (%v, %v), want = (_, %s)", res, err, &tcpip.ErrWouldBlock{})
			}
		})
	}
}

// fragmentData holds the IPv6 payload for a fragmented IPv6 packet.
type fragmentData struct {
	srcAddr tcpip.Address
	dstAddr tcpip.Address
	nextHdr uint8
	data    []byte
}

func udpGen(payload []byte, multiplier uint8, src, dst tcpip.Address) []byte {
	payloadLen := len(payload)
	for i := 0; i < payloadLen; i++ {
		payload[i] = uint8(i) * multiplier
	}

	udpLength := header.UDPMinimumSize + payloadLen

	hdr := prependable.New(udpLength)
	u := header.UDP(hdr.Prepend(udpLength))
	u.Encode(&header.UDPFields{
		SrcPort: 5555,
		DstPort: 80,
		Length:  uint16(udpLength),
	})
	copy(u.Payload(), payload)
	sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(udpLength))
	sum = checksum.Checksum(payload, sum)
	u.SetChecksum(^u.CalculateChecksum(sum))
	return hdr.View()
}

func TestReceiveIPv6Fragments(t *testing.T) {
	const (
		udpPayload1Length = 256
		udpPayload2Length = 128
		// Used to test cases where the fragment blocks are not a multiple of
		// the fragment block size of 8 (RFC 8200 section 4.5).
		udpPayload3Length     = 127
		udpPayload4Length     = header.IPv6MaximumPayloadSize - header.UDPMinimumSize
		udpMaximumSizeMinus15 = header.UDPMaximumSize - 15
		fragmentExtHdrLen     = 8
		// Note, not all routing extension headers will be 8 bytes but this test
		// uses 8 byte routing extension headers for most sub tests.
		routingExtHdrLen = 8
	)

	var udpPayload1Addr1ToAddr2Buf [udpPayload1Length]byte
	udpPayload1Addr1ToAddr2 := udpPayload1Addr1ToAddr2Buf[:]
	ipv6Payload1Addr1ToAddr2 := udpGen(udpPayload1Addr1ToAddr2, 1, addr1, addr2)

	var udpPayload1Addr3ToAddr2Buf [udpPayload1Length]byte
	udpPayload1Addr3ToAddr2 := udpPayload1Addr3ToAddr2Buf[:]
	ipv6Payload1Addr3ToAddr2 := udpGen(udpPayload1Addr3ToAddr2, 4, addr3, addr2)

	var udpPayload2Addr1ToAddr2Buf [udpPayload2Length]byte
	udpPayload2Addr1ToAddr2 := udpPayload2Addr1ToAddr2Buf[:]
	ipv6Payload2Addr1ToAddr2 := udpGen(udpPayload2Addr1ToAddr2, 2, addr1, addr2)

	var udpPayload3Addr1ToAddr2Buf [udpPayload3Length]byte
	udpPayload3Addr1ToAddr2 := udpPayload3Addr1ToAddr2Buf[:]
	ipv6Payload3Addr1ToAddr2 := udpGen(udpPayload3Addr1ToAddr2, 3, addr1, addr2)

	var udpPayload4Addr1ToAddr2Buf [udpPayload4Length]byte
	udpPayload4Addr1ToAddr2 := udpPayload4Addr1ToAddr2Buf[:]
	ipv6Payload4Addr1ToAddr2 := udpGen(udpPayload4Addr1ToAddr2, 4, addr1, addr2)

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
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: uint8(header.UDPProtocolNumber),
					data:    ipv6Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Atomic fragment",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 0, 0, 0, 0, 0},
						ipv6Payload1Addr1ToAddr2...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Atomic fragment with size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 0, 0, 0, 0, 0},
						ipv6Payload3Addr1ToAddr2...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "Two fragments",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[:64]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments out of order",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[:64]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with different Next Header values",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[:64]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 1
						// NextHeader value is different than the one in the first fragment, so
						// this NextHeader should be ignored.
						[]byte{uint8(header.IPv6NoNextHeaderIdentifier), 0, 0, 64, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with last fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload3Addr1ToAddr2[:64]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},
						ipv6Payload3Addr1ToAddr2[64:]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "Two fragments with first fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload3Addr1ToAddr2[:63]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},
						ipv6Payload3Addr1ToAddr2[63:]...,
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with different IDs",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[:64]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 2
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 2},
						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments reassembled into a maximum UDP packet",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload4Addr1ToAddr2[:udpMaximumSizeMinus15]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = udpMaximumSizeMinus15/8, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0,
							udpMaximumSizeMinus15 >> 8,
							udpMaximumSizeMinus15 & 0xff,
							0, 0, 0, 1},
						ipv6Payload4Addr1ToAddr2[udpMaximumSizeMinus15:]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload4Addr1ToAddr2},
		},
		{
			name: "Two fragments with MF flag reassembled into a maximum UDP packet",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload4Addr1ToAddr2[:udpMaximumSizeMinus15]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = udpMaximumSizeMinus15/8, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0,
							udpMaximumSizeMinus15 >> 8,
							(udpMaximumSizeMinus15 & 0xff) + 1,
							0, 0, 0, 1},

						ipv6Payload4Addr1ToAddr2[udpMaximumSizeMinus15:]...,
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with per-fragment routing header with zero segments left",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: routingExtHdrID,
					data: append(
						// Routing extension header.
						//
						// Segments left = 0.
						[]byte{fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5},
						append(
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
							ipv6Payload1Addr1ToAddr2[:64]...,
						)...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: routingExtHdrID,
					data: append(
						// Routing extension header.
						//
						// Segments left = 0.
						[]byte{fragmentExtHdrID, 0, 1, 0, 2, 3, 4, 5},
						append(
							// Fragment extension header.
							//
							// Fragment offset = 8, More = false, ID = 1
							[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},
							ipv6Payload1Addr1ToAddr2[64:]...,
						)...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with per-fragment routing header with non-zero segments left",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: routingExtHdrID,
					data: append(
						// Routing extension header.
						//
						// Segments left = 1.
						[]byte{fragmentExtHdrID, 0, 1, 1, 2, 3, 4, 5},
						append(
							// Fragment extension header.
							//
							// Fragment offset = 0, More = true, ID = 1
							[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
							ipv6Payload1Addr1ToAddr2[:64]...,
						)...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: routingExtHdrID,
					data: append(
						// Routing extension header.
						//
						// Segments left = 1.
						[]byte{fragmentExtHdrID, 0, 1, 1, 2, 3, 4, 5},

						append(
							// Fragment extension header.
							//
							// Fragment offset = 9, More = false, ID = 1
							[]byte{uint8(header.UDPProtocolNumber), 0, 0, 72, 0, 0, 0, 1},
							ipv6Payload1Addr1ToAddr2[64:]...,
						)...,
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with zero segments left",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1},
						append(
							// Routing extension header.
							//
							// Segments left = 0.
							[]byte{uint8(header.UDPProtocolNumber), 0, 1, 0, 2, 3, 4, 5},
							ipv6Payload1Addr1ToAddr2[:64]...,
						)...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 9, More = false, ID = 1
						[]byte{routingExtHdrID, 0, 0, 72, 0, 0, 0, 1},

						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with routing header with non-zero segments left",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1},
						append(
							// Routing extension header.
							//
							// Segments left = 1.
							[]byte{uint8(header.UDPProtocolNumber), 0, 1, 1, 2, 3, 4, 5},
							ipv6Payload1Addr1ToAddr2[:64]...,
						)...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 9, More = false, ID = 1
						[]byte{routingExtHdrID, 0, 0, 72, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with zero segments left across fragments",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment offset = 0, More = true, ID = 1
						[]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1},
						// Routing extension header (part 1)
						//
						// Segments left = 0.
						[]byte{uint8(header.UDPProtocolNumber), 1, 1, 0, 2, 3, 4, 5}...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 1, More = false, ID = 1
						[]byte{routingExtHdrID, 0, 0, 8, 0, 0, 0, 1},
						append(
							// Routing extension header (part 2)
							[]byte{6, 7, 8, 9, 10, 11, 12, 13},
							ipv6Payload1Addr1ToAddr2...,
						)...,
					),
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with routing header with non-zero segments left across fragments",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{routingExtHdrID, 0, 0, 1, 0, 0, 0, 1},

						// Routing extension header (part 1)
						//
						// Segments left = 1.
						[]byte{uint8(header.UDPProtocolNumber), 1, 1, 1, 2, 3, 4, 5}...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 1, More = false, ID = 1
						[]byte{routingExtHdrID, 0, 0, 8, 0, 0, 0, 1},
						append(
							// Routing extension header (part 2)
							[]byte{6, 7, 8, 9, 10, 11, 12, 13},
							ipv6Payload1Addr1ToAddr2...,
						)...,
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
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[:64]...,
					),
				},
				// This fragment has the same ID as the other fragments but is an atomic
				// fragment. It should not interfere with the other fragments.
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 0, 0, 0, 0, 1},
						ipv6Payload2Addr1ToAddr2...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},

						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload2Addr1ToAddr2, udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two interleaved fragmented packets",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[:64]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 2
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 2},
						ipv6Payload2Addr1ToAddr2[:32]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 4, More = false, ID = 2
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 32, 0, 0, 0, 2},
						ipv6Payload2Addr1ToAddr2[32:]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload2Addr1ToAddr2},
		},
		{
			name: "Two interleaved fragmented packets from different sources but with same ID",
			fragments: []fragmentData{
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},

						ipv6Payload1Addr1ToAddr2[:64]...,
					),
				},
				{
					srcAddr: addr3,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 0, More = true, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
						ipv6Payload1Addr3ToAddr2[:32]...,
					),
				},
				{
					srcAddr: addr1,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 8, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},
						ipv6Payload1Addr1ToAddr2[64:]...,
					),
				},
				{
					srcAddr: addr3,
					dstAddr: addr2,
					nextHdr: fragmentExtHdrID,
					data: append(
						// Fragment extension header.
						//
						// Fragment offset = 4, More = false, ID = 1
						[]byte{uint8(header.UDPProtocolNumber), 0, 0, 32, 0, 0, 0, 1},
						ipv6Payload1Addr3ToAddr2[32:]...,
					),
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload1Addr3ToAddr2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			e := channel.New(0, header.IPv6MinimumMTU, linkAddr1)
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
			wq.EventRegister(&we)
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
				hdr := prependable.New(header.IPv6MinimumSize)

				// Serialize IPv6 fixed header.
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(len(f.data)),
					// We're lying about transport protocol here so that we can generate
					// raw extension headers for the tests.
					TransportProtocol: tcpip.TransportProtocolNumber(f.nextHdr),
					HopLimit:          255,
					SrcAddr:           f.srcAddr,
					DstAddr:           f.dstAddr,
				})

				buf := buffer.MakeWithData(hdr.View())
				buf.Append(buffer.NewViewWithData(f.data))
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buf,
				})
				e.InjectInbound(ProtocolNumber, pkt)
				pkt.DecRef()
			}

			if got, want := s.Stats().UDP.PacketsReceived.Value(), uint64(len(test.expectedPayloads)); got != want {
				t.Errorf("got UDP Rx Packets = %d, want = %d", got, want)
			}

			for i, p := range test.expectedPayloads {
				var buf bytes.Buffer
				_, err := ep.Read(&buf, tcpip.ReadOptions{})
				if err != nil {
					t.Fatalf("(i=%d) Read: %s", i, err)
				}
				if diff := cmp.Diff(p, buf.Bytes()); diff != "" {
					t.Errorf("(i=%d) got UDP payload mismatch (-want +got):\n%s", i, diff)
				}
			}

			res, err := ep.Read(ioutil.Discard, tcpip.ReadOptions{})
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				t.Fatalf("(last) got Read = (%v, %v), want = (_, %s)", res, err, &tcpip.ErrWouldBlock{})
			}
		})
	}
}

func TestConcurrentFragmentWrites(t *testing.T) {
	const udpPayload1Length = 256
	const udpPayload2Length = 128
	var udpPayload1Addr1ToAddr2Buf [udpPayload1Length]byte
	udpPayload1Addr1ToAddr2 := udpPayload1Addr1ToAddr2Buf[:]
	ipv6Payload1Addr1ToAddr2 := udpGen(udpPayload1Addr1ToAddr2, 1, addr1, addr2)

	var udpPayload2Addr1ToAddr2Buf [udpPayload2Length]byte
	udpPayload2Addr1ToAddr2 := udpPayload2Addr1ToAddr2Buf[:]
	ipv6Payload2Addr1ToAddr2 := udpGen(udpPayload2Addr1ToAddr2, 2, addr1, addr2)

	fragments := []fragmentData{
		{
			srcAddr: addr1,
			dstAddr: addr2,
			nextHdr: fragmentExtHdrID,
			data: append(
				// Fragment extension header.
				//
				// Fragment offset = 0, More = true, ID = 1
				[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 1},
				ipv6Payload1Addr1ToAddr2[:64]...,
			),
		},
		{
			srcAddr: addr1,
			dstAddr: addr2,
			nextHdr: fragmentExtHdrID,
			data: append(
				// Fragment extension header.
				//
				// Fragment offset = 0, More = true, ID = 2
				[]byte{uint8(header.UDPProtocolNumber), 0, 0, 1, 0, 0, 0, 2},
				ipv6Payload2Addr1ToAddr2[:32]...,
			),
		},
		{
			srcAddr: addr1,
			dstAddr: addr2,
			nextHdr: fragmentExtHdrID,
			data: append(
				// Fragment extension header.
				//
				// Fragment offset = 8, More = false, ID = 1
				[]byte{uint8(header.UDPProtocolNumber), 0, 0, 64, 0, 0, 0, 1},
				ipv6Payload1Addr1ToAddr2[64:]...,
			),
		},
	}

	c := newTestContext()
	defer c.cleanup()
	s := c.s

	e := channel.New(0, header.IPv6MinimumMTU, linkAddr1)
	defer e.Close()
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ProtocolNumber,
		AddressWithPrefix: addr2.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
	}

	wq := waiter.Queue{}
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
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

	var wg sync.WaitGroup
	defer wg.Wait()
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				for _, f := range fragments {
					hdr := prependable.New(header.IPv6MinimumSize)

					// Serialize IPv6 fixed header.
					ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
					ip.Encode(&header.IPv6Fields{
						PayloadLength: uint16(len(f.data)),
						// We're lying about transport protocol here so that we can generate
						// raw extension headers for the tests.
						TransportProtocol: tcpip.TransportProtocolNumber(f.nextHdr),
						HopLimit:          255,
						SrcAddr:           f.srcAddr,
						DstAddr:           f.dstAddr,
					})

					buf := buffer.MakeWithData(hdr.View())
					buf.Append(buffer.NewViewWithData(f.data))
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload: buf,
					})
					e.InjectInbound(ProtocolNumber, pkt)
					pkt.DecRef()
				}
			}
		}()
	}
}

func TestInvalidIPv6Fragments(t *testing.T) {
	const (
		linkAddr1 = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
		nicID     = 1
		hoplimit  = 255
		ident     = 1
		data      = "TEST_INVALID_IPV6_FRAGMENTS"
	)

	var (
		addr1 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"))
		addr2 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"))
	)

	type fragmentData struct {
		ipv6Fields         header.IPv6Fields
		ipv6FragmentFields header.IPv6SerializableFragmentExtHdr
		payload            []byte
	}

	tests := []struct {
		name                   string
		fragments              []fragmentData
		wantMalformedIPPackets uint64
		wantMalformedFragments uint64
		expectICMP             bool
		expectICMPType         header.ICMPv6Type
		expectICMPCode         header.ICMPv6Code
		expectICMPTypeSpecific uint32
	}{
		{
			name: "fragment size is not a multiple of 8 and the M flag is true",
			fragments: []fragmentData{
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     header.IPv6FragmentHeaderSize + 9,
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 0 >> 3,
						M:              true,
						Identification: ident,
					},
					payload: []byte(data)[:9],
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
			expectICMP:             true,
			expectICMPType:         header.ICMPv6ParamProblem,
			expectICMPCode:         header.ICMPv6ErroneousHeader,
			expectICMPTypeSpecific: header.IPv6PayloadLenOffset,
		},
		{
			name: "fragments reassembled into a payload exceeding the max IPv6 payload size",
			fragments: []fragmentData{
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     header.IPv6FragmentHeaderSize + 16,
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: ((header.IPv6MaximumPayloadSize + 1) - 16) >> 3,
						M:              false,
						Identification: ident,
					},
					payload: []byte(data)[:16],
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
			expectICMP:             true,
			expectICMPType:         header.ICMPv6ParamProblem,
			expectICMPCode:         header.ICMPv6ErroneousHeader,
			expectICMPTypeSpecific: header.IPv6MinimumSize + 2, /* offset for 'Fragment Offset' in the fragment header */
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			e := channel.New(1, 1500, linkAddr1)
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}
			s.SetRouteTable([]tcpip.Route{{
				Destination: header.IPv6EmptySubnet,
				NIC:         nicID,
			}})

			var expectICMPPayload []byte
			for _, f := range test.fragments {
				hdr := prependable.New(header.IPv6MinimumSize + header.IPv6FragmentHeaderSize)

				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize + header.IPv6FragmentHeaderSize))
				encodeArgs := f.ipv6Fields
				encodeArgs.ExtensionHeaders = append(encodeArgs.ExtensionHeaders, &f.ipv6FragmentFields)
				ip.Encode(&encodeArgs)

				buf := buffer.MakeWithData(append(hdr.View(), f.payload...))
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buf,
				})

				if test.expectICMP {
					payload := stack.PayloadSince(pkt.NetworkHeader())
					defer payload.Release()
					expectICMPPayload = payload.AsSlice()
				}

				e.InjectInbound(ProtocolNumber, pkt)
				pkt.DecRef()
			}

			if got, want := s.Stats().IP.MalformedPacketsReceived.Value(), test.wantMalformedIPPackets; got != want {
				t.Errorf("got Stats.IP.MalformedPacketsReceived = %d, want = %d", got, want)
			}
			if got, want := s.Stats().IP.MalformedFragmentsReceived.Value(), test.wantMalformedFragments; got != want {
				t.Errorf("got Stats.IP.MalformedFragmentsReceived = %d, want = %d", got, want)
			}

			reply := e.Read()
			if !test.expectICMP {
				if !reply.IsNil() {
					t.Fatalf("unexpected ICMP error message received: %#v", reply)
				}
				return
			}
			if reply.IsNil() {
				t.Fatal("expected ICMP error message missing")
			}

			payload := stack.PayloadSince(reply.NetworkHeader())
			defer payload.Release()
			checker.IPv6(t, payload,
				checker.SrcAddr(addr2),
				checker.DstAddr(addr1),
				checker.IPFullLength(uint16(header.IPv6MinimumSize+header.ICMPv6MinimumSize+len(expectICMPPayload))),
				checker.ICMPv6(
					checker.ICMPv6Type(test.expectICMPType),
					checker.ICMPv6Code(test.expectICMPCode),
					checker.ICMPv6TypeSpecific(test.expectICMPTypeSpecific),
					checker.ICMPv6Payload(expectICMPPayload),
				),
			)
			reply.DecRef()
		})
	}
}

func TestFragmentReassemblyTimeout(t *testing.T) {
	const (
		linkAddr1 = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
		nicID     = 1
		hoplimit  = 255
		ident     = 1
		data      = "TEST_FRAGMENT_REASSEMBLY_TIMEOUT"
	)
	var (
		addr1 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"))
		addr2 = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"))
	)

	type fragmentData struct {
		ipv6Fields         header.IPv6Fields
		ipv6FragmentFields header.IPv6SerializableFragmentExtHdr
		payload            []byte
	}

	tests := []struct {
		name       string
		fragments  []fragmentData
		expectICMP bool
	}{
		{
			name: "first fragment only",
			fragments: []fragmentData{
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     header.IPv6FragmentHeaderSize + 16,
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 0,
						M:              true,
						Identification: ident,
					},
					payload: []byte(data)[:16],
				},
			},
			expectICMP: true,
		},
		{
			name: "two first fragments",
			fragments: []fragmentData{
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     header.IPv6FragmentHeaderSize + 16,
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 0,
						M:              true,
						Identification: ident,
					},
					payload: []byte(data)[:16],
				},
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     header.IPv6FragmentHeaderSize + 16,
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 0,
						M:              true,
						Identification: ident,
					},
					payload: []byte(data)[:16],
				},
			},
			expectICMP: true,
		},
		{
			name: "second fragment only",
			fragments: []fragmentData{
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     uint16(header.IPv6FragmentHeaderSize + len(data) - 16),
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 8,
						M:              false,
						Identification: ident,
					},
					payload: []byte(data)[16:],
				},
			},
			expectICMP: false,
		},
		{
			name: "two fragments with a gap",
			fragments: []fragmentData{
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     header.IPv6FragmentHeaderSize + 16,
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 0,
						M:              true,
						Identification: ident,
					},
					payload: []byte(data)[:16],
				},
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     uint16(header.IPv6FragmentHeaderSize + len(data) - 16),
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 8,
						M:              false,
						Identification: ident,
					},
					payload: []byte(data)[16:],
				},
			},
			expectICMP: true,
		},
		{
			name: "two fragments with a gap in reverse order",
			fragments: []fragmentData{
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     uint16(header.IPv6FragmentHeaderSize + len(data) - 16),
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 8,
						M:              false,
						Identification: ident,
					},
					payload: []byte(data)[16:],
				},
				{
					ipv6Fields: header.IPv6Fields{
						PayloadLength:     header.IPv6FragmentHeaderSize + 16,
						TransportProtocol: header.UDPProtocolNumber,
						HopLimit:          hoplimit,
						SrcAddr:           addr1,
						DstAddr:           addr2,
					},
					ipv6FragmentFields: header.IPv6SerializableFragmentExtHdr{
						FragmentOffset: 0,
						M:              true,
						Identification: ident,
					},
					payload: []byte(data)[:16],
				},
			},
			expectICMP: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			e := channel.New(1, 1500, linkAddr1)
			defer e.Close()
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}
			s.SetRouteTable([]tcpip.Route{{
				Destination: header.IPv6EmptySubnet,
				NIC:         nicID,
			}})

			var firstFragmentSent []byte
			for _, f := range test.fragments {
				hdr := prependable.New(header.IPv6MinimumSize + header.IPv6FragmentHeaderSize)

				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize + header.IPv6FragmentHeaderSize))
				encodeArgs := f.ipv6Fields
				encodeArgs.ExtensionHeaders = append(encodeArgs.ExtensionHeaders, &f.ipv6FragmentFields)
				ip.Encode(&encodeArgs)

				fragHDR := header.IPv6Fragment(hdr.View()[header.IPv6MinimumSize:])

				buf := buffer.MakeWithData(append(hdr.View(), f.payload...))
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buf,
				})

				if firstFragmentSent == nil && fragHDR.FragmentOffset() == 0 {
					payload := stack.PayloadSince(pkt.NetworkHeader())
					defer payload.Release()
					firstFragmentSent = payload.AsSlice()
				}

				e.InjectInbound(ProtocolNumber, pkt)
				pkt.DecRef()
			}

			c.clock.Advance(ReassembleTimeout)

			reply := e.Read()
			if !test.expectICMP {
				if !reply.IsNil() {
					t.Fatalf("unexpected ICMP error message received: %#v", reply)
				}
				return
			}
			if reply.IsNil() {
				t.Fatal("expected ICMP error message missing")
			}
			if firstFragmentSent == nil {
				t.Fatalf("unexpected ICMP error message received: %#v", reply)
			}

			payload := stack.PayloadSince(reply.NetworkHeader())
			defer payload.Release()
			checker.IPv6(t, payload,
				checker.SrcAddr(addr2),
				checker.DstAddr(addr1),
				checker.IPFullLength(uint16(header.IPv6MinimumSize+header.ICMPv6MinimumSize+len(firstFragmentSent))),
				checker.ICMPv6(
					checker.ICMPv6Type(header.ICMPv6TimeExceeded),
					checker.ICMPv6Code(header.ICMPv6ReassemblyTimeout),
					checker.ICMPv6Payload(firstFragmentSent),
				),
			)
			reply.DecRef()
		})
	}
}

func TestWriteStats(t *testing.T) {
	const nPackets = 3
	tests := []struct {
		name                     string
		setup                    func(*testing.T, *stack.Stack)
		allowPackets             int
		expectSent               int
		expectOutputDropped      int
		expectPostroutingDropped int
		expectWritten            int
	}{
		{
			name: "Accept all",
			// No setup needed, tables accept everything by default.
			setup:                    func(*testing.T, *stack.Stack) {},
			allowPackets:             math.MaxInt32,
			expectSent:               nPackets,
			expectOutputDropped:      0,
			expectPostroutingDropped: 0,
			expectWritten:            nPackets,
		}, {
			name: "Accept all with error",
			// No setup needed, tables accept everything by default.
			setup:                    func(*testing.T, *stack.Stack) {},
			allowPackets:             nPackets - 1,
			expectSent:               nPackets - 1,
			expectOutputDropped:      0,
			expectPostroutingDropped: 0,
			expectWritten:            nPackets - 1,
		}, {
			name: "Drop all with Output chain",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule.
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.FilterID, true /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				ipt.ForceReplaceTable(stack.FilterID, filter, true /* ipv6 */)
			},
			allowPackets:             math.MaxInt32,
			expectSent:               0,
			expectOutputDropped:      nPackets,
			expectPostroutingDropped: 0,
			expectWritten:            nPackets,
		}, {
			name: "Drop all with Postrouting chain",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule.
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.NATID, true /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Postrouting]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				ipt.ForceReplaceTable(stack.NATID, filter, true /* ipv6 */)
			},
			allowPackets:             math.MaxInt32,
			expectSent:               0,
			expectOutputDropped:      0,
			expectPostroutingDropped: nPackets,
			expectWritten:            nPackets,
		}, {
			name: "Drop some with Output chain",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule that matches only 1
				// of the 3 packets.
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.FilterID, true /* ipv6 */)
				// We'll match and DROP the last packet.
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&limitedMatcher{nPackets - 1}}
				// Make sure the next rule is ACCEPT.
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				ipt.ForceReplaceTable(stack.FilterID, filter, true /* ipv6 */)
			},
			allowPackets:             math.MaxInt32,
			expectSent:               nPackets - 1,
			expectOutputDropped:      1,
			expectPostroutingDropped: 0,
			expectWritten:            nPackets,
		}, {
			name: "Drop some with Postrouting chain",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Postrouting DROP rule that matches only 1
				// of the 3 packets.
				ipt := stk.IPTables()
				filter := ipt.GetTable(stack.NATID, true /* ipv6 */)
				// We'll match and DROP the last packet.
				ruleIdx := filter.BuiltinChains[stack.Postrouting]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&limitedMatcher{nPackets - 1}}
				// Make sure the next rule is ACCEPT.
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				ipt.ForceReplaceTable(stack.NATID, filter, true /* ipv6 */)
			},
			allowPackets:             math.MaxInt32,
			expectSent:               nPackets - 1,
			expectOutputDropped:      0,
			expectPostroutingDropped: 1,
			expectWritten:            nPackets,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()

			ep := iptestutil.NewMockLinkEndpoint(header.IPv6MinimumMTU, &tcpip.ErrInvalidEndpointState{}, test.allowPackets)
			defer ep.Close()

			rt := buildRoute(t, c, ep)
			defer rt.Release()
			test.setup(t, rt.Stack())

			nWritten := 0
			for i := 0; i < nPackets; i++ {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.UDPMinimumSize + int(rt.MaxHeaderLength()),
					Payload:            buffer.Buffer{},
				})
				defer pkt.DecRef()
				pkt.TransportHeader().Push(header.UDPMinimumSize)
				if err := rt.WritePacket(stack.NetworkHeaderParams{}, pkt); err != nil {
					break
				}
				nWritten++
			}

			if got := int(rt.Stats().IP.PacketsSent.Value()); got != test.expectSent {
				t.Errorf("got rt.Stats().IP.PacketsSent.Value() = %d, want = %d", got, test.expectSent)
			}
			if got := int(rt.Stats().IP.IPTablesOutputDropped.Value()); got != test.expectOutputDropped {
				t.Errorf("got rt.Stats().IP.IPTablesOutputDropped.Value() = %d, want = %d", got, test.expectOutputDropped)
			}
			if got := int(rt.Stats().IP.IPTablesPostroutingDropped.Value()); got != test.expectPostroutingDropped {
				t.Errorf("got r.Stats().IP.IPTablesPostroutingDropped.Value() = %d, want = %d", got, test.expectPostroutingDropped)
			}
			if nWritten != test.expectWritten {
				t.Errorf("got nWritten = %d, want = %d", nWritten, test.expectWritten)
			}
		})
	}
}

func buildRoute(t *testing.T, c testContext, ep stack.LinkEndpoint) *stack.Route {
	s := c.s
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC(1, _) failed: %s", err)
	}
	var (
		src = tcpip.AddrFromSlice([]byte("\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"))
		dst = tcpip.AddrFromSlice([]byte("\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"))
	)
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ProtocolNumber,
		AddressWithPrefix: src.WithPrefix(),
	}
	if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", 1, protocolAddr, err)
	}
	{
		mask := tcpip.MaskFrom("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
		subnet, err := tcpip.NewSubnet(dst, mask)
		if err != nil {
			t.Fatalf("NewSubnet(%s, %s) failed: %v", dst, mask, err)
		}
		s.SetRouteTable([]tcpip.Route{{
			Destination: subnet,
			NIC:         1,
		}})
	}
	rt, err := s.FindRoute(1, src, dst, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(1, %s, %s, %d, false) = %s, want = nil", src, dst, ProtocolNumber, err)
	}
	return rt
}

// limitedMatcher is an iptables matcher that matches after a certain number of
// packets are checked against it.
type limitedMatcher struct {
	limit int
}

// Name implements Matcher.Name.
func (*limitedMatcher) Name() string {
	return "limitedMatcher"
}

// Match implements Matcher.Match.
func (lm *limitedMatcher) Match(stack.Hook, stack.PacketBufferPtr, string, string) (bool, bool) {
	if lm.limit == 0 {
		return true, false
	}
	lm.limit--
	return false, false
}

func knownNICIDs(proto *protocol) []tcpip.NICID {
	var nicIDs []tcpip.NICID

	for k := range proto.mu.eps {
		nicIDs = append(nicIDs, k)
	}

	return nicIDs
}

func TestClearEndpointFromProtocolOnClose(t *testing.T) {
	c := newTestContext()
	defer c.cleanup()
	s := c.s

	proto := s.NetworkProtocolInstance(ProtocolNumber).(*protocol)
	var nic testInterface
	ep := proto.NewEndpoint(&nic, nil).(*endpoint)
	var nicIDs []tcpip.NICID

	proto.mu.Lock()
	foundEP, hasEndpointBeforeClose := proto.mu.eps[nic.ID()]
	nicIDs = knownNICIDs(proto)
	proto.mu.Unlock()
	if !hasEndpointBeforeClose {
		t.Fatalf("expected to find the nic id %d in the protocol's known nic ids (%v)", nic.ID(), nicIDs)
	}
	if foundEP != ep {
		t.Fatalf("found an incorrect endpoint mapped to nic id %d", nic.ID())
	}

	ep.Close()

	proto.mu.Lock()
	_, hasEndpointAfterClose := proto.mu.eps[nic.ID()]
	nicIDs = knownNICIDs(proto)
	proto.mu.Unlock()
	if hasEndpointAfterClose {
		t.Fatalf("unexpectedly found an endpoint mapped to the nic id %d in the protocol's known nic ids (%v)", nic.ID(), nicIDs)
	}
}

type fragmentInfo struct {
	offset      uint16
	more        bool
	payloadSize uint16
}

var fragmentationTests = []struct {
	description   string
	mtu           uint32
	transHdrLen   int
	payloadSize   int
	wantFragments []fragmentInfo
}{
	{
		description: "No fragmentation",
		mtu:         header.IPv6MinimumMTU,
		transHdrLen: 0,
		payloadSize: 1000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1000, more: false},
		},
	},
	{
		description: "Fragmented",
		mtu:         header.IPv6MinimumMTU,
		transHdrLen: 0,
		payloadSize: 2000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1240, more: true},
			{offset: 154, payloadSize: 776, more: false},
		},
	},
	{
		description: "Fragmented with mtu not a multiple of 8",
		mtu:         header.IPv6MinimumMTU + 1,
		transHdrLen: 0,
		payloadSize: 2000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1240, more: true},
			{offset: 154, payloadSize: 776, more: false},
		},
	},
	{
		description: "No fragmentation with big header",
		mtu:         2000,
		transHdrLen: 100,
		payloadSize: 1000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1100, more: false},
		},
	},
	{
		description: "Fragmented with big header",
		mtu:         header.IPv6MinimumMTU,
		transHdrLen: 100,
		payloadSize: 1200,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1240, more: true},
			{offset: 154, payloadSize: 76, more: false},
		},
	},
}

func TestFragmentationWritePacket(t *testing.T) {
	const ttl = 42

	for _, ft := range fragmentationTests {
		t.Run(ft.description, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()

			pkt := iptestutil.MakeRandPkt(ft.transHdrLen, extraHeaderReserve+header.IPv6MinimumSize, []int{ft.payloadSize}, header.IPv6ProtocolNumber)
			defer pkt.DecRef()
			source := pkt.Clone()
			defer source.DecRef()

			ep := iptestutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
			defer ep.Close()

			r := buildRoute(t, c, ep)
			defer r.Release()
			err := r.WritePacket(stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != nil {
				t.Fatalf("WritePacket(_, _, _): = %s", err)
			}
			if got := len(ep.WrittenPackets); got != len(ft.wantFragments) {
				t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, len(ft.wantFragments))
			}
			if got := int(r.Stats().IP.PacketsSent.Value()); got != len(ft.wantFragments) {
				t.Errorf("got c.Route.Stats().IP.PacketsSent.Value() = %d, want = %d", got, len(ft.wantFragments))
			}
			if got := r.Stats().IP.OutgoingPacketErrors.Value(); got != 0 {
				t.Errorf("got r.Stats().IP.OutgoingPacketErrors.Value() = %d, want = 0", got)
			}
			if err := compareFragments(ep.WrittenPackets, source, ft.mtu, ft.wantFragments, tcp.ProtocolNumber); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestFragmentationErrors checks that errors are returned from WritePacket
// correctly.
func TestFragmentationErrors(t *testing.T) {
	const ttl = 42

	tests := []struct {
		description    string
		mtu            uint32
		transHdrLen    int
		payloadSize    int
		allowPackets   int
		outgoingErrors int
		mockError      tcpip.Error
		wantError      tcpip.Error
	}{
		{
			description:    "No frag",
			mtu:            2000,
			payloadSize:    1000,
			transHdrLen:    0,
			allowPackets:   0,
			outgoingErrors: 1,
			mockError:      &tcpip.ErrAborted{},
			wantError:      &tcpip.ErrAborted{},
		},
		{
			description:    "Error on first frag",
			mtu:            1300,
			payloadSize:    3000,
			transHdrLen:    0,
			allowPackets:   0,
			outgoingErrors: 3,
			mockError:      &tcpip.ErrAborted{},
			wantError:      &tcpip.ErrAborted{},
		},
		{
			description:    "Error on second frag",
			mtu:            1500,
			payloadSize:    4000,
			transHdrLen:    0,
			allowPackets:   1,
			outgoingErrors: 2,
			mockError:      &tcpip.ErrAborted{},
			wantError:      &tcpip.ErrAborted{},
		},
		{
			description:    "Error when MTU is smaller than transport header",
			mtu:            header.IPv6MinimumMTU,
			transHdrLen:    1500,
			payloadSize:    500,
			allowPackets:   0,
			outgoingErrors: 1,
			mockError:      nil,
			wantError:      &tcpip.ErrMessageTooLong{},
		},
		{
			description:    "Error when MTU is smaller than IPv6 minimum MTU",
			mtu:            header.IPv6MinimumMTU - 1,
			transHdrLen:    0,
			payloadSize:    500,
			allowPackets:   0,
			outgoingErrors: 1,
			mockError:      nil,
			wantError:      &tcpip.ErrInvalidEndpointState{},
		},
	}

	for _, ft := range tests {
		t.Run(ft.description, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()

			pkt := iptestutil.MakeRandPkt(ft.transHdrLen, extraHeaderReserve+header.IPv6MinimumSize, []int{ft.payloadSize}, header.IPv6ProtocolNumber)
			defer pkt.DecRef()
			ep := iptestutil.NewMockLinkEndpoint(ft.mtu, ft.mockError, ft.allowPackets)
			defer ep.Close()

			r := buildRoute(t, c, ep)
			defer r.Release()
			err := r.WritePacket(stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if diff := cmp.Diff(ft.wantError, err); diff != "" {
				t.Errorf("unexpected error from WritePacket(_, _, _), (-want, +got):\n%s", diff)
			}
			if got := int(r.Stats().IP.PacketsSent.Value()); got != ft.allowPackets {
				t.Errorf("got r.Stats().IP.PacketsSent.Value() = %d, want = %d", got, ft.allowPackets)
			}
			if got := int(r.Stats().IP.OutgoingPacketErrors.Value()); got != ft.outgoingErrors {
				t.Errorf("got r.Stats().IP.OutgoingPacketErrors.Value() = %d, want = %d", got, ft.outgoingErrors)
			}
		})
	}
}

type icmpError struct {
	icmpType header.ICMPv6Type
	icmpCode header.ICMPv6Code
}

const (
	incomingNICID  = 1
	outgoingNICID  = 2
	randomSequence = 123
	randomIdent    = 42
)

var (
	incomingIPv6Addr = tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(net.ParseIP("10::1").To16()),
		PrefixLen: 64,
	}
	outgoingIPv6Addr = tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(net.ParseIP("11::1").To16()),
		PrefixLen: 64,
	}
	multicastIPv6Addr = tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(net.ParseIP("ff00::").To16()),
		PrefixLen: 64,
	}
	remoteIPv6Addr1        = tcpip.AddrFromSlice(net.ParseIP("10::2").To16())
	remoteIPv6Addr2        = tcpip.AddrFromSlice(net.ParseIP("11::2").To16())
	unreachableIPv6Addr    = tcpip.AddrFromSlice(net.ParseIP("12::2").To16())
	linkLocalIPv6Addr      = tcpip.AddrFromSlice(net.ParseIP("fe80::").To16())
	defaultEndpointConfigs = map[tcpip.NICID]tcpip.AddressWithPrefix{
		incomingNICID: incomingIPv6Addr,
		outgoingNICID: outgoingIPv6Addr,
	}
)

func TestForwarding(t *testing.T) {
	tests := []struct {
		name                             string
		extHdr                           func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker)
		TTL                              uint8
		payloadLength                    int
		srcAddr                          tcpip.Address
		dstAddr                          tcpip.Address
		expectedPacketUnrouteableErrors  uint64
		expectedInitializingSourceErrors uint64
		expectedLinkLocalSourceErrors    uint64
		expectedLinkLocalDestErrors      uint64
		expectedExtensionHeaderErrors    uint64
		expectedPacketTooBigErrors       uint64
		expectedExhaustedTTLErrors       uint64
		expectPacketForwarded            bool
		expectedFragmentsForwarded       []fragmentInfo
		expectedICMPError                *icmpError
	}{
		{
			name:    "TTL of zero",
			TTL:     0,
			srcAddr: remoteIPv6Addr1,
			dstAddr: remoteIPv6Addr2,
			expectedICMPError: &icmpError{
				icmpType: header.ICMPv6TimeExceeded,
				icmpCode: header.ICMPv6HopLimitExceeded,
			},
			expectedExhaustedTTLErrors: 1,
			expectPacketForwarded:      false,
		},
		{
			name:    "TTL of one",
			TTL:     1,
			srcAddr: remoteIPv6Addr1,
			dstAddr: remoteIPv6Addr2,
			expectedICMPError: &icmpError{
				icmpType: header.ICMPv6TimeExceeded,
				icmpCode: header.ICMPv6HopLimitExceeded,
			},
			expectedExhaustedTTLErrors: 1,
			expectPacketForwarded:      false,
		},
		{
			name:                  "TTL of two",
			TTL:                   2,
			srcAddr:               remoteIPv6Addr1,
			dstAddr:               remoteIPv6Addr2,
			expectPacketForwarded: true,
		},
		{
			name:                  "TTL of three",
			TTL:                   3,
			srcAddr:               remoteIPv6Addr1,
			dstAddr:               remoteIPv6Addr2,
			expectPacketForwarded: true,
		},
		{
			name:                  "Max TTL",
			TTL:                   math.MaxUint8,
			srcAddr:               remoteIPv6Addr1,
			dstAddr:               remoteIPv6Addr2,
			expectPacketForwarded: true,
		},
		{
			name:    "Network unreachable",
			TTL:     2,
			srcAddr: remoteIPv6Addr1,
			dstAddr: unreachableIPv6Addr,
			expectedICMPError: &icmpError{
				icmpType: header.ICMPv6DstUnreachable,
				icmpCode: header.ICMPv6NetworkUnreachable,
			},
			expectedPacketUnrouteableErrors: 1,
			expectPacketForwarded:           false,
		},
		{
			name:                        "Link local destination",
			TTL:                         2,
			srcAddr:                     remoteIPv6Addr1,
			dstAddr:                     linkLocalIPv6Addr,
			expectedLinkLocalDestErrors: 1,
			expectPacketForwarded:       false,
		},
		{
			name:                          "Link local source",
			TTL:                           2,
			srcAddr:                       linkLocalIPv6Addr,
			dstAddr:                       remoteIPv6Addr2,
			expectedLinkLocalSourceErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name:                             "Unspecified source",
			TTL:                              2,
			srcAddr:                          header.IPv6Any,
			dstAddr:                          remoteIPv6Addr2,
			expectedInitializingSourceErrors: 1,
			expectPacketForwarded:            false,
		},
		{
			name:    "Hopbyhop with unknown option skippable action",
			TTL:     2,
			srcAddr: remoteIPv6Addr1,
			dstAddr: remoteIPv6Addr2,
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Skippable unknown.
					62, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID, checker.IPv6ExtHdr(checker.IPv6HopByHopExtensionHeader(checker.IPv6UnknownOption(), checker.IPv6UnknownOption()))
			},
			expectPacketForwarded: true,
		},
		{
			name:    "Hopbyhop with unknown option discard action",
			TTL:     2,
			srcAddr: remoteIPv6Addr1,
			dstAddr: remoteIPv6Addr2,
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard unknown.
					127, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID, nil
			},
			expectedExtensionHeaderErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name:    "Hopbyhop with unknown option discard and send icmp action",
			TTL:     2,
			srcAddr: remoteIPv6Addr1,
			dstAddr: remoteIPv6Addr2,
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID, nil
			},
			expectedICMPError: &icmpError{
				icmpType: header.ICMPv6ParamProblem,
				icmpCode: header.ICMPv6UnknownOption,
			},
			expectedExtensionHeaderErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name:    "Hopbyhop with unknown option discard and send icmp action",
			TTL:     2,
			srcAddr: remoteIPv6Addr1,
			dstAddr: remoteIPv6Addr2,
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID, nil
			},
			expectedICMPError: &icmpError{
				icmpType: header.ICMPv6ParamProblem,
				icmpCode: header.ICMPv6UnknownOption,
			},
			expectedExtensionHeaderErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name:    "Hopbyhop with router alert option",
			TTL:     2,
			srcAddr: remoteIPv6Addr1,
			dstAddr: remoteIPv6Addr2,
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 0,

					// Router Alert option.
					5, 2, 0, 0, 0, 0,
				}, hopByHopExtHdrID, checker.IPv6ExtHdr(checker.IPv6HopByHopExtensionHeader(checker.IPv6RouterAlert(header.IPv6RouterAlertMLD)))
			},
			expectPacketForwarded: true,
		},
		{
			name:    "Hopbyhop with two router alert options",
			TTL:     2,
			srcAddr: remoteIPv6Addr1,
			dstAddr: remoteIPv6Addr2,
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Router Alert option.
					5, 2, 0, 0, 0, 0,

					// Router Alert option.
					5, 2, 0, 0, 0, 0,
				}, hopByHopExtHdrID, nil
			},
			expectedExtensionHeaderErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name:          "Can't fragment",
			TTL:           2,
			payloadLength: header.IPv6MinimumMTU + 1,
			srcAddr:       remoteIPv6Addr1,
			dstAddr:       remoteIPv6Addr2,
			expectedICMPError: &icmpError{
				icmpType: header.ICMPv6PacketTooBig,
				icmpCode: header.ICMPv6UnusedCode,
			},
			expectedPacketTooBigErrors: 1,
			expectPacketForwarded:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			endpoints := make(map[tcpip.NICID]*channel.Endpoint)
			for nicID, addr := range defaultEndpointConfigs {
				ep := channel.New(1, header.IPv6MinimumMTU, "")
				defer ep.Close()

				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{Protocol: ProtocolNumber, AddressWithPrefix: addr}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
				s.SetNICMulticastForwarding(nicID, ProtocolNumber, true /* enabled */)
				endpoints[nicID] = ep
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: incomingIPv6Addr.Subnet(),
					NIC:         incomingNICID,
				},
				{
					Destination: outgoingIPv6Addr.Subnet(),
					NIC:         outgoingNICID,
				},
				{
					Destination: multicastIPv6Addr.Subnet(),
					NIC:         outgoingNICID,
				},
			})

			if err := s.SetForwardingDefaultAndAllNICs(ProtocolNumber, true); err != nil {
				t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", ProtocolNumber, err)
			}

			transportProtocol := header.ICMPv6ProtocolNumber
			var extHdrBytes []byte
			extHdrChecker := checker.IPv6ExtHdr()
			if test.extHdr != nil {
				nextHdrID := hopByHopExtHdrID
				extHdrBytes, nextHdrID, extHdrChecker = test.extHdr(uint8(header.ICMPv6ProtocolNumber))
				transportProtocol = tcpip.TransportProtocolNumber(nextHdrID)
			}
			extHdrLen := len(extHdrBytes)

			ipHeaderLength := header.IPv6MinimumSize
			icmpHeaderLength := header.ICMPv6MinimumSize
			payloadLength := icmpHeaderLength + test.payloadLength + extHdrLen
			totalLength := ipHeaderLength + payloadLength
			hdr := prependable.New(totalLength)
			hdr.Prepend(test.payloadLength)
			icmpH := header.ICMPv6(hdr.Prepend(icmpHeaderLength))

			icmpH.SetIdent(randomIdent)
			icmpH.SetSequence(randomSequence)
			icmpH.SetType(header.ICMPv6EchoRequest)
			icmpH.SetCode(header.ICMPv6UnusedCode)
			icmpH.SetChecksum(0)
			icmpH.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpH,
				Src:    test.srcAddr,
				Dst:    test.dstAddr,
			}))
			copy(hdr.Prepend(extHdrLen), extHdrBytes)
			ip := header.IPv6(hdr.Prepend(ipHeaderLength))
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(payloadLength),
				TransportProtocol: transportProtocol,
				HopLimit:          test.TTL,
				SrcAddr:           test.srcAddr,
				DstAddr:           test.dstAddr,
			})
			request := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(hdr.View()),
			})

			incomingEndpoint, ok := endpoints[incomingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", incomingNICID)
			}

			incomingEndpoint.InjectInbound(ProtocolNumber, request)
			request.DecRef()

			reply := incomingEndpoint.Read()

			outgoingEndpoint, ok := endpoints[outgoingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
			}

			if test.expectedICMPError != nil {
				if reply.IsNil() {
					t.Fatalf("Expected ICMP packet type %d through incoming NIC", test.expectedICMPError.icmpType)
				}

				// As per RFC 4443, page 9:
				//
				//   The returned ICMP packet will contain as much of invoking packet
				//   as possible without the ICMPv6 packet exceeding the minimum IPv6
				//   MTU.
				expectedICMPPayloadLength := func() int {
					maxICMPPayloadLength := header.IPv6MinimumMTU - ipHeaderLength - icmpHeaderLength
					if len(hdr.View()) > maxICMPPayloadLength {
						return maxICMPPayloadLength
					}
					return len(hdr.View())
				}

				payload := stack.PayloadSince(reply.NetworkHeader())
				defer payload.Release()
				checker.IPv6(t, payload,
					checker.SrcAddr(incomingIPv6Addr.Address),
					checker.DstAddr(test.srcAddr),
					checker.TTL(DefaultTTL),
					checker.ICMPv6(
						checker.ICMPv6Type(test.expectedICMPError.icmpType),
						checker.ICMPv6Code(test.expectedICMPError.icmpCode),
						checker.ICMPv6Payload(hdr.View()[:expectedICMPPayloadLength()]),
					),
				)
				reply.DecRef()

				if n := outgoingEndpoint.Drain(); n != 0 {
					t.Fatalf("e2.Drain() = %d, want = 0", n)
				}
			} else if !reply.IsNil() {
				t.Fatalf("Expected no ICMP packet through incoming NIC, instead found: %#v", reply)
			}

			reply = outgoingEndpoint.Read()
			if test.expectPacketForwarded {
				if reply.IsNil() {
					t.Fatal("Expected ICMP Echo Request packet through outgoing NIC")
				}

				payload := stack.PayloadSince(reply.NetworkHeader())
				defer payload.Release()
				checker.IPv6WithExtHdr(t, payload,
					checker.SrcAddr(test.srcAddr),
					checker.DstAddr(test.dstAddr),
					checker.TTL(test.TTL-1),
					extHdrChecker,
					checker.ICMPv6(
						checker.ICMPv6Type(header.ICMPv6EchoRequest),
						checker.ICMPv6Code(header.ICMPv6UnusedCode),
						checker.ICMPv6Payload(nil),
					),
				)
				reply.DecRef()

				if n := incomingEndpoint.Drain(); n != 0 {
					t.Fatalf("e1.Drain() = %d, want = 0", n)
				}
			} else if !reply.IsNil() {
				t.Fatalf("Expected no ICMP Echo packet through outgoing NIC, instead found: %#v", reply)
			}

			if got, want := s.Stats().IP.Forwarding.InitializingSource.Value(), test.expectedInitializingSourceErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.InitializingSource.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.LinkLocalSource.Value(), test.expectedLinkLocalSourceErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.LinkLocalSource.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.LinkLocalDestination.Value(), test.expectedLinkLocalDestErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.LinkLocalDestination.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.ExhaustedTTL.Value(), test.expectedExhaustedTTLErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.ExhaustedTTL.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.Unrouteable.Value(), test.expectedPacketUnrouteableErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.Unrouteable.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.ExtensionHeaderProblem.Value(), test.expectedExtensionHeaderErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.ExtensionHeaderProblem.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.PacketTooBig.Value(), test.expectedPacketTooBigErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.PacketTooBig.Value() = %d, want = %d", got, want)
			}

			totalExpectedErrors := test.expectedPacketUnrouteableErrors + test.expectedPacketTooBigErrors + test.expectedExtensionHeaderErrors + test.expectedLinkLocalSourceErrors + test.expectedLinkLocalDestErrors + test.expectedExhaustedTTLErrors + test.expectedInitializingSourceErrors
			if got, want := s.Stats().IP.Forwarding.Errors.Value(), totalExpectedErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.Errors.Value() = %d, want = %d", got, want)
			}
		})
	}
}

func TestMulticastForwarding(t *testing.T) {
	const (
		multicastRouteMinTTL = 2
		packetTTL            = 2
	)

	tests := []struct {
		name                          string
		extHdr                        func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker)
		payloadLength                 int
		expectedExtensionHeaderErrors uint64
		expectedPacketTooBigErrors    uint64
		expectPacketForwarded         bool
		expectedICMPError             *icmpError
	}{
		{
			name: "Hopbyhop with unknown option skippable action",
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Skippable unknown.
					62, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID, checker.IPv6ExtHdr(checker.IPv6HopByHopExtensionHeader(checker.IPv6UnknownOption(), checker.IPv6UnknownOption()))
			},
			expectPacketForwarded: true,
		},
		{
			name: "Hopbyhop with unknown option discard action",
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard unknown.
					127, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID, nil
			},
			expectedExtensionHeaderErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name: "Hopbyhop with unknown option discard and send icmp action",
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP if option is unknown.
					191, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID, nil
			},
			expectedICMPError: &icmpError{
				icmpType: header.ICMPv6ParamProblem,
				icmpCode: header.ICMPv6UnknownOption,
			},
			expectedExtensionHeaderErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name: "Hopbyhop with unknown option discard and don't send icmp action for multicast",
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Skippable unknown.
					63, 4, 1, 2, 3, 4,

					// Discard & send ICMP unless packet is for multicast destination if
					// option is unknown.
					255, 6, 1, 2, 3, 4, 5, 6,
				}, hopByHopExtHdrID, nil
			},
			expectedExtensionHeaderErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name: "Hopbyhop with router alert option",
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 0,

					// Router Alert option.
					5, 2, 0, 0, 0, 0,
				}, hopByHopExtHdrID, checker.IPv6ExtHdr(checker.IPv6HopByHopExtensionHeader(checker.IPv6RouterAlert(header.IPv6RouterAlertMLD)))
			},
			expectPacketForwarded: true,
		},
		{
			name: "Hopbyhop with two router alert options",
			extHdr: func(nextHdr uint8) ([]byte, uint8, checker.NetworkChecker) {
				return []byte{
					nextHdr, 1,

					// Router Alert option.
					5, 2, 0, 0, 0, 0,

					// Router Alert option.
					5, 2, 0, 0, 0, 0,
				}, hopByHopExtHdrID, nil
			},
			expectedExtensionHeaderErrors: 1,
			expectPacketForwarded:         false,
		},
		{
			name:          "Can't fragment",
			payloadLength: header.IPv6MinimumMTU + 1,
			expectedICMPError: &icmpError{
				icmpType: header.ICMPv6PacketTooBig,
				icmpCode: header.ICMPv6UnusedCode,
			},
			expectedPacketTooBigErrors: 1,
			expectPacketForwarded:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTestContext()
			defer c.cleanup()
			s := c.s

			if _, err := s.EnableMulticastForwardingForProtocol(ProtocolNumber, &fakeMulticastEventDispatcher{}); err != nil {
				t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, _): (_, %s)", ProtocolNumber, err)
			}

			endpoints := make(map[tcpip.NICID]*channel.Endpoint)
			for nicID, addr := range defaultEndpointConfigs {
				ep := channel.New(1, header.IPv6MinimumMTU, "")
				defer ep.Close()

				if err := s.CreateNIC(nicID, ep); err != nil {
					t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
				}
				addr := tcpip.ProtocolAddress{Protocol: ProtocolNumber, AddressWithPrefix: addr}
				if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
					t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
				}
				s.SetNICMulticastForwarding(nicID, ProtocolNumber, true /* enabled */)
				endpoints[nicID] = ep
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         incomingNICID,
				},
			})

			srcAddr := remoteIPv6Addr1
			dstAddr := multicastIPv6Addr.Address

			outgoingInterfaces := []stack.MulticastRouteOutgoingInterface{
				{ID: outgoingNICID, MinTTL: multicastRouteMinTTL},
			}
			addresses := stack.UnicastSourceAndMulticastDestination{
				Source:      srcAddr,
				Destination: multicastIPv6Addr.Address,
			}

			route := stack.MulticastRoute{
				ExpectedInputInterface: incomingNICID,
				OutgoingInterfaces:     outgoingInterfaces,
			}

			if err := s.AddMulticastRoute(ProtocolNumber, addresses, route); err != nil {
				t.Fatalf("s.AddMulticastRoute(%d, %#v, %#v): = %s", ProtocolNumber, addresses, route, err)
			}

			transportProtocol := header.ICMPv6ProtocolNumber
			var extHdrBytes []byte
			extHdrChecker := checker.IPv6ExtHdr()
			if test.extHdr != nil {
				nextHdrID := hopByHopExtHdrID
				extHdrBytes, nextHdrID, extHdrChecker = test.extHdr(uint8(header.ICMPv6ProtocolNumber))
				transportProtocol = tcpip.TransportProtocolNumber(nextHdrID)
			}
			extHdrLen := len(extHdrBytes)

			ipHeaderLength := header.IPv6MinimumSize
			icmpHeaderLength := header.ICMPv6MinimumSize
			payloadLength := icmpHeaderLength + test.payloadLength + extHdrLen
			totalLength := ipHeaderLength + payloadLength
			hdr := prependable.New(totalLength)
			hdr.Prepend(test.payloadLength)
			icmpH := header.ICMPv6(hdr.Prepend(icmpHeaderLength))

			icmpH.SetIdent(randomIdent)
			icmpH.SetSequence(randomSequence)
			icmpH.SetType(header.ICMPv6EchoRequest)
			icmpH.SetCode(header.ICMPv6UnusedCode)
			icmpH.SetChecksum(0)
			icmpH.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpH,
				Src:    srcAddr,
				Dst:    dstAddr,
			}))
			copy(hdr.Prepend(extHdrLen), extHdrBytes)
			ip := header.IPv6(hdr.Prepend(ipHeaderLength))
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(payloadLength),
				TransportProtocol: transportProtocol,
				HopLimit:          packetTTL,
				SrcAddr:           srcAddr,
				DstAddr:           dstAddr,
			})
			request := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(hdr.View()),
			})

			incomingEndpoint, ok := endpoints[incomingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", incomingNICID)
			}

			incomingEndpoint.InjectInbound(ProtocolNumber, request)
			request.DecRef()

			reply := incomingEndpoint.Read()

			outgoingEndpoint, ok := endpoints[outgoingNICID]
			if !ok {
				t.Fatalf("endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
			}

			if test.expectedICMPError != nil {
				if reply.IsNil() {
					t.Fatalf("Expected ICMP packet type %d through incoming NIC", test.expectedICMPError.icmpType)
				}

				// As per RFC 4443, page 9:
				//
				//   The returned ICMP packet will contain as much of invoking packet
				//   as possible without the ICMPv6 packet exceeding the minimum IPv6
				//   MTU.
				expectedICMPPayloadLength := func() int {
					maxICMPPayloadLength := header.IPv6MinimumMTU - ipHeaderLength - icmpHeaderLength
					if len(hdr.View()) > maxICMPPayloadLength {
						return maxICMPPayloadLength
					}
					return len(hdr.View())
				}

				payload := stack.PayloadSince(reply.NetworkHeader())
				defer payload.Release()
				checker.IPv6(t, payload,
					checker.SrcAddr(incomingIPv6Addr.Address),
					checker.DstAddr(srcAddr),
					checker.TTL(DefaultTTL),
					checker.ICMPv6(
						checker.ICMPv6Type(test.expectedICMPError.icmpType),
						checker.ICMPv6Code(test.expectedICMPError.icmpCode),
						checker.ICMPv6Payload(hdr.View()[:expectedICMPPayloadLength()]),
					),
				)
				reply.DecRef()

				if n := outgoingEndpoint.Drain(); n != 0 {
					t.Fatalf("e2.Drain() = %d, want = 0", n)
				}
			} else if !reply.IsNil() {
				t.Fatalf("Expected no ICMP packet through incoming NIC, instead found: %#v", reply)
			}

			reply = outgoingEndpoint.Read()
			if test.expectPacketForwarded {
				if reply.IsNil() {
					t.Fatal("Expected ICMP Echo Request packet through outgoing NIC")
				}

				payload := stack.PayloadSince(reply.NetworkHeader())
				defer payload.Release()
				checker.IPv6WithExtHdr(t, payload,
					checker.SrcAddr(srcAddr),
					checker.DstAddr(dstAddr),
					checker.TTL(packetTTL-1),
					extHdrChecker,
					checker.ICMPv6(
						checker.ICMPv6Type(header.ICMPv6EchoRequest),
						checker.ICMPv6Code(header.ICMPv6UnusedCode),
						checker.ICMPv6Payload(nil),
					),
				)
				reply.DecRef()

				if n := incomingEndpoint.Drain(); n != 0 {
					t.Fatalf("e1.Drain() = %d, want = 0", n)
				}
			} else if !reply.IsNil() {
				t.Fatalf("Expected no ICMP Echo packet through outgoing NIC, instead found: %#v", reply)
			}

			if got, want := s.Stats().IP.Forwarding.ExtensionHeaderProblem.Value(), test.expectedExtensionHeaderErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.ExtensionHeaderProblem.Value() = %d, want = %d", got, want)
			}

			if got, want := s.Stats().IP.Forwarding.PacketTooBig.Value(), test.expectedPacketTooBigErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.PacketTooBig.Value() = %d, want = %d", got, want)
			}

			totalExpectedErrors := test.expectedPacketTooBigErrors + test.expectedExtensionHeaderErrors
			if got, want := s.Stats().IP.Forwarding.Errors.Value(), totalExpectedErrors; got != want {
				t.Errorf("s.Stats().IP.Forwarding.Errors.Value() = %d, want = %d", got, want)
			}
		})
	}
}

func TestMultiCounterStatsInitialization(t *testing.T) {
	c := newTestContext()
	defer c.cleanup()
	s := c.s

	proto := s.NetworkProtocolInstance(ProtocolNumber).(*protocol)
	var nic testInterface
	ep := proto.NewEndpoint(&nic, nil).(*endpoint)
	// At this point, the Stack's stats and the NetworkEndpoint's stats are
	// supposed to be bound.
	refStack := s.Stats()
	refEP := ep.stats.localStats
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&ep.stats.ip).Elem(), []reflect.Value{reflect.ValueOf(&refStack.IP).Elem(), reflect.ValueOf(&refEP.IP).Elem()}, testutil.ValidateMultiCounterStatsOptions{
		ExpectMultiCounterStat:            true,
		ExpectMultiIntegralStatCounterMap: false,
	}); err != nil {
		t.Error(err)
	}
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&ep.stats.icmp).Elem(), []reflect.Value{reflect.ValueOf(&refStack.ICMP.V6).Elem(), reflect.ValueOf(&refEP.ICMP).Elem()}, testutil.ValidateMultiCounterStatsOptions{
		ExpectMultiCounterStat:            true,
		ExpectMultiIntegralStatCounterMap: false,
	}); err != nil {
		t.Error(err)
	}
}

func TestIcmpRateLimit(t *testing.T) {
	var (
		host1IPv6Addr = tcpip.ProtocolAddress{
			Protocol: ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(net.ParseIP("10::1").To16()),
				PrefixLen: 64,
			},
		}
		host2IPv6Addr = tcpip.ProtocolAddress{
			Protocol: ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(net.ParseIP("10::2").To16()),
				PrefixLen: 64,
			},
		}
	)
	const icmpBurst = 5

	c := newTestContext()
	defer c.cleanup()
	s := c.s

	s.SetICMPBurst(icmpBurst)

	e := channel.New(1, defaultMTU, tcpip.LinkAddress(""))
	defer e.Close()
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	if err := s.AddProtocolAddress(nicID, host1IPv6Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, host1IPv6Addr, err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: host1IPv6Addr.AddressWithPrefix.Subnet(),
			NIC:         nicID,
		},
	})
	tests := []struct {
		name         string
		createPacket func() []byte
		check        func(*testing.T, *channel.Endpoint, int)
	}{
		{
			name: "echo",
			createPacket: func() []byte {
				totalLength := header.IPv6MinimumSize + header.ICMPv6MinimumSize
				hdr := prependable.New(totalLength)
				icmpH := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))
				icmpH.SetIdent(1)
				icmpH.SetSequence(1)
				icmpH.SetType(header.ICMPv6EchoRequest)
				icmpH.SetCode(header.ICMPv6UnusedCode)
				icmpH.SetChecksum(0)
				icmpH.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header: icmpH,
					Src:    host2IPv6Addr.AddressWithPrefix.Address,
					Dst:    host1IPv6Addr.AddressWithPrefix.Address,
				}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength:     uint16(payloadLength),
					TransportProtocol: header.ICMPv6ProtocolNumber,
					HopLimit:          1,
					SrcAddr:           host2IPv6Addr.AddressWithPrefix.Address,
					DstAddr:           host1IPv6Addr.AddressWithPrefix.Address,
				})
				return hdr.View()
			},
			check: func(t *testing.T, e *channel.Endpoint, round int) {
				p := e.Read()
				if p.IsNil() {
					t.Fatalf("expected echo response, no packet read in endpoint in round %d", round)
				}
				defer p.DecRef()
				if got, want := p.NetworkProtocolNumber, header.IPv6ProtocolNumber; got != want {
					t.Errorf("got p.NetworkProtocolNumber = %d, want = %d", got, want)
				}
				payload := stack.PayloadSince(p.NetworkHeader())
				defer payload.Release()
				checker.IPv6(t, payload,
					checker.SrcAddr(host1IPv6Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv6Addr.AddressWithPrefix.Address),
					checker.ICMPv6(
						checker.ICMPv6Type(header.ICMPv6EchoReply),
					))
			},
		},
		{
			name: "dst unreachable",
			createPacket: func() []byte {
				totalLength := header.IPv6MinimumSize + header.UDPMinimumSize
				hdr := prependable.New(totalLength)
				udpH := header.UDP(hdr.Prepend(header.UDPMinimumSize))
				udpH.Encode(&header.UDPFields{
					SrcPort: 100,
					DstPort: 101,
					Length:  header.UDPMinimumSize,
				})

				// Calculate the UDP checksum and set it.
				sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, host2IPv6Addr.AddressWithPrefix.Address, host1IPv6Addr.AddressWithPrefix.Address, header.UDPMinimumSize)
				sum = checksum.Checksum(nil, sum)
				udpH.SetChecksum(^udpH.CalculateChecksum(sum))

				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength:     uint16(payloadLength),
					TransportProtocol: header.UDPProtocolNumber,
					HopLimit:          1,
					SrcAddr:           host2IPv6Addr.AddressWithPrefix.Address,
					DstAddr:           host1IPv6Addr.AddressWithPrefix.Address,
				})
				return hdr.View()
			},
			check: func(t *testing.T, e *channel.Endpoint, round int) {
				p := e.Read()
				if round >= icmpBurst {
					if !p.IsNil() {
						t.Errorf("got packet %x in round %d, expected ICMP rate limit to stop it", p.Data().AsRange().ToSlice(), round)
						p.DecRef()
					}
					return
				}
				if p.IsNil() {
					t.Fatalf("expected unreachable in round %d, no packet read in endpoint", round)
				}
				payload := stack.PayloadSince(p.NetworkHeader())
				defer payload.Release()
				checker.IPv6(t, payload,
					checker.SrcAddr(host1IPv6Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv6Addr.AddressWithPrefix.Address),
					checker.ICMPv6(
						checker.ICMPv6Type(header.ICMPv6DstUnreachable),
					))
				p.DecRef()
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			for round := 0; round < icmpBurst+1; round++ {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(testCase.createPacket()),
				})
				e.InjectInbound(header.IPv6ProtocolNumber, pkt)
				pkt.DecRef()
				testCase.check(t, e, round)
			}
		})
	}
}

// TestRejectMartianMappedPackets tests that IPv6 endpoints reject packets
// containing IPv4-mapped IPv6 addresses.
func TestRejectMartianMappedPackets(t *testing.T) {
	tcs := []struct {
		name            string
		wantSrcReceived uint64
		wantDstReceived uint64
		wantDelivered   uint64
		srcAddr         tcpip.Address
		dstAddr         tcpip.Address
	}{
		{
			name:            "bad source",
			wantSrcReceived: 1,
			srcAddr:         testutil.MustParse6("::ffff:1.2.3.4"),
			dstAddr:         testutil.MustParse6("fe80::2"),
		},
		{
			name:            "bad destination",
			wantDstReceived: 1,
			srcAddr:         testutil.MustParse6("fe80::2"),
			dstAddr:         testutil.MustParse6("::ffff:1.2.3.4"),
		},
		{
			name:            "bad source and destination",
			wantSrcReceived: 1,
			wantDstReceived: 1,
			srcAddr:         testutil.MustParse6("::ffff:1.2.3.4"),
			dstAddr:         testutil.MustParse6("::ffff:5.6.7.8"),
		},
		{
			name:          "valid source and destination",
			wantDelivered: 1,
			srcAddr:       testutil.MustParse6("fe80::2"),
			dstAddr:       header.IPv6AllNodesMulticastAddress,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize the stack and add an address.
			ctx := newTestContext()
			defer ctx.cleanup()
			stk := ctx.s

			channelEP := channel.New(1, header.IPv6MinimumMTU, linkAddr1)
			defer channelEP.Close()
			if err := stk.CreateNIC(nicID, channelEP); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			stk.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			protocolAddr := tcpip.ProtocolAddress{
				Protocol:          ProtocolNumber,
				AddressWithPrefix: addr2.WithPrefix(),
			}
			if err := stk.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}

			// We don't have to setup the UDP header properly, as
			// it should be rejected at the IP layer.
			hdr := prependable.New(header.IPv6MinimumSize + header.UDPMinimumSize)
			_ = header.UDP(hdr.Prepend(header.UDPMinimumSize))

			payloadLength := hdr.UsedLength()
			ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(payloadLength),
				TransportProtocol: udp.ProtocolNumber,
				HopLimit:          255,
				SrcAddr:           tc.srcAddr,
				DstAddr:           tc.dstAddr,
			})

			// Send the packet out.
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(hdr.View()),
			})
			channelEP.InjectInbound(ProtocolNumber, pkt)
			pkt.DecRef()

			// Verify that stat counters are appropriately updated.
			srcStat := stk.Stats().IP.InvalidSourceAddressesReceived
			if got := srcStat.Value(); got != tc.wantSrcReceived {
				t.Errorf("got InvalidSourceAddressesReceived = %d, want = %d", got, tc.wantSrcReceived)
			}
			dstStat := stk.Stats().IP.InvalidDestinationAddressesReceived
			if got := dstStat.Value(); got != tc.wantDstReceived {
				t.Errorf("got InvalidDestinationAddressesReceived = %d, want = %d", got, tc.wantDstReceived)
			}
			deliveredStat := stk.Stats().IP.PacketsDelivered
			if got := deliveredStat.Value(); got != tc.wantDelivered {
				t.Errorf("got PacketsDelivered = %d, want = %d", got, tc.wantDelivered)
			}
		})
	}
}
