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

package ipv4_test

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestExcludeBroadcast(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})

	const defaultMTU = 65536
	ep := stack.LinkEndpoint(channel.New(256, defaultMTU, ""))
	if testing.Verbose() {
		ep = sniffer.New(ep)
	}
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         1,
	}})

	randomAddr := tcpip.FullAddress{NIC: 1, Addr: "\x0a\x00\x00\x01", Port: 53}

	var wq waiter.Queue
	t.Run("WithoutPrimaryAddress", func(t *testing.T) {
		ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Close()

		// Cannot connect using a broadcast address as the source.
		if err := ep.Connect(randomAddr); err != tcpip.ErrNoRoute {
			t.Errorf("got ep.Connect(...) = %v, want = %v", err, tcpip.ErrNoRoute)
		}

		// However, we can bind to a broadcast address to listen.
		if err := ep.Bind(tcpip.FullAddress{Addr: header.IPv4Broadcast, Port: 53, NIC: 1}); err != nil {
			t.Errorf("Bind failed: %v", err)
		}
	})

	t.Run("WithPrimaryAddress", func(t *testing.T) {
		ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Close()

		// Add a valid primary endpoint address, now we can connect.
		if err := s.AddAddress(1, ipv4.ProtocolNumber, "\x0a\x00\x00\x02"); err != nil {
			t.Fatalf("AddAddress failed: %v", err)
		}
		if err := ep.Connect(randomAddr); err != nil {
			t.Errorf("Connect failed: %v", err)
		}
	})
}

// comparePayloads compared the contents of all the packets against the contents
// of the source packet.
func compareFragments(t *testing.T, packets []*stack.PacketBuffer, sourcePacketInfo *stack.PacketBuffer, mtu uint32) {
	t.Helper()
	// Make a complete array of the sourcePacketInfo packet.
	source := header.IPv4(packets[0].NetworkHeader().View()[:header.IPv4MinimumSize])
	vv := buffer.NewVectorisedView(sourcePacketInfo.Size(), sourcePacketInfo.Views())
	source = append(source, vv.ToView()...)

	// Make a copy of the IP header, which will be modified in some fields to make
	// an expected header.
	sourceCopy := header.IPv4(append(buffer.View(nil), source[:source.HeaderLength()]...))
	sourceCopy.SetChecksum(0)
	sourceCopy.SetFlagsFragmentOffset(0, 0)
	sourceCopy.SetTotalLength(0)
	var offset uint16
	// Build up an array of the bytes sent.
	var reassembledPayload []byte
	for i, packet := range packets {
		// Confirm that the packet is valid.
		allBytes := buffer.NewVectorisedView(packet.Size(), packet.Views())
		ip := header.IPv4(allBytes.ToView())
		if !ip.IsValid(len(ip)) {
			t.Errorf("IP packet is invalid:\n%s", hex.Dump(ip))
		}
		if got, want := ip.CalculateChecksum(), uint16(0xffff); got != want {
			t.Errorf("ip.CalculateChecksum() got %#x, want %#x", got, want)
		}
		if got, want := len(ip), int(mtu); got > want {
			t.Errorf("fragment is too large, got %d want %d", got, want)
		}
		if i == 0 {
			got := packet.NetworkHeader().View().Size() + packet.TransportHeader().View().Size()
			// sourcePacketInfo does not have NetworkHeader added, simulate one.
			want := header.IPv4MinimumSize + sourcePacketInfo.TransportHeader().View().Size()
			// Check that it kept the transport header in packet.TransportHeader if
			// it fits in the first fragment.
			if want < int(mtu) && got != want {
				t.Errorf("first fragment hdr parts should have unmodified length if possible: got %d, want %d", got, want)
			}
		}
		if got, want := packet.AvailableHeaderBytes(), sourcePacketInfo.AvailableHeaderBytes()-header.IPv4MinimumSize; got != want {
			t.Errorf("fragment #%d should have the same available space for prepending as source: got %d, want %d", i, got, want)
		}
		if got, want := packet.NetworkProtocolNumber, sourcePacketInfo.NetworkProtocolNumber; got != want {
			t.Errorf("fragment #%d has wrong network protocol number: got %d, want %d", i, got, want)
		}
		if i < len(packets)-1 {
			sourceCopy.SetFlagsFragmentOffset(sourceCopy.Flags()|header.IPv4FlagMoreFragments, offset)
		} else {
			sourceCopy.SetFlagsFragmentOffset(sourceCopy.Flags()&^header.IPv4FlagMoreFragments, offset)
		}
		reassembledPayload = append(reassembledPayload, ip.Payload()...)
		offset += ip.TotalLength() - uint16(ip.HeaderLength())
		// Clear out the checksum and length from the ip because we can't compare
		// it.
		sourceCopy.SetTotalLength(uint16(len(ip)))
		sourceCopy.SetChecksum(0)
		sourceCopy.SetChecksum(^sourceCopy.CalculateChecksum())
		if !bytes.Equal(ip[:ip.HeaderLength()], sourceCopy[:sourceCopy.HeaderLength()]) {
			t.Errorf("ip[:ip.HeaderLength()] got:\n%s\nwant:\n%s", hex.Dump(ip[:ip.HeaderLength()]), hex.Dump(sourceCopy[:sourceCopy.HeaderLength()]))
		}
	}
	expected := source[source.HeaderLength():]
	if !bytes.Equal(reassembledPayload, expected) {
		t.Errorf("reassembledPayload got:\n%s\nwant:\n%s", hex.Dump(reassembledPayload), hex.Dump(expected))
	}
}

func TestFragmentation(t *testing.T) {
	var manyPayloadViewsSizes [1000]int
	for i := range manyPayloadViewsSizes {
		manyPayloadViewsSizes[i] = 7
	}
	fragTests := []struct {
		description              string
		mtu                      uint32
		gso                      *stack.GSO
		transportHeaderLength    int
		extraHeaderReserveLength int
		payloadViewsSizes        []int
		expectedFrags            int
	}{
		{"NoFragmentation", 2000, &stack.GSO{}, 0, header.IPv4MinimumSize, []int{1000}, 1},
		{"NoFragmentationWithBigHeader", 2000, &stack.GSO{}, 16, header.IPv4MinimumSize, []int{1000}, 1},
		{"Fragmented", 800, &stack.GSO{}, 0, header.IPv4MinimumSize, []int{1000}, 2},
		{"FragmentedWithGsoNil", 800, nil, 0, header.IPv4MinimumSize, []int{1000}, 2},
		{"FragmentedWithManyViews", 300, &stack.GSO{}, 0, header.IPv4MinimumSize, manyPayloadViewsSizes[:], 25},
		{"FragmentedWithManyViewsAndPrependableBytes", 300, &stack.GSO{}, 0, header.IPv4MinimumSize + 55, manyPayloadViewsSizes[:], 25},
		{"FragmentedWithBigHeader", 800, &stack.GSO{}, 20, header.IPv4MinimumSize, []int{1000}, 2},
		{"FragmentedWithBigHeaderAndPrependableBytes", 800, &stack.GSO{}, 20, header.IPv4MinimumSize + 66, []int{1000}, 2},
		{"FragmentedWithMTUSmallerThanHeaderAndPrependableBytes", 300, &stack.GSO{}, 1000, header.IPv4MinimumSize + 77, []int{500}, 6},
	}

	for _, ft := range fragTests {
		t.Run(ft.description, func(t *testing.T) {
			ep := testutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
			r := buildRoute(t, ep)
			pkt := testutil.MakeRandPkt(ft.transportHeaderLength, ft.extraHeaderReserveLength, ft.payloadViewsSizes, header.IPv4ProtocolNumber)
			source := pkt.Clone()
			err := r.WritePacket(ft.gso, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      42,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != nil {
				t.Errorf("got err = %s, want = nil", err)
			}

			if got := len(ep.WrittenPackets); got != ft.expectedFrags {
				t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, ft.expectedFrags)
			}
			if got, want := len(ep.WrittenPackets), int(r.Stats().IP.PacketsSent.Value()); got != want {
				t.Errorf("no errors yet got len(ep.WrittenPackets) = %d, want = %d", got, want)
			}
			compareFragments(t, ep.WrittenPackets, source, ft.mtu)
		})
	}
}

// TestFragmentationErrors checks that errors are returned from write packet
// correctly.
func TestFragmentationErrors(t *testing.T) {
	fragTests := []struct {
		description           string
		mtu                   uint32
		transportHeaderLength int
		payloadViewsSizes     []int
		err                   *tcpip.Error
		allowPackets          int
	}{
		{"NoFrag", 2000, 0, []int{1000}, tcpip.ErrAborted, 0},
		{"ErrorOnFirstFrag", 500, 0, []int{1000}, tcpip.ErrAborted, 0},
		{"ErrorOnSecondFrag", 500, 0, []int{1000}, tcpip.ErrAborted, 1},
		{"ErrorOnFirstFragMTUSmallerThanHeader", 500, 1000, []int{500}, tcpip.ErrAborted, 0},
	}

	for _, ft := range fragTests {
		t.Run(ft.description, func(t *testing.T) {
			ep := testutil.NewMockLinkEndpoint(ft.mtu, ft.err, ft.allowPackets)
			r := buildRoute(t, ep)
			pkt := testutil.MakeRandPkt(ft.transportHeaderLength, header.IPv4MinimumSize, ft.payloadViewsSizes, header.IPv4ProtocolNumber)
			err := r.WritePacket(&stack.GSO{}, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      42,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != ft.err {
				t.Errorf("got WritePacket() = %s, want = %s", err, ft.err)
			}
			if got, want := len(ep.WrittenPackets), int(r.Stats().IP.PacketsSent.Value()); err != nil && got != want {
				t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, want)
			}
		})
	}
}

func TestInvalidFragments(t *testing.T) {
	const (
		nicID    = 1
		linkAddr = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
		addr1    = "\x0a\x00\x00\x01"
		addr2    = "\x0a\x00\x00\x02"
		tos      = 0
		ident    = 1
		ttl      = 48
		protocol = 6
	)

	payloadGen := func(payloadLen int) []byte {
		payload := make([]byte, payloadLen)
		for i := 0; i < len(payload); i++ {
			payload[i] = 0x30
		}
		return payload
	}

	type fragmentData struct {
		ipv4fields   header.IPv4Fields
		payload      []byte
		autoChecksum bool // if true, the Checksum field will be overwritten.
	}

	// These packets have both IHL and TotalLength set to 0.
	tests := []struct {
		name                   string
		fragments              []fragmentData
		wantMalformedIPPackets uint64
		wantMalformedFragments uint64
	}{
		{
			name: "IHL and TotalLength zero, FragmentOffset non-zero",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						IHL:            0,
						TOS:            tos,
						TotalLength:    0,
						ID:             ident,
						Flags:          header.IPv4FlagDontFragment | header.IPv4FlagMoreFragments,
						FragmentOffset: 59776,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(12),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 0,
		},
		{
			name: "IHL and TotalLength zero, FragmentOffset zero",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						IHL:            0,
						TOS:            tos,
						TotalLength:    0,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(12),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 0,
		},
		{
			// Payload 17 octets and Fragment offset 65520
			// Leading to the fragment end to be past 65536.
			name: "fragment ends past 65536",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 17,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 65520,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(17),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
		{
			// Payload 16 octets and fragment offset 65520
			// Leading to the fragment end to be exactly 65536.
			name: "fragment ends exactly at 65536",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 16,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 65520,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(16),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 0,
			wantMalformedFragments: 0,
		},
		{
			name: "IHL less than IPv4 minimum size",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize - 12,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 28,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 1944,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize - 12,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize - 12,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 2,
			wantMalformedFragments: 0,
		},
		{
			name: "fragment with short TotalLength and extra payload",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize + 4,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 28,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 28816,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize + 4,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 4,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(28),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
		{
			name: "multiple fragments with More Fragments flag set to false",
			fragments: []fragmentData{
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 128,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          0,
						FragmentOffset: 8,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
				{
					ipv4fields: header.IPv4Fields{
						IHL:            header.IPv4MinimumSize,
						TOS:            tos,
						TotalLength:    header.IPv4MinimumSize + 8,
						ID:             ident,
						Flags:          header.IPv4FlagMoreFragments,
						FragmentOffset: 0,
						TTL:            ttl,
						Protocol:       protocol,
						SrcAddr:        addr1,
						DstAddr:        addr2,
					},
					payload:      payloadGen(8),
					autoChecksum: true,
				},
			},
			wantMalformedIPPackets: 1,
			wantMalformedFragments: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{
					ipv4.NewProtocol,
				},
			})
			e := channel.New(0, 1500, linkAddr)
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, ipv4.ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv4ProtocolNumber, addr2, err)
			}

			for _, f := range test.fragments {
				pktSize := header.IPv4MinimumSize + len(f.payload)
				hdr := buffer.NewPrependable(pktSize)

				ip := header.IPv4(hdr.Prepend(pktSize))
				ip.Encode(&f.ipv4fields)
				copy(ip[header.IPv4MinimumSize:], f.payload)

				if f.autoChecksum {
					ip.SetChecksum(0)
					ip.SetChecksum(^ip.CalculateChecksum())
				}

				vv := hdr.View().ToVectorisedView()
				e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: vv,
				}))
			}

			if got, want := s.Stats().IP.MalformedPacketsReceived.Value(), test.wantMalformedIPPackets; got != want {
				t.Errorf("incorrect Stats.IP.MalformedPacketsReceived, got: %d, want: %d", got, want)
			}
			if got, want := s.Stats().IP.MalformedFragmentsReceived.Value(), test.wantMalformedFragments; got != want {
				t.Errorf("incorrect Stats.IP.MalformedFragmentsReceived, got: %d, want: %d", got, want)
			}
		})
	}
}

// TestReceiveFragments feeds fragments in through the incoming packet path to
// test reassembly
func TestReceiveFragments(t *testing.T) {
	const (
		nicID = 1

		addr1 = "\x0c\xa8\x00\x01" // 192.168.0.1
		addr2 = "\x0c\xa8\x00\x02" // 192.168.0.2
		addr3 = "\x0c\xa8\x00\x03" // 192.168.0.3
	)

	// Build and return a UDP header containing payload.
	udpGen := func(payloadLen int, multiplier uint8, src, dst tcpip.Address) buffer.View {
		payload := buffer.NewView(payloadLen)
		for i := 0; i < len(payload); i++ {
			payload[i] = uint8(i) * multiplier
		}

		udpLength := header.UDPMinimumSize + len(payload)

		hdr := buffer.NewPrependable(udpLength)
		u := header.UDP(hdr.Prepend(udpLength))
		u.Encode(&header.UDPFields{
			SrcPort: 5555,
			DstPort: 80,
			Length:  uint16(udpLength),
		})
		copy(u.Payload(), payload)
		sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(udpLength))
		sum = header.Checksum(payload, sum)
		u.SetChecksum(^u.CalculateChecksum(sum))
		return hdr.View()
	}

	// UDP header plus a payload of 0..256
	ipv4Payload1Addr1ToAddr2 := udpGen(256, 1, addr1, addr2)
	udpPayload1Addr1ToAddr2 := ipv4Payload1Addr1ToAddr2[header.UDPMinimumSize:]
	ipv4Payload1Addr3ToAddr2 := udpGen(256, 1, addr3, addr2)
	udpPayload1Addr3ToAddr2 := ipv4Payload1Addr3ToAddr2[header.UDPMinimumSize:]
	// UDP header plus a payload of 0..256 in increments of 2.
	ipv4Payload2Addr1ToAddr2 := udpGen(128, 2, addr1, addr2)
	udpPayload2Addr1ToAddr2 := ipv4Payload2Addr1ToAddr2[header.UDPMinimumSize:]
	// UDP header plus a payload of 0..256 in increments of 3.
	// Used to test cases where the fragment blocks are not a multiple of
	// the fragment block size of 8 (RFC 791 section 3.1 page 14).
	ipv4Payload3Addr1ToAddr2 := udpGen(127, 3, addr1, addr2)
	udpPayload3Addr1ToAddr2 := ipv4Payload3Addr1ToAddr2[header.UDPMinimumSize:]
	// Used to test the max reassembled payload length (65,535 octets).
	ipv4Payload4Addr1ToAddr2 := udpGen(header.UDPMaximumSize-header.UDPMinimumSize, 4, addr1, addr2)
	udpPayload4Addr1ToAddr2 := ipv4Payload4Addr1ToAddr2[header.UDPMinimumSize:]

	type fragmentData struct {
		srcAddr        tcpip.Address
		dstAddr        tcpip.Address
		id             uint16
		flags          uint8
		fragmentOffset uint16
		payload        buffer.View
	}

	tests := []struct {
		name             string
		fragments        []fragmentData
		expectedPayloads [][]byte
	}{
		{
			name: "No fragmentation",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "No fragmentation with size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2,
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "More fragments without payload",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Non-zero fragment offset without payload",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 8,
					payload:        ipv4Payload1Addr1ToAddr2,
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments out of order",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2},
		},
		{
			name: "Two fragments with last fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload3Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload3Addr1ToAddr2},
		},
		{
			name: "Two fragments with first fragment size not a multiple of fragment block size",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload3Addr1ToAddr2[:63],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 63,
					payload:        ipv4Payload3Addr1ToAddr2[63:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Second fragment has MoreFlags set",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments with different IDs",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two interleaved fragmented packets",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload2Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             2,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload2Addr1ToAddr2[64:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload2Addr1ToAddr2},
		},
		{
			name: "Two interleaved fragmented packets from different sources but with same ID",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
				{
					srcAddr:        addr3,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr3ToAddr2[:32],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 64,
					payload:        ipv4Payload1Addr1ToAddr2[64:],
				},
				{
					srcAddr:        addr3,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 32,
					payload:        ipv4Payload1Addr3ToAddr2[32:],
				},
			},
			expectedPayloads: [][]byte{udpPayload1Addr1ToAddr2, udpPayload1Addr3ToAddr2},
		},
		{
			name: "Fragment without followup",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload1Addr1ToAddr2[:64],
				},
			},
			expectedPayloads: nil,
		},
		{
			name: "Two fragments reassembled into a maximum UDP packet",
			fragments: []fragmentData{
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          header.IPv4FlagMoreFragments,
					fragmentOffset: 0,
					payload:        ipv4Payload4Addr1ToAddr2[:65512],
				},
				{
					srcAddr:        addr1,
					dstAddr:        addr2,
					id:             1,
					flags:          0,
					fragmentOffset: 65512,
					payload:        ipv4Payload4Addr1ToAddr2[65512:],
				},
			},
			expectedPayloads: [][]byte{udpPayload4Addr1ToAddr2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Setup a stack and endpoint.
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			e := channel.New(0, 1280, tcpip.LinkAddress("\xf0\x00"))
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			if err := s.AddAddress(nicID, header.IPv4ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv4ProtocolNumber, addr2, err)
			}

			wq := waiter.Queue{}
			we, ch := waiter.NewChannelEntry(nil)
			wq.EventRegister(&we, waiter.EventIn)
			defer wq.EventUnregister(&we)
			defer close(ch)
			ep, err := s.NewEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, header.IPv4ProtocolNumber, err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{Addr: addr2, Port: 80}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("Bind(%+v): %s", bindAddr, err)
			}

			// Prepare and send the fragments.
			for _, frag := range test.fragments {
				hdr := buffer.NewPrependable(header.IPv4MinimumSize)

				// Serialize IPv4 fixed header.
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					IHL:            header.IPv4MinimumSize,
					TotalLength:    header.IPv4MinimumSize + uint16(len(frag.payload)),
					ID:             frag.id,
					Flags:          frag.flags,
					FragmentOffset: frag.fragmentOffset,
					TTL:            64,
					Protocol:       uint8(header.UDPProtocolNumber),
					SrcAddr:        frag.srcAddr,
					DstAddr:        frag.dstAddr,
				})

				vv := hdr.View().ToVectorisedView()
				vv.AppendView(frag.payload)

				e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: vv,
				}))
			}

			if got, want := s.Stats().UDP.PacketsReceived.Value(), uint64(len(test.expectedPayloads)); got != want {
				t.Errorf("got UDP Rx Packets = %d, want = %d", got, want)
			}

			for i, expectedPayload := range test.expectedPayloads {
				gotPayload, _, err := ep.Read(nil)
				if err != nil {
					t.Fatalf("(i=%d) Read(nil): %s", i, err)
				}
				if diff := cmp.Diff(buffer.View(expectedPayload), gotPayload); diff != "" {
					t.Errorf("(i=%d) got UDP payload mismatch (-want +got):\n%s", i, diff)
				}
			}

			if gotPayload, _, err := ep.Read(nil); err != tcpip.ErrWouldBlock {
				t.Fatalf("(last) got Read(nil) = (%x, _, %v), want = (_, _, %s)", gotPayload, err, tcpip.ErrWouldBlock)
			}
		})
	}
}

func TestWriteStats(t *testing.T) {
	const nPackets = 3
	tests := []struct {
		name          string
		setup         func(*testing.T, *stack.Stack)
		allowPackets  int
		expectSent    int
		expectDropped int
		expectWritten int
	}{
		{
			name: "Accept all",
			// No setup needed, tables accept everything by default.
			setup:         func(*testing.T, *stack.Stack) {},
			allowPackets:  math.MaxInt32,
			expectSent:    nPackets,
			expectDropped: 0,
			expectWritten: nPackets,
		}, {
			name: "Accept all with error",
			// No setup needed, tables accept everything by default.
			setup:         func(*testing.T, *stack.Stack) {},
			allowPackets:  nPackets - 1,
			expectSent:    nPackets - 1,
			expectDropped: 0,
			expectWritten: nPackets - 1,
		}, {
			name: "Drop all",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule.
				t.Helper()
				ipt := stk.IPTables()
				filter, ok := ipt.GetTable(stack.FilterTable, false /* ipv6 */)
				if !ok {
					t.Fatalf("failed to find filter table")
				}
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = stack.DropTarget{}
				if err := ipt.ReplaceTable(stack.FilterTable, filter, false /* ipv6 */); err != nil {
					t.Fatalf("failed to replace table: %s", err)
				}
			},
			allowPackets:  math.MaxInt32,
			expectSent:    0,
			expectDropped: nPackets,
			expectWritten: nPackets,
		}, {
			name: "Drop some",
			setup: func(t *testing.T, stk *stack.Stack) {
				// Install Output DROP rule that matches only 1
				// of the 3 packets.
				t.Helper()
				ipt := stk.IPTables()
				filter, ok := ipt.GetTable(stack.FilterTable, false /* ipv6 */)
				if !ok {
					t.Fatalf("failed to find filter table")
				}
				// We'll match and DROP the last packet.
				ruleIdx := filter.BuiltinChains[stack.Output]
				filter.Rules[ruleIdx].Target = stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&limitedMatcher{nPackets - 1}}
				// Make sure the next rule is ACCEPT.
				filter.Rules[ruleIdx+1].Target = stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterTable, filter, false /* ipv6 */); err != nil {
					t.Fatalf("failed to replace table: %s", err)
				}
			},
			allowPackets:  math.MaxInt32,
			expectSent:    nPackets - 1,
			expectDropped: 1,
			expectWritten: nPackets,
		},
	}

	// Parameterize the tests to run with both WritePacket and WritePackets.
	writers := []struct {
		name         string
		writePackets func(*stack.Route, stack.PacketBufferList) (int, *tcpip.Error)
	}{
		{
			name: "WritePacket",
			writePackets: func(rt *stack.Route, pkts stack.PacketBufferList) (int, *tcpip.Error) {
				nWritten := 0
				for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
					if err := rt.WritePacket(nil, stack.NetworkHeaderParams{}, pkt); err != nil {
						return nWritten, err
					}
					nWritten++
				}
				return nWritten, nil
			},
		}, {
			name: "WritePackets",
			writePackets: func(rt *stack.Route, pkts stack.PacketBufferList) (int, *tcpip.Error) {
				return rt.WritePackets(nil, pkts, stack.NetworkHeaderParams{})
			},
		},
	}

	for _, writer := range writers {
		t.Run(writer.name, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					ep := testutil.NewMockLinkEndpoint(header.IPv4MinimumSize+header.UDPMinimumSize, tcpip.ErrInvalidEndpointState, test.allowPackets)
					rt := buildRoute(t, ep)

					var pkts stack.PacketBufferList
					for i := 0; i < nPackets; i++ {
						pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
							ReserveHeaderBytes: header.UDPMinimumSize + int(rt.MaxHeaderLength()),
							Data:               buffer.NewView(0).ToVectorisedView(),
						})
						pkt.TransportHeader().Push(header.UDPMinimumSize)
						pkts.PushBack(pkt)
					}

					test.setup(t, rt.Stack())

					nWritten, _ := writer.writePackets(&rt, pkts)

					if got := int(rt.Stats().IP.PacketsSent.Value()); got != test.expectSent {
						t.Errorf("sent %d packets, but expected to send %d", got, test.expectSent)
					}
					if got := int(rt.Stats().IP.IPTablesOutputDropped.Value()); got != test.expectDropped {
						t.Errorf("dropped %d packets, but expected to drop %d", got, test.expectDropped)
					}
					if nWritten != test.expectWritten {
						t.Errorf("wrote %d packets, but expected WritePackets to return %d", nWritten, test.expectWritten)
					}
				})
			}
		})
	}
}

func buildRoute(t *testing.T, ep stack.LinkEndpoint) stack.Route {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC(1, _) failed: %s", err)
	}
	const (
		src = "\x10\x00\x00\x01"
		dst = "\x10\x00\x00\x02"
	)
	if err := s.AddAddress(1, ipv4.ProtocolNumber, src); err != nil {
		t.Fatalf("AddAddress(1, %d, _) failed: %s", ipv4.ProtocolNumber, err)
	}
	{
		subnet, err := tcpip.NewSubnet(dst, tcpip.AddressMask(header.IPv4Broadcast))
		if err != nil {
			t.Fatalf("NewSubnet(_, _) failed: %v", err)
		}
		s.SetRouteTable([]tcpip.Route{{
			Destination: subnet,
			NIC:         1,
		}})
	}
	rt, err := s.FindRoute(1, src, dst, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("got FindRoute(1, _, _, %d, false) = %s, want = nil", ipv4.ProtocolNumber, err)
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
func (lm *limitedMatcher) Match(stack.Hook, *stack.PacketBuffer, string) (bool, bool) {
	if lm.limit == 0 {
		return true, false
	}
	lm.limit--
	return false, false
}
