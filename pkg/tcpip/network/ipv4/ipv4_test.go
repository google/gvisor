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
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	extraHeaderReserve = 50
	defaultMTU         = 65536
)

func TestExcludeBroadcast(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})

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

// TestIPv4Sanity sends IP/ICMP packets with various problems to the stack and
// checks the response.
func TestIPv4Sanity(t *testing.T) {
	const (
		ttl            = 255
		nicID          = 1
		randomSequence = 123
		randomIdent    = 42
	)
	var (
		ipv4Addr = tcpip.AddressWithPrefix{
			Address:   tcpip.Address(net.ParseIP("192.168.1.58").To4()),
			PrefixLen: 24,
		}
		remoteIPv4Addr = tcpip.Address(net.ParseIP("10.0.0.1").To4())
	)

	tests := []struct {
		name              string
		headerLength      uint8 // value of 0 means "use correct size"
		badHeaderChecksum bool
		maxTotalLength    uint16
		transportProtocol uint8
		TTL               uint8
		shouldFail        bool
		expectICMP        bool
		ICMPType          header.ICMPv4Type
		ICMPCode          header.ICMPv4Code
		options           []byte
	}{
		{
			name:              "valid",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
		},
		{
			name:              "bad header checksum",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			badHeaderChecksum: true,
			shouldFail:        true,
		},
		// The TTL tests check that we are not rejecting an incoming packet
		// with a zero or one TTL, which has been a point of confusion in the
		// past as RFC 791 says: "If this field contains the value zero, then the
		// datagram must be destroyed". However RFC 1122 section 3.2.1.7 clarifies
		// for the case of the destination host, stating as follows.
		//
		//      A host MUST NOT send a datagram with a Time-to-Live (TTL)
		//      value of zero.
		//
		//      A host MUST NOT discard a datagram just because it was
		//      received with TTL less than 2.
		{
			name:              "zero TTL",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               0,
			shouldFail:        false,
		},
		{
			name:              "one TTL",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               1,
			shouldFail:        false,
		},
		{
			name:              "End options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           []byte{0, 0, 0, 0},
		},
		{
			name:              "NOP options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           []byte{1, 1, 1, 1},
		},
		{
			name:              "NOP and End options",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			options:           []byte{1, 1, 0, 0},
		},
		{
			name:              "bad header length",
			headerLength:      header.IPv4MinimumSize - 1,
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
			expectICMP:        false,
		},
		{
			name:              "bad total length (0)",
			maxTotalLength:    0,
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
			expectICMP:        false,
		},
		{
			name:              "bad total length (ip - 1)",
			maxTotalLength:    uint16(header.IPv4MinimumSize - 1),
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
			expectICMP:        false,
		},
		{
			name:              "bad total length (ip + icmp - 1)",
			maxTotalLength:    uint16(header.IPv4MinimumSize + header.ICMPv4MinimumSize - 1),
			transportProtocol: uint8(header.ICMPv4ProtocolNumber),
			TTL:               ttl,
			shouldFail:        true,
			expectICMP:        false,
		},
		{
			name:              "bad protocol",
			maxTotalLength:    ipv4.MaxTotalSize,
			transportProtocol: 99,
			TTL:               ttl,
			shouldFail:        true,
			expectICMP:        true,
			ICMPType:          header.ICMPv4DstUnreachable,
			ICMPCode:          header.ICMPv4ProtoUnreachable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
			})
			// We expect at most a single packet in response to our ICMP Echo Request.
			e := channel.New(1, defaultMTU, "")
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _): %s", nicID, err)
			}
			ipv4ProtoAddr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: ipv4Addr}
			if err := s.AddProtocolAddress(nicID, ipv4ProtoAddr); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %#v): %s", nicID, ipv4ProtoAddr, err)
			}

			// Default routes for IPv4 so ICMP can find a route to the remote
			// node when attempting to send the ICMP Echo Reply.
			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
			})

			// Round up the header size to the next multiple of 4 as RFC 791, page 11
			// says: "Internet Header Length is the length of the internet header
			// in 32 bit words..." and on page 23: "The internet header padding is
			// used to ensure that the internet header ends on a 32 bit boundary."
			ipHeaderLength := ((header.IPv4MinimumSize + len(test.options)) + header.IPv4IHLStride - 1) & ^(header.IPv4IHLStride - 1)

			if ipHeaderLength > header.IPv4MaximumHeaderSize {
				t.Fatalf("too many bytes in options: got = %d, want <= %d ", ipHeaderLength, header.IPv4MaximumHeaderSize)
			}
			totalLen := uint16(ipHeaderLength + header.ICMPv4MinimumSize)
			hdr := buffer.NewPrependable(int(totalLen))
			icmp := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))

			// Specify ident/seq to make sure we get the same in the response.
			icmp.SetIdent(randomIdent)
			icmp.SetSequence(randomSequence)
			icmp.SetType(header.ICMPv4Echo)
			icmp.SetCode(header.ICMPv4UnusedCode)
			icmp.SetChecksum(0)
			icmp.SetChecksum(^header.Checksum(icmp, 0))
			ip := header.IPv4(hdr.Prepend(ipHeaderLength))
			if test.maxTotalLength < totalLen {
				totalLen = test.maxTotalLength
			}
			ip.Encode(&header.IPv4Fields{
				IHL:         uint8(ipHeaderLength),
				TotalLength: totalLen,
				Protocol:    test.transportProtocol,
				TTL:         test.TTL,
				SrcAddr:     remoteIPv4Addr,
				DstAddr:     ipv4Addr.Address,
			})
			if n := copy(ip.Options(), test.options); n != len(test.options) {
				t.Fatalf("options larger than available space: copied %d/%d bytes", n, len(test.options))
			}
			// Override the correct value if the test case specified one.
			if test.headerLength != 0 {
				ip.SetHeaderLength(test.headerLength)
			}
			ip.SetChecksum(0)
			ipHeaderChecksum := ip.CalculateChecksum()
			if test.badHeaderChecksum {
				ipHeaderChecksum += 42
			}
			ip.SetChecksum(^ipHeaderChecksum)
			requestPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Data: hdr.View().ToVectorisedView(),
			})
			e.InjectInbound(header.IPv4ProtocolNumber, requestPkt)
			reply, ok := e.Read()
			if !ok {
				if test.shouldFail {
					if test.expectICMP {
						t.Fatal("expected ICMP error response missing")
					}
					return // Expected silent failure.
				}
				t.Fatal("expected ICMP echo reply missing")
			}

			// Check the route that brought the packet to us.
			if reply.Route.LocalAddress != ipv4Addr.Address {
				t.Errorf("got pkt.Route.LocalAddress = %s, want = %s", reply.Route.LocalAddress, ipv4Addr.Address)
			}
			if reply.Route.RemoteAddress != remoteIPv4Addr {
				t.Errorf("got pkt.Route.RemoteAddress = %s, want = %s", reply.Route.RemoteAddress, remoteIPv4Addr)
			}

			// Make sure it's all in one buffer.
			vv := buffer.NewVectorisedView(reply.Pkt.Size(), reply.Pkt.Views())
			replyIPHeader := header.IPv4(vv.ToView())

			// At this stage we only know it's an IP header so verify that much.
			checker.IPv4(t, replyIPHeader,
				checker.SrcAddr(ipv4Addr.Address),
				checker.DstAddr(remoteIPv4Addr),
			)

			// All expected responses are ICMP packets.
			if got, want := replyIPHeader.Protocol(), uint8(header.ICMPv4ProtocolNumber); got != want {
				t.Fatalf("not ICMP response, got protocol %d, want = %d", got, want)
			}
			replyICMPHeader := header.ICMPv4(replyIPHeader.Payload())

			// Sanity check the response.
			switch replyICMPHeader.Type() {
			case header.ICMPv4DstUnreachable:
				checker.IPv4(t, replyIPHeader,
					checker.IPFullLength(uint16(header.IPv4MinimumSize+header.ICMPv4MinimumSize+requestPkt.Size())),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.ICMPv4(
						checker.ICMPv4Code(test.ICMPCode),
						checker.ICMPv4Checksum(),
						checker.ICMPv4Payload([]byte(hdr.View())),
					),
				)
				if !test.shouldFail || !test.expectICMP {
					t.Fatalf("unexpected packet rejection, got ICMP error packet type %d, code %d",
						header.ICMPv4DstUnreachable, replyICMPHeader.Code())
				}
				return
			case header.ICMPv4EchoReply:
				checker.IPv4(t, replyIPHeader,
					checker.IPv4HeaderLength(ipHeaderLength),
					checker.IPv4Options(test.options),
					checker.IPFullLength(uint16(requestPkt.Size())),
					checker.ICMPv4(
						checker.ICMPv4Code(header.ICMPv4UnusedCode),
						checker.ICMPv4Seq(randomSequence),
						checker.ICMPv4Ident(randomIdent),
						checker.ICMPv4Checksum(),
					),
				)
				if test.shouldFail {
					t.Fatalf("unexpected Echo Reply packet\n")
				}
			default:
				t.Fatalf("unexpected ICMP response, got type %d, want = %d or %d",
					replyICMPHeader.Type(), header.ICMPv4EchoReply, header.ICMPv4DstUnreachable)
			}
		})
	}
}

// comparePayloads compared the contents of all the packets against the contents
// of the source packet.
func compareFragments(packets []*stack.PacketBuffer, sourcePacket *stack.PacketBuffer, mtu uint32, wantFragments []fragmentInfo, proto tcpip.TransportProtocolNumber) error {
	// Make a complete array of the sourcePacket packet.
	source := header.IPv4(packets[0].NetworkHeader().View())
	vv := buffer.NewVectorisedView(sourcePacket.Size(), sourcePacket.Views())
	source = append(source, vv.ToView()...)

	// Make a copy of the IP header, which will be modified in some fields to make
	// an expected header.
	sourceCopy := header.IPv4(append(buffer.View(nil), source[:source.HeaderLength()]...))
	sourceCopy.SetChecksum(0)
	sourceCopy.SetFlagsFragmentOffset(0, 0)
	sourceCopy.SetTotalLength(0)
	// Build up an array of the bytes sent.
	var reassembledPayload buffer.VectorisedView
	for i, packet := range packets {
		// Confirm that the packet is valid.
		allBytes := buffer.NewVectorisedView(packet.Size(), packet.Views())
		fragmentIPHeader := header.IPv4(allBytes.ToView())
		if !fragmentIPHeader.IsValid(len(fragmentIPHeader)) {
			return fmt.Errorf("fragment #%d: IP packet is invalid:\n%s", i, hex.Dump(fragmentIPHeader))
		}
		if got := len(fragmentIPHeader); got > int(mtu) {
			return fmt.Errorf("fragment #%d: got len(fragmentIPHeader) = %d, want <= %d", i, got, mtu)
		}
		if got := fragmentIPHeader.TransportProtocol(); got != proto {
			return fmt.Errorf("fragment #%d: got fragmentIPHeader.TransportProtocol() = %d, want = %d", i, got, uint8(proto))
		}
		if got := packet.AvailableHeaderBytes(); got != extraHeaderReserve {
			return fmt.Errorf("fragment #%d: got packet.AvailableHeaderBytes() = %d, want = %d", i, got, extraHeaderReserve)
		}
		if got, want := packet.NetworkProtocolNumber, sourcePacket.NetworkProtocolNumber; got != want {
			return fmt.Errorf("fragment #%d: got fragment.NetworkProtocolNumber = %d, want = %d", i, got, want)
		}
		if got, want := fragmentIPHeader.CalculateChecksum(), uint16(0xffff); got != want {
			return fmt.Errorf("fragment #%d: got ip.CalculateChecksum() = %#x, want = %#x", i, got, want)
		}
		if wantFragments[i].more {
			sourceCopy.SetFlagsFragmentOffset(sourceCopy.Flags()|header.IPv4FlagMoreFragments, wantFragments[i].offset)
		} else {
			sourceCopy.SetFlagsFragmentOffset(sourceCopy.Flags()&^header.IPv4FlagMoreFragments, wantFragments[i].offset)
		}
		reassembledPayload.AppendView(packet.TransportHeader().View())
		reassembledPayload.Append(packet.Data)
		// Clear out the checksum and length from the ip because we can't compare
		// it.
		sourceCopy.SetTotalLength(wantFragments[i].payloadSize + header.IPv4MinimumSize)
		sourceCopy.SetChecksum(0)
		sourceCopy.SetChecksum(^sourceCopy.CalculateChecksum())
		if diff := cmp.Diff(fragmentIPHeader[:fragmentIPHeader.HeaderLength()], sourceCopy[:sourceCopy.HeaderLength()]); diff != "" {
			return fmt.Errorf("fragment #%d: fragmentIPHeader mismatch (-want +got):\n%s", i, diff)
		}
	}

	expected := buffer.View(source[source.HeaderLength():])
	if diff := cmp.Diff(expected, reassembledPayload.ToView()); diff != "" {
		return fmt.Errorf("reassembledPayload mismatch (-want +got):\n%s", diff)
	}

	return nil
}

type fragmentInfo struct {
	offset      uint16
	more        bool
	payloadSize uint16
}

var fragmentationTests = []struct {
	description           string
	mtu                   uint32
	gso                   *stack.GSO
	transportHeaderLength int
	payloadSize           int
	wantFragments         []fragmentInfo
}{
	{
		description:           "No fragmentation",
		mtu:                   1280,
		gso:                   nil,
		transportHeaderLength: 0,
		payloadSize:           1000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1000, more: false},
		},
	},
	{
		description:           "Fragmented",
		mtu:                   1280,
		gso:                   nil,
		transportHeaderLength: 0,
		payloadSize:           2000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1256, more: true},
			{offset: 1256, payloadSize: 744, more: false},
		},
	},
	{
		description:           "Fragmented with the minimum mtu",
		mtu:                   header.IPv4MinimumMTU,
		gso:                   nil,
		transportHeaderLength: 0,
		payloadSize:           100,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 48, more: true},
			{offset: 48, payloadSize: 48, more: true},
			{offset: 96, payloadSize: 4, more: false},
		},
	},
	{
		description:           "Fragmented with mtu not a multiple of 8",
		mtu:                   header.IPv4MinimumMTU + 1,
		gso:                   nil,
		transportHeaderLength: 0,
		payloadSize:           100,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 48, more: true},
			{offset: 48, payloadSize: 48, more: true},
			{offset: 96, payloadSize: 4, more: false},
		},
	},
	{
		description:           "No fragmentation with big header",
		mtu:                   2000,
		gso:                   nil,
		transportHeaderLength: 100,
		payloadSize:           1000,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1100, more: false},
		},
	},
	{
		description:           "Fragmented with gso none",
		mtu:                   1280,
		gso:                   &stack.GSO{Type: stack.GSONone},
		transportHeaderLength: 0,
		payloadSize:           1400,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1256, more: true},
			{offset: 1256, payloadSize: 144, more: false},
		},
	},
	{
		description:           "Fragmented with big header",
		mtu:                   1280,
		gso:                   nil,
		transportHeaderLength: 100,
		payloadSize:           1200,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 1256, more: true},
			{offset: 1256, payloadSize: 44, more: false},
		},
	},
	{
		description:           "Fragmented with MTU smaller than header",
		mtu:                   300,
		gso:                   nil,
		transportHeaderLength: 1000,
		payloadSize:           500,
		wantFragments: []fragmentInfo{
			{offset: 0, payloadSize: 280, more: true},
			{offset: 280, payloadSize: 280, more: true},
			{offset: 560, payloadSize: 280, more: true},
			{offset: 840, payloadSize: 280, more: true},
			{offset: 1120, payloadSize: 280, more: true},
			{offset: 1400, payloadSize: 100, more: false},
		},
	},
}

func TestFragmentationWritePacket(t *testing.T) {
	const ttl = 42

	for _, ft := range fragmentationTests {
		t.Run(ft.description, func(t *testing.T) {
			ep := testutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
			r := buildRoute(t, ep)
			pkt := testutil.MakeRandPkt(ft.transportHeaderLength, extraHeaderReserve+header.IPv4MinimumSize, []int{ft.payloadSize}, header.IPv4ProtocolNumber)
			source := pkt.Clone()
			err := r.WritePacket(ft.gso, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != nil {
				t.Fatalf("r.WritePacket(_, _, _) = %s", err)
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

func TestFragmentationWritePackets(t *testing.T) {
	const ttl = 42
	writePacketsTests := []struct {
		description  string
		insertBefore int
		insertAfter  int
	}{
		{
			description:  "Single packet",
			insertBefore: 0,
			insertAfter:  0,
		},
		{
			description:  "With packet before",
			insertBefore: 1,
			insertAfter:  0,
		},
		{
			description:  "With packet after",
			insertBefore: 0,
			insertAfter:  1,
		},
		{
			description:  "With packet before and after",
			insertBefore: 1,
			insertAfter:  1,
		},
	}
	tinyPacket := testutil.MakeRandPkt(header.TCPMinimumSize, extraHeaderReserve+header.IPv4MinimumSize, []int{1}, header.IPv4ProtocolNumber)

	for _, test := range writePacketsTests {
		t.Run(test.description, func(t *testing.T) {
			for _, ft := range fragmentationTests {
				t.Run(ft.description, func(t *testing.T) {
					var pkts stack.PacketBufferList
					for i := 0; i < test.insertBefore; i++ {
						pkts.PushBack(tinyPacket.Clone())
					}
					pkt := testutil.MakeRandPkt(ft.transportHeaderLength, extraHeaderReserve+header.IPv4MinimumSize, []int{ft.payloadSize}, header.IPv4ProtocolNumber)
					pkts.PushBack(pkt.Clone())
					for i := 0; i < test.insertAfter; i++ {
						pkts.PushBack(tinyPacket.Clone())
					}

					ep := testutil.NewMockLinkEndpoint(ft.mtu, nil, math.MaxInt32)
					r := buildRoute(t, ep)

					wantTotalPackets := len(ft.wantFragments) + test.insertBefore + test.insertAfter
					n, err := r.WritePackets(ft.gso, pkts, stack.NetworkHeaderParams{
						Protocol: tcp.ProtocolNumber,
						TTL:      ttl,
						TOS:      stack.DefaultTOS,
					})
					if err != nil {
						t.Errorf("got WritePackets(_, _, _) = (_, %s), want = (_, nil)", err)
					}
					if n != wantTotalPackets {
						t.Errorf("got WritePackets(_, _, _) = (%d, _), want = (%d, _)", n, wantTotalPackets)
					}
					if got := len(ep.WrittenPackets); got != wantTotalPackets {
						t.Errorf("got len(ep.WrittenPackets) = %d, want = %d", got, wantTotalPackets)
					}
					if got := int(r.Stats().IP.PacketsSent.Value()); got != wantTotalPackets {
						t.Errorf("got c.Route.Stats().IP.PacketsSent.Value() = %d, want = %d", got, wantTotalPackets)
					}
					if got := int(r.Stats().IP.OutgoingPacketErrors.Value()); got != 0 {
						t.Errorf("got r.Stats().IP.OutgoingPacketErrors.Value() = %d, want = 0", got)
					}

					if wantTotalPackets == 0 {
						return
					}

					fragments := ep.WrittenPackets[test.insertBefore : len(ft.wantFragments)+test.insertBefore]
					if err := compareFragments(fragments, pkt, ft.mtu, ft.wantFragments, tcp.ProtocolNumber); err != nil {
						t.Error(err)
					}
				})
			}
		})
	}
}

// TestFragmentationErrors checks that errors are returned from WritePacket
// correctly.
func TestFragmentationErrors(t *testing.T) {
	const ttl = 42

	tests := []struct {
		description           string
		mtu                   uint32
		transportHeaderLength int
		payloadSize           int
		allowPackets          int
		outgoingErrors        int
		mockError             *tcpip.Error
		wantError             *tcpip.Error
	}{
		{
			description:           "No frag",
			mtu:                   2000,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          0,
			outgoingErrors:        1,
			mockError:             tcpip.ErrAborted,
			wantError:             tcpip.ErrAborted,
		},
		{
			description:           "Error on first frag",
			mtu:                   500,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          0,
			outgoingErrors:        3,
			mockError:             tcpip.ErrAborted,
			wantError:             tcpip.ErrAborted,
		},
		{
			description:           "Error on second frag",
			mtu:                   500,
			payloadSize:           1000,
			transportHeaderLength: 0,
			allowPackets:          1,
			outgoingErrors:        2,
			mockError:             tcpip.ErrAborted,
			wantError:             tcpip.ErrAborted,
		},
		{
			description:           "Error on first frag MTU smaller than header",
			mtu:                   500,
			transportHeaderLength: 1000,
			payloadSize:           500,
			allowPackets:          0,
			outgoingErrors:        4,
			mockError:             tcpip.ErrAborted,
			wantError:             tcpip.ErrAborted,
		},
		{
			description:           "Error when MTU is smaller than IPv4 minimum MTU",
			mtu:                   header.IPv4MinimumMTU - 1,
			transportHeaderLength: 0,
			payloadSize:           500,
			allowPackets:          0,
			outgoingErrors:        1,
			mockError:             nil,
			wantError:             tcpip.ErrInvalidEndpointState,
		},
	}

	for _, ft := range tests {
		t.Run(ft.description, func(t *testing.T) {
			pkt := testutil.MakeRandPkt(ft.transportHeaderLength, extraHeaderReserve+header.IPv4MinimumSize, []int{ft.payloadSize}, header.IPv4ProtocolNumber)
			ep := testutil.NewMockLinkEndpoint(ft.mtu, ft.mockError, ft.allowPackets)
			r := buildRoute(t, ep)
			err := r.WritePacket(&stack.GSO{}, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      ttl,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != ft.wantError {
				t.Errorf("got WritePacket(_, _, _) = %s, want = %s", err, ft.wantError)
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
				ip.SetChecksum(^ip.CalculateChecksum())

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
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
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
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&limitedMatcher{nPackets - 1}}
				// Make sure the next rule is ACCEPT.
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
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
					ep := testutil.NewMockLinkEndpoint(header.IPv4MinimumMTU, tcpip.ErrInvalidEndpointState, test.allowPackets)
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
		t.Fatalf("AddAddress(1, %d, %s) failed: %s", ipv4.ProtocolNumber, src, err)
	}
	{
		mask := tcpip.AddressMask(header.IPv4Broadcast)
		subnet, err := tcpip.NewSubnet(dst, mask)
		if err != nil {
			t.Fatalf("NewSubnet(%s, %s) failed: %v", dst, mask, err)
		}
		s.SetRouteTable([]tcpip.Route{{
			Destination: subnet,
			NIC:         1,
		}})
	}
	rt, err := s.FindRoute(1, src, dst, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(1, %s, %s, %d, false) = %s", src, dst, ipv4.ProtocolNumber, err)
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

func TestPacketQueing(t *testing.T) {
	const nicID = 1

	var (
		host1NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
		host2NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")

		host1IPv4Addr = tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("192.168.0.1").To4()),
				PrefixLen: 24,
			},
		}
		host2IPv4Addr = tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("192.168.0.2").To4()),
				PrefixLen: 8,
			},
		}
	)

	tests := []struct {
		name      string
		rxPkt     func(*channel.Endpoint)
		checkResp func(*testing.T, *channel.Endpoint)
	}{
		{
			name: "ICMP Error",
			rxPkt: func(e *channel.Endpoint) {
				hdr := buffer.NewPrependable(header.IPv4MinimumSize + header.UDPMinimumSize)
				u := header.UDP(hdr.Prepend(header.UDPMinimumSize))
				u.Encode(&header.UDPFields{
					SrcPort: 5555,
					DstPort: 80,
					Length:  header.UDPMinimumSize,
				})
				sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, host2IPv4Addr.AddressWithPrefix.Address, host1IPv4Addr.AddressWithPrefix.Address, header.UDPMinimumSize)
				sum = header.Checksum(header.UDP([]byte{}), sum)
				u.SetChecksum(^u.CalculateChecksum(sum))
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					IHL:         header.IPv4MinimumSize,
					TotalLength: header.IPv4MinimumSize + header.UDPMinimumSize,
					TTL:         ipv4.DefaultTTL,
					Protocol:    uint8(udp.ProtocolNumber),
					SrcAddr:     host2IPv4Addr.AddressWithPrefix.Address,
					DstAddr:     host1IPv4Addr.AddressWithPrefix.Address,
				})
				ip.SetChecksum(^ip.CalculateChecksum())
				e.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
				}))
			},
			checkResp: func(t *testing.T, e *channel.Endpoint) {
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != header.IPv4ProtocolNumber {
					t.Errorf("got p.Proto = %d, want = %d", p.Proto, header.IPv4ProtocolNumber)
				}
				if p.Route.RemoteLinkAddress != host2NICLinkAddr {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, host2NICLinkAddr)
				}
				checker.IPv4(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
					checker.SrcAddr(host1IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4DstUnreachable),
						checker.ICMPv4Code(header.ICMPv4PortUnreachable)))
			},
		},

		{
			name: "Ping",
			rxPkt: func(e *channel.Endpoint) {
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
					TTL:         ipv4.DefaultTTL,
					SrcAddr:     host2IPv4Addr.AddressWithPrefix.Address,
					DstAddr:     host1IPv4Addr.AddressWithPrefix.Address,
				})
				ip.SetChecksum(^ip.CalculateChecksum())
				e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
				}))
			},
			checkResp: func(t *testing.T, e *channel.Endpoint) {
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != header.IPv4ProtocolNumber {
					t.Errorf("got p.Proto = %d, want = %d", p.Proto, header.IPv4ProtocolNumber)
				}
				if p.Route.RemoteLinkAddress != host2NICLinkAddr {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, host2NICLinkAddr)
				}
				checker.IPv4(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
					checker.SrcAddr(host1IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4EchoReply),
						checker.ICMPv4Code(header.ICMPv4UnusedCode)))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := channel.New(1, defaultMTU, host1NICLinkAddr)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})

			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
			}
			if err := s.AddAddress(nicID, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
				t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, arp.ProtocolNumber, arp.ProtocolAddress, err)
			}
			if err := s.AddProtocolAddress(nicID, host1IPv4Addr); err != nil {
				t.Fatalf("s.AddProtocolAddress(%d, %#v): %s", nicID, host1IPv4Addr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: host1IPv4Addr.AddressWithPrefix.Subnet(),
					NIC:         nicID,
				},
			})

			// Receive a packet to trigger link resolution before a response is sent.
			test.rxPkt(e)

			// Wait for a ARP request since link address resolution should be
			// performed.
			{
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != arp.ProtocolNumber {
					t.Errorf("got p.Proto = %d, want = %d", p.Proto, arp.ProtocolNumber)
				}
				if p.Route.RemoteLinkAddress != header.EthernetBroadcastAddress {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, header.EthernetBroadcastAddress)
				}
				rep := header.ARP(p.Pkt.NetworkHeader().View())
				if got := rep.Op(); got != header.ARPRequest {
					t.Errorf("got Op() = %d, want = %d", got, header.ARPRequest)
				}
				if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != host1NICLinkAddr {
					t.Errorf("got HardwareAddressSender = %s, want = %s", got, host1NICLinkAddr)
				}
				if got := tcpip.Address(rep.ProtocolAddressSender()); got != host1IPv4Addr.AddressWithPrefix.Address {
					t.Errorf("got ProtocolAddressSender = %s, want = %s", got, host1IPv4Addr.AddressWithPrefix.Address)
				}
				if got := tcpip.Address(rep.ProtocolAddressTarget()); got != host2IPv4Addr.AddressWithPrefix.Address {
					t.Errorf("got ProtocolAddressTarget = %s, want = %s", got, host2IPv4Addr.AddressWithPrefix.Address)
				}
			}

			// Send an ARP reply to complete link address resolution.
			{
				hdr := buffer.View(make([]byte, header.ARPSize))
				packet := header.ARP(hdr)
				packet.SetIPv4OverEthernet()
				packet.SetOp(header.ARPReply)
				copy(packet.HardwareAddressSender(), host2NICLinkAddr)
				copy(packet.ProtocolAddressSender(), host2IPv4Addr.AddressWithPrefix.Address)
				copy(packet.HardwareAddressTarget(), host1NICLinkAddr)
				copy(packet.ProtocolAddressTarget(), host1IPv4Addr.AddressWithPrefix.Address)
				e.InjectInbound(arp.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.ToVectorisedView(),
				}))
			}

			// Expect the response now that the link address has resolved.
			test.checkResp(t, e)

			// Since link resolution was already performed, it shouldn't be performed
			// again.
			test.rxPkt(e)
			test.checkResp(t, e)
		})
	}
}
