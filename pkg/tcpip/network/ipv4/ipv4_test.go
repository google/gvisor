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
	"math/rand"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestExcludeBroadcast(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
	})

	const defaultMTU = 65536
	ep := stack.LinkEndpoint(channel.New(256, defaultMTU, ""))
	if testing.Verbose() {
		ep = sniffer.New(ep)
	}
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, header.IPv4Any); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
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

// makeHdrAndPayload generates a randomize packet. hdrLength indicates how much
// data should already be in the header before WritePacket. extraLength
// indicates how much extra space should be in the header. The payload is made
// from many Views of the sizes listed in viewSizes.
func makeHdrAndPayload(hdrLength int, extraLength int, viewSizes []int) (buffer.Prependable, buffer.VectorisedView) {
	hdr := buffer.NewPrependable(hdrLength + extraLength)
	hdr.Prepend(hdrLength)
	rand.Read(hdr.View())

	var views []buffer.View
	totalLength := 0
	for _, s := range viewSizes {
		newView := buffer.NewView(s)
		rand.Read(newView)
		views = append(views, newView)
		totalLength += s
	}
	payload := buffer.NewVectorisedView(totalLength, views)
	return hdr, payload
}

// comparePayloads compared the contents of all the packets against the contents
// of the source packet.
func compareFragments(t *testing.T, packets []packetInfo, sourcePacketInfo packetInfo, mtu uint32) {
	t.Helper()
	// Make a complete array of the sourcePacketInfo packet.
	source := header.IPv4(packets[0].Header.View()[:header.IPv4MinimumSize])
	source = append(source, sourcePacketInfo.Header.View()...)
	source = append(source, sourcePacketInfo.Payload.ToView()...)

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
		allBytes := packet.Header.View().ToVectorisedView()
		allBytes.Append(packet.Payload)
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
		if got, want := packet.Header.UsedLength(), sourcePacketInfo.Header.UsedLength()+header.IPv4MinimumSize; i == 0 && want < int(mtu) && got != want {
			t.Errorf("first fragment hdr parts should have unmodified length if possible: got %d, want %d", got, want)
		}
		if got, want := packet.Header.AvailableLength(), sourcePacketInfo.Header.AvailableLength()-header.IPv4MinimumSize; got != want {
			t.Errorf("fragment #%d should have the same available space for prepending as source: got %d, want %d", i, got, want)
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

type errorChannel struct {
	*channel.Endpoint
	Ch                    chan packetInfo
	packetCollectorErrors []*tcpip.Error
}

// newErrorChannel creates a new errorChannel endpoint. Each call to WritePacket
// will return successive errors from packetCollectorErrors until the list is
// empty and then return nil each time.
func newErrorChannel(size int, mtu uint32, linkAddr tcpip.LinkAddress, packetCollectorErrors []*tcpip.Error) *errorChannel {
	return &errorChannel{
		Endpoint:              channel.New(size, mtu, linkAddr),
		Ch:                    make(chan packetInfo, size),
		packetCollectorErrors: packetCollectorErrors,
	}
}

// packetInfo holds all the information about an outbound packet.
type packetInfo struct {
	Header  buffer.Prependable
	Payload buffer.VectorisedView
}

// Drain removes all outbound packets from the channel and counts them.
func (e *errorChannel) Drain() int {
	c := 0
	for {
		select {
		case <-e.Ch:
			c++
		default:
			return c
		}
	}
}

// WritePacket stores outbound packets into the channel.
func (e *errorChannel) WritePacket(r *stack.Route, gso *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	p := packetInfo{
		Header:  hdr,
		Payload: payload,
	}

	select {
	case e.Ch <- p:
	default:
	}

	nextError := (*tcpip.Error)(nil)
	if len(e.packetCollectorErrors) > 0 {
		nextError = e.packetCollectorErrors[0]
		e.packetCollectorErrors = e.packetCollectorErrors[1:]
	}
	return nextError
}

type context struct {
	stack.Route
	linkEP *errorChannel
}

func buildContext(t *testing.T, packetCollectorErrors []*tcpip.Error, mtu uint32) context {
	// Make the packet and write it.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv4.NewProtocol()},
	})
	ep := newErrorChannel(100 /* Enough for all tests. */, mtu, "", packetCollectorErrors)
	s.CreateNIC(1, ep)
	const (
		src = "\x10\x00\x00\x01"
		dst = "\x10\x00\x00\x02"
	)
	s.AddAddress(1, ipv4.ProtocolNumber, src)
	{
		subnet, err := tcpip.NewSubnet(dst, tcpip.AddressMask(header.IPv4Broadcast))
		if err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{
			Destination: subnet,
			NIC:         1,
		}})
	}
	r, err := s.FindRoute(0, src, dst, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("s.FindRoute got %v, want %v", err, nil)
	}
	return context{
		Route:  r,
		linkEP: ep,
	}
}

func TestFragmentation(t *testing.T) {
	var manyPayloadViewsSizes [1000]int
	for i := range manyPayloadViewsSizes {
		manyPayloadViewsSizes[i] = 7
	}
	fragTests := []struct {
		description       string
		mtu               uint32
		gso               *stack.GSO
		hdrLength         int
		extraLength       int
		payloadViewsSizes []int
		expectedFrags     int
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
			hdr, payload := makeHdrAndPayload(ft.hdrLength, ft.extraLength, ft.payloadViewsSizes)
			source := packetInfo{
				Header: hdr,
				// Save the source payload because WritePacket will modify it.
				Payload: payload.Clone([]buffer.View{}),
			}
			c := buildContext(t, nil, ft.mtu)
			err := c.Route.WritePacket(ft.gso, hdr, payload, stack.NetworkHeaderParams{Protocol: tcp.ProtocolNumber, TTL: 42, TOS: stack.DefaultTOS})
			if err != nil {
				t.Errorf("err got %v, want %v", err, nil)
			}

			var results []packetInfo
		L:
			for {
				select {
				case pi := <-c.linkEP.Ch:
					results = append(results, pi)
				default:
					break L
				}
			}

			if got, want := len(results), ft.expectedFrags; got != want {
				t.Errorf("len(result) got %d, want %d", got, want)
			}
			if got, want := len(results), int(c.Route.Stats().IP.PacketsSent.Value()); got != want {
				t.Errorf("no errors yet len(result) got %d, want %d", got, want)
			}
			compareFragments(t, results, source, ft.mtu)
		})
	}
}

// TestFragmentationErrors checks that errors are returned from write packet
// correctly.
func TestFragmentationErrors(t *testing.T) {
	fragTests := []struct {
		description           string
		mtu                   uint32
		hdrLength             int
		payloadViewsSizes     []int
		packetCollectorErrors []*tcpip.Error
	}{
		{"NoFrag", 2000, 0, []int{1000}, []*tcpip.Error{tcpip.ErrAborted}},
		{"ErrorOnFirstFrag", 500, 0, []int{1000}, []*tcpip.Error{tcpip.ErrAborted}},
		{"ErrorOnSecondFrag", 500, 0, []int{1000}, []*tcpip.Error{nil, tcpip.ErrAborted}},
		{"ErrorOnFirstFragMTUSmallerThanHdr", 500, 1000, []int{500}, []*tcpip.Error{tcpip.ErrAborted}},
	}

	for _, ft := range fragTests {
		t.Run(ft.description, func(t *testing.T) {
			hdr, payload := makeHdrAndPayload(ft.hdrLength, header.IPv4MinimumSize, ft.payloadViewsSizes)
			c := buildContext(t, ft.packetCollectorErrors, ft.mtu)
			err := c.Route.WritePacket(&stack.GSO{}, hdr, payload, stack.NetworkHeaderParams{Protocol: tcp.ProtocolNumber, TTL: 42, TOS: stack.DefaultTOS})
			for i := 0; i < len(ft.packetCollectorErrors)-1; i++ {
				if got, want := ft.packetCollectorErrors[i], (*tcpip.Error)(nil); got != want {
					t.Errorf("ft.packetCollectorErrors[%d] got %v, want %v", i, got, want)
				}
			}
			// We only need to check that last error because all the ones before are
			// nil.
			if got, want := err, ft.packetCollectorErrors[len(ft.packetCollectorErrors)-1]; got != want {
				t.Errorf("err got %v, want %v", got, want)
			}
			if got, want := c.linkEP.Drain(), int(c.Route.Stats().IP.PacketsSent.Value())+1; err != nil && got != want {
				t.Errorf("after linkEP error len(result) got %d, want %d", got, want)
			}
		})
	}
}

func TestInvalidFragments(t *testing.T) {
	// These packets have both IHL and TotalLength set to 0.
	testCases := []struct {
		name                   string
		packets                [][]byte
		wantMalformedIPPackets uint64
		wantMalformedFragments uint64
	}{
		{
			"ihl_totallen_zero_valid_frag_offset",
			[][]byte{
				{0x40, 0x30, 0x00, 0x00, 0x6c, 0x74, 0x7d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x39, 0x32, 0x39, 0x33, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
			},
			1,
			0,
		},
		{
			"ihl_totallen_zero_invalid_frag_offset",
			[][]byte{
				{0x40, 0x30, 0x00, 0x00, 0x6c, 0x74, 0x20, 0x00, 0x30, 0x30, 0x30, 0x30, 0x39, 0x32, 0x39, 0x33, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
			},
			1,
			0,
		},
		{
			// Total Length of 37(20 bytes IP header + 17 bytes of
			// payload)
			// Frag Offset of 0x1ffe = 8190*8 = 65520
			// Leading to the fragment end to be past 65535.
			"ihl_totallen_valid_invalid_frag_offset_1",
			[][]byte{
				{0x45, 0x30, 0x00, 0x25, 0x6c, 0x74, 0x1f, 0xfe, 0x30, 0x30, 0x30, 0x30, 0x39, 0x32, 0x39, 0x33, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
			},
			1,
			1,
		},
		// The following 3 tests were found by running a fuzzer and were
		// triggering a panic in the IPv4 reassembler code.
		{
			"ihl_less_than_ipv4_minimum_size_1",
			[][]byte{
				{0x42, 0x30, 0x0, 0x30, 0x30, 0x40, 0x0, 0xf3, 0x30, 0x1, 0x30, 0x30, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
				{0x42, 0x30, 0x0, 0x8, 0x30, 0x40, 0x20, 0x0, 0x30, 0x1, 0x30, 0x30, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
			},
			2,
			0,
		},
		{
			"ihl_less_than_ipv4_minimum_size_2",
			[][]byte{
				{0x42, 0x30, 0x0, 0x30, 0x30, 0x40, 0xb3, 0x12, 0x30, 0x6, 0x30, 0x30, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
				{0x42, 0x30, 0x0, 0x8, 0x30, 0x40, 0x20, 0x0, 0x30, 0x6, 0x30, 0x30, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
			},
			2,
			0,
		},
		{
			"ihl_less_than_ipv4_minimum_size_3",
			[][]byte{
				{0x42, 0x30, 0x0, 0x30, 0x30, 0x40, 0xb3, 0x30, 0x30, 0x6, 0x30, 0x30, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
				{0x42, 0x30, 0x0, 0x8, 0x30, 0x40, 0x20, 0x0, 0x30, 0x6, 0x30, 0x30, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
			},
			2,
			0,
		},
		{
			"fragment_with_short_total_len_extra_payload",
			[][]byte{
				{0x46, 0x30, 0x00, 0x30, 0x30, 0x40, 0x0e, 0x12, 0x30, 0x06, 0x30, 0x30, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
				{0x46, 0x30, 0x00, 0x18, 0x30, 0x40, 0x20, 0x00, 0x30, 0x06, 0x30, 0x30, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30},
			},
			1,
			1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			const nicid tcpip.NICID = 42
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{
					ipv4.NewProtocol(),
				},
			})

			var linkAddr = tcpip.LinkAddress([]byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30})
			var remoteLinkAddr = tcpip.LinkAddress([]byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x31})
			ep := channel.New(10, 1500, linkAddr)
			s.CreateNIC(nicid, sniffer.New(ep))

			for _, pkt := range tc.packets {
				ep.InjectLinkAddr(header.IPv4ProtocolNumber, remoteLinkAddr, buffer.NewVectorisedView(len(pkt), []buffer.View{pkt}))
			}

			if got, want := s.Stats().IP.MalformedPacketsReceived.Value(), tc.wantMalformedIPPackets; got != want {
				t.Errorf("incorrect Stats.IP.MalformedPacketsReceived, got: %d, want: %d", got, want)
			}
			if got, want := s.Stats().IP.MalformedFragmentsReceived.Value(), tc.wantMalformedFragments; got != want {
				t.Errorf("incorrect Stats.IP.MalformedFragmentsReceived, got: %d, want: %d", got, want)
			}
		})
	}
}
