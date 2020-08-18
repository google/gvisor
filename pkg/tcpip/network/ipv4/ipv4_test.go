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
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
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

// makeRandPkt generates a randomize packet. hdrLength indicates how much
// data should already be in the header before WritePacket. extraLength
// indicates how much extra space should be in the header. The payload is made
// from many Views of the sizes listed in viewSizes.
func makeRandPkt(hdrLength int, extraLength int, viewSizes []int) *stack.PacketBuffer {
	var views []buffer.View
	totalLength := 0
	for _, s := range viewSizes {
		newView := buffer.NewView(s)
		rand.Read(newView)
		views = append(views, newView)
		totalLength += s
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: hdrLength + extraLength,
		Data:               buffer.NewVectorisedView(totalLength, views),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	if _, err := rand.Read(pkt.TransportHeader().Push(hdrLength)); err != nil {
		panic(fmt.Sprintf("rand.Read: %s", err))
	}
	return pkt
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

type errorChannel struct {
	*channel.Endpoint
	Ch                    chan *stack.PacketBuffer
	packetCollectorErrors []*tcpip.Error
}

// newErrorChannel creates a new errorChannel endpoint. Each call to WritePacket
// will return successive errors from packetCollectorErrors until the list is
// empty and then return nil each time.
func newErrorChannel(size int, mtu uint32, linkAddr tcpip.LinkAddress, packetCollectorErrors []*tcpip.Error) *errorChannel {
	return &errorChannel{
		Endpoint:              channel.New(size, mtu, linkAddr),
		Ch:                    make(chan *stack.PacketBuffer, size),
		packetCollectorErrors: packetCollectorErrors,
	}
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
func (e *errorChannel) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	select {
	case e.Ch <- pkt:
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
			pkt := makeRandPkt(ft.hdrLength, ft.extraLength, ft.payloadViewsSizes)
			source := pkt.Clone()
			c := buildContext(t, nil, ft.mtu)
			err := c.Route.WritePacket(ft.gso, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      42,
				TOS:      stack.DefaultTOS,
			}, pkt)
			if err != nil {
				t.Errorf("err got %v, want %v", err, nil)
			}

			var results []*stack.PacketBuffer
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
			pkt := makeRandPkt(ft.hdrLength, header.IPv4MinimumSize, ft.payloadViewsSizes)
			c := buildContext(t, ft.packetCollectorErrors, ft.mtu)
			err := c.Route.WritePacket(&stack.GSO{}, stack.NetworkHeaderParams{
				Protocol: tcp.ProtocolNumber,
				TTL:      42,
				TOS:      stack.DefaultTOS,
			}, pkt)
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
		{
			"multiple_fragments_with_more_fragments_set_to_false",
			[][]byte{
				{0x45, 0x00, 0x00, 0x1c, 0x30, 0x40, 0x00, 0x10, 0x00, 0x06, 0x34, 0x69, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				{0x45, 0x00, 0x00, 0x1c, 0x30, 0x40, 0x00, 0x01, 0x61, 0x06, 0x34, 0x69, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				{0x45, 0x00, 0x00, 0x1c, 0x30, 0x40, 0x20, 0x00, 0x00, 0x06, 0x34, 0x1e, 0x73, 0x73, 0x69, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			},
			1,
			1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			const nicID tcpip.NICID = 42
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{
					ipv4.NewProtocol(),
				},
			})

			var linkAddr = tcpip.LinkAddress([]byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30})
			var remoteLinkAddr = tcpip.LinkAddress([]byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x31})
			ep := channel.New(10, 1500, linkAddr)
			s.CreateNIC(nicID, sniffer.New(ep))

			for _, pkt := range tc.packets {
				ep.InjectLinkAddr(header.IPv4ProtocolNumber, remoteLinkAddr, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: buffer.NewVectorisedView(len(pkt), []buffer.View{pkt}),
				}))
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Setup a stack and endpoint.
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()},
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
