// Copyright 2018 Google Inc.
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

package ip_test

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

// testObject implements two interfaces: LinkEndpoint and TransportDispatcher.
// The former is used to pretend that it's a link endpoint so that we can
// inspect packets written by the network endpoints. The latter is used to
// pretend that it's the network stack so that it can inspect incoming packets
// that have been handled by the network endpoints.
//
// Packets are checked by comparing their fields/values against the expected
// values stored in the test object itself.
type testObject struct {
	t        *testing.T
	protocol tcpip.TransportProtocolNumber
	contents []byte
	srcAddr  tcpip.Address
	dstAddr  tcpip.Address
	v4       bool
	typ      stack.ControlType
	extra    uint32

	dataCalls    int
	controlCalls int
}

// checkValues verifies that the transport protocol, data contents, src & dst
// addresses of a packet match what's expected. If any field doesn't match, the
// test fails.
func (t *testObject) checkValues(protocol tcpip.TransportProtocolNumber, vv *buffer.VectorisedView, srcAddr, dstAddr tcpip.Address) {
	v := vv.ToView()
	if protocol != t.protocol {
		t.t.Errorf("protocol = %v, want %v", protocol, t.protocol)
	}

	if srcAddr != t.srcAddr {
		t.t.Errorf("srcAddr = %v, want %v", srcAddr, t.srcAddr)
	}

	if dstAddr != t.dstAddr {
		t.t.Errorf("dstAddr = %v, want %v", dstAddr, t.dstAddr)
	}

	if len(v) != len(t.contents) {
		t.t.Fatalf("len(payload) = %v, want %v", len(v), len(t.contents))
	}

	for i := range t.contents {
		if t.contents[i] != v[i] {
			t.t.Fatalf("payload[%v] = %v, want %v", i, v[i], t.contents[i])
		}
	}
}

// DeliverTransportPacket is called by network endpoints after parsing incoming
// packets. This is used by the test object to verify that the results of the
// parsing are expected.
func (t *testObject) DeliverTransportPacket(r *stack.Route, protocol tcpip.TransportProtocolNumber, vv *buffer.VectorisedView) {
	t.checkValues(protocol, vv, r.RemoteAddress, r.LocalAddress)
	t.dataCalls++
}

// DeliverTransportControlPacket is called by network endpoints after parsing
// incoming control (ICMP) packets. This is used by the test object to verify
// that the results of the parsing are expected.
func (t *testObject) DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ stack.ControlType, extra uint32, vv *buffer.VectorisedView) {
	t.checkValues(trans, vv, remote, local)
	if typ != t.typ {
		t.t.Errorf("typ = %v, want %v", typ, t.typ)
	}
	if extra != t.extra {
		t.t.Errorf("extra = %v, want %v", extra, t.extra)
	}
	t.controlCalls++
}

// Attach is only implemented to satisfy the LinkEndpoint interface.
func (*testObject) Attach(stack.NetworkDispatcher) {}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (*testObject) IsAttached() bool {
	return true
}

// MTU implements stack.LinkEndpoint.MTU. It just returns a constant that
// matches the linux loopback MTU.
func (*testObject) MTU() uint32 {
	return 65536
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (*testObject) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}

// MaxHeaderLength is only implemented to satisfy the LinkEndpoint interface.
func (*testObject) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (*testObject) LinkAddress() tcpip.LinkAddress {
	return ""
}

// WritePacket is called by network endpoints after producing a packet and
// writing it to the link endpoint. This is used by the test object to verify
// that the produced packet is as expected.
func (t *testObject) WritePacket(_ *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	var prot tcpip.TransportProtocolNumber
	var srcAddr tcpip.Address
	var dstAddr tcpip.Address

	if t.v4 {
		h := header.IPv4(hdr.UsedBytes())
		prot = tcpip.TransportProtocolNumber(h.Protocol())
		srcAddr = h.SourceAddress()
		dstAddr = h.DestinationAddress()

	} else {
		h := header.IPv6(hdr.UsedBytes())
		prot = tcpip.TransportProtocolNumber(h.NextHeader())
		srcAddr = h.SourceAddress()
		dstAddr = h.DestinationAddress()
	}
	var views [1]buffer.View
	vv := payload.ToVectorisedView(views)
	t.checkValues(prot, &vv, srcAddr, dstAddr)
	return nil
}

func TestIPv4Send(t *testing.T) {
	o := testObject{t: t, v4: true}
	proto := ipv4.NewProtocol()
	ep, err := proto.NewEndpoint(1, "\x0a\x00\x00\x01", nil, nil, &o)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Allocate and initialize the payload view.
	payload := buffer.NewView(100)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}

	// Allocate the header buffer.
	hdr := buffer.NewPrependable(int(ep.MaxHeaderLength()))

	// Issue the write.
	o.protocol = 123
	o.srcAddr = "\x0a\x00\x00\x01"
	o.dstAddr = "\x0a\x00\x00\x02"
	o.contents = payload

	r := stack.Route{
		RemoteAddress: o.dstAddr,
		LocalAddress:  o.srcAddr,
	}
	if err := ep.WritePacket(&r, &hdr, payload, 123); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func TestIPv4Receive(t *testing.T) {
	o := testObject{t: t, v4: true}
	proto := ipv4.NewProtocol()
	ep, err := proto.NewEndpoint(1, "\x0a\x00\x00\x01", nil, &o, nil)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	totalLen := header.IPv4MinimumSize + 30
	view := buffer.NewView(totalLen)
	ip := header.IPv4(view)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: uint16(totalLen),
		TTL:         20,
		Protocol:    10,
		SrcAddr:     "\x0a\x00\x00\x02",
		DstAddr:     "\x0a\x00\x00\x01",
	})

	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		view[i] = uint8(i)
	}

	// Give packet to ipv4 endpoint, dispatcher will validate that it's ok.
	o.protocol = 10
	o.srcAddr = "\x0a\x00\x00\x02"
	o.dstAddr = "\x0a\x00\x00\x01"
	o.contents = view[header.IPv4MinimumSize:totalLen]

	r := stack.Route{
		LocalAddress:  o.dstAddr,
		RemoteAddress: o.srcAddr,
	}
	var views [1]buffer.View
	vv := view.ToVectorisedView(views)
	ep.HandlePacket(&r, &vv)
	if o.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", o.dataCalls)
	}
}

func TestIPv4ReceiveControl(t *testing.T) {
	const mtu = 0xbeef - header.IPv4MinimumSize
	cases := []struct {
		name           string
		expectedCount  int
		fragmentOffset uint16
		code           uint8
		expectedTyp    stack.ControlType
		expectedExtra  uint32
		trunc          int
	}{
		{"FragmentationNeeded", 1, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 0},
		{"Truncated (10 bytes missing)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 10},
		{"Truncated (missing IPv4 header)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, header.IPv4MinimumSize + 8},
		{"Truncated (missing 'extra info')", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 4 + header.IPv4MinimumSize + 8},
		{"Truncated (missing ICMP header)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, header.ICMPv4DstUnreachableMinimumSize + header.IPv4MinimumSize + 8},
		{"Port unreachable", 1, 0, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Non-zero fragment offset", 0, 100, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Zero-length packet", 0, 0, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 2*header.IPv4MinimumSize + header.ICMPv4DstUnreachableMinimumSize + 8},
	}
	r := stack.Route{
		LocalAddress:  "\x0a\x00\x00\x01",
		RemoteAddress: "\x0a\x00\x00\xbb",
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var views [1]buffer.View
			o := testObject{t: t}
			proto := ipv4.NewProtocol()
			ep, err := proto.NewEndpoint(1, "\x0a\x00\x00\x01", nil, &o, nil)
			if err != nil {
				t.Fatalf("NewEndpoint failed: %v", err)
			}
			defer ep.Close()

			const dataOffset = header.IPv4MinimumSize*2 + header.ICMPv4MinimumSize + 4
			view := buffer.NewView(dataOffset + 8)

			// Create the outer IPv4 header.
			ip := header.IPv4(view)
			ip.Encode(&header.IPv4Fields{
				IHL:         header.IPv4MinimumSize,
				TotalLength: uint16(len(view) - c.trunc),
				TTL:         20,
				Protocol:    uint8(header.ICMPv4ProtocolNumber),
				SrcAddr:     "\x0a\x00\x00\xbb",
				DstAddr:     "\x0a\x00\x00\x01",
			})

			// Create the ICMP header.
			icmp := header.ICMPv4(view[header.IPv4MinimumSize:])
			icmp.SetType(header.ICMPv4DstUnreachable)
			icmp.SetCode(c.code)
			copy(view[header.IPv4MinimumSize+header.ICMPv4MinimumSize:], []byte{0xde, 0xad, 0xbe, 0xef})

			// Create the inner IPv4 header.
			ip = header.IPv4(view[header.IPv4MinimumSize+header.ICMPv4MinimumSize+4:])
			ip.Encode(&header.IPv4Fields{
				IHL:            header.IPv4MinimumSize,
				TotalLength:    100,
				TTL:            20,
				Protocol:       10,
				FragmentOffset: c.fragmentOffset,
				SrcAddr:        "\x0a\x00\x00\x01",
				DstAddr:        "\x0a\x00\x00\x02",
			})

			// Make payload be non-zero.
			for i := dataOffset; i < len(view); i++ {
				view[i] = uint8(i)
			}

			// Give packet to IPv4 endpoint, dispatcher will validate that
			// it's ok.
			o.protocol = 10
			o.srcAddr = "\x0a\x00\x00\x02"
			o.dstAddr = "\x0a\x00\x00\x01"
			o.contents = view[dataOffset:]
			o.typ = c.expectedTyp
			o.extra = c.expectedExtra

			vv := view.ToVectorisedView(views)
			vv.CapLength(len(view) - c.trunc)
			ep.HandlePacket(&r, &vv)
			if want := c.expectedCount; o.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, o.controlCalls, want)
			}
		})
	}
}

func TestIPv4FragmentationReceive(t *testing.T) {
	o := testObject{t: t, v4: true}
	proto := ipv4.NewProtocol()
	ep, err := proto.NewEndpoint(1, "\x0a\x00\x00\x01", nil, &o, nil)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	totalLen := header.IPv4MinimumSize + 24

	frag1 := buffer.NewView(totalLen)
	ip1 := header.IPv4(frag1)
	ip1.Encode(&header.IPv4Fields{
		IHL:            header.IPv4MinimumSize,
		TotalLength:    uint16(totalLen),
		TTL:            20,
		Protocol:       10,
		FragmentOffset: 0,
		Flags:          header.IPv4FlagMoreFragments,
		SrcAddr:        "\x0a\x00\x00\x02",
		DstAddr:        "\x0a\x00\x00\x01",
	})
	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		frag1[i] = uint8(i)
	}

	frag2 := buffer.NewView(totalLen)
	ip2 := header.IPv4(frag2)
	ip2.Encode(&header.IPv4Fields{
		IHL:            header.IPv4MinimumSize,
		TotalLength:    uint16(totalLen),
		TTL:            20,
		Protocol:       10,
		FragmentOffset: 24,
		SrcAddr:        "\x0a\x00\x00\x02",
		DstAddr:        "\x0a\x00\x00\x01",
	})
	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		frag2[i] = uint8(i)
	}

	// Give packet to ipv4 endpoint, dispatcher will validate that it's ok.
	o.protocol = 10
	o.srcAddr = "\x0a\x00\x00\x02"
	o.dstAddr = "\x0a\x00\x00\x01"
	o.contents = append(frag1[header.IPv4MinimumSize:totalLen], frag2[header.IPv4MinimumSize:totalLen]...)

	r := stack.Route{
		LocalAddress:  o.dstAddr,
		RemoteAddress: o.srcAddr,
	}

	// Send first segment.
	var views1 [1]buffer.View
	vv1 := frag1.ToVectorisedView(views1)
	ep.HandlePacket(&r, &vv1)
	if o.dataCalls != 0 {
		t.Fatalf("Bad number of data calls: got %x, want 0", o.dataCalls)
	}

	// Send second segment.
	var views2 [1]buffer.View
	vv2 := frag2.ToVectorisedView(views2)
	ep.HandlePacket(&r, &vv2)

	if o.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", o.dataCalls)
	}
}

func TestIPv6Send(t *testing.T) {
	o := testObject{t: t}
	proto := ipv6.NewProtocol()
	ep, err := proto.NewEndpoint(1, "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", nil, nil, &o)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Allocate and initialize the payload view.
	payload := buffer.NewView(100)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}

	// Allocate the header buffer.
	hdr := buffer.NewPrependable(int(ep.MaxHeaderLength()))

	// Issue the write.
	o.protocol = 123
	o.srcAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	o.dstAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	o.contents = payload

	r := stack.Route{
		RemoteAddress: o.dstAddr,
		LocalAddress:  o.srcAddr,
	}
	if err := ep.WritePacket(&r, &hdr, payload, 123); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func TestIPv6Receive(t *testing.T) {
	o := testObject{t: t}
	proto := ipv6.NewProtocol()
	ep, err := proto.NewEndpoint(1, "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", nil, &o, nil)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	totalLen := header.IPv6MinimumSize + 30
	view := buffer.NewView(totalLen)
	ip := header.IPv6(view)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(totalLen - header.IPv6MinimumSize),
		NextHeader:    10,
		HopLimit:      20,
		SrcAddr:       "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
		DstAddr:       "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
	})

	// Make payload be non-zero.
	for i := header.IPv6MinimumSize; i < totalLen; i++ {
		view[i] = uint8(i)
	}

	// Give packet to ipv6 endpoint, dispatcher will validate that it's ok.
	o.protocol = 10
	o.srcAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	o.dstAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	o.contents = view[header.IPv6MinimumSize:totalLen]

	r := stack.Route{
		LocalAddress:  o.dstAddr,
		RemoteAddress: o.srcAddr,
	}
	var views [1]buffer.View
	vv := view.ToVectorisedView(views)
	ep.HandlePacket(&r, &vv)

	if o.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", o.dataCalls)
	}
}

func TestIPv6ReceiveControl(t *testing.T) {
	newUint16 := func(v uint16) *uint16 { return &v }

	const mtu = 0xffff
	cases := []struct {
		name           string
		expectedCount  int
		fragmentOffset *uint16
		typ            header.ICMPv6Type
		code           uint8
		expectedTyp    stack.ControlType
		expectedExtra  uint32
		trunc          int
	}{
		{"PacketTooBig", 1, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, 0},
		{"Truncated (10 bytes missing)", 0, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, 10},
		{"Truncated (missing IPv6 header)", 0, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, header.IPv6MinimumSize + 8},
		{"Truncated PacketTooBig (missing 'extra info')", 0, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, 4 + header.IPv6MinimumSize + 8},
		{"Truncated (missing ICMP header)", 0, nil, header.ICMPv6PacketTooBig, 0, stack.ControlPacketTooBig, mtu, header.ICMPv6PacketTooBigMinimumSize + header.IPv6MinimumSize + 8},
		{"Port unreachable", 1, nil, header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Truncated DstUnreachable (missing 'extra info')", 0, nil, header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 4 + header.IPv6MinimumSize + 8},
		{"Fragmented, zero offset", 1, newUint16(0), header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Non-zero fragment offset", 0, newUint16(100), header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Zero-length packet", 0, nil, header.ICMPv6DstUnreachable, header.ICMPv6PortUnreachable, stack.ControlPortUnreachable, 0, 2*header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + 8},
	}
	r := stack.Route{
		LocalAddress:  "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
		RemoteAddress: "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa",
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var views [1]buffer.View
			o := testObject{t: t}
			proto := ipv6.NewProtocol()
			ep, err := proto.NewEndpoint(1, "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", nil, &o, nil)
			if err != nil {
				t.Fatalf("NewEndpoint failed: %v", err)
			}

			defer ep.Close()

			dataOffset := header.IPv6MinimumSize*2 + header.ICMPv6MinimumSize + 4
			if c.fragmentOffset != nil {
				dataOffset += header.IPv6FragmentHeaderSize
			}
			view := buffer.NewView(dataOffset + 8)

			// Create the outer IPv6 header.
			ip := header.IPv6(view)
			ip.Encode(&header.IPv6Fields{
				PayloadLength: uint16(len(view) - header.IPv6MinimumSize - c.trunc),
				NextHeader:    uint8(header.ICMPv6ProtocolNumber),
				HopLimit:      20,
				SrcAddr:       "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa",
				DstAddr:       "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			})

			// Create the ICMP header.
			icmp := header.ICMPv6(view[header.IPv6MinimumSize:])
			icmp.SetType(c.typ)
			icmp.SetCode(c.code)
			copy(view[header.IPv6MinimumSize+header.ICMPv6MinimumSize:], []byte{0xde, 0xad, 0xbe, 0xef})

			// Create the inner IPv6 header.
			ip = header.IPv6(view[header.IPv6MinimumSize+header.ICMPv6MinimumSize+4:])
			ip.Encode(&header.IPv6Fields{
				PayloadLength: 100,
				NextHeader:    10,
				HopLimit:      20,
				SrcAddr:       "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
				DstAddr:       "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
			})

			// Build the fragmentation header if needed.
			if c.fragmentOffset != nil {
				ip.SetNextHeader(header.IPv6FragmentHeader)
				frag := header.IPv6Fragment(view[2*header.IPv6MinimumSize+header.ICMPv6MinimumSize+4:])
				frag.Encode(&header.IPv6FragmentFields{
					NextHeader:     10,
					FragmentOffset: *c.fragmentOffset,
					M:              true,
					Identification: 0x12345678,
				})
			}

			// Make payload be non-zero.
			for i := dataOffset; i < len(view); i++ {
				view[i] = uint8(i)
			}

			// Give packet to IPv6 endpoint, dispatcher will validate that
			// it's ok.
			o.protocol = 10
			o.srcAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
			o.dstAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
			o.contents = view[dataOffset:]
			o.typ = c.expectedTyp
			o.extra = c.expectedExtra

			vv := view.ToVectorisedView(views)
			vv.CapLength(len(view) - c.trunc)
			ep.HandlePacket(&r, &vv)
			if want := c.expectedCount; o.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, o.controlCalls, want)
			}
		})
	}
}
