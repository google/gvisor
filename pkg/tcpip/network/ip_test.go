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

package ip_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	localIpv4Addr      = "\x0a\x00\x00\x01"
	localIpv4PrefixLen = 24
	remoteIpv4Addr     = "\x0a\x00\x00\x02"
	ipv4SubnetAddr     = "\x0a\x00\x00\x00"
	ipv4SubnetMask     = "\xff\xff\xff\x00"
	ipv4Gateway        = "\x0a\x00\x00\x03"
	localIpv6Addr      = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	localIpv6PrefixLen = 120
	remoteIpv6Addr     = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	ipv6SubnetAddr     = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	ipv6SubnetMask     = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00"
	ipv6Gateway        = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
	nicID              = 1
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
func (t *testObject) checkValues(protocol tcpip.TransportProtocolNumber, vv buffer.VectorisedView, srcAddr, dstAddr tcpip.Address) {
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
func (t *testObject) DeliverTransportPacket(r *stack.Route, protocol tcpip.TransportProtocolNumber, pkt *stack.PacketBuffer) {
	t.checkValues(protocol, pkt.Data, r.RemoteAddress, r.LocalAddress)
	t.dataCalls++
}

// DeliverTransportControlPacket is called by network endpoints after parsing
// incoming control (ICMP) packets. This is used by the test object to verify
// that the results of the parsing are expected.
func (t *testObject) DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ stack.ControlType, extra uint32, pkt *stack.PacketBuffer) {
	t.checkValues(trans, pkt.Data, remote, local)
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

// Wait implements stack.LinkEndpoint.Wait.
func (*testObject) Wait() {}

// WritePacket is called by network endpoints after producing a packet and
// writing it to the link endpoint. This is used by the test object to verify
// that the produced packet is as expected.
func (t *testObject) WritePacket(_ *stack.Route, _ *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	var prot tcpip.TransportProtocolNumber
	var srcAddr tcpip.Address
	var dstAddr tcpip.Address

	if t.v4 {
		h := header.IPv4(pkt.NetworkHeader().View())
		prot = tcpip.TransportProtocolNumber(h.Protocol())
		srcAddr = h.SourceAddress()
		dstAddr = h.DestinationAddress()

	} else {
		h := header.IPv6(pkt.NetworkHeader().View())
		prot = tcpip.TransportProtocolNumber(h.NextHeader())
		srcAddr = h.SourceAddress()
		dstAddr = h.DestinationAddress()
	}
	t.checkValues(prot, pkt.Data, srcAddr, dstAddr)
	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (*testObject) WritePackets(_ *stack.Route, _ *stack.GSO, pkt stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	panic("not implemented")
}

func (*testObject) WriteRawPacket(_ buffer.VectorisedView) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*testObject) ARPHardwareType() header.ARPHardwareType {
	panic("not implemented")
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*testObject) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	panic("not implemented")
}

func buildIPv4Route(local, remote tcpip.Address) (stack.Route, *tcpip.Error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{udp.NewProtocol(), tcp.NewProtocol()},
	})
	s.CreateNIC(nicID, loopback.New())
	s.AddAddress(nicID, ipv4.ProtocolNumber, local)
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		Gateway:     ipv4Gateway,
		NIC:         1,
	}})

	return s.FindRoute(nicID, local, remote, ipv4.ProtocolNumber, false /* multicastLoop */)
}

func buildIPv6Route(local, remote tcpip.Address) (stack.Route, *tcpip.Error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv6.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{udp.NewProtocol(), tcp.NewProtocol()},
	})
	s.CreateNIC(nicID, loopback.New())
	s.AddAddress(nicID, ipv6.ProtocolNumber, local)
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv6EmptySubnet,
		Gateway:     ipv6Gateway,
		NIC:         1,
	}})

	return s.FindRoute(nicID, local, remote, ipv6.ProtocolNumber, false /* multicastLoop */)
}

func buildDummyStack(t *testing.T) *stack.Stack {
	t.Helper()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{udp.NewProtocol(), tcp.NewProtocol()},
	})
	e := channel.New(0, 1280, "")
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	if err := s.AddAddress(nicID, header.IPv4ProtocolNumber, localIpv4Addr); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv4ProtocolNumber, localIpv4Addr, err)
	}

	if err := s.AddAddress(nicID, header.IPv6ProtocolNumber, localIpv6Addr); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv6ProtocolNumber, localIpv6Addr, err)
	}

	return s
}

var testNIC stack.NetworkInterface = (*testInterface)(nil)

type testInterface struct{}

func (*testInterface) ID() tcpip.NICID {
	return nicID
}

func (*testInterface) IsLoopback() bool {
	return false
}

func TestIPv4Send(t *testing.T) {
	o := testObject{t: t, v4: true}
	proto := ipv4.NewProtocol()
	ep := proto.NewEndpoint(testNIC, nil, nil, nil, &o, buildDummyStack(t))
	defer ep.Close()

	// Allocate and initialize the payload view.
	payload := buffer.NewView(100)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}

	// Setup the packet buffer.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Data:               payload.ToVectorisedView(),
	})

	// Issue the write.
	o.protocol = 123
	o.srcAddr = localIpv4Addr
	o.dstAddr = remoteIpv4Addr
	o.contents = payload

	r, err := buildIPv4Route(localIpv4Addr, remoteIpv4Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}
	if err := ep.WritePacket(&r, nil /* gso */, stack.NetworkHeaderParams{
		Protocol: 123,
		TTL:      123,
		TOS:      stack.DefaultTOS,
	}, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func TestIPv4Receive(t *testing.T) {
	o := testObject{t: t, v4: true}
	proto := ipv4.NewProtocol()
	ep := proto.NewEndpoint(testNIC, nil, nil, &o, nil, buildDummyStack(t))
	defer ep.Close()

	totalLen := header.IPv4MinimumSize + 30
	view := buffer.NewView(totalLen)
	ip := header.IPv4(view)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: uint16(totalLen),
		TTL:         20,
		Protocol:    10,
		SrcAddr:     remoteIpv4Addr,
		DstAddr:     localIpv4Addr,
	})

	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		view[i] = uint8(i)
	}

	// Give packet to ipv4 endpoint, dispatcher will validate that it's ok.
	o.protocol = 10
	o.srcAddr = remoteIpv4Addr
	o.dstAddr = localIpv4Addr
	o.contents = view[header.IPv4MinimumSize:totalLen]

	r, err := buildIPv4Route(localIpv4Addr, remoteIpv4Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: view.ToVectorisedView(),
	})
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	ep.HandlePacket(&r, pkt)
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
		code           header.ICMPv4Code
		expectedTyp    stack.ControlType
		expectedExtra  uint32
		trunc          int
	}{
		{"FragmentationNeeded", 1, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 0},
		{"Truncated (10 bytes missing)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 10},
		{"Truncated (missing IPv4 header)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, header.IPv4MinimumSize + 8},
		{"Truncated (missing 'extra info')", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, 4 + header.IPv4MinimumSize + 8},
		{"Truncated (missing ICMP header)", 0, 0, header.ICMPv4FragmentationNeeded, stack.ControlPacketTooBig, mtu, header.ICMPv4MinimumSize + header.IPv4MinimumSize + 8},
		{"Port unreachable", 1, 0, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Non-zero fragment offset", 0, 100, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 0},
		{"Zero-length packet", 0, 0, header.ICMPv4PortUnreachable, stack.ControlPortUnreachable, 0, 2*header.IPv4MinimumSize + header.ICMPv4MinimumSize + 8},
	}
	r, err := buildIPv4Route(localIpv4Addr, "\x0a\x00\x00\xbb")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := testObject{t: t}
			proto := ipv4.NewProtocol()
			ep := proto.NewEndpoint(testNIC, nil, nil, &o, nil, buildDummyStack(t))
			defer ep.Close()

			const dataOffset = header.IPv4MinimumSize*2 + header.ICMPv4MinimumSize
			view := buffer.NewView(dataOffset + 8)

			// Create the outer IPv4 header.
			ip := header.IPv4(view)
			ip.Encode(&header.IPv4Fields{
				IHL:         header.IPv4MinimumSize,
				TotalLength: uint16(len(view) - c.trunc),
				TTL:         20,
				Protocol:    uint8(header.ICMPv4ProtocolNumber),
				SrcAddr:     "\x0a\x00\x00\xbb",
				DstAddr:     localIpv4Addr,
			})

			// Create the ICMP header.
			icmp := header.ICMPv4(view[header.IPv4MinimumSize:])
			icmp.SetType(header.ICMPv4DstUnreachable)
			icmp.SetCode(c.code)
			icmp.SetIdent(0xdead)
			icmp.SetSequence(0xbeef)

			// Create the inner IPv4 header.
			ip = header.IPv4(view[header.IPv4MinimumSize+header.ICMPv4MinimumSize:])
			ip.Encode(&header.IPv4Fields{
				IHL:            header.IPv4MinimumSize,
				TotalLength:    100,
				TTL:            20,
				Protocol:       10,
				FragmentOffset: c.fragmentOffset,
				SrcAddr:        localIpv4Addr,
				DstAddr:        remoteIpv4Addr,
			})

			// Make payload be non-zero.
			for i := dataOffset; i < len(view); i++ {
				view[i] = uint8(i)
			}

			// Give packet to IPv4 endpoint, dispatcher will validate that
			// it's ok.
			o.protocol = 10
			o.srcAddr = remoteIpv4Addr
			o.dstAddr = localIpv4Addr
			o.contents = view[dataOffset:]
			o.typ = c.expectedTyp
			o.extra = c.expectedExtra

			ep.HandlePacket(&r, truncatedPacket(view, c.trunc, header.IPv4MinimumSize))
			if want := c.expectedCount; o.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, o.controlCalls, want)
			}
		})
	}
}

func TestIPv4FragmentationReceive(t *testing.T) {
	o := testObject{t: t, v4: true}
	proto := ipv4.NewProtocol()
	ep := proto.NewEndpoint(testNIC, nil, nil, &o, nil, buildDummyStack(t))
	defer ep.Close()

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
		SrcAddr:        remoteIpv4Addr,
		DstAddr:        localIpv4Addr,
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
		SrcAddr:        remoteIpv4Addr,
		DstAddr:        localIpv4Addr,
	})
	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		frag2[i] = uint8(i)
	}

	// Give packet to ipv4 endpoint, dispatcher will validate that it's ok.
	o.protocol = 10
	o.srcAddr = remoteIpv4Addr
	o.dstAddr = localIpv4Addr
	o.contents = append(frag1[header.IPv4MinimumSize:totalLen], frag2[header.IPv4MinimumSize:totalLen]...)

	r, err := buildIPv4Route(localIpv4Addr, remoteIpv4Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}

	// Send first segment.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: frag1.ToVectorisedView(),
	})
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	ep.HandlePacket(&r, pkt)
	if o.dataCalls != 0 {
		t.Fatalf("Bad number of data calls: got %x, want 0", o.dataCalls)
	}

	// Send second segment.
	pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: frag2.ToVectorisedView(),
	})
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	ep.HandlePacket(&r, pkt)
	if o.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", o.dataCalls)
	}
}

func TestIPv6Send(t *testing.T) {
	o := testObject{t: t}
	proto := ipv6.NewProtocol()
	ep := proto.NewEndpoint(testNIC, nil, nil, &o, channel.New(0, 1280, ""), buildDummyStack(t))
	defer ep.Close()

	// Allocate and initialize the payload view.
	payload := buffer.NewView(100)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}

	// Setup the packet buffer.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Data:               payload.ToVectorisedView(),
	})

	// Issue the write.
	o.protocol = 123
	o.srcAddr = localIpv6Addr
	o.dstAddr = remoteIpv6Addr
	o.contents = payload

	r, err := buildIPv6Route(localIpv6Addr, remoteIpv6Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}
	if err := ep.WritePacket(&r, nil /* gso */, stack.NetworkHeaderParams{
		Protocol: 123,
		TTL:      123,
		TOS:      stack.DefaultTOS,
	}, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func TestIPv6Receive(t *testing.T) {
	o := testObject{t: t}
	proto := ipv6.NewProtocol()
	ep := proto.NewEndpoint(testNIC, nil, nil, &o, nil, buildDummyStack(t))
	defer ep.Close()

	totalLen := header.IPv6MinimumSize + 30
	view := buffer.NewView(totalLen)
	ip := header.IPv6(view)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(totalLen - header.IPv6MinimumSize),
		NextHeader:    10,
		HopLimit:      20,
		SrcAddr:       remoteIpv6Addr,
		DstAddr:       localIpv6Addr,
	})

	// Make payload be non-zero.
	for i := header.IPv6MinimumSize; i < totalLen; i++ {
		view[i] = uint8(i)
	}

	// Give packet to ipv6 endpoint, dispatcher will validate that it's ok.
	o.protocol = 10
	o.srcAddr = remoteIpv6Addr
	o.dstAddr = localIpv6Addr
	o.contents = view[header.IPv6MinimumSize:totalLen]

	r, err := buildIPv6Route(localIpv6Addr, remoteIpv6Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: view.ToVectorisedView(),
	})
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	ep.HandlePacket(&r, pkt)
	if o.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", o.dataCalls)
	}
}

func TestIPv6ReceiveControl(t *testing.T) {
	newUint16 := func(v uint16) *uint16 { return &v }

	const mtu = 0xffff
	const outerSrcAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa"
	cases := []struct {
		name           string
		expectedCount  int
		fragmentOffset *uint16
		typ            header.ICMPv6Type
		code           header.ICMPv6Code
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
	r, err := buildIPv6Route(
		localIpv6Addr,
		"\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa",
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := testObject{t: t}
			proto := ipv6.NewProtocol()
			ep := proto.NewEndpoint(testNIC, nil, nil, &o, nil, buildDummyStack(t))
			defer ep.Close()

			dataOffset := header.IPv6MinimumSize*2 + header.ICMPv6MinimumSize
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
				SrcAddr:       outerSrcAddr,
				DstAddr:       localIpv6Addr,
			})

			// Create the ICMP header.
			icmp := header.ICMPv6(view[header.IPv6MinimumSize:])
			icmp.SetType(c.typ)
			icmp.SetCode(c.code)
			icmp.SetIdent(0xdead)
			icmp.SetSequence(0xbeef)

			// Create the inner IPv6 header.
			ip = header.IPv6(view[header.IPv6MinimumSize+header.ICMPv6PayloadOffset:])
			ip.Encode(&header.IPv6Fields{
				PayloadLength: 100,
				NextHeader:    10,
				HopLimit:      20,
				SrcAddr:       localIpv6Addr,
				DstAddr:       remoteIpv6Addr,
			})

			// Build the fragmentation header if needed.
			if c.fragmentOffset != nil {
				ip.SetNextHeader(header.IPv6FragmentHeader)
				frag := header.IPv6Fragment(view[2*header.IPv6MinimumSize+header.ICMPv6MinimumSize:])
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
			o.srcAddr = remoteIpv6Addr
			o.dstAddr = localIpv6Addr
			o.contents = view[dataOffset:]
			o.typ = c.expectedTyp
			o.extra = c.expectedExtra

			// Set ICMPv6 checksum.
			icmp.SetChecksum(header.ICMPv6Checksum(icmp, outerSrcAddr, localIpv6Addr, buffer.VectorisedView{}))

			ep.HandlePacket(&r, truncatedPacket(view, c.trunc, header.IPv6MinimumSize))
			if want := c.expectedCount; o.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, o.controlCalls, want)
			}
		})
	}
}

// truncatedPacket returns a PacketBuffer based on a truncated view. If view,
// after truncation, is large enough to hold a network header, it makes part of
// view the packet's NetworkHeader and the rest its Data. Otherwise all of view
// becomes Data.
func truncatedPacket(view buffer.View, trunc, netHdrLen int) *stack.PacketBuffer {
	v := view[:len(view)-trunc]
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: v.ToVectorisedView(),
	})
	_, _ = pkt.NetworkHeader().Consume(netHdrLen)
	return pkt
}
