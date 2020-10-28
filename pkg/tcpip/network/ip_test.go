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
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	localIPv4Addr  = "\x0a\x00\x00\x01"
	remoteIPv4Addr = "\x0a\x00\x00\x02"
	ipv4SubnetAddr = "\x0a\x00\x00\x00"
	ipv4SubnetMask = "\xff\xff\xff\x00"
	ipv4Gateway    = "\x0a\x00\x00\x03"
	localIPv6Addr  = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	remoteIPv6Addr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	ipv6SubnetAddr = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	ipv6SubnetMask = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00"
	ipv6Gateway    = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
	nicID          = 1
)

var localIPv4AddrWithPrefix = tcpip.AddressWithPrefix{
	Address:   localIPv4Addr,
	PrefixLen: 24,
}

var localIPv6AddrWithPrefix = tcpip.AddressWithPrefix{
	Address:   localIPv6Addr,
	PrefixLen: 120,
}

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
func (t *testObject) DeliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt *stack.PacketBuffer) stack.TransportPacketDisposition {
	netHdr := pkt.Network()
	t.checkValues(protocol, pkt.Data, netHdr.SourceAddress(), netHdr.DestinationAddress())
	t.dataCalls++
	return stack.TransportPacketHandled
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
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
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
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
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

func buildDummyStackWithLinkEndpoint(t *testing.T) (*stack.Stack, *channel.Endpoint) {
	t.Helper()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
	})
	e := channel.New(0, 1280, "")
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	v4Addr := tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: localIPv4AddrWithPrefix}
	if err := s.AddProtocolAddress(nicID, v4Addr); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %#v) = %s", nicID, v4Addr, err)
	}

	v6Addr := tcpip.ProtocolAddress{Protocol: header.IPv6ProtocolNumber, AddressWithPrefix: localIPv6AddrWithPrefix}
	if err := s.AddProtocolAddress(nicID, v6Addr); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %#v) = %s", nicID, v6Addr, err)
	}

	return s, e
}

func buildDummyStack(t *testing.T) *stack.Stack {
	t.Helper()

	s, _ := buildDummyStackWithLinkEndpoint(t)
	return s
}

var _ stack.NetworkInterface = (*testInterface)(nil)

type testInterface struct {
	testObject

	mu struct {
		sync.RWMutex
		disabled bool
	}
}

func (*testInterface) ID() tcpip.NICID {
	return nicID
}

func (*testInterface) IsLoopback() bool {
	return false
}

func (*testInterface) Name() string {
	return ""
}

func (t *testInterface) Enabled() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return !t.mu.disabled
}

func (t *testInterface) setEnabled(v bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mu.disabled = !v
}

func (*testInterface) WritePacketToRemote(tcpip.LinkAddress, *stack.GSO, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) *tcpip.Error {
	return tcpip.ErrNotSupported
}

func TestSourceAddressValidation(t *testing.T) {
	rxIPv4ICMP := func(e *channel.Endpoint, src tcpip.Address) {
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
			SrcAddr:     src,
			DstAddr:     localIPv4Addr,
		})
		ip.SetChecksum(^ip.CalculateChecksum())

		e.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	rxIPv6ICMP := func(e *channel.Endpoint, src tcpip.Address) {
		totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
		hdr := buffer.NewPrependable(totalLen)
		pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))
		pkt.SetType(header.ICMPv6EchoRequest)
		pkt.SetCode(0)
		pkt.SetChecksum(0)
		pkt.SetChecksum(header.ICMPv6Checksum(pkt, src, localIPv6Addr, buffer.VectorisedView{}))
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength: header.ICMPv6MinimumSize,
			NextHeader:    uint8(icmp.ProtocolNumber6),
			HopLimit:      ipv6.DefaultTTL,
			SrcAddr:       src,
			DstAddr:       localIPv6Addr,
		})
		e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: hdr.View().ToVectorisedView(),
		}))
	}

	tests := []struct {
		name       string
		srcAddress tcpip.Address
		rxICMP     func(*channel.Endpoint, tcpip.Address)
		valid      bool
	}{
		{
			name:       "IPv4 valid",
			srcAddress: "\x01\x02\x03\x04",
			rxICMP:     rxIPv4ICMP,
			valid:      true,
		},
		{
			name:       "IPv6 valid",
			srcAddress: "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
			rxICMP:     rxIPv6ICMP,
			valid:      true,
		},
		{
			name:       "IPv4 unspecified",
			srcAddress: header.IPv4Any,
			rxICMP:     rxIPv4ICMP,
			valid:      true,
		},
		{
			name:       "IPv6 unspecified",
			srcAddress: header.IPv4Any,
			rxICMP:     rxIPv6ICMP,
			valid:      true,
		},
		{
			name:       "IPv4 multicast",
			srcAddress: "\xe0\x00\x00\x01",
			rxICMP:     rxIPv4ICMP,
			valid:      false,
		},
		{
			name:       "IPv6 multicast",
			srcAddress: "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			rxICMP:     rxIPv6ICMP,
			valid:      false,
		},
		{
			name:       "IPv4 broadcast",
			srcAddress: header.IPv4Broadcast,
			rxICMP:     rxIPv4ICMP,
			valid:      false,
		},
		{
			name: "IPv4 subnet broadcast",
			srcAddress: func() tcpip.Address {
				subnet := localIPv4AddrWithPrefix.Subnet()
				return subnet.Broadcast()
			}(),
			rxICMP: rxIPv4ICMP,
			valid:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, e := buildDummyStackWithLinkEndpoint(t)
			test.rxICMP(e, test.srcAddress)

			var wantValid uint64
			if test.valid {
				wantValid = 1
			}

			if got, want := s.Stats().IP.InvalidSourceAddressesReceived.Value(), 1-wantValid; got != want {
				t.Errorf("got s.Stats().IP.InvalidSourceAddressesReceived.Value() = %d, want = %d", got, want)
			}
			if got := s.Stats().IP.PacketsDelivered.Value(); got != wantValid {
				t.Errorf("got s.Stats().IP.PacketsDelivered.Value() = %d, want = %d", got, wantValid)
			}
		})
	}
}

func TestEnableWhenNICDisabled(t *testing.T) {
	tests := []struct {
		name            string
		protocolFactory stack.NetworkProtocolFactory
		protoNum        tcpip.NetworkProtocolNumber
	}{
		{
			name:            "IPv4",
			protocolFactory: ipv4.NewProtocol,
			protoNum:        ipv4.ProtocolNumber,
		},
		{
			name:            "IPv6",
			protocolFactory: ipv6.NewProtocol,
			protoNum:        ipv6.ProtocolNumber,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var nic testInterface
			nic.setEnabled(false)

			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{test.protocolFactory},
			})
			p := s.NetworkProtocolInstance(test.protoNum)

			// We pass nil for all parameters except the NetworkInterface and Stack
			// since Enable only depends on these.
			ep := p.NewEndpoint(&nic, nil, nil, nil)

			// The endpoint should initially be disabled, regardless the NIC's enabled
			// status.
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}
			nic.setEnabled(true)
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}

			// Attempting to enable the endpoint while the NIC is disabled should
			// fail.
			nic.setEnabled(false)
			if err := ep.Enable(); err != tcpip.ErrNotPermitted {
				t.Fatalf("got ep.Enable() = %s, want = %s", err, tcpip.ErrNotPermitted)
			}
			// ep should consider the NIC's enabled status when determining its own
			// enabled status so we "enable" the NIC to read just the endpoint's
			// enabled status.
			nic.setEnabled(true)
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}

			// Enabling the interface after the NIC has been enabled should succeed.
			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}
			if !ep.Enabled() {
				t.Fatal("got ep.Enabled() = false, want = true")
			}

			// ep should consider the NIC's enabled status when determining its own
			// enabled status.
			nic.setEnabled(false)
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}

			// Disabling the endpoint when the NIC is enabled should make the endpoint
			// disabled.
			nic.setEnabled(true)
			ep.Disable()
			if ep.Enabled() {
				t.Fatal("got ep.Enabled() = true, want = false")
			}
		})
	}
}

func TestIPv4Send(t *testing.T) {
	s := buildDummyStack(t)
	proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t:  t,
			v4: true,
		},
	}
	ep := proto.NewEndpoint(&nic, nil, nil, nil)
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
	nic.testObject.protocol = 123
	nic.testObject.srcAddr = localIPv4Addr
	nic.testObject.dstAddr = remoteIPv4Addr
	nic.testObject.contents = payload

	r, err := buildIPv4Route(localIPv4Addr, remoteIPv4Addr)
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
	s := buildDummyStack(t)
	proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t:  t,
			v4: true,
		},
	}
	ep := proto.NewEndpoint(&nic, nil, nil, &nic.testObject)
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	totalLen := header.IPv4MinimumSize + 30
	view := buffer.NewView(totalLen)
	ip := header.IPv4(view)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: uint16(totalLen),
		TTL:         20,
		Protocol:    10,
		SrcAddr:     remoteIPv4Addr,
		DstAddr:     localIPv4Addr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		view[i] = uint8(i)
	}

	// Give packet to ipv4 endpoint, dispatcher will validate that it's ok.
	nic.testObject.protocol = 10
	nic.testObject.srcAddr = remoteIPv4Addr
	nic.testObject.dstAddr = localIPv4Addr
	nic.testObject.contents = view[header.IPv4MinimumSize:totalLen]

	r, err := buildIPv4Route(localIPv4Addr, remoteIPv4Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: view.ToVectorisedView(),
	})
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	r.PopulatePacketInfo(pkt)
	ep.HandlePacket(pkt)
	if nic.testObject.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", nic.testObject.dataCalls)
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
	r, err := buildIPv4Route(localIPv4Addr, "\x0a\x00\x00\xbb")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := buildDummyStack(t)
			proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
			nic := testInterface{
				testObject: testObject{
					t: t,
				},
			}
			ep := proto.NewEndpoint(&nic, nil, nil, &nic.testObject)
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

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
				DstAddr:     localIPv4Addr,
			})
			ip.SetChecksum(^ip.CalculateChecksum())

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
				SrcAddr:        localIPv4Addr,
				DstAddr:        remoteIPv4Addr,
			})
			ip.SetChecksum(^ip.CalculateChecksum())

			// Make payload be non-zero.
			for i := dataOffset; i < len(view); i++ {
				view[i] = uint8(i)
			}

			icmp.SetChecksum(0)
			checksum := ^header.Checksum(icmp, 0 /* initial */)
			icmp.SetChecksum(checksum)

			// Give packet to IPv4 endpoint, dispatcher will validate that
			// it's ok.
			nic.testObject.protocol = 10
			nic.testObject.srcAddr = remoteIPv4Addr
			nic.testObject.dstAddr = localIPv4Addr
			nic.testObject.contents = view[dataOffset:]
			nic.testObject.typ = c.expectedTyp
			nic.testObject.extra = c.expectedExtra

			pkt := truncatedPacket(view, c.trunc, header.IPv4MinimumSize)
			r.PopulatePacketInfo(pkt)
			ep.HandlePacket(pkt)
			if want := c.expectedCount; nic.testObject.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, nic.testObject.controlCalls, want)
			}
		})
	}
}

func TestIPv4FragmentationReceive(t *testing.T) {
	s := buildDummyStack(t)
	proto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t:  t,
			v4: true,
		},
	}
	ep := proto.NewEndpoint(&nic, nil, nil, &nic.testObject)
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
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
		SrcAddr:        remoteIPv4Addr,
		DstAddr:        localIPv4Addr,
	})
	ip1.SetChecksum(^ip1.CalculateChecksum())

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
		SrcAddr:        remoteIPv4Addr,
		DstAddr:        localIPv4Addr,
	})
	ip2.SetChecksum(^ip2.CalculateChecksum())

	// Make payload be non-zero.
	for i := header.IPv4MinimumSize; i < totalLen; i++ {
		frag2[i] = uint8(i)
	}

	// Give packet to ipv4 endpoint, dispatcher will validate that it's ok.
	nic.testObject.protocol = 10
	nic.testObject.srcAddr = remoteIPv4Addr
	nic.testObject.dstAddr = localIPv4Addr
	nic.testObject.contents = append(frag1[header.IPv4MinimumSize:totalLen], frag2[header.IPv4MinimumSize:totalLen]...)

	r, err := buildIPv4Route(localIPv4Addr, remoteIPv4Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}

	// Send first segment.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: frag1.ToVectorisedView(),
	})
	r.PopulatePacketInfo(pkt)
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	ep.HandlePacket(pkt)
	if nic.testObject.dataCalls != 0 {
		t.Fatalf("Bad number of data calls: got %x, want 0", nic.testObject.dataCalls)
	}

	// Send second segment.
	pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: frag2.ToVectorisedView(),
	})
	r.PopulatePacketInfo(pkt)
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	ep.HandlePacket(pkt)
	if nic.testObject.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", nic.testObject.dataCalls)
	}
}

func TestIPv6Send(t *testing.T) {
	s := buildDummyStack(t)
	proto := s.NetworkProtocolInstance(ipv6.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t: t,
		},
	}
	ep := proto.NewEndpoint(&nic, nil, nil, nil)
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

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
	nic.testObject.protocol = 123
	nic.testObject.srcAddr = localIPv6Addr
	nic.testObject.dstAddr = remoteIPv6Addr
	nic.testObject.contents = payload

	r, err := buildIPv6Route(localIPv6Addr, remoteIPv6Addr)
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
	s := buildDummyStack(t)
	proto := s.NetworkProtocolInstance(ipv6.ProtocolNumber)
	nic := testInterface{
		testObject: testObject{
			t: t,
		},
	}
	ep := proto.NewEndpoint(&nic, nil, nil, &nic.testObject)
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	totalLen := header.IPv6MinimumSize + 30
	view := buffer.NewView(totalLen)
	ip := header.IPv6(view)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(totalLen - header.IPv6MinimumSize),
		NextHeader:    10,
		HopLimit:      20,
		SrcAddr:       remoteIPv6Addr,
		DstAddr:       localIPv6Addr,
	})

	// Make payload be non-zero.
	for i := header.IPv6MinimumSize; i < totalLen; i++ {
		view[i] = uint8(i)
	}

	// Give packet to ipv6 endpoint, dispatcher will validate that it's ok.
	nic.testObject.protocol = 10
	nic.testObject.srcAddr = remoteIPv6Addr
	nic.testObject.dstAddr = localIPv6Addr
	nic.testObject.contents = view[header.IPv6MinimumSize:totalLen]

	r, err := buildIPv6Route(localIPv6Addr, remoteIPv6Addr)
	if err != nil {
		t.Fatalf("could not find route: %v", err)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: view.ToVectorisedView(),
	})
	r.PopulatePacketInfo(pkt)
	if _, _, ok := proto.Parse(pkt); !ok {
		t.Fatalf("failed to parse packet: %x", pkt.Data.ToView())
	}
	ep.HandlePacket(pkt)
	if nic.testObject.dataCalls != 1 {
		t.Fatalf("Bad number of data calls: got %x, want 1", nic.testObject.dataCalls)
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
		localIPv6Addr,
		"\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa",
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := buildDummyStack(t)
			proto := s.NetworkProtocolInstance(ipv6.ProtocolNumber)
			nic := testInterface{
				testObject: testObject{
					t: t,
				},
			}
			ep := proto.NewEndpoint(&nic, nil, nil, &nic.testObject)
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

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
				DstAddr:       localIPv6Addr,
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
				SrcAddr:       localIPv6Addr,
				DstAddr:       remoteIPv6Addr,
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
			nic.testObject.protocol = 10
			nic.testObject.srcAddr = remoteIPv6Addr
			nic.testObject.dstAddr = localIPv6Addr
			nic.testObject.contents = view[dataOffset:]
			nic.testObject.typ = c.expectedTyp
			nic.testObject.extra = c.expectedExtra

			// Set ICMPv6 checksum.
			icmp.SetChecksum(header.ICMPv6Checksum(icmp, outerSrcAddr, localIPv6Addr, buffer.VectorisedView{}))

			pkt := truncatedPacket(view, c.trunc, header.IPv6MinimumSize)
			r.PopulatePacketInfo(pkt)
			ep.HandlePacket(pkt)
			if want := c.expectedCount; nic.testObject.controlCalls != want {
				t.Fatalf("Bad number of control calls for %q case: got %v, want %v", c.name, nic.testObject.controlCalls, want)
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

func TestWriteHeaderIncludedPacket(t *testing.T) {
	const (
		nicID          = 1
		transportProto = 5

		dataLen    = 4
		optionsLen = 4
	)

	dataBuf := [dataLen]byte{1, 2, 3, 4}
	data := dataBuf[:]

	ipv4OptionsBuf := [optionsLen]byte{0, 1, 0, 1}
	ipv4Options := ipv4OptionsBuf[:]

	ipv6FragmentExtHdrBuf := [header.IPv6FragmentExtHdrLength]byte{transportProto, 0, 62, 4, 1, 2, 3, 4}
	ipv6FragmentExtHdr := ipv6FragmentExtHdrBuf[:]

	var ipv6PayloadWithExtHdrBuf [dataLen + header.IPv6FragmentExtHdrLength]byte
	ipv6PayloadWithExtHdr := ipv6PayloadWithExtHdrBuf[:]
	if n := copy(ipv6PayloadWithExtHdr, ipv6FragmentExtHdr); n != len(ipv6FragmentExtHdr) {
		t.Fatalf("copied %d bytes, expected %d bytes", n, len(ipv6FragmentExtHdr))
	}
	if n := copy(ipv6PayloadWithExtHdr[header.IPv6FragmentExtHdrLength:], data); n != len(data) {
		t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
	}

	tests := []struct {
		name         string
		protoFactory stack.NetworkProtocolFactory
		protoNum     tcpip.NetworkProtocolNumber
		nicAddr      tcpip.Address
		remoteAddr   tcpip.Address
		pktGen       func(*testing.T, tcpip.Address) buffer.VectorisedView
		checker      func(*testing.T, *stack.PacketBuffer, tcpip.Address)
		expectedErr  *tcpip.Error
	}{
		{
			name:         "IPv4",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				totalLen := header.IPv4MinimumSize + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					IHL:      header.IPv4MinimumSize,
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				return hdr.View().ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.View()) != header.IPv4MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), header.IPv4MinimumSize)
				}

				checker.IPv4(t, stack.PayloadSince(netHdr),
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv4Addr),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.IPFullLength(uint16(header.IPv4MinimumSize+len(data))),
					checker.IPPayload(data),
				)
			},
		},
		{
			name:         "IPv4 with IHL too small",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				totalLen := header.IPv4MinimumSize + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					IHL:      header.IPv4MinimumSize - 1,
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				return hdr.View().ToVectorisedView()
			},
			expectedErr: tcpip.ErrMalformedHeader,
		},
		{
			name:         "IPv4 too small",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					IHL:      header.IPv4MinimumSize,
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				return buffer.View(ip[:len(ip)-1]).ToVectorisedView()
			},
			expectedErr: tcpip.ErrMalformedHeader,
		},
		{
			name:         "IPv4 minimum size",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					IHL:      header.IPv4MinimumSize,
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				return buffer.View(ip).ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.View()) != header.IPv4MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), header.IPv4MinimumSize)
				}

				checker.IPv4(t, stack.PayloadSince(netHdr),
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv4Addr),
					checker.IPv4HeaderLength(header.IPv4MinimumSize),
					checker.IPFullLength(header.IPv4MinimumSize),
					checker.IPPayload(nil),
				)
			},
		},
		{
			name:         "IPv4 with options",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ipHdrLen := header.IPv4MinimumSize + len(ipv4Options)
				totalLen := ipHdrLen + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv4(hdr.Prepend(ipHdrLen))
				ip.Encode(&header.IPv4Fields{
					IHL:      uint8(ipHdrLen),
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				if n := copy(ip.Options(), ipv4Options); n != len(ipv4Options) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(ipv4Options))
				}
				return hdr.View().ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				hdrLen := header.IPv4MinimumSize + len(ipv4Options)
				if len(netHdr.View()) != hdrLen {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), hdrLen)
				}

				checker.IPv4(t, stack.PayloadSince(netHdr),
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv4Addr),
					checker.IPv4HeaderLength(hdrLen),
					checker.IPFullLength(uint16(hdrLen+len(data))),
					checker.IPv4Options(ipv4Options),
					checker.IPPayload(data),
				)
			},
		},
		{
			name:         "IPv4 with options and data across views",
			protoFactory: ipv4.NewProtocol,
			protoNum:     ipv4.ProtocolNumber,
			nicAddr:      localIPv4Addr,
			remoteAddr:   remoteIPv4Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
				ip.Encode(&header.IPv4Fields{
					IHL:      uint8(header.IPv4MinimumSize + len(ipv4Options)),
					Protocol: transportProto,
					TTL:      ipv4.DefaultTTL,
					SrcAddr:  src,
					DstAddr:  header.IPv4Any,
				})
				vv := buffer.View(ip).ToVectorisedView()
				vv.AppendView(ipv4Options)
				vv.AppendView(data)
				return vv
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv4Any {
					src = localIPv4Addr
				}

				netHdr := pkt.NetworkHeader()

				hdrLen := header.IPv4MinimumSize + len(ipv4Options)
				if len(netHdr.View()) != hdrLen {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), hdrLen)
				}

				checker.IPv4(t, stack.PayloadSince(netHdr),
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv4Addr),
					checker.IPv4HeaderLength(hdrLen),
					checker.IPFullLength(uint16(hdrLen+len(data))),
					checker.IPv4Options(ipv4Options),
					checker.IPPayload(data),
				)
			},
		},
		{
			name:         "IPv6",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			nicAddr:      localIPv6Addr,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				totalLen := header.IPv6MinimumSize + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					NextHeader: transportProto,
					HopLimit:   ipv6.DefaultTTL,
					SrcAddr:    src,
					DstAddr:    header.IPv4Any,
				})
				return hdr.View().ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.View()) != header.IPv6MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), header.IPv6MinimumSize)
				}

				checker.IPv6(t, stack.PayloadSince(netHdr),
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv6Addr),
					checker.IPFullLength(uint16(header.IPv6MinimumSize+len(data))),
					checker.IPPayload(data),
				)
			},
		},
		{
			name:         "IPv6 with extension header",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			nicAddr:      localIPv6Addr,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				totalLen := header.IPv6MinimumSize + len(ipv6FragmentExtHdr) + len(data)
				hdr := buffer.NewPrependable(totalLen)
				if n := copy(hdr.Prepend(len(data)), data); n != len(data) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(data))
				}
				if n := copy(hdr.Prepend(len(ipv6FragmentExtHdr)), ipv6FragmentExtHdr); n != len(ipv6FragmentExtHdr) {
					t.Fatalf("copied %d bytes, expected %d bytes", n, len(ipv6FragmentExtHdr))
				}
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					NextHeader: uint8(header.IPv6FragmentExtHdrIdentifier),
					HopLimit:   ipv6.DefaultTTL,
					SrcAddr:    src,
					DstAddr:    header.IPv4Any,
				})
				return hdr.View().ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if want := header.IPv6MinimumSize + len(ipv6FragmentExtHdr); len(netHdr.View()) != want {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), want)
				}

				checker.IPv6(t, stack.PayloadSince(netHdr),
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv6Addr),
					checker.IPFullLength(uint16(header.IPv6MinimumSize+len(ipv6PayloadWithExtHdr))),
					checker.IPPayload(ipv6PayloadWithExtHdr),
				)
			},
		},
		{
			name:         "IPv6 minimum size",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			nicAddr:      localIPv6Addr,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv6(make([]byte, header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					NextHeader: transportProto,
					HopLimit:   ipv6.DefaultTTL,
					SrcAddr:    src,
					DstAddr:    header.IPv4Any,
				})
				return buffer.View(ip).ToVectorisedView()
			},
			checker: func(t *testing.T, pkt *stack.PacketBuffer, src tcpip.Address) {
				if src == header.IPv6Any {
					src = localIPv6Addr
				}

				netHdr := pkt.NetworkHeader()

				if len(netHdr.View()) != header.IPv6MinimumSize {
					t.Errorf("got len(netHdr.View()) = %d, want = %d", len(netHdr.View()), header.IPv6MinimumSize)
				}

				checker.IPv6(t, stack.PayloadSince(netHdr),
					checker.SrcAddr(src),
					checker.DstAddr(remoteIPv6Addr),
					checker.IPFullLength(header.IPv6MinimumSize),
					checker.IPPayload(nil),
				)
			},
		},
		{
			name:         "IPv6 too small",
			protoFactory: ipv6.NewProtocol,
			protoNum:     ipv6.ProtocolNumber,
			nicAddr:      localIPv6Addr,
			remoteAddr:   remoteIPv6Addr,
			pktGen: func(t *testing.T, src tcpip.Address) buffer.VectorisedView {
				ip := header.IPv6(make([]byte, header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					NextHeader: transportProto,
					HopLimit:   ipv6.DefaultTTL,
					SrcAddr:    src,
					DstAddr:    header.IPv4Any,
				})
				return buffer.View(ip[:len(ip)-1]).ToVectorisedView()
			},
			expectedErr: tcpip.ErrMalformedHeader,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subTests := []struct {
				name    string
				srcAddr tcpip.Address
			}{
				{
					name:    "unspecified source",
					srcAddr: tcpip.Address(strings.Repeat("\x00", len(test.nicAddr))),
				},
				{
					name:    "random source",
					srcAddr: tcpip.Address(strings.Repeat("\xab", len(test.nicAddr))),
				},
			}

			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols: []stack.NetworkProtocolFactory{test.protoFactory},
					})
					e := channel.New(1, 1280, "")
					if err := s.CreateNIC(nicID, e); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					if err := s.AddAddress(nicID, test.protoNum, test.nicAddr); err != nil {
						t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, test.protoNum, test.nicAddr, err)
					}

					s.SetRouteTable([]tcpip.Route{{Destination: test.remoteAddr.WithPrefix().Subnet(), NIC: nicID}})

					r, err := s.FindRoute(nicID, test.nicAddr, test.remoteAddr, test.protoNum, false /* multicastLoop */)
					if err != nil {
						t.Fatalf("s.FindRoute(%d, %s, %s, %d, false): %s", nicID, test.remoteAddr, test.nicAddr, test.protoNum, err)
					}
					defer r.Release()

					if err := r.WriteHeaderIncludedPacket(stack.NewPacketBuffer(stack.PacketBufferOptions{
						Data: test.pktGen(t, subTest.srcAddr),
					})); err != test.expectedErr {
						t.Fatalf("got r.WriteHeaderIncludedPacket(_) = %s, want = %s", err, test.expectedErr)
					}

					if test.expectedErr != nil {
						return
					}

					pkt, ok := e.Read()
					if !ok {
						t.Fatal("expected a packet to be written")
					}
					test.checker(t, pkt.Pkt, subTest.srcAddr)
				})
			}
		})
	}
}
