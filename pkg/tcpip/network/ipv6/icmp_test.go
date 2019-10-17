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

package ipv6

import (
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	linkAddr0 = tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06")
	linkAddr1 = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0f")
)

var (
	lladdr0 = header.LinkLocalAddr(linkAddr0)
	lladdr1 = header.LinkLocalAddr(linkAddr1)
)

type stubLinkEndpoint struct {
	stack.LinkEndpoint
}

func (*stubLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}

func (*stubLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (*stubLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (*stubLinkEndpoint) WritePacket(*stack.Route, *stack.GSO, buffer.Prependable, buffer.VectorisedView, tcpip.NetworkProtocolNumber) *tcpip.Error {
	return nil
}

func (*stubLinkEndpoint) Attach(stack.NetworkDispatcher) {}

type stubDispatcher struct {
	stack.TransportDispatcher
}

func (*stubDispatcher) DeliverTransportPacket(*stack.Route, tcpip.TransportProtocolNumber, buffer.View, buffer.VectorisedView) {
}

type stubLinkAddressCache struct {
	stack.LinkAddressCache
}

func (*stubLinkAddressCache) CheckLocalAddress(tcpip.NICID, tcpip.NetworkProtocolNumber, tcpip.Address) tcpip.NICID {
	return 0
}

func (*stubLinkAddressCache) AddLinkAddress(tcpip.NICID, tcpip.Address, tcpip.LinkAddress) {
}

func TestICMPCounts(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol6()},
	})
	{
		if err := s.CreateNIC(1, &stubLinkEndpoint{}); err != nil {
			t.Fatalf("CreateNIC(_) = %s", err)
		}
		if err := s.AddAddress(1, ProtocolNumber, lladdr0); err != nil {
			t.Fatalf("AddAddress(_, %d, %s) = %s", ProtocolNumber, lladdr0, err)
		}
	}
	{
		subnet, err := tcpip.NewSubnet(lladdr1, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr1))))
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
	ep, err := netProto.NewEndpoint(0, tcpip.AddressWithPrefix{lladdr1, netProto.DefaultPrefixLen()}, &stubLinkAddressCache{}, &stubDispatcher{}, nil)
	if err != nil {
		t.Fatalf("NewEndpoint(_) = _, %s, want = _, nil", err)
	}

	r, err := s.FindRoute(1, lladdr0, lladdr1, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(_) = _, %s, want = _, nil", err)
	}
	defer r.Release()

	types := []struct {
		typ  header.ICMPv6Type
		size int
	}{
		{header.ICMPv6DstUnreachable, header.ICMPv6DstUnreachableMinimumSize},
		{header.ICMPv6PacketTooBig, header.ICMPv6PacketTooBigMinimumSize},
		{header.ICMPv6TimeExceeded, header.ICMPv6MinimumSize},
		{header.ICMPv6ParamProblem, header.ICMPv6MinimumSize},
		{header.ICMPv6EchoRequest, header.ICMPv6EchoMinimumSize},
		{header.ICMPv6EchoReply, header.ICMPv6EchoMinimumSize},
		{header.ICMPv6RouterSolicit, header.ICMPv6MinimumSize},
		{header.ICMPv6RouterAdvert, header.ICMPv6MinimumSize},
		{header.ICMPv6NeighborSolicit, header.ICMPv6NeighborSolicitMinimumSize},
		{header.ICMPv6NeighborAdvert, header.ICMPv6NeighborAdvertSize},
		{header.ICMPv6RedirectMsg, header.ICMPv6MinimumSize},
	}

	handleIPv6Payload := func(hdr buffer.Prependable) {
		payloadLength := hdr.UsedLength()
		ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength: uint16(payloadLength),
			NextHeader:    uint8(header.ICMPv6ProtocolNumber),
			HopLimit:      header.NDPHopLimit,
			SrcAddr:       r.LocalAddress,
			DstAddr:       r.RemoteAddress,
		})
		ep.HandlePacket(&r, hdr.View().ToVectorisedView())
	}

	for _, typ := range types {
		hdr := buffer.NewPrependable(header.IPv6MinimumSize + typ.size)
		pkt := header.ICMPv6(hdr.Prepend(typ.size))
		pkt.SetType(typ.typ)
		pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

		handleIPv6Payload(hdr)
	}

	// Construct an empty ICMP packet so that
	// Stats().ICMP.ICMPv6ReceivedPacketStats.Invalid is incremented.
	handleIPv6Payload(buffer.NewPrependable(header.IPv6MinimumSize))

	icmpv6Stats := s.Stats().ICMP.V6PacketsReceived
	visitStats(reflect.ValueOf(&icmpv6Stats).Elem(), func(name string, s *tcpip.StatCounter) {
		if got, want := s.Value(), uint64(1); got != want {
			t.Errorf("got %s = %d, want = %d", name, got, want)
		}
	})
	if t.Failed() {
		t.Logf("stats:\n%+v", s.Stats())
	}
}

func visitStats(v reflect.Value, f func(string, *tcpip.StatCounter)) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		v := v.Field(i)
		if s, ok := v.Interface().(*tcpip.StatCounter); ok {
			f(t.Field(i).Name, s)
		} else {
			visitStats(v, f)
		}
	}
}

type testContext struct {
	s0 *stack.Stack
	s1 *stack.Stack

	linkEP0 *channel.Endpoint
	linkEP1 *channel.Endpoint
}

type endpointWithResolutionCapability struct {
	stack.LinkEndpoint
}

func (e endpointWithResolutionCapability) Capabilities() stack.LinkEndpointCapabilities {
	return e.LinkEndpoint.Capabilities() | stack.CapabilityResolutionRequired
}

func newTestContext(t *testing.T) *testContext {
	c := &testContext{
		s0: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
			TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol6()},
		}),
		s1: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
			TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol6()},
		}),
	}

	const defaultMTU = 65536
	c.linkEP0 = channel.New(256, defaultMTU, linkAddr0)

	wrappedEP0 := stack.LinkEndpoint(endpointWithResolutionCapability{LinkEndpoint: c.linkEP0})
	if testing.Verbose() {
		wrappedEP0 = sniffer.New(wrappedEP0)
	}
	if err := c.s0.CreateNIC(1, wrappedEP0); err != nil {
		t.Fatalf("CreateNIC s0: %v", err)
	}
	if err := c.s0.AddAddress(1, ProtocolNumber, lladdr0); err != nil {
		t.Fatalf("AddAddress lladdr0: %v", err)
	}

	c.linkEP1 = channel.New(256, defaultMTU, linkAddr1)
	wrappedEP1 := stack.LinkEndpoint(endpointWithResolutionCapability{LinkEndpoint: c.linkEP1})
	if err := c.s1.CreateNIC(1, wrappedEP1); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}
	if err := c.s1.AddAddress(1, ProtocolNumber, lladdr1); err != nil {
		t.Fatalf("AddAddress lladdr1: %v", err)
	}

	subnet0, err := tcpip.NewSubnet(lladdr1, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr1))))
	if err != nil {
		t.Fatal(err)
	}
	c.s0.SetRouteTable(
		[]tcpip.Route{{
			Destination: subnet0,
			NIC:         1,
		}},
	)
	subnet1, err := tcpip.NewSubnet(lladdr0, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr0))))
	if err != nil {
		t.Fatal(err)
	}
	c.s1.SetRouteTable(
		[]tcpip.Route{{
			Destination: subnet1,
			NIC:         1,
		}},
	)

	return c
}

func (c *testContext) cleanup() {
	close(c.linkEP0.C)
	close(c.linkEP1.C)
}

type routeArgs struct {
	src, dst *channel.Endpoint
	typ      header.ICMPv6Type
}

func routeICMPv6Packet(t *testing.T, args routeArgs, fn func(*testing.T, header.ICMPv6)) {
	t.Helper()

	pkt := <-args.src.C

	{
		views := []buffer.View{pkt.Header, pkt.Payload}
		size := len(pkt.Header) + len(pkt.Payload)
		vv := buffer.NewVectorisedView(size, views)
		args.dst.InjectLinkAddr(pkt.Proto, args.dst.LinkAddress(), vv)
	}

	if pkt.Proto != ProtocolNumber {
		t.Errorf("unexpected protocol number %d", pkt.Proto)
		return
	}
	ipv6 := header.IPv6(pkt.Header)
	transProto := tcpip.TransportProtocolNumber(ipv6.NextHeader())
	if transProto != header.ICMPv6ProtocolNumber {
		t.Errorf("unexpected transport protocol number %d", transProto)
		return
	}
	icmpv6 := header.ICMPv6(ipv6.Payload())
	if got, want := icmpv6.Type(), args.typ; got != want {
		t.Errorf("got ICMPv6 type = %d, want = %d", got, want)
		return
	}
	if fn != nil {
		fn(t, icmpv6)
	}
}

func TestLinkResolution(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

	r, err := c.s0.FindRoute(1, lladdr0, lladdr1, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(_) = _, %s, want = _, nil", err)
	}
	defer r.Release()

	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.IPv6MinimumSize + header.ICMPv6EchoMinimumSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6EchoMinimumSize))
	pkt.SetType(header.ICMPv6EchoRequest)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))
	payload := tcpip.SlicePayload(hdr.View())

	// We can't send our payload directly over the route because that
	// doesn't provoke NDP discovery.
	var wq waiter.Queue
	ep, err := c.s0.NewEndpoint(header.ICMPv6ProtocolNumber, ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint(_) = _, %s, want = _, nil", err)
	}

	for {
		_, resCh, err := ep.Write(payload, tcpip.WriteOptions{To: &tcpip.FullAddress{NIC: 1, Addr: lladdr1}})
		if resCh != nil {
			if err != tcpip.ErrNoLinkAddress {
				t.Fatalf("ep.Write(_) = _, <non-nil>, %s, want = _, <non-nil>, tcpip.ErrNoLinkAddress", err)
			}
			for _, args := range []routeArgs{
				{src: c.linkEP0, dst: c.linkEP1, typ: header.ICMPv6NeighborSolicit},
				{src: c.linkEP1, dst: c.linkEP0, typ: header.ICMPv6NeighborAdvert},
			} {
				routeICMPv6Packet(t, args, func(t *testing.T, icmpv6 header.ICMPv6) {
					if got, want := tcpip.Address(icmpv6[8:][:16]), lladdr1; got != want {
						t.Errorf("%d: got target = %s, want = %s", icmpv6.Type(), got, want)
					}
				})
			}
			<-resCh
			continue
		}
		if err != nil {
			t.Fatalf("ep.Write(_) = _, _, %s", err)
		}
		break
	}

	for _, args := range []routeArgs{
		{src: c.linkEP0, dst: c.linkEP1, typ: header.ICMPv6EchoRequest},
		{src: c.linkEP1, dst: c.linkEP0, typ: header.ICMPv6EchoReply},
	} {
		routeICMPv6Packet(t, args, nil)
	}
}
