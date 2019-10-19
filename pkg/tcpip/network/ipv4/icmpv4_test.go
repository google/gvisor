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

package ipv4_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

const (
	linkAddr0 = tcpip.LinkAddress("\xaa\xbb\xcc\xdd\xee\xff")
	linkAddr1 = tcpip.LinkAddress("\xab\xcd\xef\xac\xad\xae")
)

const (
	lladdr0 = tcpip.Address("\x10\x00\x00\x01")
	lladdr1 = tcpip.Address("\x10\x00\x00\x02")
)

const (
	// defaultMTU is the loopback MTU value
	defaultMTU = 65536

	// defaultTTL is the TTL value used in IPv4 packet
	defaultTTL = 127

	// channelSize is the default size of the channel
	channelSize = 256
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

func (*stubLinkEndpoint) Attach(stack.NetworkDispatcher) {
}

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

// MTU implements stack.LinkEndpoint.MTU. It just returns a constant that
// matches the linux loopback MTU.
func (*stubLinkEndpoint) MTU() uint32 {
	return defaultMTU
}

func TestICMPCounts(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol4()},
	})
	{
		if err := s.CreateNIC(1, &stubLinkEndpoint{}); err != nil {
			t.Fatalf("CreateNIC(_) = %s", err)
		}
		if err := s.AddAddress(1, ipv4.ProtocolNumber, lladdr0); err != nil {
			t.Fatalf("AddAddress(_, %d, %s) = %s", ipv4.ProtocolNumber, lladdr0, err)
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

	netProto := s.NetworkProtocolInstance(ipv4.ProtocolNumber)
	if netProto == nil {
		t.Fatalf("cannot find protocol instance for network protocol %d", ipv4.ProtocolNumber)
	}

	ep, err := netProto.NewEndpoint(0, tcpip.AddressWithPrefix{lladdr1, netProto.DefaultPrefixLen()}, &stubLinkAddressCache{}, &stubDispatcher{}, nil)
	if err != nil {
		t.Fatalf("NewEndpoint(_) = _, %s, want = _, nil", err)
	}

	r, err := s.FindRoute(1, lladdr0, lladdr1, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(_) = _, %s, want = _, nil", err)
	}
	defer r.Release()

	types := []struct {
		typ  header.ICMPv4Type
		size int
	}{
		// Generating EchoRequest and TimestampRequest packets for testing
		{header.ICMPv4Echo, header.ICMPv4MinimumSize},
		{header.ICMPv4Timestamp, header.ICMPv4TimeStampMinimumSize},
	}

	handleIPv4Payload := func(hdr buffer.Prependable) {
		length := uint16(hdr.UsedLength() + header.IPv4MinimumSize)
		id := uint32(0)
		ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
		ip.Encode(&header.IPv4Fields{
			IHL:         header.IPv4MinimumSize,
			TotalLength: length,
			ID:          uint16(id),
			TTL:         uint8(defaultTTL),
			Protocol:    uint8(header.ICMPv4ProtocolNumber),
			SrcAddr:     r.LocalAddress,
			DstAddr:     r.RemoteAddress,
		})
		ep.HandlePacket(&r, hdr.View().ToVectorisedView())
	}

	for _, typ := range types {
		hdr := buffer.NewPrependable(header.IPv4MinimumSize + typ.size)
		pkt := header.ICMPv4(hdr.Prepend(typ.size))
		pkt.SetType(typ.typ)
		pkt.SetChecksum(header.ICMPv4Checksum(pkt, buffer.VectorisedView{}))

		handleIPv4Payload(hdr)
	}

	// Construct an empty ICMP packet so that
	// Stats().ICMP.ICMPv4ReceivedPacketStats.Invalid is incremented.
	handleIPv4Payload(buffer.NewPrependable(header.IPv4MinimumSize))

	icmpv4Stats := s.Stats().ICMP.V4PacketsReceived
	icmpv4SentStats := s.Stats().ICMP.V4PacketsSent
	visitStats(reflect.ValueOf(&icmpv4Stats).Elem(), reflect.ValueOf(&icmpv4SentStats).Elem(), func(name string, nameSent string, receive *tcpip.StatCounter, sent *tcpip.StatCounter) {
		// Check if the Request/Reply packets are received
		if got, want := receive.Value(), uint64(1); got == want {
			fmt.Printf("Received %s = %d\n", name, got)
		}
		// Check if the corresponding reply sent for the request messages
		if got := sent.Value(); got == uint64(1) {
			fmt.Printf("----------->%s sent\n\n", nameSent)
		}
	})
	if t.Failed() {
		t.Logf("stats:\n%+v", s.Stats())
	}
}

func visitStats(v reflect.Value, vs reflect.Value, f func(string, string, *tcpip.StatCounter, *tcpip.StatCounter)) {
	t := v.Type()
	p := vs.Type()
	for i := 0; i < v.NumField(); i++ {
		v := v.Field(i)
		vs := vs.Field(i)
		switch v.Kind() {
		case reflect.Ptr:
			f(t.Field(i).Name, p.Field(i).Name, v.Interface().(*tcpip.StatCounter), vs.Interface().(*tcpip.StatCounter))
		case reflect.Struct:
			visitStats(v, vs, f)
		default:
			panic(fmt.Sprintf("unexpected type %s", v.Type()))
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
			NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
			TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol4()},
		}),
		s1: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
			TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol4()},
		}),
	}

	c.linkEP0 = channel.New(channelSize, defaultMTU, linkAddr0)

	wrappedEP0 := stack.LinkEndpoint(endpointWithResolutionCapability{LinkEndpoint: c.linkEP0})
	if testing.Verbose() {
		wrappedEP0 = sniffer.New(wrappedEP0)
	}
	if err := c.s0.CreateNIC(1, wrappedEP0); err != nil {
		t.Fatalf("CreateNIC s0: %v", err)
	}
	if err := c.s0.AddAddress(1, ipv4.ProtocolNumber, lladdr0); err != nil {
		t.Fatalf("AddAddress lladdr0: %v", err)
	}

	c.linkEP1 = channel.New(channelSize, defaultMTU, linkAddr1)
	wrappedEP1 := stack.LinkEndpoint(endpointWithResolutionCapability{LinkEndpoint: c.linkEP1})
	if err := c.s1.CreateNIC(1, wrappedEP1); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}
	if err := c.s1.AddAddress(1, ipv4.ProtocolNumber, lladdr1); err != nil {
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
	typ      header.ICMPv4Type
}

func routeICMPv4Packet(t *testing.T, args routeArgs, fn func(*testing.T, header.ICMPv4)) {
	t.Helper()

	pkt := <-args.src.C

	{
		views := []buffer.View{pkt.Header, pkt.Payload}
		size := len(pkt.Header) + len(pkt.Payload)
		vv := buffer.NewVectorisedView(size, views)
		args.dst.InjectLinkAddr(pkt.Proto, args.dst.LinkAddress(), vv)
	}

	if pkt.Proto != ipv4.ProtocolNumber {
		t.Errorf("unexpected protocol number %d", pkt.Proto)
		return
	}
	ipv4 := header.IPv4(pkt.Header)
	transProto := tcpip.TransportProtocolNumber(ipv4.TransportProtocol())
	if transProto != header.ICMPv4ProtocolNumber {
		t.Errorf("unexpected transport protocol number %d", transProto)
		return
	}
	icmpv4 := header.ICMPv4(ipv4.Payload())
	if got, want := icmpv4.Type(), args.typ; got != want {
		t.Errorf("got ICMPv6 type = %d, want = %d", got, want)
		return
	}
	if fn != nil {
		fn(t, icmpv4)
	}
}
