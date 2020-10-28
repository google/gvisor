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
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1

	linkAddr0 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	linkAddr1 = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
	linkAddr2 = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0f")

	defaultChannelSize = 1
	defaultMTU         = 65536

	// Extra time to use when waiting for an async event to occur.
	defaultAsyncPositiveEventTimeout = 30 * time.Second
)

var (
	lladdr0 = header.LinkLocalAddr(linkAddr0)
	lladdr1 = header.LinkLocalAddr(linkAddr1)
	lladdr2 = header.LinkLocalAddr(linkAddr2)
)

type stubLinkEndpoint struct {
	stack.LinkEndpoint
}

func (*stubLinkEndpoint) MTU() uint32 {
	return defaultMTU
}

func (*stubLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	// Indicate that resolution for link layer addresses is required to send
	// packets over this link. This is needed so the NIC knows to allocate a
	// neighbor table.
	return stack.CapabilityResolutionRequired
}

func (*stubLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (*stubLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (*stubLinkEndpoint) WritePacket(*stack.Route, *stack.GSO, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) *tcpip.Error {
	return nil
}

func (*stubLinkEndpoint) Attach(stack.NetworkDispatcher) {}

type stubDispatcher struct {
	stack.TransportDispatcher
}

func (*stubDispatcher) DeliverTransportPacket(tcpip.TransportProtocolNumber, *stack.PacketBuffer) stack.TransportPacketDisposition {
	return stack.TransportPacketHandled
}

type stubLinkAddressCache struct {
	stack.LinkAddressCache
}

func (*stubLinkAddressCache) CheckLocalAddress(tcpip.NICID, tcpip.NetworkProtocolNumber, tcpip.Address) tcpip.NICID {
	return 0
}

func (*stubLinkAddressCache) AddLinkAddress(tcpip.NICID, tcpip.Address, tcpip.LinkAddress) {
}

type stubNUDHandler struct {
	probeCount        int
	confirmationCount int
}

var _ stack.NUDHandler = (*stubNUDHandler)(nil)

func (s *stubNUDHandler) HandleProbe(tcpip.Address, tcpip.NetworkProtocolNumber, tcpip.LinkAddress, stack.LinkAddressResolver) {
	s.probeCount++
}

func (s *stubNUDHandler) HandleConfirmation(tcpip.Address, tcpip.LinkAddress, stack.ReachabilityConfirmationFlags) {
	s.confirmationCount++
}

func (*stubNUDHandler) HandleUpperLevelConfirmation(tcpip.Address) {
}

var _ stack.NetworkInterface = (*testInterface)(nil)

type testInterface struct {
	stack.LinkEndpoint

	nicID tcpip.NICID
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

func (*testInterface) Enabled() bool {
	return true
}

func (t *testInterface) WritePacketToRemote(remoteLinkAddr tcpip.LinkAddress, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	r := stack.Route{
		NetProto:          protocol,
		RemoteLinkAddress: remoteLinkAddr,
	}
	return t.LinkEndpoint.WritePacket(&r, gso, protocol, pkt)
}

func TestICMPCounts(t *testing.T) {
	tests := []struct {
		name             string
		useNeighborCache bool
	}{
		{
			name:             "linkAddrCache",
			useNeighborCache: false,
		},
		{
			name:             "neighborCache",
			useNeighborCache: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol6},
				UseNeighborCache:   test.useNeighborCache,
			})
			{
				if err := s.CreateNIC(nicID, &stubLinkEndpoint{}); err != nil {
					t.Fatalf("CreateNIC(_, _) = %s", err)
				}
				if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
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
						NIC:         nicID,
					}},
				)
			}

			netProto := s.NetworkProtocolInstance(ProtocolNumber)
			if netProto == nil {
				t.Fatalf("cannot find protocol instance for network protocol %d", ProtocolNumber)
			}
			ep := netProto.NewEndpoint(&testInterface{}, &stubLinkAddressCache{}, &stubNUDHandler{}, &stubDispatcher{})
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

			r, err := s.FindRoute(nicID, lladdr0, lladdr1, ProtocolNumber, false /* multicastLoop */)
			if err != nil {
				t.Fatalf("FindRoute(%d, %s, %s, _, false) = (_, %s), want = (_, nil)", nicID, lladdr0, lladdr1, err)
			}
			defer r.Release()

			var tllData [header.NDPLinkLayerAddressSize]byte
			header.NDPOptions(tllData[:]).Serialize(header.NDPOptionsSerializer{
				header.NDPTargetLinkLayerAddressOption(linkAddr1),
			})

			types := []struct {
				typ       header.ICMPv6Type
				size      int
				extraData []byte
			}{
				{
					typ:  header.ICMPv6DstUnreachable,
					size: header.ICMPv6DstUnreachableMinimumSize,
				},
				{
					typ:  header.ICMPv6PacketTooBig,
					size: header.ICMPv6PacketTooBigMinimumSize,
				},
				{
					typ:  header.ICMPv6TimeExceeded,
					size: header.ICMPv6MinimumSize,
				},
				{
					typ:  header.ICMPv6ParamProblem,
					size: header.ICMPv6MinimumSize,
				},
				{
					typ:  header.ICMPv6EchoRequest,
					size: header.ICMPv6EchoMinimumSize,
				},
				{
					typ:  header.ICMPv6EchoReply,
					size: header.ICMPv6EchoMinimumSize,
				},
				{
					typ:  header.ICMPv6RouterSolicit,
					size: header.ICMPv6MinimumSize,
				},
				{
					typ:  header.ICMPv6RouterAdvert,
					size: header.ICMPv6HeaderSize + header.NDPRAMinimumSize,
				},
				{
					typ:  header.ICMPv6NeighborSolicit,
					size: header.ICMPv6NeighborSolicitMinimumSize,
				},
				{
					typ:       header.ICMPv6NeighborAdvert,
					size:      header.ICMPv6NeighborAdvertMinimumSize,
					extraData: tllData[:],
				},
				{
					typ:  header.ICMPv6RedirectMsg,
					size: header.ICMPv6MinimumSize,
				},
			}

			handleIPv6Payload := func(icmp header.ICMPv6) {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.IPv6MinimumSize,
					Data:               buffer.View(icmp).ToVectorisedView(),
				})
				ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(len(icmp)),
					NextHeader:    uint8(header.ICMPv6ProtocolNumber),
					HopLimit:      header.NDPHopLimit,
					SrcAddr:       r.LocalAddress,
					DstAddr:       r.RemoteAddress,
				})
				r.PopulatePacketInfo(pkt)
				ep.HandlePacket(pkt)
			}

			for _, typ := range types {
				icmp := header.ICMPv6(buffer.NewView(typ.size + len(typ.extraData)))
				copy(icmp[typ.size:], typ.extraData)
				icmp.SetType(typ.typ)
				icmp.SetChecksum(header.ICMPv6Checksum(icmp[:typ.size], r.LocalAddress, r.RemoteAddress, buffer.View(typ.extraData).ToVectorisedView()))
				handleIPv6Payload(icmp)
			}

			// Construct an empty ICMP packet so that
			// Stats().ICMP.ICMPv6ReceivedPacketStats.Invalid is incremented.
			handleIPv6Payload(header.ICMPv6(buffer.NewView(header.IPv6MinimumSize)))

			icmpv6Stats := s.Stats().ICMP.V6PacketsReceived
			visitStats(reflect.ValueOf(&icmpv6Stats).Elem(), func(name string, s *tcpip.StatCounter) {
				if got, want := s.Value(), uint64(1); got != want {
					t.Errorf("got %s = %d, want = %d", name, got, want)
				}
			})
			if t.Failed() {
				t.Logf("stats:\n%+v", s.Stats())
			}
		})
	}
}

func TestICMPCountsWithNeighborCache(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol6},
		UseNeighborCache:   true,
	})
	{
		if err := s.CreateNIC(nicID, &stubLinkEndpoint{}); err != nil {
			t.Fatalf("CreateNIC(_, _) = %s", err)
		}
		if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
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
				NIC:         nicID,
			}},
		)
	}

	netProto := s.NetworkProtocolInstance(ProtocolNumber)
	if netProto == nil {
		t.Fatalf("cannot find protocol instance for network protocol %d", ProtocolNumber)
	}
	ep := netProto.NewEndpoint(&testInterface{}, nil, &stubNUDHandler{}, &stubDispatcher{})
	defer ep.Close()

	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	r, err := s.FindRoute(nicID, lladdr0, lladdr1, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(%d, %s, %s, _, false) = (_, %s), want = (_, nil)", nicID, lladdr0, lladdr1, err)
	}
	defer r.Release()

	var tllData [header.NDPLinkLayerAddressSize]byte
	header.NDPOptions(tllData[:]).Serialize(header.NDPOptionsSerializer{
		header.NDPTargetLinkLayerAddressOption(linkAddr1),
	})

	types := []struct {
		typ       header.ICMPv6Type
		size      int
		extraData []byte
	}{
		{
			typ:  header.ICMPv6DstUnreachable,
			size: header.ICMPv6DstUnreachableMinimumSize,
		},
		{
			typ:  header.ICMPv6PacketTooBig,
			size: header.ICMPv6PacketTooBigMinimumSize,
		},
		{
			typ:  header.ICMPv6TimeExceeded,
			size: header.ICMPv6MinimumSize,
		},
		{
			typ:  header.ICMPv6ParamProblem,
			size: header.ICMPv6MinimumSize,
		},
		{
			typ:  header.ICMPv6EchoRequest,
			size: header.ICMPv6EchoMinimumSize,
		},
		{
			typ:  header.ICMPv6EchoReply,
			size: header.ICMPv6EchoMinimumSize,
		},
		{
			typ:  header.ICMPv6RouterSolicit,
			size: header.ICMPv6MinimumSize,
		},
		{
			typ:  header.ICMPv6RouterAdvert,
			size: header.ICMPv6HeaderSize + header.NDPRAMinimumSize,
		},
		{
			typ:  header.ICMPv6NeighborSolicit,
			size: header.ICMPv6NeighborSolicitMinimumSize,
		},
		{
			typ:       header.ICMPv6NeighborAdvert,
			size:      header.ICMPv6NeighborAdvertMinimumSize,
			extraData: tllData[:],
		},
		{
			typ:  header.ICMPv6RedirectMsg,
			size: header.ICMPv6MinimumSize,
		},
	}

	handleIPv6Payload := func(icmp header.ICMPv6) {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: header.IPv6MinimumSize,
			Data:               buffer.View(icmp).ToVectorisedView(),
		})
		ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ip.Encode(&header.IPv6Fields{
			PayloadLength: uint16(len(icmp)),
			NextHeader:    uint8(header.ICMPv6ProtocolNumber),
			HopLimit:      header.NDPHopLimit,
			SrcAddr:       r.LocalAddress,
			DstAddr:       r.RemoteAddress,
		})
		r.PopulatePacketInfo(pkt)
		ep.HandlePacket(pkt)
	}

	for _, typ := range types {
		icmp := header.ICMPv6(buffer.NewView(typ.size + len(typ.extraData)))
		copy(icmp[typ.size:], typ.extraData)
		icmp.SetType(typ.typ)
		icmp.SetChecksum(header.ICMPv6Checksum(icmp[:typ.size], r.LocalAddress, r.RemoteAddress, buffer.View(typ.extraData).ToVectorisedView()))
		handleIPv6Payload(icmp)
	}

	// Construct an empty ICMP packet so that
	// Stats().ICMP.ICMPv6ReceivedPacketStats.Invalid is incremented.
	handleIPv6Payload(header.ICMPv6(buffer.NewView(header.IPv6MinimumSize)))

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
			NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol6},
		}),
		s1: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol6},
		}),
	}

	c.linkEP0 = channel.New(defaultChannelSize, defaultMTU, linkAddr0)

	wrappedEP0 := stack.LinkEndpoint(endpointWithResolutionCapability{LinkEndpoint: c.linkEP0})
	if testing.Verbose() {
		wrappedEP0 = sniffer.New(wrappedEP0)
	}
	if err := c.s0.CreateNIC(nicID, wrappedEP0); err != nil {
		t.Fatalf("CreateNIC s0: %v", err)
	}
	if err := c.s0.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
		t.Fatalf("AddAddress lladdr0: %v", err)
	}

	c.linkEP1 = channel.New(defaultChannelSize, defaultMTU, linkAddr1)
	wrappedEP1 := stack.LinkEndpoint(endpointWithResolutionCapability{LinkEndpoint: c.linkEP1})
	if err := c.s1.CreateNIC(nicID, wrappedEP1); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}
	if err := c.s1.AddAddress(nicID, ProtocolNumber, lladdr1); err != nil {
		t.Fatalf("AddAddress lladdr1: %v", err)
	}

	subnet0, err := tcpip.NewSubnet(lladdr1, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr1))))
	if err != nil {
		t.Fatal(err)
	}
	c.s0.SetRouteTable(
		[]tcpip.Route{{
			Destination: subnet0,
			NIC:         nicID,
		}},
	)
	subnet1, err := tcpip.NewSubnet(lladdr0, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr0))))
	if err != nil {
		t.Fatal(err)
	}
	c.s1.SetRouteTable(
		[]tcpip.Route{{
			Destination: subnet1,
			NIC:         nicID,
		}},
	)

	return c
}

func (c *testContext) cleanup() {
	c.linkEP0.Close()
	c.linkEP1.Close()
}

type routeArgs struct {
	src, dst       *channel.Endpoint
	typ            header.ICMPv6Type
	remoteLinkAddr tcpip.LinkAddress
}

func routeICMPv6Packet(t *testing.T, args routeArgs, fn func(*testing.T, header.ICMPv6)) {
	t.Helper()

	pi, _ := args.src.ReadContext(context.Background())

	{
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.NewVectorisedView(pi.Pkt.Size(), pi.Pkt.Views()),
		})
		args.dst.InjectLinkAddr(pi.Proto, args.dst.LinkAddress(), pkt)
	}

	if pi.Proto != ProtocolNumber {
		t.Errorf("unexpected protocol number %d", pi.Proto)
		return
	}

	if len(args.remoteLinkAddr) != 0 && args.remoteLinkAddr != pi.Route.RemoteLinkAddress {
		t.Errorf("got remote link address = %s, want = %s", pi.Route.RemoteLinkAddress, args.remoteLinkAddr)
	}

	// Pull the full payload since network header. Needed for header.IPv6 to
	// extract its payload.
	ipv6 := header.IPv6(stack.PayloadSince(pi.Pkt.NetworkHeader()))
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

	r, err := c.s0.FindRoute(nicID, lladdr0, lladdr1, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute(%d, %s, %s, _, false) = (_, %s), want = (_, nil)", nicID, lladdr0, lladdr1, err)
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
		t.Fatalf("NewEndpoint(_) = (_, %s), want = (_, nil)", err)
	}

	for {
		_, resCh, err := ep.Write(payload, tcpip.WriteOptions{To: &tcpip.FullAddress{NIC: nicID, Addr: lladdr1}})
		if resCh != nil {
			if err != tcpip.ErrNoLinkAddress {
				t.Fatalf("ep.Write(_) = (_, <non-nil>, %s), want = (_, <non-nil>, tcpip.ErrNoLinkAddress)", err)
			}
			for _, args := range []routeArgs{
				{src: c.linkEP0, dst: c.linkEP1, typ: header.ICMPv6NeighborSolicit, remoteLinkAddr: header.EthernetAddressFromMulticastIPv6Address(header.SolicitedNodeAddr(lladdr1))},
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
			t.Fatalf("ep.Write(_) = (_, _, %s)", err)
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

func TestICMPChecksumValidationSimple(t *testing.T) {
	var tllData [header.NDPLinkLayerAddressSize]byte
	header.NDPOptions(tllData[:]).Serialize(header.NDPOptionsSerializer{
		header.NDPTargetLinkLayerAddressOption(linkAddr1),
	})

	types := []struct {
		name        string
		typ         header.ICMPv6Type
		size        int
		extraData   []byte
		statCounter func(tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
		routerOnly  bool
	}{
		{
			name: "DstUnreachable",
			typ:  header.ICMPv6DstUnreachable,
			size: header.ICMPv6DstUnreachableMinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.DstUnreachable
			},
		},
		{
			name: "PacketTooBig",
			typ:  header.ICMPv6PacketTooBig,
			size: header.ICMPv6PacketTooBigMinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.PacketTooBig
			},
		},
		{
			name: "TimeExceeded",
			typ:  header.ICMPv6TimeExceeded,
			size: header.ICMPv6MinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.TimeExceeded
			},
		},
		{
			name: "ParamProblem",
			typ:  header.ICMPv6ParamProblem,
			size: header.ICMPv6MinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.ParamProblem
			},
		},
		{
			name: "EchoRequest",
			typ:  header.ICMPv6EchoRequest,
			size: header.ICMPv6EchoMinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.EchoRequest
			},
		},
		{
			name: "EchoReply",
			typ:  header.ICMPv6EchoReply,
			size: header.ICMPv6EchoMinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.EchoReply
			},
		},
		{
			name: "RouterSolicit",
			typ:  header.ICMPv6RouterSolicit,
			size: header.ICMPv6MinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.RouterSolicit
			},
			// Hosts MUST silently discard any received Router Solicitation messages.
			routerOnly: true,
		},
		{
			name: "RouterAdvert",
			typ:  header.ICMPv6RouterAdvert,
			size: header.ICMPv6HeaderSize + header.NDPRAMinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.RouterAdvert
			},
		},
		{
			name: "NeighborSolicit",
			typ:  header.ICMPv6NeighborSolicit,
			size: header.ICMPv6NeighborSolicitMinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.NeighborSolicit
			},
		},
		{
			name:      "NeighborAdvert",
			typ:       header.ICMPv6NeighborAdvert,
			size:      header.ICMPv6NeighborAdvertMinimumSize,
			extraData: tllData[:],
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.NeighborAdvert
			},
		},
		{
			name: "RedirectMsg",
			typ:  header.ICMPv6RedirectMsg,
			size: header.ICMPv6MinimumSize,
			statCounter: func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.RedirectMsg
			},
		},
	}

	tests := []struct {
		name             string
		useNeighborCache bool
	}{
		{
			name:             "linkAddrCache",
			useNeighborCache: false,
		},
		{
			name:             "neighborCache",
			useNeighborCache: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, typ := range types {
				for _, isRouter := range []bool{false, true} {
					name := typ.name
					if isRouter {
						name += " (Router)"
					}
					t.Run(name, func(t *testing.T) {
						e := channel.New(0, 1280, linkAddr0)

						// Indicate that resolution for link layer addresses is required to
						// send packets over this link. This is needed so the NIC knows to
						// allocate a neighbor table.
						e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

						s := stack.New(stack.Options{
							NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
							UseNeighborCache: test.useNeighborCache,
						})
						if isRouter {
							// Enabling forwarding makes the stack act as a router.
							s.SetForwarding(ProtocolNumber, true)
						}
						if err := s.CreateNIC(nicID, e); err != nil {
							t.Fatalf("CreateNIC(_, _) = %s", err)
						}

						if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
							t.Fatalf("AddAddress(_, %d, %s) = %s", ProtocolNumber, lladdr0, err)
						}
						{
							subnet, err := tcpip.NewSubnet(lladdr1, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr1))))
							if err != nil {
								t.Fatal(err)
							}
							s.SetRouteTable(
								[]tcpip.Route{{
									Destination: subnet,
									NIC:         nicID,
								}},
							)
						}

						handleIPv6Payload := func(checksum bool) {
							icmp := header.ICMPv6(buffer.NewView(typ.size + len(typ.extraData)))
							copy(icmp[typ.size:], typ.extraData)
							icmp.SetType(typ.typ)
							if checksum {
								icmp.SetChecksum(header.ICMPv6Checksum(icmp, lladdr1, lladdr0, buffer.View{}.ToVectorisedView()))
							}
							ip := header.IPv6(buffer.NewView(header.IPv6MinimumSize))
							ip.Encode(&header.IPv6Fields{
								PayloadLength: uint16(len(icmp)),
								NextHeader:    uint8(header.ICMPv6ProtocolNumber),
								HopLimit:      header.NDPHopLimit,
								SrcAddr:       lladdr1,
								DstAddr:       lladdr0,
							})
							pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
								Data: buffer.NewVectorisedView(len(ip)+len(icmp), []buffer.View{buffer.View(ip), buffer.View(icmp)}),
							})
							e.InjectInbound(ProtocolNumber, pkt)
						}

						stats := s.Stats().ICMP.V6PacketsReceived
						invalid := stats.Invalid
						routerOnly := stats.RouterOnlyPacketsDroppedByHost
						typStat := typ.statCounter(stats)

						// Initial stat counts should be 0.
						if got := invalid.Value(); got != 0 {
							t.Fatalf("got invalid = %d, want = 0", got)
						}
						if got := routerOnly.Value(); got != 0 {
							t.Fatalf("got RouterOnlyPacketsReceivedByHost = %d, want = 0", got)
						}
						if got := typStat.Value(); got != 0 {
							t.Fatalf("got %s = %d, want = 0", typ.name, got)
						}

						// Without setting checksum, the incoming packet should
						// be invalid.
						handleIPv6Payload(false)
						if got := invalid.Value(); got != 1 {
							t.Fatalf("got invalid = %d, want = 1", got)
						}
						// Router only count should not have increased.
						if got := routerOnly.Value(); got != 0 {
							t.Fatalf("got RouterOnlyPacketsReceivedByHost = %d, want = 0", got)
						}
						// Rx count of type typ.typ should not have increased.
						if got := typStat.Value(); got != 0 {
							t.Fatalf("got %s = %d, want = 0", typ.name, got)
						}

						// When checksum is set, it should be received.
						handleIPv6Payload(true)
						if got := typStat.Value(); got != 1 {
							t.Fatalf("got %s = %d, want = 1", typ.name, got)
						}
						// Invalid count should not have increased again.
						if got := invalid.Value(); got != 1 {
							t.Fatalf("got invalid = %d, want = 1", got)
						}
						if !isRouter && typ.routerOnly && test.useNeighborCache {
							// Router only count should have increased.
							if got := routerOnly.Value(); got != 1 {
								t.Fatalf("got RouterOnlyPacketsReceivedByHost = %d, want = 1", got)
							}
						}
					})
				}
			}
		})
	}
}

func TestICMPChecksumValidationWithPayload(t *testing.T) {
	const simpleBodySize = 64
	simpleBody := func(view buffer.View) {
		for i := 0; i < simpleBodySize; i++ {
			view[i] = uint8(i)
		}
	}

	const errorICMPBodySize = header.IPv6MinimumSize + simpleBodySize
	errorICMPBody := func(view buffer.View) {
		ip := header.IPv6(view)
		ip.Encode(&header.IPv6Fields{
			PayloadLength: simpleBodySize,
			NextHeader:    10,
			HopLimit:      20,
			SrcAddr:       lladdr0,
			DstAddr:       lladdr1,
		})
		simpleBody(view[header.IPv6MinimumSize:])
	}

	types := []struct {
		name        string
		typ         header.ICMPv6Type
		size        int
		statCounter func(tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
		payloadSize int
		payload     func(buffer.View)
	}{
		{
			"DstUnreachable",
			header.ICMPv6DstUnreachable,
			header.ICMPv6DstUnreachableMinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.DstUnreachable
			},
			errorICMPBodySize,
			errorICMPBody,
		},
		{
			"PacketTooBig",
			header.ICMPv6PacketTooBig,
			header.ICMPv6PacketTooBigMinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.PacketTooBig
			},
			errorICMPBodySize,
			errorICMPBody,
		},
		{
			"TimeExceeded",
			header.ICMPv6TimeExceeded,
			header.ICMPv6MinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.TimeExceeded
			},
			errorICMPBodySize,
			errorICMPBody,
		},
		{
			"ParamProblem",
			header.ICMPv6ParamProblem,
			header.ICMPv6MinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.ParamProblem
			},
			errorICMPBodySize,
			errorICMPBody,
		},
		{
			"EchoRequest",
			header.ICMPv6EchoRequest,
			header.ICMPv6EchoMinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.EchoRequest
			},
			simpleBodySize,
			simpleBody,
		},
		{
			"EchoReply",
			header.ICMPv6EchoReply,
			header.ICMPv6EchoMinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.EchoReply
			},
			simpleBodySize,
			simpleBody,
		},
	}

	for _, typ := range types {
		t.Run(typ.name, func(t *testing.T) {
			e := channel.New(10, 1280, linkAddr0)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(_, _) = %s", err)
			}

			if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
				t.Fatalf("AddAddress(_, %d, %s) = %s", ProtocolNumber, lladdr0, err)
			}
			{
				subnet, err := tcpip.NewSubnet(lladdr1, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr1))))
				if err != nil {
					t.Fatal(err)
				}
				s.SetRouteTable(
					[]tcpip.Route{{
						Destination: subnet,
						NIC:         nicID,
					}},
				)
			}

			handleIPv6Payload := func(typ header.ICMPv6Type, size, payloadSize int, payloadFn func(buffer.View), checksum bool) {
				icmpSize := size + payloadSize
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + icmpSize)
				icmpHdr := header.ICMPv6(hdr.Prepend(icmpSize))
				icmpHdr.SetType(typ)
				payloadFn(icmpHdr.Payload())

				if checksum {
					icmpHdr.SetChecksum(header.ICMPv6Checksum(icmpHdr, lladdr1, lladdr0, buffer.VectorisedView{}))
				}

				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(icmpSize),
					NextHeader:    uint8(header.ICMPv6ProtocolNumber),
					HopLimit:      header.NDPHopLimit,
					SrcAddr:       lladdr1,
					DstAddr:       lladdr0,
				})
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
				})
				e.InjectInbound(ProtocolNumber, pkt)
			}

			stats := s.Stats().ICMP.V6PacketsReceived
			invalid := stats.Invalid
			typStat := typ.statCounter(stats)

			// Initial stat counts should be 0.
			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}
			if got := typStat.Value(); got != 0 {
				t.Fatalf("got = %d, want = 0", got)
			}

			// Without setting checksum, the incoming packet should
			// be invalid.
			handleIPv6Payload(typ.typ, typ.size, typ.payloadSize, typ.payload, false)
			if got := invalid.Value(); got != 1 {
				t.Fatalf("got invalid = %d, want = 1", got)
			}
			// Rx count of type typ.typ should not have increased.
			if got := typStat.Value(); got != 0 {
				t.Fatalf("got = %d, want = 0", got)
			}

			// When checksum is set, it should be received.
			handleIPv6Payload(typ.typ, typ.size, typ.payloadSize, typ.payload, true)
			if got := typStat.Value(); got != 1 {
				t.Fatalf("got = %d, want = 0", got)
			}
			// Invalid count should not have increased again.
			if got := invalid.Value(); got != 1 {
				t.Fatalf("got invalid = %d, want = 1", got)
			}
		})
	}
}

func TestICMPChecksumValidationWithPayloadMultipleViews(t *testing.T) {
	const simpleBodySize = 64
	simpleBody := func(view buffer.View) {
		for i := 0; i < simpleBodySize; i++ {
			view[i] = uint8(i)
		}
	}

	const errorICMPBodySize = header.IPv6MinimumSize + simpleBodySize
	errorICMPBody := func(view buffer.View) {
		ip := header.IPv6(view)
		ip.Encode(&header.IPv6Fields{
			PayloadLength: simpleBodySize,
			NextHeader:    10,
			HopLimit:      20,
			SrcAddr:       lladdr0,
			DstAddr:       lladdr1,
		})
		simpleBody(view[header.IPv6MinimumSize:])
	}

	types := []struct {
		name        string
		typ         header.ICMPv6Type
		size        int
		statCounter func(tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
		payloadSize int
		payload     func(buffer.View)
	}{
		{
			"DstUnreachable",
			header.ICMPv6DstUnreachable,
			header.ICMPv6DstUnreachableMinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.DstUnreachable
			},
			errorICMPBodySize,
			errorICMPBody,
		},
		{
			"PacketTooBig",
			header.ICMPv6PacketTooBig,
			header.ICMPv6PacketTooBigMinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.PacketTooBig
			},
			errorICMPBodySize,
			errorICMPBody,
		},
		{
			"TimeExceeded",
			header.ICMPv6TimeExceeded,
			header.ICMPv6MinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.TimeExceeded
			},
			errorICMPBodySize,
			errorICMPBody,
		},
		{
			"ParamProblem",
			header.ICMPv6ParamProblem,
			header.ICMPv6MinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.ParamProblem
			},
			errorICMPBodySize,
			errorICMPBody,
		},
		{
			"EchoRequest",
			header.ICMPv6EchoRequest,
			header.ICMPv6EchoMinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.EchoRequest
			},
			simpleBodySize,
			simpleBody,
		},
		{
			"EchoReply",
			header.ICMPv6EchoReply,
			header.ICMPv6EchoMinimumSize,
			func(stats tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return stats.EchoReply
			},
			simpleBodySize,
			simpleBody,
		},
	}

	for _, typ := range types {
		t.Run(typ.name, func(t *testing.T) {
			e := channel.New(10, 1280, linkAddr0)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}

			if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, ProtocolNumber, lladdr0, err)
			}
			{
				subnet, err := tcpip.NewSubnet(lladdr1, tcpip.AddressMask(strings.Repeat("\xff", len(lladdr1))))
				if err != nil {
					t.Fatal(err)
				}
				s.SetRouteTable(
					[]tcpip.Route{{
						Destination: subnet,
						NIC:         nicID,
					}},
				)
			}

			handleIPv6Payload := func(typ header.ICMPv6Type, size, payloadSize int, payloadFn func(buffer.View), checksum bool) {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + size)
				icmpHdr := header.ICMPv6(hdr.Prepend(size))
				icmpHdr.SetType(typ)

				payload := buffer.NewView(payloadSize)
				payloadFn(payload)

				if checksum {
					icmpHdr.SetChecksum(header.ICMPv6Checksum(icmpHdr, lladdr1, lladdr0, payload.ToVectorisedView()))
				}

				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(size + payloadSize),
					NextHeader:    uint8(header.ICMPv6ProtocolNumber),
					HopLimit:      header.NDPHopLimit,
					SrcAddr:       lladdr1,
					DstAddr:       lladdr0,
				})
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: buffer.NewVectorisedView(header.IPv6MinimumSize+size+payloadSize, []buffer.View{hdr.View(), payload}),
				})
				e.InjectInbound(ProtocolNumber, pkt)
			}

			stats := s.Stats().ICMP.V6PacketsReceived
			invalid := stats.Invalid
			typStat := typ.statCounter(stats)

			// Initial stat counts should be 0.
			if got := invalid.Value(); got != 0 {
				t.Fatalf("got invalid = %d, want = 0", got)
			}
			if got := typStat.Value(); got != 0 {
				t.Fatalf("got = %d, want = 0", got)
			}

			// Without setting checksum, the incoming packet should
			// be invalid.
			handleIPv6Payload(typ.typ, typ.size, typ.payloadSize, typ.payload, false)
			if got := invalid.Value(); got != 1 {
				t.Fatalf("got invalid = %d, want = 1", got)
			}
			// Rx count of type typ.typ should not have increased.
			if got := typStat.Value(); got != 0 {
				t.Fatalf("got = %d, want = 0", got)
			}

			// When checksum is set, it should be received.
			handleIPv6Payload(typ.typ, typ.size, typ.payloadSize, typ.payload, true)
			if got := typStat.Value(); got != 1 {
				t.Fatalf("got = %d, want = 0", got)
			}
			// Invalid count should not have increased again.
			if got := invalid.Value(); got != 1 {
				t.Fatalf("got invalid = %d, want = 1", got)
			}
		})
	}
}

func TestLinkAddressRequest(t *testing.T) {
	const nicID = 1

	snaddr := header.SolicitedNodeAddr(lladdr0)
	mcaddr := header.EthernetAddressFromMulticastIPv6Address(snaddr)

	tests := []struct {
		name           string
		nicAddr        tcpip.Address
		localAddr      tcpip.Address
		remoteLinkAddr tcpip.LinkAddress

		expectedErr            *tcpip.Error
		expectedRemoteAddr     tcpip.Address
		expectedRemoteLinkAddr tcpip.LinkAddress
	}{
		{
			name:                   "Unicast",
			nicAddr:                lladdr1,
			localAddr:              lladdr1,
			remoteLinkAddr:         linkAddr1,
			expectedRemoteAddr:     lladdr0,
			expectedRemoteLinkAddr: linkAddr1,
		},
		{
			name:                   "Multicast",
			nicAddr:                lladdr1,
			localAddr:              lladdr1,
			remoteLinkAddr:         "",
			expectedRemoteAddr:     snaddr,
			expectedRemoteLinkAddr: mcaddr,
		},
		{
			name:                   "Unicast with unspecified source",
			nicAddr:                lladdr1,
			remoteLinkAddr:         linkAddr1,
			expectedRemoteAddr:     lladdr0,
			expectedRemoteLinkAddr: linkAddr1,
		},
		{
			name:                   "Multicast with unspecified source",
			nicAddr:                lladdr1,
			remoteLinkAddr:         "",
			expectedRemoteAddr:     snaddr,
			expectedRemoteLinkAddr: mcaddr,
		},
		{
			name:           "Unicast with unassigned address",
			localAddr:      lladdr1,
			remoteLinkAddr: linkAddr1,
			expectedErr:    tcpip.ErrNetworkUnreachable,
		},
		{
			name:           "Multicast with unassigned address",
			localAddr:      lladdr1,
			remoteLinkAddr: "",
			expectedErr:    tcpip.ErrNetworkUnreachable,
		},
		{
			name:           "Unicast with no local address available",
			remoteLinkAddr: linkAddr1,
			expectedErr:    tcpip.ErrNetworkUnreachable,
		},
		{
			name:           "Multicast with no local address available",
			remoteLinkAddr: "",
			expectedErr:    tcpip.ErrNetworkUnreachable,
		},
	}

	for _, test := range tests {
		s := stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
		})
		p := s.NetworkProtocolInstance(ProtocolNumber)
		linkRes, ok := p.(stack.LinkAddressResolver)
		if !ok {
			t.Fatalf("expected IPv6 protocol to implement stack.LinkAddressResolver")
		}

		linkEP := channel.New(defaultChannelSize, defaultMTU, linkAddr0)
		if err := s.CreateNIC(nicID, linkEP); err != nil {
			t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
		}
		if len(test.nicAddr) != 0 {
			if err := s.AddAddress(nicID, ProtocolNumber, test.nicAddr); err != nil {
				t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID, ProtocolNumber, test.nicAddr, err)
			}
		}

		// We pass a test network interface to LinkAddressRequest with the same NIC
		// ID and link endpoint used by the NIC we created earlier so that we can
		// mock a link address request and observe the packets sent to the link
		// endpoint even though the stack uses the real NIC.
		if err := linkRes.LinkAddressRequest(lladdr0, test.localAddr, test.remoteLinkAddr, &testInterface{LinkEndpoint: linkEP, nicID: nicID}); err != test.expectedErr {
			t.Errorf("got p.LinkAddressRequest(%s, %s, %s, _) = %s, want = %s", lladdr0, test.localAddr, test.remoteLinkAddr, err, test.expectedErr)
		}

		if test.expectedErr != nil {
			return
		}

		pkt, ok := linkEP.Read()
		if !ok {
			t.Fatal("expected to send a link address request")
		}
		if pkt.Route.RemoteLinkAddress != test.expectedRemoteLinkAddr {
			t.Errorf("got pkt.Route.RemoteLinkAddress = %s, want = %s", pkt.Route.RemoteLinkAddress, test.expectedRemoteLinkAddr)
		}
		if pkt.Route.RemoteAddress != test.expectedRemoteAddr {
			t.Errorf("got pkt.Route.RemoteAddress = %s, want = %s", pkt.Route.RemoteAddress, test.expectedRemoteAddr)
		}
		if pkt.Route.LocalAddress != lladdr1 {
			t.Errorf("got pkt.Route.LocalAddress = %s, want = %s", pkt.Route.LocalAddress, lladdr1)
		}
		checker.IPv6(t, stack.PayloadSince(pkt.Pkt.NetworkHeader()),
			checker.SrcAddr(lladdr1),
			checker.DstAddr(test.expectedRemoteAddr),
			checker.TTL(header.NDPHopLimit),
			checker.NDPNS(
				checker.NDPNSTargetAddress(lladdr0),
				checker.NDPNSOptions([]header.NDPOption{header.NDPSourceLinkLayerAddressOption(linkAddr0)}),
			))
	}
}

func TestPacketQueing(t *testing.T) {
	const nicID = 1

	var (
		host1NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x06")
		host2NICLinkAddr = tcpip.LinkAddress("\x02\x03\x03\x04\x05\x09")

		host1IPv6Addr = tcpip.ProtocolAddress{
			Protocol: ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("a::1").To16()),
				PrefixLen: 64,
			},
		}
		host2IPv6Addr = tcpip.ProtocolAddress{
			Protocol: ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(net.ParseIP("a::2").To16()),
				PrefixLen: 64,
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
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.UDPMinimumSize)
				u := header.UDP(hdr.Prepend(header.UDPMinimumSize))
				u.Encode(&header.UDPFields{
					SrcPort: 5555,
					DstPort: 80,
					Length:  header.UDPMinimumSize,
				})
				sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, host2IPv6Addr.AddressWithPrefix.Address, host1IPv6Addr.AddressWithPrefix.Address, header.UDPMinimumSize)
				sum = header.Checksum(header.UDP([]byte{}), sum)
				u.SetChecksum(^u.CalculateChecksum(sum))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(udp.ProtocolNumber),
					HopLimit:      DefaultTTL,
					SrcAddr:       host2IPv6Addr.AddressWithPrefix.Address,
					DstAddr:       host1IPv6Addr.AddressWithPrefix.Address,
				})
				e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
				}))
			},
			checkResp: func(t *testing.T, e *channel.Endpoint) {
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != ProtocolNumber {
					t.Errorf("got p.Proto = %d, want = %d", p.Proto, ProtocolNumber)
				}
				if p.Route.RemoteLinkAddress != host2NICLinkAddr {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, host2NICLinkAddr)
				}
				checker.IPv6(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
					checker.SrcAddr(host1IPv6Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv6Addr.AddressWithPrefix.Address),
					checker.ICMPv6(
						checker.ICMPv6Type(header.ICMPv6DstUnreachable),
						checker.ICMPv6Code(header.ICMPv6PortUnreachable)))
			},
		},

		{
			name: "Ping",
			rxPkt: func(e *channel.Endpoint) {
				totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
				hdr := buffer.NewPrependable(totalLen)
				pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6MinimumSize))
				pkt.SetType(header.ICMPv6EchoRequest)
				pkt.SetCode(0)
				pkt.SetChecksum(0)
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, host2IPv6Addr.AddressWithPrefix.Address, host1IPv6Addr.AddressWithPrefix.Address, buffer.VectorisedView{}))
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: header.ICMPv6MinimumSize,
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      DefaultTTL,
					SrcAddr:       host2IPv6Addr.AddressWithPrefix.Address,
					DstAddr:       host1IPv6Addr.AddressWithPrefix.Address,
				})
				e.InjectInbound(header.IPv6ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
				}))
			},
			checkResp: func(t *testing.T, e *channel.Endpoint) {
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != ProtocolNumber {
					t.Errorf("got p.Proto = %d, want = %d", p.Proto, ProtocolNumber)
				}
				if p.Route.RemoteLinkAddress != host2NICLinkAddr {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, host2NICLinkAddr)
				}
				checker.IPv6(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
					checker.SrcAddr(host1IPv6Addr.AddressWithPrefix.Address),
					checker.DstAddr(host2IPv6Addr.AddressWithPrefix.Address),
					checker.ICMPv6(
						checker.ICMPv6Type(header.ICMPv6EchoReply),
						checker.ICMPv6Code(header.ICMPv6UnusedCode)))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			e := channel.New(1, header.IPv6MinimumMTU, host1NICLinkAddr)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})

			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
			}
			if err := s.AddProtocolAddress(nicID, host1IPv6Addr); err != nil {
				t.Fatalf("s.AddProtocolAddress(%d, %#v): %s", nicID, host1IPv6Addr, err)
			}

			s.SetRouteTable([]tcpip.Route{
				tcpip.Route{
					Destination: host1IPv6Addr.AddressWithPrefix.Subnet(),
					NIC:         nicID,
				},
			})

			// Receive a packet to trigger link resolution before a response is sent.
			test.rxPkt(e)

			// Wait for a neighbor solicitation since link address resolution should
			// be performed.
			{
				p, ok := e.ReadContext(context.Background())
				if !ok {
					t.Fatalf("timed out waiting for packet")
				}
				if p.Proto != ProtocolNumber {
					t.Errorf("got Proto = %d, want = %d", p.Proto, ProtocolNumber)
				}
				snmc := header.SolicitedNodeAddr(host2IPv6Addr.AddressWithPrefix.Address)
				if want := header.EthernetAddressFromMulticastIPv6Address(snmc); p.Route.RemoteLinkAddress != want {
					t.Errorf("got p.Route.RemoteLinkAddress = %s, want = %s", p.Route.RemoteLinkAddress, want)
				}
				checker.IPv6(t, stack.PayloadSince(p.Pkt.NetworkHeader()),
					checker.SrcAddr(host1IPv6Addr.AddressWithPrefix.Address),
					checker.DstAddr(snmc),
					checker.TTL(header.NDPHopLimit),
					checker.NDPNS(
						checker.NDPNSTargetAddress(host2IPv6Addr.AddressWithPrefix.Address),
						checker.NDPNSOptions([]header.NDPOption{header.NDPSourceLinkLayerAddressOption(host1NICLinkAddr)}),
					))
			}

			// Send a neighbor advertisement to complete link address resolution.
			{
				naSize := header.ICMPv6NeighborAdvertMinimumSize + header.NDPLinkLayerAddressSize
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + naSize)
				pkt := header.ICMPv6(hdr.Prepend(naSize))
				pkt.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(pkt.NDPPayload())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(true)
				na.SetTargetAddress(host2IPv6Addr.AddressWithPrefix.Address)
				na.Options().Serialize(header.NDPOptionsSerializer{
					header.NDPTargetLinkLayerAddressOption(host2NICLinkAddr),
				})
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, host2IPv6Addr.AddressWithPrefix.Address, host1IPv6Addr.AddressWithPrefix.Address, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      header.NDPHopLimit,
					SrcAddr:       host2IPv6Addr.AddressWithPrefix.Address,
					DstAddr:       host1IPv6Addr.AddressWithPrefix.Address,
				})
				e.InjectInbound(ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Data: hdr.View().ToVectorisedView(),
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

func TestCallsToNeighborCache(t *testing.T) {
	tests := []struct {
		name                  string
		createPacket          func() header.ICMPv6
		multicast             bool
		source                tcpip.Address
		destination           tcpip.Address
		wantProbeCount        int
		wantConfirmationCount int
	}{
		{
			name: "Unicast Neighbor Solicitation without source link-layer address option",
			createPacket: func() header.ICMPv6 {
				nsSize := header.ICMPv6NeighborSolicitMinimumSize + header.NDPLinkLayerAddressSize
				icmp := header.ICMPv6(buffer.NewView(nsSize))
				icmp.SetType(header.ICMPv6NeighborSolicit)
				ns := header.NDPNeighborSolicit(icmp.NDPPayload())
				ns.SetTargetAddress(lladdr0)
				return icmp
			},
			source:      lladdr1,
			destination: lladdr0,
			// "The source link-layer address option SHOULD be included in unicast
			//  solicitations." - RFC 4861 section 4.3
			//
			// A Neighbor Advertisement needs to be sent in response, but the
			// Neighbor Cache shouldn't be updated since we have no useful
			// information about the sender.
			wantProbeCount: 0,
		},
		{
			name: "Unicast Neighbor Solicitation with source link-layer address option",
			createPacket: func() header.ICMPv6 {
				nsSize := header.ICMPv6NeighborSolicitMinimumSize + header.NDPLinkLayerAddressSize
				icmp := header.ICMPv6(buffer.NewView(nsSize))
				icmp.SetType(header.ICMPv6NeighborSolicit)
				ns := header.NDPNeighborSolicit(icmp.NDPPayload())
				ns.SetTargetAddress(lladdr0)
				ns.Options().Serialize(header.NDPOptionsSerializer{
					header.NDPSourceLinkLayerAddressOption(linkAddr1),
				})
				return icmp
			},
			source:         lladdr1,
			destination:    lladdr0,
			wantProbeCount: 1,
		},
		{
			name: "Multicast Neighbor Solicitation without source link-layer address option",
			createPacket: func() header.ICMPv6 {
				nsSize := header.ICMPv6NeighborSolicitMinimumSize + header.NDPLinkLayerAddressSize
				icmp := header.ICMPv6(buffer.NewView(nsSize))
				icmp.SetType(header.ICMPv6NeighborSolicit)
				ns := header.NDPNeighborSolicit(icmp.NDPPayload())
				ns.SetTargetAddress(lladdr0)
				return icmp
			},
			source:      lladdr1,
			destination: header.SolicitedNodeAddr(lladdr0),
			// "The source link-layer address option MUST be included in multicast
			//  solicitations." - RFC 4861 section 4.3
			wantProbeCount: 0,
		},
		{
			name: "Multicast Neighbor Solicitation with source link-layer address option",
			createPacket: func() header.ICMPv6 {
				nsSize := header.ICMPv6NeighborSolicitMinimumSize + header.NDPLinkLayerAddressSize
				icmp := header.ICMPv6(buffer.NewView(nsSize))
				icmp.SetType(header.ICMPv6NeighborSolicit)
				ns := header.NDPNeighborSolicit(icmp.NDPPayload())
				ns.SetTargetAddress(lladdr0)
				ns.Options().Serialize(header.NDPOptionsSerializer{
					header.NDPSourceLinkLayerAddressOption(linkAddr1),
				})
				return icmp
			},
			source:         lladdr1,
			destination:    header.SolicitedNodeAddr(lladdr0),
			wantProbeCount: 1,
		},
		{
			name: "Unicast Neighbor Advertisement without target link-layer address option",
			createPacket: func() header.ICMPv6 {
				naSize := header.ICMPv6NeighborAdvertMinimumSize
				icmp := header.ICMPv6(buffer.NewView(naSize))
				icmp.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(icmp.NDPPayload())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(false)
				na.SetTargetAddress(lladdr1)
				return icmp
			},
			source:      lladdr1,
			destination: lladdr0,
			// "When responding to unicast solicitations, the target link-layer
			//  address option can be omitted since the sender of the solicitation has
			//  the correct link-layer address; otherwise, it would not be able to
			//  send the unicast solicitation in the first place."
			//   - RFC 4861 section 4.4
			wantConfirmationCount: 1,
		},
		{
			name: "Unicast Neighbor Advertisement with target link-layer address option",
			createPacket: func() header.ICMPv6 {
				naSize := header.ICMPv6NeighborAdvertMinimumSize + header.NDPLinkLayerAddressSize
				icmp := header.ICMPv6(buffer.NewView(naSize))
				icmp.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(icmp.NDPPayload())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(false)
				na.SetTargetAddress(lladdr1)
				na.Options().Serialize(header.NDPOptionsSerializer{
					header.NDPTargetLinkLayerAddressOption(linkAddr1),
				})
				return icmp
			},
			source:                lladdr1,
			destination:           lladdr0,
			wantConfirmationCount: 1,
		},
		{
			name: "Multicast Neighbor Advertisement without target link-layer address option",
			createPacket: func() header.ICMPv6 {
				naSize := header.ICMPv6NeighborAdvertMinimumSize + header.NDPLinkLayerAddressSize
				icmp := header.ICMPv6(buffer.NewView(naSize))
				icmp.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(icmp.NDPPayload())
				na.SetSolicitedFlag(false)
				na.SetOverrideFlag(false)
				na.SetTargetAddress(lladdr1)
				return icmp
			},
			source:      lladdr1,
			destination: header.IPv6AllNodesMulticastAddress,
			// "Target link-layer address MUST be included for multicast solicitations
			//  in order to avoid infinite Neighbor Solicitation "recursion" when the
			//  peer node does not have a cache entry to return a Neighbor
			//  Advertisements message." - RFC 4861 section 4.4
			wantConfirmationCount: 0,
		},
		{
			name: "Multicast Neighbor Advertisement with target link-layer address option",
			createPacket: func() header.ICMPv6 {
				naSize := header.ICMPv6NeighborAdvertMinimumSize + header.NDPLinkLayerAddressSize
				icmp := header.ICMPv6(buffer.NewView(naSize))
				icmp.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(icmp.NDPPayload())
				na.SetSolicitedFlag(false)
				na.SetOverrideFlag(false)
				na.SetTargetAddress(lladdr1)
				na.Options().Serialize(header.NDPOptionsSerializer{
					header.NDPTargetLinkLayerAddressOption(linkAddr1),
				})
				return icmp
			},
			source:                lladdr1,
			destination:           header.IPv6AllNodesMulticastAddress,
			wantConfirmationCount: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol6},
				UseNeighborCache:   true,
			})
			{
				if err := s.CreateNIC(nicID, &stubLinkEndpoint{}); err != nil {
					t.Fatalf("CreateNIC(_, _) = %s", err)
				}
				if err := s.AddAddress(nicID, ProtocolNumber, lladdr0); err != nil {
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
						NIC:         nicID,
					}},
				)
			}

			netProto := s.NetworkProtocolInstance(ProtocolNumber)
			if netProto == nil {
				t.Fatalf("cannot find protocol instance for network protocol %d", ProtocolNumber)
			}
			nudHandler := &stubNUDHandler{}
			ep := netProto.NewEndpoint(&testInterface{LinkEndpoint: channel.New(0, header.IPv6MinimumMTU, linkAddr0)}, &stubLinkAddressCache{}, nudHandler, &stubDispatcher{})
			defer ep.Close()

			if err := ep.Enable(); err != nil {
				t.Fatalf("ep.Enable(): %s", err)
			}

			r, err := s.FindRoute(nicID, lladdr0, test.source, ProtocolNumber, false /* multicastLoop */)
			if err != nil {
				t.Fatalf("FindRoute(%d, %s, %s, _, false) = (_, %s), want = (_, nil)", nicID, lladdr0, lladdr1, err)
			}
			defer r.Release()

			// TODO(gvisor.dev/issue/4517): Remove the need for this manual patch.
			r.LocalAddress = test.destination

			icmp := test.createPacket()
			icmp.SetChecksum(header.ICMPv6Checksum(icmp, r.RemoteAddress, r.LocalAddress, buffer.VectorisedView{}))
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: header.IPv6MinimumSize,
				Data:               buffer.View(icmp).ToVectorisedView(),
			})
			ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
			ip.Encode(&header.IPv6Fields{
				PayloadLength: uint16(len(icmp)),
				NextHeader:    uint8(header.ICMPv6ProtocolNumber),
				HopLimit:      header.NDPHopLimit,
				SrcAddr:       r.RemoteAddress,
				DstAddr:       r.LocalAddress,
			})
			r.PopulatePacketInfo(pkt)
			ep.HandlePacket(pkt)

			// Confirm the endpoint calls the correct NUDHandler method.
			if nudHandler.probeCount != test.wantProbeCount {
				t.Errorf("got nudHandler.probeCount = %d, want = %d", nudHandler.probeCount, test.wantProbeCount)
			}
			if nudHandler.confirmationCount != test.wantConfirmationCount {
				t.Errorf("got nudHandler.confirmationCount = %d, want = %d", nudHandler.confirmationCount, test.wantConfirmationCount)
			}
		})
	}
}
