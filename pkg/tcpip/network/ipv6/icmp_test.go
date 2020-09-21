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
	nicID = 1

	linkAddr0 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	linkAddr1 = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
	linkAddr2 = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0f")

	defaultChannelSize = 1
	defaultMTU         = 65536
)

var (
	lladdr0 = header.LinkLocalAddr(linkAddr0)
	lladdr1 = header.LinkLocalAddr(linkAddr1)
)

type stubLinkEndpoint struct {
	stack.LinkEndpoint
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

func (*stubDispatcher) DeliverTransportPacket(*stack.Route, tcpip.TransportProtocolNumber, *stack.PacketBuffer) {
}

type stubLinkAddressCache struct {
	stack.LinkAddressCache
}

func (*stubLinkAddressCache) CheckLocalAddress(tcpip.NICID, tcpip.NetworkProtocolNumber, tcpip.Address) tcpip.NICID {
	return 0
}

func (*stubLinkAddressCache) AddLinkAddress(tcpip.NICID, tcpip.Address, tcpip.LinkAddress) {
}

type stubNUDHandler struct{}

var _ stack.NUDHandler = (*stubNUDHandler)(nil)

func (*stubNUDHandler) HandleProbe(remoteAddr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, remoteLinkAddr tcpip.LinkAddress, linkRes stack.LinkAddressResolver) {
}

func (*stubNUDHandler) HandleConfirmation(addr tcpip.Address, linkAddr tcpip.LinkAddress, flags stack.ReachabilityConfirmationFlags) {
}

func (*stubNUDHandler) HandleUpperLevelConfirmation(addr tcpip.Address) {
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
				NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol6()},
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
			ep := netProto.NewEndpoint(0, &stubLinkAddressCache{}, &stubNUDHandler{}, &stubDispatcher{}, nil, s)
			defer ep.Close()

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
				ep.HandlePacket(&r, pkt)
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
		NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol6()},
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
	ep := netProto.NewEndpoint(0, nil, &stubNUDHandler{}, &stubDispatcher{}, nil, s)
	defer ep.Close()

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
		ep.HandlePacket(&r, pkt)
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
			NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
			TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol6()},
		}),
		s1: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocol{NewProtocol()},
			TransportProtocols: []stack.TransportProtocol{icmp.NewProtocol6()},
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
							NetworkProtocols: []stack.NetworkProtocol{NewProtocol()},
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
				NetworkProtocols: []stack.NetworkProtocol{NewProtocol()},
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
				NetworkProtocols: []stack.NetworkProtocol{NewProtocol()},
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
	snaddr := header.SolicitedNodeAddr(lladdr0)
	mcaddr := header.EthernetAddressFromMulticastIPv6Address(snaddr)

	tests := []struct {
		name           string
		remoteLinkAddr tcpip.LinkAddress
		expectLinkAddr tcpip.LinkAddress
	}{
		{
			name:           "Unicast",
			remoteLinkAddr: linkAddr1,
			expectLinkAddr: linkAddr1,
		},
		{
			name:           "Multicast",
			remoteLinkAddr: "",
			expectLinkAddr: mcaddr,
		},
	}

	for _, test := range tests {
		p := NewProtocol()
		linkRes, ok := p.(stack.LinkAddressResolver)
		if !ok {
			t.Fatalf("expected IPv6 protocol to implement stack.LinkAddressResolver")
		}

		linkEP := channel.New(defaultChannelSize, defaultMTU, linkAddr0)
		if err := linkRes.LinkAddressRequest(lladdr0, lladdr1, test.remoteLinkAddr, linkEP); err != nil {
			t.Errorf("got p.LinkAddressRequest(%s, %s, %s, _) = %s", lladdr0, lladdr1, test.remoteLinkAddr, err)
		}

		pkt, ok := linkEP.Read()
		if !ok {
			t.Fatal("expected to send a link address request")
		}

		if got, want := pkt.Route.RemoteLinkAddress, test.expectLinkAddr; got != want {
			t.Errorf("got pkt.Route.RemoteLinkAddress = %s, want = %s", got, want)
		}
	}
}
