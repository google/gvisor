// Copyright 2022 The gVisor Authors.
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

package multicast_forward_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	incomingNICID      = 1
	outgoingNICID      = 2
	otherOutgoingNICID = 3
	otherNICID         = 4
	unknownNICID       = 5
	packetTTL          = 64
	routeMinTTL        = 2
)

type addrType int

const (
	emptyAddr addrType = iota
	anyAddr
	linkLocalMulticastAddr
	linkLocalUnicastAddr
	multicastAddr
	otherMulticastAddr
	remoteUnicastAddr
)

type endpointAddrType int

const (
	incomingEndpointAddr endpointAddrType = iota
	otherEndpointAddr
	outgoingEndpointAddr
	otherOutgoingEndpointAddr
)

type onMissingRouteData struct {
	context stack.MulticastPacketContext
}

type onUnexpectedInputInterfaceData struct {
	context                stack.MulticastPacketContext
	expectedInputInterface tcpip.NICID
}

var _ stack.MulticastForwardingEventDispatcher = (*fakeMulticastEventDispatcher)(nil)

type fakeMulticastEventDispatcher struct {
	onMissingRouteData             *onMissingRouteData
	onUnexpectedInputInterfaceData *onUnexpectedInputInterfaceData
}

func (m *fakeMulticastEventDispatcher) OnMissingRoute(context stack.MulticastPacketContext) {
	m.onMissingRouteData = &onMissingRouteData{context}
}

func (m *fakeMulticastEventDispatcher) OnUnexpectedInputInterface(context stack.MulticastPacketContext, expectedInputInterface tcpip.NICID) {
	m.onUnexpectedInputInterfaceData = &onUnexpectedInputInterfaceData{
		context,
		expectedInputInterface,
	}
}

var (
	v4Addrs = map[addrType]tcpip.Address{
		anyAddr:                header.IPv4Any,
		emptyAddr:              "",
		linkLocalMulticastAddr: testutil.MustParse4("224.0.0.1"),
		linkLocalUnicastAddr:   testutil.MustParse4("169.254.0.10"),
		multicastAddr:          testutil.MustParse4("225.0.0.0"),
		otherMulticastAddr:     testutil.MustParse4("225.0.0.1"),
		remoteUnicastAddr:      utils.RemoteIPv4Addr,
	}

	v6Addrs = map[addrType]tcpip.Address{
		anyAddr:                header.IPv6Any,
		emptyAddr:              "",
		linkLocalMulticastAddr: testutil.MustParse6("ff02::a"),
		linkLocalUnicastAddr:   testutil.MustParse6("fe80::a"),
		multicastAddr:          testutil.MustParse6("ff0e::a"),
		otherMulticastAddr:     testutil.MustParse6("ff0e::b"),
		remoteUnicastAddr:      utils.RemoteIPv6Addr,
	}

	v4EndpointAddrs = map[endpointAddrType]tcpip.AddressWithPrefix{
		incomingEndpointAddr: utils.RouterNIC1IPv4Addr.AddressWithPrefix,
		otherEndpointAddr:    utils.Host1IPv4Addr.AddressWithPrefix,
		outgoingEndpointAddr: utils.RouterNIC2IPv4Addr.AddressWithPrefix,
		otherOutgoingNICID:   utils.Host2IPv4Addr.AddressWithPrefix,
	}

	v6EndpointAddrs = map[endpointAddrType]tcpip.AddressWithPrefix{
		incomingEndpointAddr: utils.RouterNIC1IPv6Addr.AddressWithPrefix,
		otherEndpointAddr:    utils.Host1IPv6Addr.AddressWithPrefix,
		outgoingEndpointAddr: utils.RouterNIC2IPv6Addr.AddressWithPrefix,
		otherOutgoingNICID:   utils.Host2IPv6Addr.AddressWithPrefix,
	}
)

func getAddr(protocol tcpip.NetworkProtocolNumber, addrType addrType) tcpip.Address {
	switch protocol {
	case ipv4.ProtocolNumber:
		if addr, ok := v4Addrs[addrType]; ok {
			return addr
		}
		panic(fmt.Sprintf("unsupported addrType: %d", addrType))
	case ipv6.ProtocolNumber:
		if addr, ok := v6Addrs[addrType]; ok {
			return addr
		}
		panic(fmt.Sprintf("unsupported addrType: %d", addrType))
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func getEndpointAddr(protocol tcpip.NetworkProtocolNumber, addrType endpointAddrType) tcpip.AddressWithPrefix {
	switch protocol {
	case ipv4.ProtocolNumber:
		if addr, ok := v4EndpointAddrs[addrType]; ok {
			return addr
		}
		panic(fmt.Sprintf("unsupported endpointAddrType: %d", addrType))
	case ipv6.ProtocolNumber:
		if addr, ok := v6EndpointAddrs[addrType]; ok {
			return addr
		}
		panic(fmt.Sprintf("unsupported endpointAddrType: %d", addrType))
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func checkEchoRequest(t *testing.T, protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr, srcAddr, dstAddr tcpip.Address, ttl uint8) {
	payload := stack.PayloadSince(pkt.NetworkHeader())
	defer payload.Release()
	switch protocol {
	case ipv4.ProtocolNumber:
		checker.IPv4(t, payload,
			checker.SrcAddr(srcAddr),
			checker.DstAddr(dstAddr),
			checker.TTL(ttl),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4Echo),
			),
		)
	case ipv6.ProtocolNumber:
		checker.IPv6(t, payload,
			checker.SrcAddr(srcAddr),
			checker.DstAddr(dstAddr),
			checker.TTL(ttl),
			checker.ICMPv6(
				checker.ICMPv6Type(header.ICMPv6EchoRequest),
			),
		)
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func checkEchoReply(t *testing.T, protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr, srcAddr, dstAddr tcpip.Address) {
	payload := stack.PayloadSince(pkt.NetworkHeader())
	defer payload.Release()
	switch protocol {
	case ipv4.ProtocolNumber:
		checker.IPv4(t, payload,
			checker.SrcAddr(srcAddr),
			checker.DstAddr(dstAddr),
			checker.ICMPv4(
				checker.ICMPv4Type(header.ICMPv4EchoReply),
			),
		)
	case ipv6.ProtocolNumber:
		checker.IPv6(t, payload,
			checker.SrcAddr(srcAddr),
			checker.DstAddr(dstAddr),
			checker.ICMPv6(
				checker.ICMPv6Type(header.ICMPv6EchoReply),
			),
		)
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func injectPacket(ep *channel.Endpoint, protocol tcpip.NetworkProtocolNumber, srcAddr, dstAddr tcpip.Address, ttl uint8) {
	switch protocol {
	case ipv4.ProtocolNumber:
		utils.RxICMPv4EchoRequest(ep, srcAddr, dstAddr, ttl)
	case ipv6.ProtocolNumber:
		utils.RxICMPv6EchoRequest(ep, srcAddr, dstAddr, ttl)
	default:
		panic(fmt.Sprintf("unsupported protocol: %d", protocol))
	}
}

func TestAddMulticastRoute(t *testing.T) {
	endpointConfigs := map[tcpip.NICID]endpointAddrType{
		incomingNICID: incomingEndpointAddr,
		outgoingNICID: outgoingEndpointAddr,
		otherNICID:    otherEndpointAddr,
	}

	type multicastForwardingEvent int
	const (
		enabledForProtocol multicastForwardingEvent = iota
		enabledForNIC
		injectPendingPacket
	)

	type multicastForwardingStateBeforeAddRouteCalled struct {
		multicastForwardingEvents []multicastForwardingEvent
	}

	tests := []struct {
		name                                          string
		srcAddr, dstAddr                              addrType
		routeIncomingNICID                            tcpip.NICID
		routeOutgoingNICID                            tcpip.NICID
		omitOutgoingInterfaces                        bool
		multicastForwardingEventsBeforeAddRouteCalled []multicastForwardingEvent
		expectForward                                 bool
		wantErr                                       tcpip.Error
	}{
		{
			name:               "no pending packets",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: nil,
		},
		{
			name:               "packet arrived after forwarding enabled but before add route called",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol, injectPendingPacket},
			expectForward: true,
		},
		{
			name:               "packet arrived before multicast forwarding enabled",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, injectPendingPacket, enabledForProtocol},
			expectForward: false,
		},
		{
			name:    "unexpected input interface",
			srcAddr: remoteUnicastAddr,
			dstAddr: multicastAddr,
			// The added route's incoming NICID does not match the pending packet's
			// incoming NICID. As a result, the packet should not be forwarded.
			routeIncomingNICID: otherNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
		},
		{
			name:               "multicast forwarding disabled for NIC",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForProtocol},
			expectForward: false,
			wantErr:       nil,
		},
		{
			name:               "multicast forwarding disabled for protocol",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC},
			wantErr: &tcpip.ErrNotPermitted{},
		},
		{
			name:               "multicast source",
			srcAddr:            multicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:               "any source",
			srcAddr:            anyAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:               "link-local unicast source",
			srcAddr:            linkLocalUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:               "empty source",
			srcAddr:            emptyAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:               "unicast destination",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            remoteUnicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:               "empty destination",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            emptyAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:               "link-local multicast destination",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            linkLocalMulticastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:               "unknown input NICID",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: unknownNICID,
			routeOutgoingNICID: outgoingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrUnknownNICID{},
		},
		{
			name:               "unknown output NICID",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: unknownNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrUnknownNICID{},
		},
		{
			name:               "input NIC matches output NIC",
			srcAddr:            remoteUnicastAddr,
			dstAddr:            multicastAddr,
			routeIncomingNICID: incomingNICID,
			routeOutgoingNICID: incomingNICID,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrMulticastInputCannotBeOutput{},
		},
		{
			name:                   "empty outgoing interfaces",
			srcAddr:                remoteUnicastAddr,
			dstAddr:                multicastAddr,
			routeIncomingNICID:     incomingNICID,
			routeOutgoingNICID:     outgoingNICID,
			omitOutgoingInterfaces: true,
			multicastForwardingEventsBeforeAddRouteCalled: []multicastForwardingEvent{enabledForNIC, enabledForProtocol},
			wantErr: &tcpip.ErrMissingRequiredFields{},
		},
	}

	for _, test := range tests {
		for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			t.Run(fmt.Sprintf("%s %d", test.name, protocol), func(t *testing.T) {
				eventDispatcher := &fakeMulticastEventDispatcher{}
				s := stack.New(stack.Options{
					NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				})
				defer s.Destroy()

				endpoints := make(map[tcpip.NICID]*channel.Endpoint)
				for nicID, addrType := range endpointConfigs {
					ep := channel.New(1, ipv4.MaxTotalSize, "")
					defer ep.Close()

					if err := s.CreateNIC(nicID, ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					addr := tcpip.ProtocolAddress{
						Protocol:          protocol,
						AddressWithPrefix: getEndpointAddr(protocol, addrType),
					}
					if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %#v, {}): %s", nicID, addr, err)
					}
					endpoints[nicID] = ep
				}

				srcAddr := getAddr(protocol, test.srcAddr)
				dstAddr := getAddr(protocol, test.dstAddr)

				for _, event := range test.multicastForwardingEventsBeforeAddRouteCalled {
					switch event {
					case enabledForNIC:
						for nicID := range endpoints {
							s.SetNICMulticastForwarding(nicID, protocol, true /* enable */)
						}
					case enabledForProtocol:
						if _, err := s.EnableMulticastForwardingForProtocol(protocol, eventDispatcher); err != nil {
							t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, _): (_, %s)", protocol, err)
						}
					case injectPendingPacket:
						incomingEp, ok := endpoints[incomingNICID]
						if !ok {
							t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", incomingNICID)
						}

						injectPacket(incomingEp, protocol, srcAddr, dstAddr, packetTTL)
						p := incomingEp.Read()

						if !p.IsNil() {
							// An ICMP error should never be sent in response to a multicast packet.
							t.Fatalf("got incomingEp.Read() = %#v, want = nil", p)
						}
					default:
						panic(fmt.Sprintf("unsupported multicastForwardingEvent: %d", event))
					}
				}

				outgoingInterfaces := []stack.MulticastRouteOutgoingInterface{
					{ID: test.routeOutgoingNICID, MinTTL: routeMinTTL},
				}
				if test.omitOutgoingInterfaces {
					outgoingInterfaces = nil
				}

				addresses := stack.UnicastSourceAndMulticastDestination{
					Source:      srcAddr,
					Destination: dstAddr,
				}

				route := stack.MulticastRoute{
					ExpectedInputInterface: test.routeIncomingNICID,
					OutgoingInterfaces:     outgoingInterfaces,
				}

				err := s.AddMulticastRoute(protocol, addresses, route)

				if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
					t.Errorf("got s.AddMulticastRoute(%d, %#v, %#v) = %s, want %s", protocol, addresses, route, err, test.wantErr)
				}

				outgoingEp, ok := endpoints[outgoingNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
				}

				p := outgoingEp.Read()

				if (!p.IsNil()) != test.expectForward {
					t.Fatalf("got outgoingEp.Read() = %#v, want = (_ == nil) = %t", p, test.expectForward)
				}

				if test.expectForward {
					checkEchoRequest(t, protocol, p, srcAddr, dstAddr, packetTTL-1)
					p.DecRef()
				}
			})
		}
	}
}

func TestEnableMulticastForwardingE(t *testing.T) {
	eventDispatcher := &fakeMulticastEventDispatcher{}

	type enableMulticastForwardingResult struct {
		AlreadyEnabled bool
		Err            tcpip.Error
	}

	tests := []struct {
		name            string
		eventDispatcher stack.MulticastForwardingEventDispatcher
		wantResult      []enableMulticastForwardingResult
	}{
		{
			name:            "success",
			eventDispatcher: eventDispatcher,
			wantResult:      []enableMulticastForwardingResult{{false, nil}},
		},
		{
			name:            "already enabled",
			eventDispatcher: eventDispatcher,
			wantResult:      []enableMulticastForwardingResult{{false, nil}, {true, nil}},
		},
		{
			name:            "invalid event dispatcher",
			eventDispatcher: nil,
			wantResult:      []enableMulticastForwardingResult{{false, &tcpip.ErrInvalidOptionValue{}}},
		},
	}
	for _, test := range tests {
		for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			t.Run(fmt.Sprintf("%s %d", test.name, protocol), func(t *testing.T) {
				s := stack.New(stack.Options{
					NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
				})
				defer s.Destroy()

				for _, wantResult := range test.wantResult {
					alreadyEnabled, err := s.EnableMulticastForwardingForProtocol(protocol, test.eventDispatcher)
					result := enableMulticastForwardingResult{alreadyEnabled, err}
					if !cmp.Equal(result, wantResult, cmpopts.EquateErrors()) {
						t.Errorf("s.EnableMulticastForwardingForProtocol(%d, %#v) = (%t, %s), want = (%t, %s)", protocol, test.eventDispatcher, alreadyEnabled, err, wantResult.AlreadyEnabled, wantResult.Err)
					}
				}
			})
		}
	}
}

func TestMulticastRouteLastUsedTime(t *testing.T) {
	endpointConfigs := map[tcpip.NICID]endpointAddrType{
		incomingNICID: incomingEndpointAddr,
		outgoingNICID: outgoingEndpointAddr,
		otherNICID:    otherEndpointAddr,
	}

	tests := []struct {
		name             string
		srcAddr, dstAddr addrType
		wantErr          tcpip.Error
	}{
		{
			name:    "success",
			srcAddr: remoteUnicastAddr,
			dstAddr: multicastAddr,
			wantErr: nil,
		},
		{
			name:    "no matching route",
			srcAddr: remoteUnicastAddr,
			dstAddr: otherMulticastAddr,
			wantErr: &tcpip.ErrHostUnreachable{},
		},
		{
			name:    "multicast source",
			srcAddr: multicastAddr,
			dstAddr: multicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "any source",
			srcAddr: anyAddr,
			dstAddr: multicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "link-local unicast source",
			srcAddr: linkLocalUnicastAddr,
			dstAddr: multicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "empty source",
			srcAddr: emptyAddr,
			dstAddr: multicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "unicast destination",
			srcAddr: remoteUnicastAddr,
			dstAddr: remoteUnicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "empty destination",
			srcAddr: remoteUnicastAddr,
			dstAddr: emptyAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "link-local multicast destination",
			srcAddr: remoteUnicastAddr,
			dstAddr: linkLocalMulticastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
	}

	for _, test := range tests {
		for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			t.Run(fmt.Sprintf("%s %d", test.name, protocol), func(t *testing.T) {
				clock := faketime.NewManualClock()
				s := stack.New(stack.Options{
					NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
					Clock:              clock,
				})
				defer s.Destroy()

				if _, err := s.EnableMulticastForwardingForProtocol(protocol, &fakeMulticastEventDispatcher{}); err != nil {
					t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, _): (_, %s)", protocol, err)
				}

				endpoints := make(map[tcpip.NICID]*channel.Endpoint)
				for nicID, addrType := range endpointConfigs {
					ep := channel.New(1, ipv4.MaxTotalSize, "")
					defer ep.Close()

					if err := s.CreateNIC(nicID, ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					addr := tcpip.ProtocolAddress{
						Protocol:          protocol,
						AddressWithPrefix: getEndpointAddr(protocol, addrType),
					}
					if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %#v, {}): %s", nicID, addr, err)
					}
					s.SetNICMulticastForwarding(nicID, protocol, true /* enabled */)
					endpoints[nicID] = ep
				}

				srcAddr := getAddr(protocol, remoteUnicastAddr)
				dstAddr := getAddr(protocol, multicastAddr)

				outgoingInterfaces := []stack.MulticastRouteOutgoingInterface{
					{ID: outgoingNICID, MinTTL: routeMinTTL},
				}

				addresses := stack.UnicastSourceAndMulticastDestination{
					Source:      srcAddr,
					Destination: dstAddr,
				}

				route := stack.MulticastRoute{
					ExpectedInputInterface: incomingNICID,
					OutgoingInterfaces:     outgoingInterfaces,
				}

				if err := s.AddMulticastRoute(protocol, addresses, route); err != nil {
					t.Fatalf("s.AddMulticastRoute(%d, %#v, %#v) = %s, want = nil", protocol, addresses, route, err)
				}

				incomingEp, ok := endpoints[incomingNICID]
				if !ok {
					t.Fatalf("Got endpoints[%d] = (_, false), want (_, true)", incomingNICID)
				}

				clock.Advance(10 * time.Second)

				injectPacket(incomingEp, protocol, srcAddr, dstAddr, packetTTL)
				p := incomingEp.Read()

				if !p.IsNil() {
					t.Fatalf("Expected no ICMP packet through incoming NIC, instead found: %#v", p)
				}

				addresses = stack.UnicastSourceAndMulticastDestination{
					Source:      getAddr(protocol, test.srcAddr),
					Destination: getAddr(protocol, test.dstAddr),
				}
				timestamp, err := s.MulticastRouteLastUsedTime(protocol, addresses)

				if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
					t.Errorf("s.MulticastRouteLastUsedTime(%d, %#v) = (_, %s), want = (_, %s)", protocol, addresses, err, test.wantErr)
				}

				if test.wantErr == nil {
					wantTimestamp := clock.NowMonotonic()
					if diff := cmp.Diff(wantTimestamp, timestamp, cmp.AllowUnexported(tcpip.MonotonicTime{})); diff != "" {
						t.Errorf("s.MulticastRouteLastUsedTime(%d, %#v) timestamp mismatch (-want +got):\n%s", protocol, addresses, diff)
					}
				}
			})
		}
	}
}

func TestRemoveMulticastRoute(t *testing.T) {
	endpointConfigs := map[tcpip.NICID]endpointAddrType{
		incomingNICID: incomingEndpointAddr,
		outgoingNICID: outgoingEndpointAddr,
		otherNICID:    otherEndpointAddr,
	}

	tests := []struct {
		name             string
		srcAddr, dstAddr addrType
		wantErr          tcpip.Error
	}{
		{
			name:    "success",
			srcAddr: remoteUnicastAddr,
			dstAddr: multicastAddr,
			wantErr: nil,
		},
		{
			name:    "no matching route",
			srcAddr: remoteUnicastAddr,
			dstAddr: otherMulticastAddr,
			wantErr: &tcpip.ErrHostUnreachable{},
		},
		{
			name:    "multicast source",
			srcAddr: multicastAddr,
			dstAddr: multicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "any source",
			srcAddr: anyAddr,
			dstAddr: multicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "link-local unicast source",
			srcAddr: linkLocalUnicastAddr,
			dstAddr: multicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "empty source",
			srcAddr: emptyAddr,
			dstAddr: multicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "unicast destination",
			srcAddr: remoteUnicastAddr,
			dstAddr: remoteUnicastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "empty destination",
			srcAddr: remoteUnicastAddr,
			dstAddr: emptyAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
		{
			name:    "link-local multicast destination",
			srcAddr: remoteUnicastAddr,
			dstAddr: linkLocalMulticastAddr,
			wantErr: &tcpip.ErrBadAddress{},
		},
	}

	for _, test := range tests {
		for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			t.Run(fmt.Sprintf("%s %d", test.name, protocol), func(t *testing.T) {
				s := stack.New(stack.Options{
					NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
				})
				defer s.Destroy()

				if _, err := s.EnableMulticastForwardingForProtocol(protocol, &fakeMulticastEventDispatcher{}); err != nil {
					t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, _): (_, %s)", protocol, err)
				}

				endpoints := make(map[tcpip.NICID]*channel.Endpoint)
				for nicID, addrType := range endpointConfigs {
					ep := channel.New(1, ipv4.MaxTotalSize, "")
					defer ep.Close()

					if err := s.CreateNIC(nicID, ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					addr := tcpip.ProtocolAddress{
						Protocol:          protocol,
						AddressWithPrefix: getEndpointAddr(protocol, addrType),
					}
					if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %#v, {}): %s", nicID, addr, err)
					}
					s.SetNICMulticastForwarding(nicID, protocol, true /* enabled */)
					endpoints[nicID] = ep
				}

				srcAddr := getAddr(protocol, remoteUnicastAddr)
				dstAddr := getAddr(protocol, multicastAddr)

				outgoingInterfaces := []stack.MulticastRouteOutgoingInterface{
					{ID: outgoingNICID, MinTTL: routeMinTTL},
				}

				addresses := stack.UnicastSourceAndMulticastDestination{
					Source:      srcAddr,
					Destination: dstAddr,
				}

				route := stack.MulticastRoute{
					ExpectedInputInterface: incomingNICID,
					OutgoingInterfaces:     outgoingInterfaces,
				}

				if err := s.AddMulticastRoute(protocol, addresses, route); err != nil {
					t.Fatalf("got s.AddMulticastRoute(%d, %#v, %#v) = %s, want = nil", protocol, addresses, route, err)
				}

				addresses = stack.UnicastSourceAndMulticastDestination{
					Source:      getAddr(protocol, test.srcAddr),
					Destination: getAddr(protocol, test.dstAddr),
				}
				err := s.RemoveMulticastRoute(protocol, addresses)

				if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
					t.Errorf("got s.RemoveMulticastRoute(%d, %#v) = %s, want %s", protocol, addresses, err, test.wantErr)
				}

				incomingEp, ok := endpoints[incomingNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", incomingNICID)
				}

				injectPacket(incomingEp, protocol, srcAddr, dstAddr, packetTTL)
				p := incomingEp.Read()

				if !p.IsNil() {
					// An ICMP error should never be sent in response to a multicast
					// packet.
					t.Errorf("expected no ICMP packet through incoming NIC, instead found: %#v", p)
				}

				outgoingEp, ok := endpoints[outgoingNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", outgoingNICID)
				}

				p = outgoingEp.Read()

				// If the route was successfully removed, then the packet should not be
				// forwarded.
				expectForward := test.wantErr != nil
				if (!p.IsNil()) != expectForward {
					t.Fatalf("got outgoingEp.Read() = %#v, want = (_ == nil) = %t", p, expectForward)
				}

				if expectForward {
					checkEchoRequest(t, protocol, p, srcAddr, dstAddr, packetTTL-1)
					p.DecRef()
				}
			})
		}
	}
}

func TestMulticastForwarding(t *testing.T) {
	endpointConfigs := map[tcpip.NICID]endpointAddrType{
		incomingNICID:      incomingEndpointAddr,
		outgoingNICID:      outgoingEndpointAddr,
		otherOutgoingNICID: otherOutgoingEndpointAddr,
		otherNICID:         otherEndpointAddr,
	}

	contains := func(want tcpip.NICID, items []tcpip.NICID) bool {
		for _, item := range items {
			if want == item {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name                                 string
		dstAddr                              addrType
		ttl                                  uint8
		routeInputInterface                  tcpip.NICID
		disableMulticastForwardingForNIC     bool
		updateMulticastForwardingForProtocol func(*testing.T, *stack.Stack, tcpip.NetworkProtocolNumber, stack.MulticastForwardingEventDispatcher)
		removeOutputInterface                tcpip.NICID
		expectMissingRouteEvent              bool
		expectUnexpectedInputInterfaceEvent  bool
		joinMulticastGroup                   bool
		expectedForwardingInterfaces         []tcpip.NICID
	}{
		{
			name:                         "forward only",
			dstAddr:                      multicastAddr,
			ttl:                          packetTTL,
			routeInputInterface:          incomingNICID,
			expectedForwardingInterfaces: []tcpip.NICID{outgoingNICID, otherOutgoingNICID},
		},
		{
			name:                         "forward and local",
			dstAddr:                      multicastAddr,
			ttl:                          packetTTL,
			routeInputInterface:          incomingNICID,
			joinMulticastGroup:           true,
			expectedForwardingInterfaces: []tcpip.NICID{outgoingNICID, otherOutgoingNICID},
		},
		{
			name:                         "local only",
			dstAddr:                      linkLocalMulticastAddr,
			ttl:                          packetTTL,
			routeInputInterface:          incomingNICID,
			joinMulticastGroup:           true,
			expectedForwardingInterfaces: []tcpip.NICID{},
		},
		{
			name:                             "multicast forwarding disabled for NIC",
			disableMulticastForwardingForNIC: true,
			dstAddr:                          multicastAddr,
			ttl:                              packetTTL,
			routeInputInterface:              incomingNICID,
			expectedForwardingInterfaces:     []tcpip.NICID{},
		},
		{
			name:    "multicast forwarding disabled for protocol",
			dstAddr: multicastAddr,
			updateMulticastForwardingForProtocol: func(t *testing.T, s *stack.Stack, protocol tcpip.NetworkProtocolNumber, disp stack.MulticastForwardingEventDispatcher) {
				s.DisableMulticastForwardingForProtocol(protocol)
			},
			ttl:                          packetTTL,
			routeInputInterface:          incomingNICID,
			expectedForwardingInterfaces: []tcpip.NICID{},
		},
		{
			name:    "route table cleared after multicast forwarding disabled for protocol",
			dstAddr: multicastAddr,
			updateMulticastForwardingForProtocol: func(t *testing.T, s *stack.Stack, protocol tcpip.NetworkProtocolNumber, disp stack.MulticastForwardingEventDispatcher) {
				t.Helper()

				s.DisableMulticastForwardingForProtocol(protocol)
				if _, err := s.EnableMulticastForwardingForProtocol(protocol, disp); err != nil {
					t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, _): (_, %s)", protocol, err)
				}
			},
			ttl:                          packetTTL,
			routeInputInterface:          incomingNICID,
			expectMissingRouteEvent:      true,
			expectedForwardingInterfaces: []tcpip.NICID{},
		},
		{
			name:                                "unexpected input interface",
			dstAddr:                             multicastAddr,
			ttl:                                 packetTTL,
			routeInputInterface:                 otherNICID,
			expectUnexpectedInputInterfaceEvent: true,
			expectedForwardingInterfaces:        []tcpip.NICID{},
		},
		{
			name:                         "output interface removed",
			dstAddr:                      multicastAddr,
			ttl:                          packetTTL,
			routeInputInterface:          incomingNICID,
			removeOutputInterface:        outgoingNICID,
			expectedForwardingInterfaces: []tcpip.NICID{otherOutgoingNICID},
		},
		{
			name:                         "ttl greater than outgoingNICID route min",
			dstAddr:                      multicastAddr,
			ttl:                          routeMinTTL + 1,
			routeInputInterface:          incomingNICID,
			expectedForwardingInterfaces: []tcpip.NICID{outgoingNICID, otherOutgoingNICID},
		},
		{
			name:                         "ttl same as outgoingNICID route min",
			dstAddr:                      multicastAddr,
			ttl:                          routeMinTTL,
			routeInputInterface:          incomingNICID,
			expectedForwardingInterfaces: []tcpip.NICID{outgoingNICID},
		},
		{
			name:                         "ttl less than outgoingNICID route min",
			dstAddr:                      multicastAddr,
			ttl:                          routeMinTTL - 1,
			routeInputInterface:          incomingNICID,
			expectedForwardingInterfaces: []tcpip.NICID{},
		},
		{
			name:                         "no matching route",
			dstAddr:                      otherMulticastAddr,
			ttl:                          packetTTL,
			routeInputInterface:          incomingNICID,
			expectMissingRouteEvent:      true,
			expectedForwardingInterfaces: []tcpip.NICID{},
		},
	}

	for _, test := range tests {
		for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			ipv4EventDispatcher := &fakeMulticastEventDispatcher{}
			ipv6EventDispatcher := &fakeMulticastEventDispatcher{}

			eventDispatchers := map[tcpip.NetworkProtocolNumber]*fakeMulticastEventDispatcher{
				ipv4.ProtocolNumber: ipv4EventDispatcher,
				ipv6.ProtocolNumber: ipv6EventDispatcher,
			}

			t.Run(fmt.Sprintf("%s %d", test.name, protocol), func(t *testing.T) {
				s := stack.New(stack.Options{
					NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
				})
				defer s.Destroy()

				eventDispatcher, ok := eventDispatchers[protocol]
				if !ok {
					t.Fatalf("eventDispatchers[%d] = (_, false), want (_, true)", protocol)
				}

				if _, err := s.EnableMulticastForwardingForProtocol(protocol, eventDispatcher); err != nil {
					t.Fatalf("s.EnableMulticastForwardingForProtocol(%d, %#v): (_, %s)", protocol, eventDispatcher, err)
				}

				endpoints := make(map[tcpip.NICID]*channel.Endpoint)
				for nicID, addrType := range endpointConfigs {
					ep := channel.New(1, ipv4.MaxTotalSize, "")
					defer ep.Close()

					if err := s.CreateNIC(nicID, ep); err != nil {
						t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
					}
					addr := tcpip.ProtocolAddress{
						Protocol:          protocol,
						AddressWithPrefix: getEndpointAddr(protocol, addrType),
					}
					if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
					}

					s.SetNICMulticastForwarding(nicID, protocol, true /* enable */)
					endpoints[nicID] = ep
				}

				if err := s.SetForwardingDefaultAndAllNICs(protocol, true /* enabled */); err != nil {
					t.Fatalf("SetForwardingDefaultAndAllNICs(%d, true): %s", protocol, err)
				}

				srcAddr := getAddr(protocol, remoteUnicastAddr)
				dstAddr := getAddr(protocol, test.dstAddr)

				outgoingInterfaces := []stack.MulticastRouteOutgoingInterface{
					{ID: outgoingNICID, MinTTL: routeMinTTL},
					{ID: otherOutgoingNICID, MinTTL: routeMinTTL + 1},
				}
				addresses := stack.UnicastSourceAndMulticastDestination{
					Source:      srcAddr,
					Destination: getAddr(protocol, multicastAddr),
				}

				route := stack.MulticastRoute{
					ExpectedInputInterface: test.routeInputInterface,
					OutgoingInterfaces:     outgoingInterfaces,
				}

				if err := s.AddMulticastRoute(protocol, addresses, route); err != nil {
					t.Fatalf("AddMulticastRoute(%d, %#v, %#v): %s", protocol, addresses, route, err)
				}

				if test.disableMulticastForwardingForNIC {
					for nicID := range endpoints {
						s.SetNICMulticastForwarding(nicID, protocol, false /* enable */)
					}
				}

				if test.updateMulticastForwardingForProtocol != nil {
					test.updateMulticastForwardingForProtocol(t, s, protocol, eventDispatcher)
				}

				if test.removeOutputInterface != 0 {
					if err := s.RemoveNIC(test.removeOutputInterface); err != nil {
						t.Fatalf("RemoveNIC(%d): %s", test.removeOutputInterface, err)
					}
				}

				// Add a route that can be used to send an ICMP echo reply (if the packet
				// is delivered locally).
				s.SetRouteTable([]tcpip.Route{
					{
						Destination: header.IPv4EmptySubnet,
						NIC:         otherNICID,
					},
					{
						Destination: header.IPv6EmptySubnet,
						NIC:         otherNICID,
					},
				})

				if test.joinMulticastGroup {
					if err := s.JoinGroup(protocol, incomingNICID, dstAddr); err != nil {
						t.Fatalf("JoinGroup(%d, %d, %s): %s", protocol, incomingNICID, dstAddr, err)
					}
				}

				incomingEp, ok := endpoints[incomingNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", incomingNICID)
				}

				injectPacket(incomingEp, protocol, srcAddr, dstAddr, test.ttl)
				p := incomingEp.Read()

				if !p.IsNil() {
					// An ICMP error should never be sent in response to a multicast packet.
					t.Fatalf("expected no ICMP packet through incoming NIC, instead found: %#v", p)
				}

				for _, nicID := range []tcpip.NICID{outgoingNICID, otherOutgoingNICID} {
					outgoingEp, ok := endpoints[nicID]
					if !ok {
						t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", nicID)
					}

					p := outgoingEp.Read()

					expectForward := contains(nicID, test.expectedForwardingInterfaces)

					if (!p.IsNil()) != expectForward {
						t.Fatalf("got outgoingEp.Read() = %#v, want = (_ == nil) = %t", p, expectForward)
					}

					if expectForward {
						checkEchoRequest(t, protocol, p, srcAddr, dstAddr, test.ttl-1)
						p.DecRef()
					}
				}

				otherEp, ok := endpoints[otherNICID]
				if !ok {
					t.Fatalf("got endpoints[%d] = (_, false), want (_, true)", otherNICID)
				}

				p = otherEp.Read()

				if (!p.IsNil()) != test.joinMulticastGroup {
					t.Fatalf("got otherEp.Read() = %#v, want = (_ == nil) = %t", p, test.joinMulticastGroup)
				}

				incomingEpAddrType, ok := endpointConfigs[incomingNICID]
				if !ok {
					t.Fatalf("got endpointConfigs[%d] = (_, false), want (_, true)", incomingNICID)
				}

				if test.joinMulticastGroup {
					checkEchoReply(t, protocol, p, getEndpointAddr(protocol, incomingEpAddrType).Address, srcAddr)
					p.DecRef()
				}

				wantUnexpectedInputInterfaceEvent := func() *onUnexpectedInputInterfaceData {
					if test.expectUnexpectedInputInterfaceEvent {
						return &onUnexpectedInputInterfaceData{stack.MulticastPacketContext{stack.UnicastSourceAndMulticastDestination{srcAddr, dstAddr}, incomingNICID}, test.routeInputInterface}
					}
					return nil
				}()

				if diff := cmp.Diff(wantUnexpectedInputInterfaceEvent, eventDispatcher.onUnexpectedInputInterfaceData, cmp.AllowUnexported(onUnexpectedInputInterfaceData{})); diff != "" {
					t.Errorf("onUnexpectedInputInterfaceData mismatch (-want +got):\n%s", diff)
				}

				wantMissingRouteEvent := func() *onMissingRouteData {
					if test.expectMissingRouteEvent {
						return &onMissingRouteData{stack.MulticastPacketContext{stack.UnicastSourceAndMulticastDestination{srcAddr, dstAddr}, incomingNICID}}
					}
					return nil
				}()

				if diff := cmp.Diff(wantMissingRouteEvent, eventDispatcher.onMissingRouteData, cmp.AllowUnexported(onMissingRouteData{})); diff != "" {
					t.Errorf("onMissingRouteData mismatch (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
