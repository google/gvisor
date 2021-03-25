// Copyright 2021 The gVisor Authors.
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

package iptables_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

type inputIfNameMatcher struct {
	name string
}

var _ stack.Matcher = (*inputIfNameMatcher)(nil)

func (*inputIfNameMatcher) Name() string {
	return "inputIfNameMatcher"
}

func (im *inputIfNameMatcher) Match(hook stack.Hook, _ *stack.PacketBuffer, inNicName, _ string) (bool, bool) {
	return (hook == stack.Input && im.name != "" && im.name == inNicName), false
}

const (
	nicID          = 1
	nicName        = "nic1"
	anotherNicName = "nic2"
	linkAddr       = tcpip.LinkAddress("\x0a\x0b\x0c\x0d\x0e\x0e")
	srcAddrV4      = "\x0a\x00\x00\x01"
	dstAddrV4      = "\x0a\x00\x00\x02"
	srcAddrV6      = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	dstAddrV6      = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	payloadSize    = 20
)

func genStackV6(t *testing.T) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocol},
	})
	e := channel.New(0, header.IPv6MinimumMTU, linkAddr)
	nicOpts := stack.NICOptions{Name: nicName}
	if err := s.CreateNICWithOptions(nicID, e, nicOpts); err != nil {
		t.Fatalf("CreateNICWithOptions(%d, _, %#v) = %s", nicID, nicOpts, err)
	}
	if err := s.AddAddress(nicID, header.IPv6ProtocolNumber, dstAddrV6); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv6ProtocolNumber, dstAddrV6, err)
	}
	return s, e
}

func genStackV4(t *testing.T) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	e := channel.New(0, header.IPv4MinimumMTU, linkAddr)
	nicOpts := stack.NICOptions{Name: nicName}
	if err := s.CreateNICWithOptions(nicID, e, nicOpts); err != nil {
		t.Fatalf("CreateNICWithOptions(%d, _, %#v) = %s", nicID, nicOpts, err)
	}
	if err := s.AddAddress(nicID, header.IPv4ProtocolNumber, dstAddrV4); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv4ProtocolNumber, dstAddrV4, err)
	}
	return s, e
}

func genPacketV6() *stack.PacketBuffer {
	pktSize := header.IPv6MinimumSize + payloadSize
	hdr := buffer.NewPrependable(pktSize)
	ip := header.IPv6(hdr.Prepend(pktSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     payloadSize,
		TransportProtocol: 99,
		HopLimit:          255,
		SrcAddr:           srcAddrV6,
		DstAddr:           dstAddrV6,
	})
	vv := hdr.View().ToVectorisedView()
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Data: vv})
}

func genPacketV4() *stack.PacketBuffer {
	pktSize := header.IPv4MinimumSize + payloadSize
	hdr := buffer.NewPrependable(pktSize)
	ip := header.IPv4(hdr.Prepend(pktSize))
	ip.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(pktSize),
		ID:             1,
		Flags:          0,
		FragmentOffset: 16,
		TTL:            48,
		Protocol:       99,
		SrcAddr:        srcAddrV4,
		DstAddr:        dstAddrV4,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	vv := hdr.View().ToVectorisedView()
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Data: vv})
}

func TestIPTablesStatsForInput(t *testing.T) {
	tests := []struct {
		name               string
		setupStack         func(*testing.T) (*stack.Stack, *channel.Endpoint)
		setupFilter        func(*testing.T, *stack.Stack)
		genPacket          func() *stack.PacketBuffer
		proto              tcpip.NetworkProtocolNumber
		expectReceived     int
		expectInputDropped int
	}{
		{
			name:               "IPv6 Accept",
			setupStack:         genStackV6,
			setupFilter:        func(*testing.T, *stack.Stack) { /* no filter */ },
			genPacket:          genPacketV6,
			proto:              header.IPv6ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 0,
		},
		{
			name:               "IPv4 Accept",
			setupStack:         genStackV4,
			setupFilter:        func(*testing.T, *stack.Stack) { /* no filter */ },
			genPacket:          genPacketV4,
			proto:              header.IPv4ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 0,
		},
		{
			name:       "IPv6 Drop (input interface matches)",
			setupStack: genStackV6,
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()
				ipt := s.IPTables()
				filter := ipt.GetTable(stack.FilterID, true /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Input]
				filter.Rules[ruleIdx].Filter = stack.IPHeaderFilter{InputInterface: nicName}
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&inputIfNameMatcher{nicName}}
				// Make sure the packet is not dropped by the next rule.
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, true /* ipv6 */); err != nil {
					t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, true, err)
				}
			},
			genPacket:          genPacketV6,
			proto:              header.IPv6ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 1,
		},
		{
			name:       "IPv4 Drop (input interface matches)",
			setupStack: genStackV4,
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()
				ipt := s.IPTables()
				filter := ipt.GetTable(stack.FilterID, false /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Input]
				filter.Rules[ruleIdx].Filter = stack.IPHeaderFilter{InputInterface: nicName}
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&inputIfNameMatcher{nicName}}
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, false /* ipv6 */); err != nil {
					t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, false, err)
				}
			},
			genPacket:          genPacketV4,
			proto:              header.IPv4ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 1,
		},
		{
			name:       "IPv6 Accept (input interface does not match)",
			setupStack: genStackV6,
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()
				ipt := s.IPTables()
				filter := ipt.GetTable(stack.FilterID, true /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Input]
				filter.Rules[ruleIdx].Filter = stack.IPHeaderFilter{InputInterface: anotherNicName}
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, true /* ipv6 */); err != nil {
					t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, true, err)
				}
			},
			genPacket:          genPacketV6,
			proto:              header.IPv6ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 0,
		},
		{
			name:       "IPv4 Accept (input interface does not match)",
			setupStack: genStackV4,
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()
				ipt := s.IPTables()
				filter := ipt.GetTable(stack.FilterID, false /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Input]
				filter.Rules[ruleIdx].Filter = stack.IPHeaderFilter{InputInterface: anotherNicName}
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, false /* ipv6 */); err != nil {
					t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, false, err)
				}
			},
			genPacket:          genPacketV4,
			proto:              header.IPv4ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 0,
		},
		{
			name:       "IPv6 Drop (input interface does not match but invert is true)",
			setupStack: genStackV6,
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()
				ipt := s.IPTables()
				filter := ipt.GetTable(stack.FilterID, true /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Input]
				filter.Rules[ruleIdx].Filter = stack.IPHeaderFilter{
					InputInterface:       anotherNicName,
					InputInterfaceInvert: true,
				}
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, true /* ipv6 */); err != nil {
					t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, true, err)
				}
			},
			genPacket:          genPacketV6,
			proto:              header.IPv6ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 1,
		},
		{
			name:       "IPv4 Drop (input interface does not match but invert is true)",
			setupStack: genStackV4,
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()
				ipt := s.IPTables()
				filter := ipt.GetTable(stack.FilterID, false /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Input]
				filter.Rules[ruleIdx].Filter = stack.IPHeaderFilter{
					InputInterface:       anotherNicName,
					InputInterfaceInvert: true,
				}
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, false /* ipv6 */); err != nil {
					t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, false, err)
				}
			},
			genPacket:          genPacketV4,
			proto:              header.IPv4ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 1,
		},
		{
			name:       "IPv6 Accept (input interface does not match using a matcher)",
			setupStack: genStackV6,
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()
				ipt := s.IPTables()
				filter := ipt.GetTable(stack.FilterID, true /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Input]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&inputIfNameMatcher{anotherNicName}}
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, true /* ipv6 */); err != nil {
					t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, true, err)
				}
			},
			genPacket:          genPacketV6,
			proto:              header.IPv6ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 0,
		},
		{
			name:       "IPv4 Accept (input interface does not match using a matcher)",
			setupStack: genStackV4,
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()
				ipt := s.IPTables()
				filter := ipt.GetTable(stack.FilterID, false /* ipv6 */)
				ruleIdx := filter.BuiltinChains[stack.Input]
				filter.Rules[ruleIdx].Target = &stack.DropTarget{}
				filter.Rules[ruleIdx].Matchers = []stack.Matcher{&inputIfNameMatcher{anotherNicName}}
				filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
				if err := ipt.ReplaceTable(stack.FilterID, filter, false /* ipv6 */); err != nil {
					t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, false, err)
				}
			},
			genPacket:          genPacketV4,
			proto:              header.IPv4ProtocolNumber,
			expectReceived:     1,
			expectInputDropped: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, e := test.setupStack(t)
			test.setupFilter(t, s)
			e.InjectInbound(test.proto, test.genPacket())

			if got := int(s.Stats().IP.PacketsReceived.Value()); got != test.expectReceived {
				t.Errorf("got PacketReceived = %d, want = %d", got, test.expectReceived)
			}
			if got := int(s.Stats().IP.IPTablesInputDropped.Value()); got != test.expectInputDropped {
				t.Errorf("got IPTablesInputDropped = %d, want = %d", got, test.expectInputDropped)
			}
		})
	}
}

const ttl = 64

var (
	ipv4GlobalMulticastAddr = testutil.MustParse4("224.0.1.10")
	ipv6GlobalMulticastAddr = testutil.MustParse6("ff0e::a")
)

func rxICMPv4EchoReply(e *channel.Endpoint, src, dst tcpip.Address) {
	utils.RxICMPv4EchoReply(e, src, dst, ttl)
}

func rxICMPv6EchoReply(e *channel.Endpoint, src, dst tcpip.Address) {
	utils.RxICMPv6EchoReply(e, src, dst, ttl)
}

func forwardedICMPv4EchoReplyChecker(t *testing.T, b []byte, src, dst tcpip.Address) {
	checker.IPv4(t, b,
		checker.SrcAddr(src),
		checker.DstAddr(dst),
		checker.TTL(ttl-1),
		checker.ICMPv4(
			checker.ICMPv4Type(header.ICMPv4EchoReply)))
}

func forwardedICMPv6EchoReplyChecker(t *testing.T, b []byte, src, dst tcpip.Address) {
	checker.IPv6(t, b,
		checker.SrcAddr(src),
		checker.DstAddr(dst),
		checker.TTL(ttl-1),
		checker.ICMPv6(
			checker.ICMPv6Type(header.ICMPv6EchoReply)))
}

func boolToInt(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

func setupDropFilter(hook stack.Hook, f stack.IPHeaderFilter) func(*testing.T, *stack.Stack, tcpip.NetworkProtocolNumber) {
	return func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber) {
		t.Helper()

		ipv6 := netProto == ipv6.ProtocolNumber

		ipt := s.IPTables()
		filter := ipt.GetTable(stack.FilterID, ipv6)
		ruleIdx := filter.BuiltinChains[hook]
		filter.Rules[ruleIdx].Filter = f
		filter.Rules[ruleIdx].Target = &stack.DropTarget{NetworkProtocol: netProto}
		// Make sure the packet is not dropped by the next rule.
		filter.Rules[ruleIdx+1].Target = &stack.AcceptTarget{NetworkProtocol: netProto}
		if err := ipt.ReplaceTable(stack.FilterID, filter, ipv6); err != nil {
			t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.FilterID, ipv6, err)
		}
	}
}

func TestForwardingHook(t *testing.T) {
	const (
		nicID1 = 1
		nicID2 = 2

		nic1Name = "nic1"
		nic2Name = "nic2"

		otherNICName = "otherNIC"
	)

	tests := []struct {
		name             string
		netProto         tcpip.NetworkProtocolNumber
		local            bool
		srcAddr, dstAddr tcpip.Address
		rx               func(*channel.Endpoint, tcpip.Address, tcpip.Address)
		checker          func(*testing.T, []byte)
	}{
		{
			name:     "IPv4 remote",
			netProto: ipv4.ProtocolNumber,
			local:    false,
			srcAddr:  utils.RemoteIPv4Addr,
			dstAddr:  utils.Ipv4Addr2.AddressWithPrefix.Address,
			rx:       rxICMPv4EchoReply,
			checker: func(t *testing.T, b []byte) {
				forwardedICMPv4EchoReplyChecker(t, b, utils.RemoteIPv4Addr, utils.Ipv4Addr2.AddressWithPrefix.Address)
			},
		},
		{
			name:     "IPv4 local",
			netProto: ipv4.ProtocolNumber,
			local:    true,
			srcAddr:  utils.RemoteIPv4Addr,
			dstAddr:  utils.Ipv4Addr.Address,
			rx:       rxICMPv4EchoReply,
		},
		{
			name:     "IPv6 remote",
			netProto: ipv6.ProtocolNumber,
			local:    false,
			srcAddr:  utils.RemoteIPv6Addr,
			dstAddr:  utils.Ipv6Addr2.AddressWithPrefix.Address,
			rx:       rxICMPv6EchoReply,
			checker: func(t *testing.T, b []byte) {
				forwardedICMPv6EchoReplyChecker(t, b, utils.RemoteIPv6Addr, utils.Ipv6Addr2.AddressWithPrefix.Address)
			},
		},
		{
			name:     "IPv6 local",
			netProto: ipv6.ProtocolNumber,
			local:    true,
			srcAddr:  utils.RemoteIPv6Addr,
			dstAddr:  utils.Ipv6Addr.Address,
			rx:       rxICMPv6EchoReply,
		},
	}

	subTests := []struct {
		name          string
		setupFilter   func(*testing.T, *stack.Stack, tcpip.NetworkProtocolNumber)
		expectForward bool
	}{
		{
			name:          "Accept",
			setupFilter:   func(*testing.T, *stack.Stack, tcpip.NetworkProtocolNumber) { /* no filter */ },
			expectForward: true,
		},

		{
			name:          "Drop",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{}),
			expectForward: false,
		},
		{
			name:          "Drop with input NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{InputInterface: nic1Name}),
			expectForward: false,
		},
		{
			name:          "Drop with output NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{OutputInterface: nic2Name}),
			expectForward: false,
		},
		{
			name:          "Drop with input and output NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{InputInterface: nic1Name, OutputInterface: nic2Name}),
			expectForward: false,
		},

		{
			name:          "Drop with other input NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{InputInterface: otherNICName}),
			expectForward: true,
		},
		{
			name:          "Drop with other output NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{OutputInterface: otherNICName}),
			expectForward: true,
		},
		{
			name:          "Drop with other input and output NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{InputInterface: otherNICName, OutputInterface: nic2Name}),
			expectForward: true,
		},
		{
			name:          "Drop with input and other output NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{InputInterface: nic1Name, OutputInterface: otherNICName}),
			expectForward: true,
		},
		{
			name:          "Drop with other input and other output NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{InputInterface: otherNICName, OutputInterface: otherNICName}),
			expectForward: true,
		},

		{
			name:          "Drop with inverted input NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{InputInterface: nic1Name, InputInterfaceInvert: true}),
			expectForward: true,
		},
		{
			name:          "Drop with inverted output NIC filtering",
			setupFilter:   setupDropFilter(stack.Forward, stack.IPHeaderFilter{OutputInterface: nic2Name, OutputInterfaceInvert: true}),
			expectForward: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					})

					subTest.setupFilter(t, s, test.netProto)

					e1 := channel.New(1, header.IPv6MinimumMTU, "")
					if err := s.CreateNICWithOptions(nicID1, e1, stack.NICOptions{Name: nic1Name}); err != nil {
						t.Fatalf("s.CreateNICWithOptions(%d, _, _): %s", nicID1, err)
					}

					e2 := channel.New(1, header.IPv6MinimumMTU, "")
					if err := s.CreateNICWithOptions(nicID2, e2, stack.NICOptions{Name: nic2Name}); err != nil {
						t.Fatalf("s.CreateNICWithOptions(%d, _, _): %s", nicID2, err)
					}

					if err := s.AddAddress(nicID2, ipv4.ProtocolNumber, utils.Ipv4Addr.Address); err != nil {
						t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID2, ipv4.ProtocolNumber, utils.Ipv4Addr.Address, err)
					}
					if err := s.AddAddress(nicID2, ipv6.ProtocolNumber, utils.Ipv6Addr.Address); err != nil {
						t.Fatalf("s.AddAddress(%d, %d, %s): %s", nicID2, ipv6.ProtocolNumber, utils.Ipv6Addr.Address, err)
					}

					if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
						t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", ipv4.ProtocolNumber, err)
					}
					if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
						t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", ipv6.ProtocolNumber, err)
					}

					s.SetRouteTable([]tcpip.Route{
						{
							Destination: header.IPv4EmptySubnet,
							NIC:         nicID2,
						},
						{
							Destination: header.IPv6EmptySubnet,
							NIC:         nicID2,
						},
					})

					test.rx(e1, test.srcAddr, test.dstAddr)

					expectTransmitPacket := subTest.expectForward && !test.local

					ep1, err := s.GetNetworkEndpoint(nicID1, test.netProto)
					if err != nil {
						t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID1, test.netProto, err)
					}
					ep1Stats := ep1.Stats()
					ipEP1Stats, ok := ep1Stats.(stack.IPNetworkEndpointStats)
					if !ok {
						t.Fatalf("got ep1Stats = %T, want = stack.IPNetworkEndpointStats", ep1Stats)
					}
					ip1Stats := ipEP1Stats.IPStats()

					if got := ip1Stats.PacketsReceived.Value(); got != 1 {
						t.Errorf("got ip1Stats.PacketsReceived.Value() = %d, want = 1", got)
					}
					if got := ip1Stats.ValidPacketsReceived.Value(); got != 1 {
						t.Errorf("got ip1Stats.ValidPacketsReceived.Value() = %d, want = 1", got)
					}
					if got, want := ip1Stats.IPTablesForwardDropped.Value(), boolToInt(!subTest.expectForward); got != want {
						t.Errorf("got ip1Stats.IPTablesForwardDropped.Value() = %d, want = %d", got, want)
					}
					if got := ip1Stats.PacketsSent.Value(); got != 0 {
						t.Errorf("got ip1Stats.PacketsSent.Value() = %d, want = 0", got)
					}

					ep2, err := s.GetNetworkEndpoint(nicID2, test.netProto)
					if err != nil {
						t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID2, test.netProto, err)
					}
					ep2Stats := ep2.Stats()
					ipEP2Stats, ok := ep2Stats.(stack.IPNetworkEndpointStats)
					if !ok {
						t.Fatalf("got ep2Stats = %T, want = stack.IPNetworkEndpointStats", ep2Stats)
					}
					ip2Stats := ipEP2Stats.IPStats()
					if got := ip2Stats.PacketsReceived.Value(); got != 0 {
						t.Errorf("got ip2Stats.PacketsReceived.Value() = %d, want = 0", got)
					}
					if got, want := ip2Stats.ValidPacketsReceived.Value(), boolToInt(subTest.expectForward && test.local); got != want {
						t.Errorf("got ip2Stats.ValidPacketsReceived.Value() = %d, want = %d", got, want)
					}
					if got, want := ip2Stats.PacketsSent.Value(), boolToInt(expectTransmitPacket); got != want {
						t.Errorf("got ip2Stats.PacketsSent.Value() = %d, want = %d", got, want)
					}

					p, ok := e2.Read()
					if ok != expectTransmitPacket {
						t.Fatalf("got e2.Read() = (%#v, %t), want = (_, %t)", p, ok, expectTransmitPacket)
					}
					if expectTransmitPacket {
						test.checker(t, stack.PayloadSince(p.Pkt.NetworkHeader()))
					}
				})
			}
		})
	}
}

func TestInputHookWithLocalForwarding(t *testing.T) {
	const (
		nicID1 = 1
		nicID2 = 2

		nic1Name = "nic1"
		nic2Name = "nic2"

		otherNICName = "otherNIC"
	)

	tests := []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		rx       func(*channel.Endpoint)
		checker  func(*testing.T, []byte)
	}{
		{
			name:     "IPv4",
			netProto: ipv4.ProtocolNumber,
			rx: func(e *channel.Endpoint) {
				utils.RxICMPv4EchoRequest(e, utils.RemoteIPv4Addr, utils.Ipv4Addr2.AddressWithPrefix.Address, ttl)
			},
			checker: func(t *testing.T, b []byte) {
				checker.IPv4(t, b,
					checker.SrcAddr(utils.Ipv4Addr2.AddressWithPrefix.Address),
					checker.DstAddr(utils.RemoteIPv4Addr),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4EchoReply)))
			},
		},
		{
			name:     "IPv6",
			netProto: ipv6.ProtocolNumber,
			rx: func(e *channel.Endpoint) {
				utils.RxICMPv6EchoRequest(e, utils.RemoteIPv6Addr, utils.Ipv6Addr2.AddressWithPrefix.Address, ttl)
			},
			checker: func(t *testing.T, b []byte) {
				checker.IPv6(t, b,
					checker.SrcAddr(utils.Ipv6Addr2.AddressWithPrefix.Address),
					checker.DstAddr(utils.RemoteIPv6Addr),
					checker.ICMPv6(
						checker.ICMPv6Type(header.ICMPv6EchoReply)))
			},
		},
	}

	subTests := []struct {
		name        string
		setupFilter func(*testing.T, *stack.Stack, tcpip.NetworkProtocolNumber)
		expectDrop  bool
	}{
		{
			name:        "Accept",
			setupFilter: func(*testing.T, *stack.Stack, tcpip.NetworkProtocolNumber) { /* no filter */ },
			expectDrop:  false,
		},

		{
			name:        "Drop",
			setupFilter: setupDropFilter(stack.Input, stack.IPHeaderFilter{}),
			expectDrop:  true,
		},
		{
			name:        "Drop with input NIC filtering on arrival NIC",
			setupFilter: setupDropFilter(stack.Input, stack.IPHeaderFilter{InputInterface: nic1Name}),
			expectDrop:  true,
		},
		{
			name:        "Drop with input NIC filtering on delivered NIC",
			setupFilter: setupDropFilter(stack.Input, stack.IPHeaderFilter{InputInterface: nic2Name}),
			expectDrop:  false,
		},

		{
			name:        "Drop with input NIC filtering on other NIC",
			setupFilter: setupDropFilter(stack.Input, stack.IPHeaderFilter{InputInterface: otherNICName}),
			expectDrop:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					s := stack.New(stack.Options{
						NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					})

					subTest.setupFilter(t, s, test.netProto)

					e1 := channel.New(1, header.IPv6MinimumMTU, "")
					if err := s.CreateNICWithOptions(nicID1, e1, stack.NICOptions{Name: nic1Name}); err != nil {
						t.Fatalf("s.CreateNICWithOptions(%d, _, _): %s", nicID1, err)
					}
					if err := s.AddProtocolAddress(nicID1, utils.Ipv4Addr1); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %#v): %s", nicID1, utils.Ipv4Addr1, err)
					}
					if err := s.AddProtocolAddress(nicID1, utils.Ipv6Addr1); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %#v): %s", nicID1, utils.Ipv6Addr1, err)
					}

					e2 := channel.New(1, header.IPv6MinimumMTU, "")
					if err := s.CreateNICWithOptions(nicID2, e2, stack.NICOptions{Name: nic2Name}); err != nil {
						t.Fatalf("s.CreateNICWithOptions(%d, _, _): %s", nicID2, err)
					}
					if err := s.AddProtocolAddress(nicID2, utils.Ipv4Addr2); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %#v): %s", nicID2, utils.Ipv4Addr2, err)
					}
					if err := s.AddProtocolAddress(nicID2, utils.Ipv6Addr2); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %#v): %s", nicID2, utils.Ipv6Addr2, err)
					}

					if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
						t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", ipv4.ProtocolNumber, err)
					}
					if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
						t.Fatalf("s.SetForwardingDefaultAndAllNICs(%d, true): %s", ipv6.ProtocolNumber, err)
					}

					s.SetRouteTable([]tcpip.Route{
						{
							Destination: header.IPv4EmptySubnet,
							NIC:         nicID1,
						},
						{
							Destination: header.IPv6EmptySubnet,
							NIC:         nicID1,
						},
					})

					test.rx(e1)

					ep1, err := s.GetNetworkEndpoint(nicID1, test.netProto)
					if err != nil {
						t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID1, test.netProto, err)
					}
					ep1Stats := ep1.Stats()
					ipEP1Stats, ok := ep1Stats.(stack.IPNetworkEndpointStats)
					if !ok {
						t.Fatalf("got ep1Stats = %T, want = stack.IPNetworkEndpointStats", ep1Stats)
					}
					ip1Stats := ipEP1Stats.IPStats()

					if got := ip1Stats.PacketsReceived.Value(); got != 1 {
						t.Errorf("got ip1Stats.PacketsReceived.Value() = %d, want = 1", got)
					}
					if got := ip1Stats.ValidPacketsReceived.Value(); got != 1 {
						t.Errorf("got ip1Stats.ValidPacketsReceived.Value() = %d, want = 1", got)
					}
					if got, want := ip1Stats.PacketsSent.Value(), boolToInt(!subTest.expectDrop); got != want {
						t.Errorf("got ip1Stats.PacketsSent.Value() = %d, want = %d", got, want)
					}

					ep2, err := s.GetNetworkEndpoint(nicID2, test.netProto)
					if err != nil {
						t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID2, test.netProto, err)
					}
					ep2Stats := ep2.Stats()
					ipEP2Stats, ok := ep2Stats.(stack.IPNetworkEndpointStats)
					if !ok {
						t.Fatalf("got ep2Stats = %T, want = stack.IPNetworkEndpointStats", ep2Stats)
					}
					ip2Stats := ipEP2Stats.IPStats()
					if got := ip2Stats.PacketsReceived.Value(); got != 0 {
						t.Errorf("got ip2Stats.PacketsReceived.Value() = %d, want = 0", got)
					}
					if got := ip2Stats.ValidPacketsReceived.Value(); got != 1 {
						t.Errorf("got ip2Stats.ValidPacketsReceived.Value() = %d, want = 1", got)
					}
					if got, want := ip2Stats.IPTablesInputDropped.Value(), boolToInt(subTest.expectDrop); got != want {
						t.Errorf("got ip2Stats.IPTablesInputDropped.Value() = %d, want = %d", got, want)
					}
					if got := ip2Stats.PacketsSent.Value(); got != 0 {
						t.Errorf("got ip2Stats.PacketsSent.Value() = %d, want = 0", got)
					}

					if p, ok := e1.Read(); ok == subTest.expectDrop {
						t.Errorf("got e1.Read() = (%#v, %t), want = (_, %t)", p, ok, !subTest.expectDrop)
					} else if !subTest.expectDrop {
						test.checker(t, stack.PayloadSince(p.Pkt.NetworkHeader()))
					}
					if p, ok := e2.Read(); ok {
						t.Errorf("got e1.Read() = (%#v, true), want = (_, false)", p)
					}
				})
			}
		})
	}
}
