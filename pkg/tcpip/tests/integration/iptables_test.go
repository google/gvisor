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

package integration_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
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
					t.Fatalf("ipt.RelaceTable(%d, _, %t): %s", stack.FilterID, true, err)
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
					t.Fatalf("ipt.RelaceTable(%d, _, %t): %s", stack.FilterID, false, err)
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
					t.Fatalf("ipt.RelaceTable(%d, _, %t): %s", stack.FilterID, true, err)
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
					t.Fatalf("ipt.RelaceTable(%d, _, %t): %s", stack.FilterID, false, err)
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
					t.Fatalf("ipt.RelaceTable(%d, _, %t): %s", stack.FilterID, true, err)
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
					t.Fatalf("ipt.RelaceTable(%d, _, %t): %s", stack.FilterID, false, err)
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
					t.Fatalf("ipt.RelaceTable(%d, _, %t): %s", stack.FilterID, true, err)
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
					t.Fatalf("ipt.RelaceTable(%d, _, %t): %s", stack.FilterID, false, err)
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
