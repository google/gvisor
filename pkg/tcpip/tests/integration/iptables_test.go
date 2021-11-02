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
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
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
	srcAddrV4      = tcpip.Address("\x0a\x00\x00\x01")
	dstAddrV4      = tcpip.Address("\x0a\x00\x00\x02")
	srcAddrV6      = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
	dstAddrV6      = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")
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
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: dstAddrV6.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
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
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: dstAddrV4.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
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

var _ stack.LinkEndpoint = (*channelEndpointWithoutWritePacket)(nil)

// channelEndpointWithoutWritePacket is a channel endpoint that does not support
// stack.LinkEndpoint.WritePacket.
type channelEndpointWithoutWritePacket struct {
	*channel.Endpoint

	t *testing.T
}

func (c *channelEndpointWithoutWritePacket) WritePacket(stack.RouteInfo, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) tcpip.Error {
	c.t.Error("unexpectedly called WritePacket; all writes should go through WritePackets")
	return &tcpip.ErrNotSupported{}
}

var _ stack.Matcher = (*udpSourcePortMatcher)(nil)

type udpSourcePortMatcher struct {
	port uint16
}

func (*udpSourcePortMatcher) Name() string {
	return "udpSourcePortMatcher"
}

func (m *udpSourcePortMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (matches, hotdrop bool) {
	udp := header.UDP(pkt.TransportHeader().View())
	if len(udp) < header.UDPMinimumSize {
		// Drop immediately as the packet is invalid.
		return false, true
	}

	return udp.SourcePort() == m.port, false
}

func TestIPTableWritePackets(t *testing.T) {
	const (
		nicID = 1

		dropLocalPort = utils.LocalPort - 1
		acceptPackets = 2
		dropPackets   = 3
	)

	udpHdr := func(hdr buffer.View, srcAddr, dstAddr tcpip.Address, srcPort, dstPort uint16) {
		u := header.UDP(hdr)
		u.Encode(&header.UDPFields{
			SrcPort: srcPort,
			DstPort: dstPort,
			Length:  header.UDPMinimumSize,
		})
		sum := header.PseudoHeaderChecksum(udp.ProtocolNumber, srcAddr, dstAddr, header.UDPMinimumSize)
		sum = header.Checksum(hdr, sum)
		u.SetChecksum(^u.CalculateChecksum(sum))
	}

	tests := []struct {
		name                string
		setupFilter         func(*testing.T, *stack.Stack)
		genPacket           func(*stack.Route) stack.PacketBufferList
		proto               tcpip.NetworkProtocolNumber
		remoteAddr          tcpip.Address
		expectSent          uint64
		expectOutputDropped uint64
	}{
		{
			name:        "IPv4 Accept",
			setupFilter: func(*testing.T, *stack.Stack) { /* no filter */ },
			genPacket: func(r *stack.Route) stack.PacketBufferList {
				var pkts stack.PacketBufferList

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: int(r.MaxHeaderLength() + header.UDPMinimumSize),
				})
				hdr := pkt.TransportHeader().Push(header.UDPMinimumSize)
				udpHdr(hdr, r.LocalAddress(), r.RemoteAddress(), utils.LocalPort, utils.RemotePort)
				pkts.PushFront(pkt)

				return pkts
			},
			proto:               header.IPv4ProtocolNumber,
			remoteAddr:          dstAddrV4,
			expectSent:          1,
			expectOutputDropped: 0,
		},
		{
			name: "IPv4 Drop Other Port",
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()

				table := stack.Table{
					Rules: []stack.Rule{
						{
							Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber},
						},
						{
							Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber},
						},
						{
							Matchers: []stack.Matcher{&udpSourcePortMatcher{port: dropLocalPort}},
							Target:   &stack.DropTarget{NetworkProtocol: header.IPv4ProtocolNumber},
						},
						{
							Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber},
						},
						{
							Target: &stack.ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber},
						},
					},
					BuiltinChains: [stack.NumHooks]int{
						stack.Prerouting:  stack.HookUnset,
						stack.Input:       0,
						stack.Forward:     1,
						stack.Output:      2,
						stack.Postrouting: stack.HookUnset,
					},
					Underflows: [stack.NumHooks]int{
						stack.Prerouting:  stack.HookUnset,
						stack.Input:       0,
						stack.Forward:     1,
						stack.Output:      2,
						stack.Postrouting: stack.HookUnset,
					},
				}

				if err := s.IPTables().ReplaceTable(stack.FilterID, table, false /* ipv4 */); err != nil {
					t.Fatalf("ReplaceTable(%d, _, false): %s", stack.FilterID, err)
				}
			},
			genPacket: func(r *stack.Route) stack.PacketBufferList {
				var pkts stack.PacketBufferList

				for i := 0; i < acceptPackets; i++ {
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						ReserveHeaderBytes: int(r.MaxHeaderLength() + header.UDPMinimumSize),
					})
					hdr := pkt.TransportHeader().Push(header.UDPMinimumSize)
					udpHdr(hdr, r.LocalAddress(), r.RemoteAddress(), utils.LocalPort, utils.RemotePort)
					pkts.PushFront(pkt)
				}
				for i := 0; i < dropPackets; i++ {
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						ReserveHeaderBytes: int(r.MaxHeaderLength() + header.UDPMinimumSize),
					})
					hdr := pkt.TransportHeader().Push(header.UDPMinimumSize)
					udpHdr(hdr, r.LocalAddress(), r.RemoteAddress(), dropLocalPort, utils.RemotePort)
					pkts.PushFront(pkt)
				}

				return pkts
			},
			proto:               header.IPv4ProtocolNumber,
			remoteAddr:          dstAddrV4,
			expectSent:          acceptPackets,
			expectOutputDropped: dropPackets,
		},
		{
			name:        "IPv6 Accept",
			setupFilter: func(*testing.T, *stack.Stack) { /* no filter */ },
			genPacket: func(r *stack.Route) stack.PacketBufferList {
				var pkts stack.PacketBufferList

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: int(r.MaxHeaderLength() + header.UDPMinimumSize),
				})
				hdr := pkt.TransportHeader().Push(header.UDPMinimumSize)
				udpHdr(hdr, r.LocalAddress(), r.RemoteAddress(), utils.LocalPort, utils.RemotePort)
				pkts.PushFront(pkt)

				return pkts
			},
			proto:               header.IPv6ProtocolNumber,
			remoteAddr:          dstAddrV6,
			expectSent:          1,
			expectOutputDropped: 0,
		},
		{
			name: "IPv6 Drop Other Port",
			setupFilter: func(t *testing.T, s *stack.Stack) {
				t.Helper()

				table := stack.Table{
					Rules: []stack.Rule{
						{
							Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber},
						},
						{
							Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber},
						},
						{
							Matchers: []stack.Matcher{&udpSourcePortMatcher{port: dropLocalPort}},
							Target:   &stack.DropTarget{NetworkProtocol: header.IPv6ProtocolNumber},
						},
						{
							Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber},
						},
						{
							Target: &stack.ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber},
						},
					},
					BuiltinChains: [stack.NumHooks]int{
						stack.Prerouting:  stack.HookUnset,
						stack.Input:       0,
						stack.Forward:     1,
						stack.Output:      2,
						stack.Postrouting: stack.HookUnset,
					},
					Underflows: [stack.NumHooks]int{
						stack.Prerouting:  stack.HookUnset,
						stack.Input:       0,
						stack.Forward:     1,
						stack.Output:      2,
						stack.Postrouting: stack.HookUnset,
					},
				}

				if err := s.IPTables().ReplaceTable(stack.FilterID, table, true /* ipv6 */); err != nil {
					t.Fatalf("ReplaceTable(%d, _, true): %s", stack.FilterID, err)
				}
			},
			genPacket: func(r *stack.Route) stack.PacketBufferList {
				var pkts stack.PacketBufferList

				for i := 0; i < acceptPackets; i++ {
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						ReserveHeaderBytes: int(r.MaxHeaderLength() + header.UDPMinimumSize),
					})
					hdr := pkt.TransportHeader().Push(header.UDPMinimumSize)
					udpHdr(hdr, r.LocalAddress(), r.RemoteAddress(), utils.LocalPort, utils.RemotePort)
					pkts.PushFront(pkt)
				}
				for i := 0; i < dropPackets; i++ {
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						ReserveHeaderBytes: int(r.MaxHeaderLength() + header.UDPMinimumSize),
					})
					hdr := pkt.TransportHeader().Push(header.UDPMinimumSize)
					udpHdr(hdr, r.LocalAddress(), r.RemoteAddress(), dropLocalPort, utils.RemotePort)
					pkts.PushFront(pkt)
				}

				return pkts
			},
			proto:               header.IPv6ProtocolNumber,
			remoteAddr:          dstAddrV6,
			expectSent:          acceptPackets,
			expectOutputDropped: dropPackets,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			e := channelEndpointWithoutWritePacket{
				Endpoint: channel.New(4, header.IPv6MinimumMTU, linkAddr),
				t:        t,
			}
			if err := s.CreateNIC(nicID, &e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			protocolAddrV6 := tcpip.ProtocolAddress{
				Protocol:          header.IPv6ProtocolNumber,
				AddressWithPrefix: srcAddrV6.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddrV6, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddrV6, err)
			}
			protocolAddrV4 := tcpip.ProtocolAddress{
				Protocol:          header.IPv4ProtocolNumber,
				AddressWithPrefix: srcAddrV4.WithPrefix(),
			}
			if err := s.AddProtocolAddress(nicID, protocolAddrV4, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddrV4, err)
			}

			s.SetRouteTable([]tcpip.Route{
				{
					Destination: header.IPv4EmptySubnet,
					NIC:         nicID,
				},
				{
					Destination: header.IPv6EmptySubnet,
					NIC:         nicID,
				},
			})

			test.setupFilter(t, s)

			r, err := s.FindRoute(nicID, "", test.remoteAddr, test.proto, false)
			if err != nil {
				t.Fatalf("FindRoute(%d, '', %s, %d, false): %s", nicID, test.remoteAddr, test.proto, err)
			}
			defer r.Release()

			pkts := test.genPacket(r)
			pktsLen := pkts.Len()
			if n, err := r.WritePackets(pkts, stack.NetworkHeaderParams{
				Protocol: header.UDPProtocolNumber,
				TTL:      64,
			}); err != nil {
				t.Fatalf("WritePackets(...): %s", err)
			} else if n != pktsLen {
				t.Fatalf("got WritePackets(...) = %d, want = %d", n, pktsLen)
			}

			if got := s.Stats().IP.PacketsSent.Value(); got != test.expectSent {
				t.Errorf("got PacketSent = %d, want = %d", got, test.expectSent)
			}
			if got := s.Stats().IP.IPTablesOutputDropped.Value(); got != test.expectOutputDropped {
				t.Errorf("got IPTablesOutputDropped = %d, want = %d", got, test.expectOutputDropped)
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

					protocolAddrV4 := tcpip.ProtocolAddress{
						Protocol:          ipv4.ProtocolNumber,
						AddressWithPrefix: utils.Ipv4Addr.Address.WithPrefix(),
					}
					if err := s.AddProtocolAddress(nicID2, protocolAddrV4, stack.AddressProperties{}); err != nil {
						t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID2, protocolAddrV4, err)
					}
					protocolAddrV6 := tcpip.ProtocolAddress{
						Protocol:          ipv6.ProtocolNumber,
						AddressWithPrefix: utils.Ipv6Addr.Address.WithPrefix(),
					}
					if err := s.AddProtocolAddress(nicID2, protocolAddrV6, stack.AddressProperties{}); err != nil {
						t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID2, protocolAddrV6, err)
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
					if err := s.AddProtocolAddress(nicID1, utils.Ipv4Addr1, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID1, utils.Ipv4Addr1, err)
					}
					if err := s.AddProtocolAddress(nicID1, utils.Ipv6Addr1, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID1, utils.Ipv6Addr1, err)
					}

					e2 := channel.New(1, header.IPv6MinimumMTU, "")
					if err := s.CreateNICWithOptions(nicID2, e2, stack.NICOptions{Name: nic2Name}); err != nil {
						t.Fatalf("s.CreateNICWithOptions(%d, _, _): %s", nicID2, err)
					}
					if err := s.AddProtocolAddress(nicID2, utils.Ipv4Addr2, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID2, utils.Ipv4Addr2, err)
					}
					if err := s.AddProtocolAddress(nicID2, utils.Ipv6Addr2, stack.AddressProperties{}); err != nil {
						t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID2, utils.Ipv6Addr2, err)
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

func TestNAT(t *testing.T) {
	const listenPort uint16 = 8080

	type endpointAndAddresses struct {
		serverEP          tcpip.Endpoint
		serverAddr        tcpip.FullAddress
		serverReadableCH  chan struct{}
		serverConnectAddr tcpip.Address

		clientEP          tcpip.Endpoint
		clientAddr        tcpip.Address
		clientReadableCH  chan struct{}
		clientConnectAddr tcpip.FullAddress
	}

	newEP := func(t *testing.T, s *stack.Stack, transProto tcpip.TransportProtocolNumber, netProto tcpip.NetworkProtocolNumber) (tcpip.Endpoint, chan struct{}) {
		t.Helper()
		var wq waiter.Queue
		we, ch := waiter.NewChannelEntry(nil)
		wq.EventRegister(&we, waiter.ReadableEvents)
		t.Cleanup(func() {
			wq.EventUnregister(&we)
		})

		ep, err := s.NewEndpoint(transProto, netProto, &wq)
		if err != nil {
			t.Fatalf("s.NewEndpoint(%d, %d, _): %s", transProto, netProto, err)
		}
		t.Cleanup(ep.Close)

		return ep, ch
	}

	setupNAT := func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, hook stack.Hook, filter stack.IPHeaderFilter, target stack.Target) {
		t.Helper()

		ipv6 := netProto == ipv6.ProtocolNumber
		ipt := s.IPTables()
		table := ipt.GetTable(stack.NATID, ipv6)
		ruleIdx := table.BuiltinChains[hook]
		table.Rules[ruleIdx].Filter = filter
		table.Rules[ruleIdx].Target = target
		// Make sure the packet is not dropped by the next rule.
		table.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
		if err := ipt.ReplaceTable(stack.NATID, table, ipv6); err != nil {
			t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.NATID, ipv6, err)
		}
	}

	setupDNAT := func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, target stack.Target) {
		t.Helper()

		setupNAT(
			t,
			s,
			netProto,
			stack.Prerouting,
			stack.IPHeaderFilter{
				Protocol:       transProto,
				CheckProtocol:  true,
				InputInterface: utils.RouterNIC2Name,
			},
			target)
	}

	setupSNAT := func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, target stack.Target) {
		t.Helper()

		setupNAT(
			t,
			s,
			netProto,
			stack.Postrouting,
			stack.IPHeaderFilter{
				Protocol:        transProto,
				CheckProtocol:   true,
				OutputInterface: utils.RouterNIC1Name,
			},
			target)
	}

	type natType struct {
		name     string
		setupNAT func(_ *testing.T, _ *stack.Stack, _ tcpip.NetworkProtocolNumber, _ tcpip.TransportProtocolNumber, snatAddr, dnatAddr tcpip.Address)
	}

	snatTypes := []natType{
		{
			name: "SNAT",
			setupNAT: func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, snatAddr, _ tcpip.Address) {
				t.Helper()

				setupSNAT(t, s, netProto, transProto, &stack.SNATTarget{NetworkProtocol: netProto, Addr: snatAddr})
			},
		},
		{
			name: "Masquerade",
			setupNAT: func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, _, _ tcpip.Address) {
				t.Helper()

				setupSNAT(t, s, netProto, transProto, &stack.MasqueradeTarget{NetworkProtocol: netProto})
			},
		},
	}
	dnatTypes := []natType{
		{
			name: "Redirect",
			setupNAT: func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, _, _ tcpip.Address) {
				t.Helper()

				setupDNAT(t, s, netProto, transProto, &stack.RedirectTarget{NetworkProtocol: netProto, Port: listenPort})
			},
		},
		{
			name: "DNAT",
			setupNAT: func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, _, dnatAddr tcpip.Address) {
				t.Helper()

				setupDNAT(t, s, netProto, transProto, &stack.DNATTarget{NetworkProtocol: netProto, Addr: dnatAddr, Port: listenPort})
			},
		},
	}

	setupTwiceNAT := func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, dnatAddr tcpip.Address, snatTarget stack.Target) {
		t.Helper()

		ipv6 := netProto == ipv6.ProtocolNumber
		ipt := s.IPTables()

		table := stack.Table{
			Rules: []stack.Rule{
				// Prerouting
				{
					Filter: stack.IPHeaderFilter{
						Protocol:       transProto,
						CheckProtocol:  true,
						InputInterface: utils.RouterNIC2Name,
					},
					Target: &stack.DNATTarget{NetworkProtocol: netProto, Addr: dnatAddr, Port: listenPort},
				},
				{
					Target: &stack.AcceptTarget{},
				},

				// Input
				{
					Target: &stack.AcceptTarget{},
				},

				// Forward
				{
					Target: &stack.AcceptTarget{},
				},

				// Output
				{
					Target: &stack.AcceptTarget{},
				},

				// Postrouting
				{
					Filter: stack.IPHeaderFilter{
						Protocol:        transProto,
						CheckProtocol:   true,
						OutputInterface: utils.RouterNIC1Name,
					},
					Target: snatTarget,
				},
				{
					Target: &stack.AcceptTarget{},
				},
			},
			BuiltinChains: [stack.NumHooks]int{
				stack.Prerouting:  0,
				stack.Input:       2,
				stack.Forward:     3,
				stack.Output:      4,
				stack.Postrouting: 5,
			},
		}

		if err := ipt.ReplaceTable(stack.NATID, table, ipv6); err != nil {
			t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.NATID, ipv6, err)
		}
	}
	twiceNATTypes := []natType{
		{
			name: "DNAT-Masquerade",
			setupNAT: func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, snatAddr, dnatAddr tcpip.Address) {
				t.Helper()

				setupTwiceNAT(t, s, netProto, transProto, dnatAddr, &stack.MasqueradeTarget{NetworkProtocol: netProto})
			},
		},
		{
			name: "DNAT-SNAT",
			setupNAT: func(t *testing.T, s *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, snatAddr, dnatAddr tcpip.Address) {
				t.Helper()

				setupTwiceNAT(t, s, netProto, transProto, dnatAddr, &stack.SNATTarget{NetworkProtocol: netProto, Addr: snatAddr})
			},
		},
	}

	tests := []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		// Setups up the stacks in such a way that:
		//
		// - Host2 is the client for all tests.
		// - When performing SNAT only:
		//   + Host1 is the server.
		//   + NAT will transform client-originating packets' source addresses to
		//     the router's NIC1's address before reaching Host1.
		// - When performing DNAT only:
		//   + Router is the server.
		//   + Client will send packets directed to Host1.
		//   + NAT will transform client-originating packets' destination addresses
		//     to the router's NIC2's address.
		// - When performing Twice-NAT:
		//   + Host1 is the server.
		//   + Client will send packets directed to router's NIC2.
		//   + NAT will transform client originating packets' destination addresses
		//     to Host1's address.
		//   + NAT will transform client-originating packets' source addresses to
		//     the router's NIC1's address before reaching Host1.
		epAndAddrs func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses
		natTypes   []natType
	}{
		{
			name:     "IPv4 SNAT",
			netProto: ipv4.ProtocolNumber,
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				t.Helper()

				listenerStack := host1Stack
				serverAddr := tcpip.FullAddress{
					Addr: utils.Host1IPv4Addr.AddressWithPrefix.Address,
					Port: listenPort,
				}
				serverConnectAddr := utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address
				clientConnectPort := serverAddr.Port
				ep1, ep1WECH := newEP(t, listenerStack, proto, ipv4.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host2Stack, proto, ipv4.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:          ep1,
					serverAddr:        serverAddr,
					serverReadableCH:  ep1WECH,
					serverConnectAddr: serverConnectAddr,

					clientEP:         ep2,
					clientAddr:       utils.Host2IPv4Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
					clientConnectAddr: tcpip.FullAddress{
						Addr: utils.Host1IPv4Addr.AddressWithPrefix.Address,
						Port: clientConnectPort,
					},
				}
			},
			natTypes: snatTypes,
		},
		{
			name:     "IPv4 DNAT",
			netProto: ipv4.ProtocolNumber,
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				t.Helper()

				// If we are performing DNAT, then the packet will be redirected
				// to the router.
				listenerStack := routerStack
				serverAddr := tcpip.FullAddress{
					Addr: utils.RouterNIC2IPv4Addr.AddressWithPrefix.Address,
					Port: listenPort,
				}
				serverConnectAddr := utils.Host2IPv4Addr.AddressWithPrefix.Address
				// DNAT will update the destination port to what the server is
				// bound to.
				clientConnectPort := serverAddr.Port + 1
				ep1, ep1WECH := newEP(t, listenerStack, proto, ipv4.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host2Stack, proto, ipv4.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:          ep1,
					serverAddr:        serverAddr,
					serverReadableCH:  ep1WECH,
					serverConnectAddr: serverConnectAddr,

					clientEP:         ep2,
					clientAddr:       utils.Host2IPv4Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
					clientConnectAddr: tcpip.FullAddress{
						Addr: utils.Host1IPv4Addr.AddressWithPrefix.Address,
						Port: clientConnectPort,
					},
				}
			},
			natTypes: dnatTypes,
		},
		{
			name:     "IPv4 Twice-NAT",
			netProto: ipv4.ProtocolNumber,
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				t.Helper()

				listenerStack := host1Stack
				serverAddr := tcpip.FullAddress{
					Addr: utils.Host1IPv4Addr.AddressWithPrefix.Address,
					Port: listenPort,
				}
				serverConnectAddr := utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address
				clientConnectPort := serverAddr.Port
				ep1, ep1WECH := newEP(t, listenerStack, proto, ipv4.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host2Stack, proto, ipv4.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:          ep1,
					serverAddr:        serverAddr,
					serverReadableCH:  ep1WECH,
					serverConnectAddr: serverConnectAddr,

					clientEP:         ep2,
					clientAddr:       utils.Host2IPv4Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
					clientConnectAddr: tcpip.FullAddress{
						Addr: utils.RouterNIC2IPv4Addr.AddressWithPrefix.Address,
						Port: clientConnectPort,
					},
				}
			},
			natTypes: twiceNATTypes,
		},
		{
			name:     "IPv6 SNAT",
			netProto: ipv6.ProtocolNumber,
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				t.Helper()

				listenerStack := host1Stack
				serverAddr := tcpip.FullAddress{
					Addr: utils.Host1IPv6Addr.AddressWithPrefix.Address,
					Port: listenPort,
				}
				serverConnectAddr := utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address
				clientConnectPort := serverAddr.Port
				ep1, ep1WECH := newEP(t, listenerStack, proto, ipv6.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host2Stack, proto, ipv6.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:          ep1,
					serverAddr:        serverAddr,
					serverReadableCH:  ep1WECH,
					serverConnectAddr: serverConnectAddr,

					clientEP:         ep2,
					clientAddr:       utils.Host2IPv6Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
					clientConnectAddr: tcpip.FullAddress{
						Addr: utils.Host1IPv6Addr.AddressWithPrefix.Address,
						Port: clientConnectPort,
					},
				}
			},
			natTypes: snatTypes,
		},
		{
			name:     "IPv6 DNAT",
			netProto: ipv6.ProtocolNumber,
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				t.Helper()

				// If we are performing DNAT, then the packet will be redirected
				// to the router.
				listenerStack := routerStack
				serverAddr := tcpip.FullAddress{
					Addr: utils.RouterNIC2IPv6Addr.AddressWithPrefix.Address,
					Port: listenPort,
				}
				serverConnectAddr := utils.Host2IPv6Addr.AddressWithPrefix.Address
				// DNAT will update the destination port to what the server is
				// bound to.
				clientConnectPort := serverAddr.Port + 1
				ep1, ep1WECH := newEP(t, listenerStack, proto, ipv6.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host2Stack, proto, ipv6.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:          ep1,
					serverAddr:        serverAddr,
					serverReadableCH:  ep1WECH,
					serverConnectAddr: serverConnectAddr,

					clientEP:         ep2,
					clientAddr:       utils.Host2IPv6Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
					clientConnectAddr: tcpip.FullAddress{
						Addr: utils.Host1IPv6Addr.AddressWithPrefix.Address,
						Port: clientConnectPort,
					},
				}
			},
			natTypes: dnatTypes,
		},
		{
			name:     "IPv6 Twice-NAT",
			netProto: ipv6.ProtocolNumber,
			epAndAddrs: func(t *testing.T, host1Stack, routerStack, host2Stack *stack.Stack, proto tcpip.TransportProtocolNumber) endpointAndAddresses {
				t.Helper()

				listenerStack := host1Stack
				serverAddr := tcpip.FullAddress{
					Addr: utils.Host1IPv6Addr.AddressWithPrefix.Address,
					Port: listenPort,
				}
				serverConnectAddr := utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address
				clientConnectPort := serverAddr.Port
				ep1, ep1WECH := newEP(t, listenerStack, proto, ipv6.ProtocolNumber)
				ep2, ep2WECH := newEP(t, host2Stack, proto, ipv6.ProtocolNumber)
				return endpointAndAddresses{
					serverEP:          ep1,
					serverAddr:        serverAddr,
					serverReadableCH:  ep1WECH,
					serverConnectAddr: serverConnectAddr,

					clientEP:         ep2,
					clientAddr:       utils.Host2IPv6Addr.AddressWithPrefix.Address,
					clientReadableCH: ep2WECH,
					clientConnectAddr: tcpip.FullAddress{
						Addr: utils.RouterNIC2IPv6Addr.AddressWithPrefix.Address,
						Port: clientConnectPort,
					},
				}
			},
			natTypes: twiceNATTypes,
		},
	}

	subTests := []struct {
		name               string
		proto              tcpip.TransportProtocolNumber
		expectedConnectErr tcpip.Error
		setupServer        func(t *testing.T, ep tcpip.Endpoint)
		setupServerConn    func(t *testing.T, ep tcpip.Endpoint, ch <-chan struct{}, clientAddr tcpip.FullAddress) (tcpip.Endpoint, chan struct{})
		needRemoteAddr     bool
	}{
		{
			name:               "UDP",
			proto:              udp.ProtocolNumber,
			expectedConnectErr: nil,
			setupServerConn: func(t *testing.T, ep tcpip.Endpoint, _ <-chan struct{}, clientAddr tcpip.FullAddress) (tcpip.Endpoint, chan struct{}) {
				t.Helper()

				if err := ep.Connect(clientAddr); err != nil {
					t.Fatalf("ep.Connect(%#v): %s", clientAddr, err)
				}
				return nil, nil
			},
			needRemoteAddr: true,
		},
		{
			name:               "TCP",
			proto:              tcp.ProtocolNumber,
			expectedConnectErr: &tcpip.ErrConnectStarted{},
			setupServer: func(t *testing.T, ep tcpip.Endpoint) {
				t.Helper()

				if err := ep.Listen(1); err != nil {
					t.Fatalf("ep.Listen(1): %s", err)
				}
			},
			setupServerConn: func(t *testing.T, ep tcpip.Endpoint, ch <-chan struct{}, clientAddr tcpip.FullAddress) (tcpip.Endpoint, chan struct{}) {
				t.Helper()

				var addr tcpip.FullAddress
				for {
					newEP, wq, err := ep.Accept(&addr)
					if _, ok := err.(*tcpip.ErrWouldBlock); ok {
						<-ch
						continue
					}
					if err != nil {
						t.Fatalf("ep.Accept(_): %s", err)
					}
					if diff := cmp.Diff(clientAddr, addr, checker.IgnoreCmpPath(
						"NIC",
					)); diff != "" {
						t.Errorf("accepted address mismatch (-want +got):\n%s", diff)
					}

					we, newCH := waiter.NewChannelEntry(nil)
					wq.EventRegister(&we, waiter.ReadableEvents)
					return newEP, newCH
				}
			},
			needRemoteAddr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					for _, natType := range test.natTypes {
						t.Run(natType.name, func(t *testing.T) {
							stackOpts := stack.Options{
								NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
								TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
							}

							host1Stack := stack.New(stackOpts)
							routerStack := stack.New(stackOpts)
							host2Stack := stack.New(stackOpts)
							utils.SetupRoutedStacks(t, host1Stack, routerStack, host2Stack)

							epsAndAddrs := test.epAndAddrs(t, host1Stack, routerStack, host2Stack, subTest.proto)
							natType.setupNAT(t, routerStack, test.netProto, subTest.proto, epsAndAddrs.serverConnectAddr, epsAndAddrs.serverAddr.Addr)

							if err := epsAndAddrs.serverEP.Bind(epsAndAddrs.serverAddr); err != nil {
								t.Fatalf("epsAndAddrs.serverEP.Bind(%#v): %s", epsAndAddrs.serverAddr, err)
							}
							clientAddr := tcpip.FullAddress{Addr: epsAndAddrs.clientAddr}
							if err := epsAndAddrs.clientEP.Bind(clientAddr); err != nil {
								t.Fatalf("epsAndAddrs.clientEP.Bind(%#v): %s", clientAddr, err)
							}

							if subTest.setupServer != nil {
								subTest.setupServer(t, epsAndAddrs.serverEP)
							}
							{
								err := epsAndAddrs.clientEP.Connect(epsAndAddrs.clientConnectAddr)
								if diff := cmp.Diff(subTest.expectedConnectErr, err); diff != "" {
									t.Fatalf("unexpected error from epsAndAddrs.clientEP.Connect(%#v), (-want, +got):\n%s", epsAndAddrs.clientConnectAddr, diff)
								}
							}
							serverConnectAddr := tcpip.FullAddress{Addr: epsAndAddrs.serverConnectAddr}
							if addr, err := epsAndAddrs.clientEP.GetLocalAddress(); err != nil {
								t.Fatalf("epsAndAddrs.clientEP.GetLocalAddress(): %s", err)
							} else {
								serverConnectAddr.Port = addr.Port
							}

							serverEP := epsAndAddrs.serverEP
							serverCH := epsAndAddrs.serverReadableCH
							if ep, ch := subTest.setupServerConn(t, serverEP, serverCH, serverConnectAddr); ep != nil {
								defer ep.Close()
								serverEP = ep
								serverCH = ch
							}

							write := func(ep tcpip.Endpoint, data []byte) {
								t.Helper()

								var r bytes.Reader
								r.Reset(data)
								var wOpts tcpip.WriteOptions
								n, err := ep.Write(&r, wOpts)
								if err != nil {
									t.Fatalf("ep.Write(_, %#v): %s", wOpts, err)
								}
								if want := int64(len(data)); n != want {
									t.Fatalf("got ep.Write(_, %#v) = (%d, _), want = (%d, _)", wOpts, n, want)
								}
							}

							read := func(ch chan struct{}, ep tcpip.Endpoint, data []byte, expectedFrom tcpip.FullAddress) {
								t.Helper()

								var buf bytes.Buffer
								var res tcpip.ReadResult
								for {
									var err tcpip.Error
									opts := tcpip.ReadOptions{NeedRemoteAddr: subTest.needRemoteAddr}
									res, err = ep.Read(&buf, opts)
									if _, ok := err.(*tcpip.ErrWouldBlock); ok {
										<-ch
										continue
									}
									if err != nil {
										t.Fatalf("ep.Read(_, %d, %#v): %s", len(data), opts, err)
									}
									break
								}

								readResult := tcpip.ReadResult{
									Count: len(data),
									Total: len(data),
								}
								if subTest.needRemoteAddr {
									readResult.RemoteAddr = expectedFrom
								}
								if diff := cmp.Diff(readResult, res, checker.IgnoreCmpPath(
									"ControlMessages",
									"RemoteAddr.NIC",
								)); diff != "" {
									t.Errorf("ep.Read: unexpected result (-want +got):\n%s", diff)
								}
								if diff := cmp.Diff(buf.Bytes(), data); diff != "" {
									t.Errorf("received data mismatch (-want +got):\n%s", diff)
								}

								if t.Failed() {
									t.FailNow()
								}
							}

							{
								data := []byte{1, 2, 3, 4}
								write(epsAndAddrs.clientEP, data)
								read(serverCH, serverEP, data, serverConnectAddr)
							}

							{
								data := []byte{5, 6, 7, 8, 9, 10, 11, 12}
								write(serverEP, data)
								read(epsAndAddrs.clientReadableCH, epsAndAddrs.clientEP, data, epsAndAddrs.clientConnectAddr)
							}
						})
					}
				})
			}
		})
	}
}

func TestNATICMPError(t *testing.T) {
	const (
		srcPort  = 1234
		dstPort  = 5432
		dataSize = 4
	)

	type icmpTypeTest struct {
		name           string
		val            uint8
		expectResponse bool
	}

	type transportTypeTest struct {
		name       string
		proto      tcpip.TransportProtocolNumber
		buf        buffer.View
		checkNATed func(*testing.T, buffer.View)
	}

	ipHdr := func(v buffer.View, totalLen int, transProto tcpip.TransportProtocolNumber, srcAddr, dstAddr tcpip.Address) {
		ip := header.IPv4(v)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(totalLen),
			Protocol:    uint8(transProto),
			TTL:         64,
			SrcAddr:     srcAddr,
			DstAddr:     dstAddr,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	}

	ip6Hdr := func(v buffer.View, payloadLen int, transProto tcpip.TransportProtocolNumber, srcAddr, dstAddr tcpip.Address) {
		ip := header.IPv6(v)
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(payloadLen),
			TransportProtocol: transProto,
			HopLimit:          64,
			SrcAddr:           srcAddr,
			DstAddr:           dstAddr,
		})
	}

	tests := []struct {
		name            string
		netProto        tcpip.NetworkProtocolNumber
		host1Addr       tcpip.Address
		icmpError       func(*testing.T, buffer.View, uint8) buffer.View
		decrementTTL    func(buffer.View)
		checkNATedError func(*testing.T, buffer.View, buffer.View, uint8)

		transportTypes []transportTypeTest
		icmpTypes      []icmpTypeTest
	}{
		{
			name:      "IPv4",
			netProto:  ipv4.ProtocolNumber,
			host1Addr: utils.Host1IPv4Addr.AddressWithPrefix.Address,
			icmpError: func(t *testing.T, original buffer.View, icmpType uint8) buffer.View {
				hdr := buffer.NewPrependable(header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(original))
				if n := copy(hdr.Prepend(len(original)), original); n != len(original) {
					t.Fatalf("got copy(...) = %d, want = %d", n, len(original))
				}
				icmp := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
				icmp.SetType(header.ICMPv4Type(icmpType))
				icmp.SetChecksum(0)
				icmp.SetChecksum(header.ICMPv4Checksum(icmp, 0))
				ipHdr(
					hdr.Prepend(header.IPv4MinimumSize),
					hdr.UsedLength(),
					header.ICMPv4ProtocolNumber,
					utils.Host1IPv4Addr.AddressWithPrefix.Address,
					utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address,
				)
				return hdr.View()
			},
			decrementTTL: func(v buffer.View) {
				ip := header.IPv4(v)
				ip.SetTTL(ip.TTL() - 1)
				ip.SetChecksum(0)
				ip.SetChecksum(^ip.CalculateChecksum())
			},
			checkNATedError: func(t *testing.T, v buffer.View, original buffer.View, icmpType uint8) {
				checker.IPv4(t, v,
					checker.SrcAddr(utils.RouterNIC2IPv4Addr.AddressWithPrefix.Address),
					checker.DstAddr(utils.Host2IPv4Addr.AddressWithPrefix.Address),
					checker.ICMPv4(
						checker.ICMPv4Type(header.ICMPv4Type(icmpType)),
						checker.ICMPv4Checksum(),
						checker.ICMPv4Payload(original),
					),
				)
			},
			transportTypes: []transportTypeTest{
				{
					name:  "UDP",
					proto: header.UDPProtocolNumber,
					buf: func() buffer.View {
						udpSize := header.UDPMinimumSize + dataSize
						hdr := buffer.NewPrependable(header.IPv4MinimumSize + udpSize)
						udp := header.UDP(hdr.Prepend(udpSize))
						udp.SetSourcePort(srcPort)
						udp.SetDestinationPort(dstPort)
						udp.SetChecksum(0)
						udp.SetChecksum(^udp.CalculateChecksum(header.PseudoHeaderChecksum(
							header.UDPProtocolNumber,
							utils.Host2IPv4Addr.AddressWithPrefix.Address,
							utils.RouterNIC2IPv4Addr.AddressWithPrefix.Address,
							uint16(len(udp)),
						)))
						ipHdr(
							hdr.Prepend(header.IPv4MinimumSize),
							hdr.UsedLength(),
							header.UDPProtocolNumber,
							utils.Host2IPv4Addr.AddressWithPrefix.Address,
							utils.RouterNIC2IPv4Addr.AddressWithPrefix.Address,
						)
						return hdr.View()
					}(),
					checkNATed: func(t *testing.T, v buffer.View) {
						checker.IPv4(t, v,
							checker.SrcAddr(utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address),
							checker.DstAddr(utils.Host1IPv4Addr.AddressWithPrefix.Address),
							checker.UDP(
								checker.SrcPort(srcPort),
								checker.DstPort(dstPort),
							),
						)
					},
				},
				{
					name:  "TCP",
					proto: header.TCPProtocolNumber,
					buf: func() buffer.View {
						tcpSize := header.TCPMinimumSize + dataSize
						hdr := buffer.NewPrependable(header.IPv4MinimumSize + tcpSize)
						tcp := header.TCP(hdr.Prepend(tcpSize))
						tcp.SetSourcePort(srcPort)
						tcp.SetDestinationPort(dstPort)
						tcp.SetDataOffset(header.TCPMinimumSize)
						tcp.SetChecksum(0)
						tcp.SetChecksum(^tcp.CalculateChecksum(header.PseudoHeaderChecksum(
							header.TCPProtocolNumber,
							utils.Host2IPv4Addr.AddressWithPrefix.Address,
							utils.RouterNIC2IPv4Addr.AddressWithPrefix.Address,
							uint16(len(tcp)),
						)))
						ipHdr(
							hdr.Prepend(header.IPv4MinimumSize),
							hdr.UsedLength(),
							header.TCPProtocolNumber,
							utils.Host2IPv4Addr.AddressWithPrefix.Address,
							utils.RouterNIC2IPv4Addr.AddressWithPrefix.Address,
						)
						return hdr.View()
					}(),
					checkNATed: func(t *testing.T, v buffer.View) {
						checker.IPv4(t, v,
							checker.SrcAddr(utils.RouterNIC1IPv4Addr.AddressWithPrefix.Address),
							checker.DstAddr(utils.Host1IPv4Addr.AddressWithPrefix.Address),
							checker.TCP(
								checker.SrcPort(srcPort),
								checker.DstPort(dstPort),
							),
						)
					},
				},
			},
			icmpTypes: []icmpTypeTest{
				{
					name:           "Destination Unreachable",
					val:            uint8(header.ICMPv4DstUnreachable),
					expectResponse: true,
				},
				{
					name:           "Time Exceeded",
					val:            uint8(header.ICMPv4TimeExceeded),
					expectResponse: true,
				},
				{
					name:           "Parameter Problem",
					val:            uint8(header.ICMPv4ParamProblem),
					expectResponse: true,
				},
				{
					name:           "Echo Request",
					val:            uint8(header.ICMPv4Echo),
					expectResponse: false,
				},
				{
					name:           "Echo Reply",
					val:            uint8(header.ICMPv4EchoReply),
					expectResponse: false,
				},
			},
		},
		{
			name:      "IPv6",
			netProto:  ipv6.ProtocolNumber,
			host1Addr: utils.Host1IPv6Addr.AddressWithPrefix.Address,
			icmpError: func(t *testing.T, original buffer.View, icmpType uint8) buffer.View {
				payloadLen := header.ICMPv6MinimumSize + len(original)
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + payloadLen)
				icmp := header.ICMPv6(hdr.Prepend(payloadLen))
				icmp.SetType(header.ICMPv6Type(icmpType))
				if n := copy(icmp.Payload(), original); n != len(original) {
					t.Fatalf("got copy(...) = %d, want = %d", n, len(original))
				}
				icmp.SetChecksum(0)
				icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header: icmp,
					Src:    utils.Host1IPv6Addr.AddressWithPrefix.Address,
					Dst:    utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
				}))
				ip6Hdr(
					hdr.Prepend(header.IPv6MinimumSize),
					payloadLen,
					header.ICMPv6ProtocolNumber,
					utils.Host1IPv6Addr.AddressWithPrefix.Address,
					utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address,
				)
				return hdr.View()
			},
			decrementTTL: func(v buffer.View) {
				ip := header.IPv6(v)
				ip.SetHopLimit(ip.HopLimit() - 1)
			},
			checkNATedError: func(t *testing.T, v buffer.View, original buffer.View, icmpType uint8) {
				checker.IPv6(t, v,
					checker.SrcAddr(utils.RouterNIC2IPv6Addr.AddressWithPrefix.Address),
					checker.DstAddr(utils.Host2IPv6Addr.AddressWithPrefix.Address),
					checker.ICMPv6(
						checker.ICMPv6Type(header.ICMPv6Type(icmpType)),
						checker.ICMPv6Payload(original),
					),
				)
			},
			transportTypes: []transportTypeTest{
				{
					name:  "UDP",
					proto: header.UDPProtocolNumber,
					buf: func() buffer.View {
						udpSize := header.UDPMinimumSize + dataSize
						hdr := buffer.NewPrependable(header.IPv6MinimumSize + udpSize)
						udp := header.UDP(hdr.Prepend(udpSize))
						udp.SetSourcePort(srcPort)
						udp.SetDestinationPort(dstPort)
						udp.SetChecksum(0)
						udp.SetChecksum(^udp.CalculateChecksum(header.PseudoHeaderChecksum(
							header.UDPProtocolNumber,
							utils.Host2IPv6Addr.AddressWithPrefix.Address,
							utils.RouterNIC2IPv6Addr.AddressWithPrefix.Address,
							uint16(len(udp)),
						)))
						ip6Hdr(
							hdr.Prepend(header.IPv6MinimumSize),
							len(udp),
							header.UDPProtocolNumber,
							utils.Host2IPv6Addr.AddressWithPrefix.Address,
							utils.RouterNIC2IPv6Addr.AddressWithPrefix.Address,
						)
						return hdr.View()
					}(),
					checkNATed: func(t *testing.T, v buffer.View) {
						checker.IPv6(t, v,
							checker.SrcAddr(utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address),
							checker.DstAddr(utils.Host1IPv6Addr.AddressWithPrefix.Address),
							checker.UDP(
								checker.SrcPort(srcPort),
								checker.DstPort(dstPort),
							),
						)
					},
				},
				{
					name:  "TCP",
					proto: header.TCPProtocolNumber,
					buf: func() buffer.View {
						tcpSize := header.TCPMinimumSize + dataSize
						hdr := buffer.NewPrependable(header.IPv6MinimumSize + tcpSize)
						tcp := header.TCP(hdr.Prepend(tcpSize))
						tcp.SetSourcePort(srcPort)
						tcp.SetDestinationPort(dstPort)
						tcp.SetDataOffset(header.TCPMinimumSize)
						tcp.SetChecksum(0)
						tcp.SetChecksum(^tcp.CalculateChecksum(header.PseudoHeaderChecksum(
							header.TCPProtocolNumber,
							utils.Host2IPv6Addr.AddressWithPrefix.Address,
							utils.RouterNIC2IPv6Addr.AddressWithPrefix.Address,
							uint16(len(tcp)),
						)))
						ip6Hdr(
							hdr.Prepend(header.IPv6MinimumSize),
							len(tcp),
							header.TCPProtocolNumber,
							utils.Host2IPv6Addr.AddressWithPrefix.Address,
							utils.RouterNIC2IPv6Addr.AddressWithPrefix.Address,
						)
						return hdr.View()
					}(),
					checkNATed: func(t *testing.T, v buffer.View) {
						checker.IPv6(t, v,
							checker.SrcAddr(utils.RouterNIC1IPv6Addr.AddressWithPrefix.Address),
							checker.DstAddr(utils.Host1IPv6Addr.AddressWithPrefix.Address),
							checker.TCP(
								checker.SrcPort(srcPort),
								checker.DstPort(dstPort),
							),
						)
					},
				},
			},
			icmpTypes: []icmpTypeTest{
				{
					name:           "Destination Unreachable",
					val:            uint8(header.ICMPv6DstUnreachable),
					expectResponse: true,
				},
				{
					name:           "Packet Too Big",
					val:            uint8(header.ICMPv6PacketTooBig),
					expectResponse: true,
				},
				{
					name:           "Time Exceeded",
					val:            uint8(header.ICMPv6TimeExceeded),
					expectResponse: true,
				},
				{
					name:           "Parameter Problem",
					val:            uint8(header.ICMPv6ParamProblem),
					expectResponse: true,
				},
				{
					name:           "Echo Request",
					val:            uint8(header.ICMPv6EchoRequest),
					expectResponse: false,
				},
				{
					name:           "Echo Reply",
					val:            uint8(header.ICMPv6EchoReply),
					expectResponse: false,
				},
			},
		},
	}

	trimTests := []struct {
		name            string
		trimLen         int
		expectNATedICMP bool
	}{
		{
			name:            "Trim nothing",
			trimLen:         0,
			expectNATedICMP: true,
		},
		{
			name:            "Trim data",
			trimLen:         dataSize,
			expectNATedICMP: true,
		},
		{
			name:            "Trim data and transport header",
			trimLen:         dataSize + 1,
			expectNATedICMP: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, transportType := range test.transportTypes {
				t.Run(transportType.name, func(t *testing.T) {
					for _, icmpType := range test.icmpTypes {
						t.Run(icmpType.name, func(t *testing.T) {
							for _, trimTest := range trimTests {
								t.Run(trimTest.name, func(t *testing.T) {
									s := stack.New(stack.Options{
										NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
										TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
									})

									ep1 := channel.New(1, header.IPv6MinimumMTU, "")
									ep2 := channel.New(1, header.IPv6MinimumMTU, "")
									utils.SetupRouterStack(t, s, ep1, ep2)

									ipv6 := test.netProto == ipv6.ProtocolNumber
									ipt := s.IPTables()

									table := stack.Table{
										Rules: []stack.Rule{
											// Prerouting
											{
												Filter: stack.IPHeaderFilter{
													Protocol:       transportType.proto,
													CheckProtocol:  true,
													InputInterface: utils.RouterNIC2Name,
												},
												Target: &stack.DNATTarget{NetworkProtocol: test.netProto, Addr: test.host1Addr, Port: dstPort},
											},
											{
												Target: &stack.AcceptTarget{},
											},

											// Input
											{
												Target: &stack.AcceptTarget{},
											},

											// Forward
											{
												Target: &stack.AcceptTarget{},
											},

											// Output
											{
												Target: &stack.AcceptTarget{},
											},

											// Postrouting
											{
												Filter: stack.IPHeaderFilter{
													Protocol:        transportType.proto,
													CheckProtocol:   true,
													OutputInterface: utils.RouterNIC1Name,
												},
												Target: &stack.MasqueradeTarget{NetworkProtocol: test.netProto},
											},
											{
												Target: &stack.AcceptTarget{},
											},
										},
										BuiltinChains: [stack.NumHooks]int{
											stack.Prerouting:  0,
											stack.Input:       2,
											stack.Forward:     3,
											stack.Output:      4,
											stack.Postrouting: 5,
										},
									}

									if err := ipt.ReplaceTable(stack.NATID, table, ipv6); err != nil {
										t.Fatalf("ipt.ReplaceTable(%d, _, %t): %s", stack.NATID, ipv6, err)
									}

									buf := transportType.buf

									ep2.InjectInbound(test.netProto, stack.NewPacketBuffer(stack.PacketBufferOptions{
										Data: append(buffer.View(nil), buf...).ToVectorisedView(),
									}))

									{
										pkt, ok := ep1.Read()
										if !ok {
											t.Fatal("expected to read a packet on ep1")
										}
										pktView := stack.PayloadSince(pkt.Pkt.NetworkHeader())
										transportType.checkNATed(t, pktView)
										if t.Failed() {
											t.FailNow()
										}

										pktView = pktView[:len(pktView)-trimTest.trimLen]
										buf = buf[:len(buf)-trimTest.trimLen]

										ep1.InjectInbound(test.netProto, stack.NewPacketBuffer(stack.PacketBufferOptions{
											Data: test.icmpError(t, pktView, icmpType.val).ToVectorisedView(),
										}))
									}

									pkt, ok := ep2.Read()
									expectResponse := icmpType.expectResponse && trimTest.expectNATedICMP
									if ok != expectResponse {
										t.Fatalf("got ep2.Read() = (%#v, %t), want = (_, %t)", pkt, ok, expectResponse)
									}
									if !expectResponse {
										return
									}
									test.decrementTTL(buf)
									test.checkNATedError(t, stack.PayloadSince(pkt.Pkt.NetworkHeader()), buf, icmpType.val)
								})
							}
						})
					}
				})
			}
		})
	}
}
