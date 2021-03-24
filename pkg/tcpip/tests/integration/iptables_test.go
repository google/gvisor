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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/tests/utils"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
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

var _ stack.LinkEndpoint = (*channelEndpointWithoutWritePacket)(nil)

// channelEndpointWithoutWritePacket is a channel endpoint that does not support
// stack.LinkEndpoint.WritePacket.
type channelEndpointWithoutWritePacket struct {
	*channel.Endpoint

	t *testing.T
}

func (c *channelEndpointWithoutWritePacket) WritePacket(stack.RouteInfo, *stack.GSO, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) tcpip.Error {
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
					t.Fatalf("RelaceTable(%d, _, false): %s", stack.FilterID, err)
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
					t.Fatalf("RelaceTable(%d, _, true): %s", stack.FilterID, err)
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
			if err := s.AddAddress(nicID, header.IPv6ProtocolNumber, srcAddrV6); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv6ProtocolNumber, srcAddrV6, err)
			}
			if err := s.AddAddress(nicID, header.IPv4ProtocolNumber, srcAddrV4); err != nil {
				t.Fatalf("AddAddress(%d, %d, %s) = %s", nicID, header.IPv4ProtocolNumber, srcAddrV4, err)
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
			if n, err := r.WritePackets(nil /* gso */, pkts, stack.NetworkHeaderParams{
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
