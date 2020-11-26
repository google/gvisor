// Copyright 2020 The gVisor Authors.
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
	"fmt"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	linkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")

	ipv4MulticastAddr = tcpip.Address("\xe0\x00\x00\x03")
	ipv6MulticastAddr = tcpip.Address("\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")

	igmpMembershipQuery    = uint8(header.IGMPMembershipQuery)
	igmpv1MembershipReport = uint8(header.IGMPv1MembershipReport)
	igmpv2MembershipReport = uint8(header.IGMPv2MembershipReport)
	igmpLeaveGroup         = uint8(header.IGMPLeaveGroup)
	mldQuery               = uint8(header.ICMPv6MulticastListenerQuery)
	mldReport              = uint8(header.ICMPv6MulticastListenerReport)
	mldDone                = uint8(header.ICMPv6MulticastListenerDone)
)

var (
	// unsolicitedIGMPReportIntervalMaxTenthSec is the maximum amount of time the
	// NIC will wait before sending an unsolicited report after joining a
	// multicast group, in deciseconds.
	unsolicitedIGMPReportIntervalMaxTenthSec = func() uint8 {
		const decisecond = time.Second / 10
		if ipv4.UnsolicitedReportIntervalMax%decisecond != 0 {
			panic(fmt.Sprintf("UnsolicitedReportIntervalMax of %d is a lossy conversion to deciseconds", ipv4.UnsolicitedReportIntervalMax))
		}
		return uint8(ipv4.UnsolicitedReportIntervalMax / decisecond)
	}()
)

// validateMLDPacket checks that a passed PacketInfo is an IPv6 MLD packet
// sent to the provided address with the passed fields set.
func validateMLDPacket(t *testing.T, p channel.PacketInfo, remoteAddress tcpip.Address, mldType uint8, maxRespTime byte, groupAddress tcpip.Address) {
	t.Helper()

	payload := header.IPv6(stack.PayloadSince(p.Pkt.NetworkHeader()))
	checker.IPv6(t, payload,
		checker.DstAddr(remoteAddress),
		// Hop Limit for an MLD message must be 1 as per RFC 2710 section 3.
		checker.TTL(1),
		checker.MLD(header.ICMPv6Type(mldType), header.MLDMinimumSize,
			checker.MLDMaxRespDelay(time.Duration(maxRespTime)*time.Millisecond),
			checker.MLDMulticastAddress(groupAddress),
		),
	)
}

// validateIGMPPacket checks that a passed PacketInfo is an IPv4 IGMP packet
// sent to the provided address with the passed fields set.
func validateIGMPPacket(t *testing.T, p channel.PacketInfo, remoteAddress tcpip.Address, igmpType uint8, maxRespTime byte, groupAddress tcpip.Address) {
	t.Helper()

	payload := header.IPv4(stack.PayloadSince(p.Pkt.NetworkHeader()))
	checker.IPv4(t, payload,
		checker.DstAddr(remoteAddress),
		// TTL for an IGMP message must be 1 as per RFC 2236 section 2.
		checker.TTL(1),
		checker.IGMP(
			checker.IGMPType(header.IGMPType(igmpType)),
			checker.IGMPMaxRespTime(header.DecisecondToDuration(maxRespTime)),
			checker.IGMPGroupAddress(groupAddress),
		),
	)
}

func createStack(t *testing.T, mgpEnabled bool) (*channel.Endpoint, *stack.Stack, *faketime.ManualClock) {
	t.Helper()

	// Create an endpoint of queue size 1, since no more than 1 packets are ever
	// queued in the tests in this file.
	e := channel.New(1, 1280, linkAddr)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				IGMP: ipv4.IGMPOptions{
					Enabled: mgpEnabled,
				},
			}),
			ipv6.NewProtocolWithOptions(ipv6.Options{
				MLD: ipv6.MLDOptions{
					Enabled: mgpEnabled,
				},
			}),
		},
		Clock: clock,
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	return e, s, clock
}

// createAndInjectIGMPPacket creates and injects an IGMP packet with the
// specified fields.
//
// Note, the router alert option is not included in this packet.
//
// TODO(b/162198658): set the router alert option.
func createAndInjectIGMPPacket(e *channel.Endpoint, igmpType byte, maxRespTime byte, groupAddress tcpip.Address) {
	buf := buffer.NewView(header.IPv4MinimumSize + header.IGMPQueryMinimumSize)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         header.IGMPTTL,
		Protocol:    uint8(header.IGMPProtocolNumber),
		SrcAddr:     header.IPv4Any,
		DstAddr:     header.IPv4AllSystems,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	igmp := header.IGMP(buf[header.IPv4MinimumSize:])
	igmp.SetType(header.IGMPType(igmpType))
	igmp.SetMaxRespTime(maxRespTime)
	igmp.SetGroupAddress(groupAddress)
	igmp.SetChecksum(header.IGMPCalculateChecksum(igmp))

	e.InjectInbound(ipv4.ProtocolNumber, &stack.PacketBuffer{
		Data: buf.ToVectorisedView(),
	})
}

// createAndInjectMLDPacket creates and injects an MLD packet with the
// specified fields.
//
// Note, the router alert option is not included in this packet.
//
// TODO(b/162198658): set the router alert option.
func createAndInjectMLDPacket(e *channel.Endpoint, mldType uint8, maxRespDelay byte, groupAddress tcpip.Address) {
	icmpSize := header.ICMPv6HeaderSize + header.MLDMinimumSize
	buf := buffer.NewView(header.IPv6MinimumSize + icmpSize)

	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(icmpSize),
		HopLimit:      header.MLDHopLimit,
		NextHeader:    uint8(header.ICMPv6ProtocolNumber),
		SrcAddr:       header.IPv4Any,
		DstAddr:       header.IPv6AllNodesMulticastAddress,
	})

	icmp := header.ICMPv6(buf[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6Type(mldType))
	mld := header.MLD(icmp.MessageBody())
	mld.SetMaximumResponseDelay(uint16(maxRespDelay))
	mld.SetMulticastAddress(groupAddress)
	icmp.SetChecksum(header.ICMPv6Checksum(icmp, header.IPv6Any, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))

	e.InjectInbound(ipv6.ProtocolNumber, &stack.PacketBuffer{
		Data: buf.ToVectorisedView(),
	})
}

// TestMGPDisabled tests that the multicast group protocol is not enabled by
// default.
func TestMGPDisabled(t *testing.T) {
	tests := []struct {
		name              string
		protoNum          tcpip.NetworkProtocolNumber
		multicastAddr     tcpip.Address
		sentReportStat    func(*stack.Stack) *tcpip.StatCounter
		receivedQueryStat func(*stack.Stack) *tcpip.StatCounter
		rxQuery           func(*channel.Endpoint)
	}{
		{
			name:          "IGMP",
			protoNum:      ipv4.ProtocolNumber,
			multicastAddr: ipv4MulticastAddr,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.MembershipQuery
			},
			rxQuery: func(e *channel.Endpoint) {
				createAndInjectIGMPPacket(e, igmpMembershipQuery, unsolicitedIGMPReportIntervalMaxTenthSec, header.IPv4Any)
			},
		},
		{
			name:          "MLD",
			protoNum:      ipv6.ProtocolNumber,
			multicastAddr: ipv6MulticastAddr,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsSent.MulticastListenerReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsReceived.MulticastListenerQuery
			},
			rxQuery: func(e *channel.Endpoint) {
				createAndInjectMLDPacket(e, mldQuery, 0, header.IPv6Any)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, false)

			// This NIC may join multicast groups when it is enabled but since MGP is
			// disabled, no reports should be sent.
			sentReportStat := test.sentReportStat(s)
			if got := sentReportStat.Value(); got != 0 {
				t.Fatalf("got sentReportState.Value() = %d, want = 0", got)
			}
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Fatalf("sent unexpected packet, stack with disabled MGP sent packet = %#v", p.Pkt)
			}

			// Test joining a specific group explicitly and verify that no reports are
			// sent.
			if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
			}
			if got := sentReportStat.Value(); got != 0 {
				t.Fatalf("got sentReportState.Value() = %d, want = 0", got)
			}
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Fatalf("sent unexpected packet, stack with disabled IGMP sent packet = %#v", p.Pkt)
			}

			// Inject a general query message. This should only trigger a report to be
			// sent if the MGP was enabled.
			test.rxQuery(e)
			if got := test.receivedQueryStat(s).Value(); got != 1 {
				t.Fatalf("got receivedQueryStat(_).Value() = %d, want = 1", got)
			}
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Fatalf("sent unexpected packet, stack with disabled IGMP sent packet = %+v", p.Pkt)
			}
		})
	}
}

func TestMGPReceiveCounters(t *testing.T) {
	tests := []struct {
		name         string
		headerType   uint8
		maxRespTime  byte
		groupAddress tcpip.Address
		statCounter  func(*stack.Stack) *tcpip.StatCounter
		rxMGPkt      func(*channel.Endpoint, byte, byte, tcpip.Address)
	}{
		{
			name:         "IGMP Membership Query",
			headerType:   igmpMembershipQuery,
			maxRespTime:  unsolicitedIGMPReportIntervalMaxTenthSec,
			groupAddress: header.IPv4Any,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.MembershipQuery
			},
			rxMGPkt: createAndInjectIGMPPacket,
		},
		{
			name:         "IGMPv1 Membership Report",
			headerType:   igmpv1MembershipReport,
			maxRespTime:  0,
			groupAddress: header.IPv4AllSystems,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.V1MembershipReport
			},
			rxMGPkt: createAndInjectIGMPPacket,
		},
		{
			name:         "IGMPv2 Membership Report",
			headerType:   igmpv2MembershipReport,
			maxRespTime:  0,
			groupAddress: header.IPv4AllSystems,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.V2MembershipReport
			},
			rxMGPkt: createAndInjectIGMPPacket,
		},
		{
			name:         "IGMP Leave Group",
			headerType:   igmpLeaveGroup,
			maxRespTime:  0,
			groupAddress: header.IPv4AllRoutersGroup,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.LeaveGroup
			},
			rxMGPkt: createAndInjectIGMPPacket,
		},
		{
			name:         "MLD Query",
			headerType:   mldQuery,
			maxRespTime:  0,
			groupAddress: header.IPv6Any,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsReceived.MulticastListenerQuery
			},
			rxMGPkt: createAndInjectMLDPacket,
		},
		{
			name:         "MLD Report",
			headerType:   mldReport,
			maxRespTime:  0,
			groupAddress: header.IPv6Any,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsReceived.MulticastListenerReport
			},
			rxMGPkt: createAndInjectMLDPacket,
		},
		{
			name:         "MLD Done",
			headerType:   mldDone,
			maxRespTime:  0,
			groupAddress: header.IPv6Any,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsReceived.MulticastListenerDone
			},
			rxMGPkt: createAndInjectMLDPacket,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, _ := createStack(t, true)

			test.rxMGPkt(e, test.headerType, test.maxRespTime, test.groupAddress)
			if got := test.statCounter(s).Value(); got != 1 {
				t.Fatalf("got %s received = %d, want = 1", test.name, got)
			}
		})
	}
}

// TestMGPJoinGroup tests that when explicitly joining a multicast group, the
// stack schedules and sends correct Membership Reports.
func TestMGPJoinGroup(t *testing.T) {
	tests := []struct {
		name                        string
		protoNum                    tcpip.NetworkProtocolNumber
		multicastAddr               tcpip.Address
		maxUnsolicitedResponseDelay time.Duration
		sentReportStat              func(*stack.Stack) *tcpip.StatCounter
		receivedQueryStat           func(*stack.Stack) *tcpip.StatCounter
		validateReport              func(*testing.T, channel.PacketInfo)
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			multicastAddr:               ipv4MulticastAddr,
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.MembershipQuery
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				validateIGMPPacket(t, p, ipv4MulticastAddr, igmpv2MembershipReport, 0, ipv4MulticastAddr)
			},
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			multicastAddr:               ipv6MulticastAddr,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsSent.MulticastListenerReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsReceived.MulticastListenerQuery
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				validateMLDPacket(t, p, ipv6MulticastAddr, mldReport, 0, ipv6MulticastAddr)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, true)

			// Test joining a specific address explicitly and verify a Report is sent
			// immediately.
			if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
			}
			sentReportStat := test.sentReportStat(s)
			if got := sentReportStat.Value(); got != 1 {
				t.Errorf("got sentReportState.Value() = %d, want = 1", got)
			}
			if p, ok := e.Read(); !ok {
				t.Fatal("expected a report message to be sent")
			} else {
				test.validateReport(t, p)
			}
			if t.Failed() {
				t.FailNow()
			}

			// Verify the second report is sent by the maximum unsolicited response
			// interval.
			p, ok := e.Read()
			if ok {
				t.Fatalf("sent unexpected packet, expected report only after advancing the clock = %#v", p.Pkt)
			}
			clock.Advance(test.maxUnsolicitedResponseDelay)
			if got := sentReportStat.Value(); got != 2 {
				t.Errorf("got sentReportState.Value() = %d, want = 2", got)
			}
			if p, ok := e.Read(); !ok {
				t.Fatal("expected a report message to be sent")
			} else {
				test.validateReport(t, p)
			}

			// Should not send any more packets.
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Fatalf("sent unexpected packet = %#v", p)
			}
		})
	}
}

// TestMGPLeaveGroup tests that when leaving a previously joined multicast
// group the stack sends a leave/done message.
func TestMGPLeaveGroup(t *testing.T) {
	tests := []struct {
		name           string
		protoNum       tcpip.NetworkProtocolNumber
		multicastAddr  tcpip.Address
		sentReportStat func(*stack.Stack) *tcpip.StatCounter
		sentLeaveStat  func(*stack.Stack) *tcpip.StatCounter
		validateReport func(*testing.T, channel.PacketInfo)
		validateLeave  func(*testing.T, channel.PacketInfo)
	}{
		{
			name:          "IGMP",
			protoNum:      ipv4.ProtocolNumber,
			multicastAddr: ipv4MulticastAddr,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.LeaveGroup
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				validateIGMPPacket(t, p, ipv4MulticastAddr, igmpv2MembershipReport, 0, ipv4MulticastAddr)
			},
			validateLeave: func(t *testing.T, p channel.PacketInfo) {
				validateIGMPPacket(t, p, header.IPv4AllRoutersGroup, igmpLeaveGroup, 0, ipv4MulticastAddr)
			},
		},
		{
			name:          "MLD",
			protoNum:      ipv6.ProtocolNumber,
			multicastAddr: ipv6MulticastAddr,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsSent.MulticastListenerReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsSent.MulticastListenerDone
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				validateMLDPacket(t, p, ipv6MulticastAddr, mldReport, 0, ipv6MulticastAddr)
			},
			validateLeave: func(t *testing.T, p channel.PacketInfo) {
				validateMLDPacket(t, p, header.IPv6AllRoutersMulticastAddress, mldDone, 0, ipv6MulticastAddr)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, true)

			if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
			}
			if got := test.sentReportStat(s).Value(); got != 1 {
				t.Errorf("got sentReportStat(_).Value() = %d, want = 1", got)
			}
			if p, ok := e.Read(); !ok {
				t.Fatal("expected a report message to be sent")
			} else {
				test.validateReport(t, p)
			}
			if t.Failed() {
				t.FailNow()
			}

			// Leaving the group should trigger an leave/done message to be sent.
			if err := s.LeaveGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("LeaveGroup(%d, nic, %s): %s", test.protoNum, test.multicastAddr, err)
			}
			if got := test.sentLeaveStat(s).Value(); got != 1 {
				t.Fatalf("got sentLeaveStat(_).Value() = %d, want = 1", got)
			}
			if p, ok := e.Read(); !ok {
				t.Fatal("expected a leave message to be sent")
			} else {
				test.validateLeave(t, p)
			}

			// Should not send any more packets.
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Fatalf("sent unexpected packet = %#v", p)
			}
		})
	}
}

// TestMGPQueryMessages tests that a report is sent in response to query
// messages.
func TestMGPQueryMessages(t *testing.T) {
	tests := []struct {
		name                        string
		protoNum                    tcpip.NetworkProtocolNumber
		multicastAddr               tcpip.Address
		maxUnsolicitedResponseDelay time.Duration
		sentReportStat              func(*stack.Stack) *tcpip.StatCounter
		receivedQueryStat           func(*stack.Stack) *tcpip.StatCounter
		rxQuery                     func(*channel.Endpoint, uint8, tcpip.Address)
		validateReport              func(*testing.T, channel.PacketInfo)
		maxRespTimeToDuration       func(uint8) time.Duration
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			multicastAddr:               ipv4MulticastAddr,
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.MembershipQuery
			},
			rxQuery: func(e *channel.Endpoint, maxRespTime uint8, groupAddress tcpip.Address) {
				createAndInjectIGMPPacket(e, igmpMembershipQuery, maxRespTime, groupAddress)
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				validateIGMPPacket(t, p, ipv4MulticastAddr, igmpv2MembershipReport, 0, ipv4MulticastAddr)
			},
			maxRespTimeToDuration: header.DecisecondToDuration,
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			multicastAddr:               ipv6MulticastAddr,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsSent.MulticastListenerReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsReceived.MulticastListenerQuery
			},
			rxQuery: func(e *channel.Endpoint, maxRespTime uint8, groupAddress tcpip.Address) {
				createAndInjectMLDPacket(e, mldQuery, maxRespTime, groupAddress)
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				validateMLDPacket(t, p, ipv6MulticastAddr, mldReport, 0, ipv6MulticastAddr)
			},
			maxRespTimeToDuration: func(d uint8) time.Duration {
				return time.Duration(d) * time.Millisecond
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subTests := []struct {
				name          string
				multicastAddr tcpip.Address
				expectReport  bool
			}{
				{
					name:          "Unspecified",
					multicastAddr: tcpip.Address(strings.Repeat("\x00", len(test.multicastAddr))),
					expectReport:  true,
				},
				{
					name:          "Specified",
					multicastAddr: test.multicastAddr,
					expectReport:  true,
				},
				{
					name: "Specified other address",
					multicastAddr: func() tcpip.Address {
						addrBytes := []byte(test.multicastAddr)
						addrBytes[len(addrBytes)-1]++
						return tcpip.Address(addrBytes)
					}(),
					expectReport: false,
				},
			}

			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					e, s, clock := createStack(t, true)

					if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
						t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
					}
					sentReportStat := test.sentReportStat(s)
					for i := uint64(1); i <= 2; i++ {
						sentReportStat := test.sentReportStat(s)
						if got := sentReportStat.Value(); got != i {
							t.Errorf("(i=%d) got sentReportState.Value() = %d, want = %d", i, got, i)
						}
						if p, ok := e.Read(); !ok {
							t.Fatalf("expected %d-th report message to be sent", i)
						} else {
							test.validateReport(t, p)
						}
						clock.Advance(test.maxUnsolicitedResponseDelay)
					}
					if t.Failed() {
						t.FailNow()
					}

					// Should not send any more packets until a query.
					clock.Advance(time.Hour)
					if p, ok := e.Read(); ok {
						t.Fatalf("sent unexpected packet = %#v", p)
					}

					// Receive a query message which should trigger a report to be sent at
					// some time before the maximum response time if the report is
					// targeted at the host.
					const maxRespTime = 100
					test.rxQuery(e, maxRespTime, subTest.multicastAddr)
					if p, ok := e.Read(); ok {
						t.Fatalf("sent unexpected packet = %#v", p.Pkt)
					}

					if subTest.expectReport {
						clock.Advance(test.maxRespTimeToDuration(maxRespTime))
						if got := sentReportStat.Value(); got != 3 {
							t.Errorf("got sentReportState.Value() = %d, want = 3", got)
						}
						if p, ok := e.Read(); !ok {
							t.Fatal("expected a report message to be sent")
						} else {
							test.validateReport(t, p)
						}
					}

					// Should not send any more packets.
					clock.Advance(time.Hour)
					if p, ok := e.Read(); ok {
						t.Fatalf("sent unexpected packet = %#v", p)
					}
				})
			}
		})
	}
}

// TestMGPQueryMessages tests that no further reports or leave/done messages
// are sent after receiving a report.
func TestMGPReportMessages(t *testing.T) {
	tests := []struct {
		name                  string
		protoNum              tcpip.NetworkProtocolNumber
		multicastAddr         tcpip.Address
		sentReportStat        func(*stack.Stack) *tcpip.StatCounter
		sentLeaveStat         func(*stack.Stack) *tcpip.StatCounter
		rxReport              func(*channel.Endpoint)
		validateReport        func(*testing.T, channel.PacketInfo)
		maxRespTimeToDuration func(uint8) time.Duration
	}{
		{
			name:          "IGMP",
			protoNum:      ipv4.ProtocolNumber,
			multicastAddr: ipv4MulticastAddr,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.LeaveGroup
			},
			rxReport: func(e *channel.Endpoint) {
				createAndInjectIGMPPacket(e, igmpv2MembershipReport, 0, ipv4MulticastAddr)
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				validateIGMPPacket(t, p, ipv4MulticastAddr, igmpv2MembershipReport, 0, ipv4MulticastAddr)
			},
			maxRespTimeToDuration: header.DecisecondToDuration,
		},
		{
			name:          "MLD",
			protoNum:      ipv6.ProtocolNumber,
			multicastAddr: ipv6MulticastAddr,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsSent.MulticastListenerReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6PacketsSent.MulticastListenerDone
			},
			rxReport: func(e *channel.Endpoint) {
				createAndInjectMLDPacket(e, mldReport, 0, ipv6MulticastAddr)
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				validateMLDPacket(t, p, ipv6MulticastAddr, mldReport, 0, ipv6MulticastAddr)
			},
			maxRespTimeToDuration: func(d uint8) time.Duration {
				return time.Duration(d) * time.Millisecond
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, true)

			if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
			}
			sentReportStat := test.sentReportStat(s)
			if got := sentReportStat.Value(); got != 1 {
				t.Errorf("got sentReportStat.Value() = %d, want = 1", got)
			}
			if p, ok := e.Read(); !ok {
				t.Fatal("expected a report message to be sent")
			} else {
				test.validateReport(t, p)
			}
			if t.Failed() {
				t.FailNow()
			}

			// Receiving a report for a group we joined should cancel any further
			// reports.
			test.rxReport(e)
			clock.Advance(time.Hour)
			if got := sentReportStat.Value(); got != 1 {
				t.Errorf("got sentReportStat.Value() = %d, want = 1", got)
			}
			if p, ok := e.Read(); ok {
				t.Errorf("sent unexpected packet = %#v", p)
			}
			if t.Failed() {
				t.FailNow()
			}

			// Leaving a group after getting a report should not send a leave/done
			// message.
			if err := s.LeaveGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("LeaveGroup(%d, nic, %s): %s", test.protoNum, test.multicastAddr, err)
			}
			clock.Advance(time.Hour)
			if got := test.sentLeaveStat(s).Value(); got != 0 {
				t.Fatalf("got sentLeaveStat(_).Value() = %d, want = 0", got)
			}

			// Should not send any more packets.
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Fatalf("sent unexpected packet = %#v", p)
			}
		})
	}
}
