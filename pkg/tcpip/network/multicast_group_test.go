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
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const (
	linkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")

	defaultIPv4PrefixLength = 24

	igmpMembershipQuery    = uint8(header.IGMPMembershipQuery)
	igmpv1MembershipReport = uint8(header.IGMPv1MembershipReport)
	igmpv2MembershipReport = uint8(header.IGMPv2MembershipReport)
	igmpLeaveGroup         = uint8(header.IGMPLeaveGroup)
	mldQuery               = uint8(header.ICMPv6MulticastListenerQuery)
	mldReport              = uint8(header.ICMPv6MulticastListenerReport)
	mldDone                = uint8(header.ICMPv6MulticastListenerDone)

	maxUnsolicitedReports = 2
)

var (
	stackIPv4Addr      = testutil.MustParse4("10.0.0.1")
	linkLocalIPv6Addr1 = testutil.MustParse6("fe80::1")
	linkLocalIPv6Addr2 = testutil.MustParse6("fe80::2")

	ipv4MulticastAddr1 = testutil.MustParse4("224.0.0.3")
	ipv4MulticastAddr2 = testutil.MustParse4("224.0.0.4")
	ipv4MulticastAddr3 = testutil.MustParse4("224.0.0.5")
	ipv6MulticastAddr1 = testutil.MustParse6("ff02::3")
	ipv6MulticastAddr2 = testutil.MustParse6("ff02::4")
	ipv6MulticastAddr3 = testutil.MustParse6("ff02::5")
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

	ipv6AddrSNMC = header.SolicitedNodeAddr(linkLocalIPv6Addr1)
)

// validateMLDPacket checks that a passed PacketInfo is an IPv6 MLD packet
// sent to the provided address with the passed fields set.
func validateMLDPacket(t *testing.T, p channel.PacketInfo, remoteAddress tcpip.Address, mldType uint8, maxRespTime byte, groupAddress tcpip.Address) {
	t.Helper()

	payload := header.IPv6(stack.PayloadSince(p.Pkt.NetworkHeader()))
	checker.IPv6WithExtHdr(t, payload,
		checker.IPv6ExtHdr(
			checker.IPv6HopByHopExtensionHeader(checker.IPv6RouterAlert(header.IPv6RouterAlertMLD)),
		),
		checker.SrcAddr(linkLocalIPv6Addr1),
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
		checker.SrcAddr(stackIPv4Addr),
		checker.DstAddr(remoteAddress),
		// TTL for an IGMP message must be 1 as per RFC 2236 section 2.
		checker.TTL(1),
		checker.IPv4RouterAlert(),
		checker.IGMP(
			checker.IGMPType(header.IGMPType(igmpType)),
			checker.IGMPMaxRespTime(header.DecisecondToDuration(maxRespTime)),
			checker.IGMPGroupAddress(groupAddress),
		),
	)
}

func createStack(t *testing.T, v4, mgpEnabled bool) (*channel.Endpoint, *stack.Stack, *faketime.ManualClock) {
	t.Helper()

	e := channel.New(maxUnsolicitedReports, header.IPv6MinimumMTU, linkAddr)
	s, clock := createStackWithLinkEndpoint(t, v4, mgpEnabled, e)
	return e, s, clock
}

func createStackWithLinkEndpoint(t *testing.T, v4, mgpEnabled bool, e stack.LinkEndpoint) (*stack.Stack, *faketime.ManualClock) {
	t.Helper()

	igmpEnabled := v4 && mgpEnabled
	mldEnabled := !v4 && mgpEnabled

	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				IGMP: ipv4.IGMPOptions{
					Enabled: igmpEnabled,
				},
			}),
			ipv6.NewProtocolWithOptions(ipv6.Options{
				MLD: ipv6.MLDOptions{
					Enabled: mldEnabled,
				},
			}),
		},
		Clock: clock,
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}
	addr := tcpip.AddressWithPrefix{
		Address:   stackIPv4Addr,
		PrefixLen: defaultIPv4PrefixLength,
	}
	if err := s.AddAddressWithPrefix(nicID, ipv4.ProtocolNumber, addr); err != nil {
		t.Fatalf("AddAddressWithPrefix(%d, %d, %s): %s", nicID, ipv4.ProtocolNumber, addr, err)
	}
	if err := s.AddAddress(nicID, ipv6.ProtocolNumber, linkLocalIPv6Addr1); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s): %s", nicID, ipv6.ProtocolNumber, linkLocalIPv6Addr1, err)
	}

	return s, clock
}

// checkInitialIPv6Groups checks the initial IPv6 groups that a NIC will join
// when it is created with an IPv6 address.
//
// To not interfere with tests, checkInitialIPv6Groups will leave the added
// address's solicited node multicast group so that the tests can all assume
// the NIC has not joined any IPv6 groups.
func checkInitialIPv6Groups(t *testing.T, e *channel.Endpoint, s *stack.Stack, clock *faketime.ManualClock) (reportCounter uint64, leaveCounter uint64) {
	t.Helper()

	stats := s.Stats().ICMP.V6.PacketsSent

	reportCounter++
	if got := stats.MulticastListenerReport.Value(); got != reportCounter {
		t.Errorf("got stats.MulticastListenerReport.Value() = %d, want = %d", got, reportCounter)
	}
	if p, ok := e.Read(); !ok {
		t.Fatal("expected a report message to be sent")
	} else {
		validateMLDPacket(t, p, ipv6AddrSNMC, mldReport, 0, ipv6AddrSNMC)
	}

	// Leave the group to not affect the tests. This is fine since we are not
	// testing DAD or the solicited node address specifically.
	if err := s.LeaveGroup(ipv6.ProtocolNumber, nicID, ipv6AddrSNMC); err != nil {
		t.Fatalf("LeaveGroup(%d, %d, %s): %s", ipv6.ProtocolNumber, nicID, ipv6AddrSNMC, err)
	}
	leaveCounter++
	if got := stats.MulticastListenerDone.Value(); got != leaveCounter {
		t.Errorf("got stats.MulticastListenerDone.Value() = %d, want = %d", got, leaveCounter)
	}
	if p, ok := e.Read(); !ok {
		t.Fatal("expected a report message to be sent")
	} else {
		validateMLDPacket(t, p, header.IPv6AllRoutersLinkLocalMulticastAddress, mldDone, 0, ipv6AddrSNMC)
	}

	// Should not send any more packets.
	clock.Advance(time.Hour)
	if p, ok := e.Read(); ok {
		t.Fatalf("sent unexpected packet = %#v", p)
	}

	return reportCounter, leaveCounter
}

// createAndInjectIGMPPacket creates and injects an IGMP packet with the
// specified fields.
func createAndInjectIGMPPacket(e *channel.Endpoint, igmpType byte, maxRespTime byte, groupAddress tcpip.Address) {
	options := header.IPv4OptionsSerializer{
		&header.IPv4SerializableRouterAlertOption{},
	}
	buf := buffer.NewView(header.IPv4MinimumSize + int(options.Length()) + header.IGMPQueryMinimumSize)
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         header.IGMPTTL,
		Protocol:    uint8(header.IGMPProtocolNumber),
		SrcAddr:     remoteIPv4Addr,
		DstAddr:     header.IPv4AllSystems,
		Options:     options,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	igmp := header.IGMP(ip.Payload())
	igmp.SetType(header.IGMPType(igmpType))
	igmp.SetMaxRespTime(maxRespTime)
	igmp.SetGroupAddress(groupAddress)
	igmp.SetChecksum(header.IGMPCalculateChecksum(igmp))

	e.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
}

// createAndInjectMLDPacket creates and injects an MLD packet with the
// specified fields.
func createAndInjectMLDPacket(e *channel.Endpoint, mldType uint8, maxRespDelay byte, groupAddress tcpip.Address) {
	extensionHeaders := header.IPv6ExtHdrSerializer{
		header.IPv6SerializableHopByHopExtHdr{
			&header.IPv6RouterAlertOption{Value: header.IPv6RouterAlertMLD},
		},
	}

	extensionHeadersLength := extensionHeaders.Length()
	payloadLength := extensionHeadersLength + header.ICMPv6HeaderSize + header.MLDMinimumSize
	buf := buffer.NewView(header.IPv6MinimumSize + payloadLength)

	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLength),
		HopLimit:          header.MLDHopLimit,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		SrcAddr:           linkLocalIPv6Addr2,
		DstAddr:           header.IPv6AllNodesMulticastAddress,
		ExtensionHeaders:  extensionHeaders,
	})

	icmp := header.ICMPv6(ip.Payload()[extensionHeadersLength:])
	icmp.SetType(header.ICMPv6Type(mldType))
	mld := header.MLD(icmp.MessageBody())
	mld.SetMaximumResponseDelay(uint16(maxRespDelay))
	mld.SetMulticastAddress(groupAddress)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    linkLocalIPv6Addr2,
		Dst:    header.IPv6AllNodesMulticastAddress,
	}))

	e.InjectInbound(ipv6.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
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
			multicastAddr: ipv4MulticastAddr1,
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
			multicastAddr: ipv6MulticastAddr1,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerQuery
			},
			rxQuery: func(e *channel.Endpoint) {
				createAndInjectMLDPacket(e, mldQuery, 0, header.IPv6Any)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, false /* mgpEnabled */)

			// This NIC may join multicast groups when it is enabled but since MGP is
			// disabled, no reports should be sent.
			sentReportStat := test.sentReportStat(s)
			if got := sentReportStat.Value(); got != 0 {
				t.Fatalf("got sentReportStat.Value() = %d, want = 0", got)
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
				t.Fatalf("got sentReportStat.Value() = %d, want = 0", got)
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
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerQuery
			},
			rxMGPkt: createAndInjectMLDPacket,
		},
		{
			name:         "MLD Report",
			headerType:   mldReport,
			maxRespTime:  0,
			groupAddress: header.IPv6Any,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerReport
			},
			rxMGPkt: createAndInjectMLDPacket,
		},
		{
			name:         "MLD Done",
			headerType:   mldDone,
			maxRespTime:  0,
			groupAddress: header.IPv6Any,
			statCounter: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerDone
			},
			rxMGPkt: createAndInjectMLDPacket,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, _ := createStack(t, len(test.groupAddress) == header.IPv4AddressSize /* v4 */, true /* mgpEnabled */)

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
		checkInitialGroups          func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) (uint64, uint64)
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			multicastAddr:               ipv4MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.MembershipQuery
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateIGMPPacket(t, p, ipv4MulticastAddr1, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
			},
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			multicastAddr:               ipv6MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerQuery
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateMLDPacket(t, p, ipv6MulticastAddr1, mldReport, 0, ipv6MulticastAddr1)
			},
			checkInitialGroups: checkInitialIPv6Groups,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)

			var reportCounter uint64
			if test.checkInitialGroups != nil {
				reportCounter, _ = test.checkInitialGroups(t, e, s, clock)
			}

			// Test joining a specific address explicitly and verify a Report is sent
			// immediately.
			if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
			}
			reportCounter++
			sentReportStat := test.sentReportStat(s)
			if got := sentReportStat.Value(); got != reportCounter {
				t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
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
			reportCounter++
			if got := sentReportStat.Value(); got != reportCounter {
				t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
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
		name               string
		protoNum           tcpip.NetworkProtocolNumber
		multicastAddr      tcpip.Address
		sentReportStat     func(*stack.Stack) *tcpip.StatCounter
		sentLeaveStat      func(*stack.Stack) *tcpip.StatCounter
		validateReport     func(*testing.T, channel.PacketInfo)
		validateLeave      func(*testing.T, channel.PacketInfo)
		checkInitialGroups func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) (uint64, uint64)
	}{
		{
			name:          "IGMP",
			protoNum:      ipv4.ProtocolNumber,
			multicastAddr: ipv4MulticastAddr1,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.LeaveGroup
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateIGMPPacket(t, p, ipv4MulticastAddr1, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
			},
			validateLeave: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateIGMPPacket(t, p, header.IPv4AllRoutersGroup, igmpLeaveGroup, 0, ipv4MulticastAddr1)
			},
		},
		{
			name:          "MLD",
			protoNum:      ipv6.ProtocolNumber,
			multicastAddr: ipv6MulticastAddr1,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerDone
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateMLDPacket(t, p, ipv6MulticastAddr1, mldReport, 0, ipv6MulticastAddr1)
			},
			validateLeave: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateMLDPacket(t, p, header.IPv6AllRoutersLinkLocalMulticastAddress, mldDone, 0, ipv6MulticastAddr1)
			},
			checkInitialGroups: checkInitialIPv6Groups,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)

			var reportCounter uint64
			var leaveCounter uint64
			if test.checkInitialGroups != nil {
				reportCounter, leaveCounter = test.checkInitialGroups(t, e, s, clock)
			}

			if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
			}
			reportCounter++
			if got := test.sentReportStat(s).Value(); got != reportCounter {
				t.Errorf("got sentReportStat(_).Value() = %d, want = %d", got, reportCounter)
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
			leaveCounter++
			if got := test.sentLeaveStat(s).Value(); got != leaveCounter {
				t.Fatalf("got sentLeaveStat(_).Value() = %d, want = %d", got, leaveCounter)
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
		checkInitialGroups          func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) (uint64, uint64)
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			multicastAddr:               ipv4MulticastAddr1,
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
				t.Helper()

				validateIGMPPacket(t, p, ipv4MulticastAddr1, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
			},
			maxRespTimeToDuration: header.DecisecondToDuration,
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			multicastAddr:               ipv6MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport
			},
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerQuery
			},
			rxQuery: func(e *channel.Endpoint, maxRespTime uint8, groupAddress tcpip.Address) {
				createAndInjectMLDPacket(e, mldQuery, maxRespTime, groupAddress)
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateMLDPacket(t, p, ipv6MulticastAddr1, mldReport, 0, ipv6MulticastAddr1)
			},
			maxRespTimeToDuration: func(d uint8) time.Duration {
				return time.Duration(d) * time.Millisecond
			},
			checkInitialGroups: checkInitialIPv6Groups,
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
					e, s, clock := createStack(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)

					var reportCounter uint64
					if test.checkInitialGroups != nil {
						reportCounter, _ = test.checkInitialGroups(t, e, s, clock)
					}

					if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
						t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
					}
					sentReportStat := test.sentReportStat(s)
					for i := 0; i < maxUnsolicitedReports; i++ {
						sentReportStat := test.sentReportStat(s)
						reportCounter++
						if got := sentReportStat.Value(); got != reportCounter {
							t.Errorf("(i=%d) got sentReportStat.Value() = %d, want = %d", i, got, reportCounter)
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
						reportCounter++
						if got := sentReportStat.Value(); got != reportCounter {
							t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
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
		checkInitialGroups    func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) (uint64, uint64)
	}{
		{
			name:          "IGMP",
			protoNum:      ipv4.ProtocolNumber,
			multicastAddr: ipv4MulticastAddr1,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.LeaveGroup
			},
			rxReport: func(e *channel.Endpoint) {
				createAndInjectIGMPPacket(e, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateIGMPPacket(t, p, ipv4MulticastAddr1, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
			},
			maxRespTimeToDuration: header.DecisecondToDuration,
		},
		{
			name:          "MLD",
			protoNum:      ipv6.ProtocolNumber,
			multicastAddr: ipv6MulticastAddr1,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerDone
			},
			rxReport: func(e *channel.Endpoint) {
				createAndInjectMLDPacket(e, mldReport, 0, ipv6MulticastAddr1)
			},
			validateReport: func(t *testing.T, p channel.PacketInfo) {
				t.Helper()

				validateMLDPacket(t, p, ipv6MulticastAddr1, mldReport, 0, ipv6MulticastAddr1)
			},
			maxRespTimeToDuration: func(d uint8) time.Duration {
				return time.Duration(d) * time.Millisecond
			},
			checkInitialGroups: checkInitialIPv6Groups,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)

			var reportCounter uint64
			var leaveCounter uint64
			if test.checkInitialGroups != nil {
				reportCounter, leaveCounter = test.checkInitialGroups(t, e, s, clock)
			}

			if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
			}
			sentReportStat := test.sentReportStat(s)
			reportCounter++
			if got := sentReportStat.Value(); got != reportCounter {
				t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
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
			if got := sentReportStat.Value(); got != reportCounter {
				t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
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
			if got := test.sentLeaveStat(s).Value(); got != leaveCounter {
				t.Fatalf("got sentLeaveStat(_).Value() = %d, want = %d", got, leaveCounter)
			}

			// Should not send any more packets.
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Fatalf("sent unexpected packet = %#v", p)
			}
		})
	}
}

func TestMGPWithNICLifecycle(t *testing.T) {
	tests := []struct {
		name                        string
		protoNum                    tcpip.NetworkProtocolNumber
		multicastAddrs              []tcpip.Address
		finalMulticastAddr          tcpip.Address
		maxUnsolicitedResponseDelay time.Duration
		sentReportStat              func(*stack.Stack) *tcpip.StatCounter
		sentLeaveStat               func(*stack.Stack) *tcpip.StatCounter
		validateReport              func(*testing.T, channel.PacketInfo, tcpip.Address)
		validateLeave               func(*testing.T, channel.PacketInfo, tcpip.Address)
		getAndCheckGroupAddress     func(*testing.T, map[tcpip.Address]bool, channel.PacketInfo) tcpip.Address
		checkInitialGroups          func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) (uint64, uint64)
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			multicastAddrs:              []tcpip.Address{ipv4MulticastAddr1, ipv4MulticastAddr2},
			finalMulticastAddr:          ipv4MulticastAddr3,
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.LeaveGroup
			},
			validateReport: func(t *testing.T, p channel.PacketInfo, addr tcpip.Address) {
				t.Helper()

				validateIGMPPacket(t, p, addr, igmpv2MembershipReport, 0, addr)
			},
			validateLeave: func(t *testing.T, p channel.PacketInfo, addr tcpip.Address) {
				t.Helper()

				validateIGMPPacket(t, p, header.IPv4AllRoutersGroup, igmpLeaveGroup, 0, addr)
			},
			getAndCheckGroupAddress: func(t *testing.T, seen map[tcpip.Address]bool, p channel.PacketInfo) tcpip.Address {
				t.Helper()

				ipv4 := header.IPv4(stack.PayloadSince(p.Pkt.NetworkHeader()))
				if got := tcpip.TransportProtocolNumber(ipv4.Protocol()); got != header.IGMPProtocolNumber {
					t.Fatalf("got ipv4.Protocol() = %d, want = %d", got, header.IGMPProtocolNumber)
				}
				addr := header.IGMP(ipv4.Payload()).GroupAddress()
				s, ok := seen[addr]
				if !ok {
					t.Fatalf("unexpectedly got a packet for group %s", addr)
				}
				if s {
					t.Fatalf("already saw packet for group %s", addr)
				}
				seen[addr] = true
				return addr
			},
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			multicastAddrs:              []tcpip.Address{ipv6MulticastAddr1, ipv6MulticastAddr2},
			finalMulticastAddr:          ipv6MulticastAddr3,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport
			},
			sentLeaveStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerDone
			},
			validateReport: func(t *testing.T, p channel.PacketInfo, addr tcpip.Address) {
				t.Helper()

				validateMLDPacket(t, p, addr, mldReport, 0, addr)
			},
			validateLeave: func(t *testing.T, p channel.PacketInfo, addr tcpip.Address) {
				t.Helper()

				validateMLDPacket(t, p, header.IPv6AllRoutersLinkLocalMulticastAddress, mldDone, 0, addr)
			},
			getAndCheckGroupAddress: func(t *testing.T, seen map[tcpip.Address]bool, p channel.PacketInfo) tcpip.Address {
				t.Helper()

				ipv6 := header.IPv6(stack.PayloadSince(p.Pkt.NetworkHeader()))

				ipv6HeaderIter := header.MakeIPv6PayloadIterator(
					header.IPv6ExtensionHeaderIdentifier(ipv6.NextHeader()),
					buffer.View(ipv6.Payload()).ToVectorisedView(),
				)

				var transport header.IPv6RawPayloadHeader
				for {
					h, done, err := ipv6HeaderIter.Next()
					if err != nil {
						t.Fatalf("ipv6HeaderIter.Next(): %s", err)
					}
					if done {
						t.Fatalf("ipv6HeaderIter.Next() = (%T, %t, _), want = (_, false, _)", h, done)
					}
					if t, ok := h.(header.IPv6RawPayloadHeader); ok {
						transport = t
						break
					}
				}

				if got := tcpip.TransportProtocolNumber(transport.Identifier); got != header.ICMPv6ProtocolNumber {
					t.Fatalf("got ipv6.NextHeader() = %d, want = %d", got, header.ICMPv6ProtocolNumber)
				}
				icmpv6 := header.ICMPv6(transport.Buf.ToView())
				if got := icmpv6.Type(); got != header.ICMPv6MulticastListenerReport && got != header.ICMPv6MulticastListenerDone {
					t.Fatalf("got icmpv6.Type() = %d, want = %d or %d", got, header.ICMPv6MulticastListenerReport, header.ICMPv6MulticastListenerDone)
				}
				addr := header.MLD(icmpv6.MessageBody()).MulticastAddress()
				s, ok := seen[addr]
				if !ok {
					t.Fatalf("unexpectedly got a packet for group %s", addr)
				}
				if s {
					t.Fatalf("already saw packet for group %s", addr)
				}
				seen[addr] = true
				return addr
			},
			checkInitialGroups: checkInitialIPv6Groups,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, clock := createStack(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)

			var reportCounter uint64
			var leaveCounter uint64
			if test.checkInitialGroups != nil {
				reportCounter, leaveCounter = test.checkInitialGroups(t, e, s, clock)
			}

			sentReportStat := test.sentReportStat(s)
			for _, a := range test.multicastAddrs {
				if err := s.JoinGroup(test.protoNum, nicID, a); err != nil {
					t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, a, err)
				}
				reportCounter++
				if got := sentReportStat.Value(); got != reportCounter {
					t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
				}
				if p, ok := e.Read(); !ok {
					t.Fatalf("expected a report message to be sent for %s", a)
				} else {
					test.validateReport(t, p, a)
				}
			}
			if t.Failed() {
				t.FailNow()
			}

			// Leave messages should be sent for the joined groups when the NIC is
			// disabled.
			if err := s.DisableNIC(nicID); err != nil {
				t.Fatalf("DisableNIC(%d): %s", nicID, err)
			}
			sentLeaveStat := test.sentLeaveStat(s)
			leaveCounter += uint64(len(test.multicastAddrs))
			if got := sentLeaveStat.Value(); got != leaveCounter {
				t.Errorf("got sentLeaveStat.Value() = %d, want = %d", got, leaveCounter)
			}
			{
				seen := make(map[tcpip.Address]bool)
				for _, a := range test.multicastAddrs {
					seen[a] = false
				}

				for i := range test.multicastAddrs {
					p, ok := e.Read()
					if !ok {
						t.Fatalf("expected (%d-th) leave message to be sent", i)
					}

					test.validateLeave(t, p, test.getAndCheckGroupAddress(t, seen, p))
				}
			}
			if t.Failed() {
				t.FailNow()
			}

			// Reports should be sent for the joined groups when the NIC is enabled.
			if err := s.EnableNIC(nicID); err != nil {
				t.Fatalf("EnableNIC(%d): %s", nicID, err)
			}
			reportCounter += uint64(len(test.multicastAddrs))
			if got := sentReportStat.Value(); got != reportCounter {
				t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
			}
			{
				seen := make(map[tcpip.Address]bool)
				for _, a := range test.multicastAddrs {
					seen[a] = false
				}

				for i := range test.multicastAddrs {
					p, ok := e.Read()
					if !ok {
						t.Fatalf("expected (%d-th) report message to be sent", i)
					}

					test.validateReport(t, p, test.getAndCheckGroupAddress(t, seen, p))
				}
			}
			if t.Failed() {
				t.FailNow()
			}

			// Joining/leaving a group while disabled should not send any messages.
			if err := s.DisableNIC(nicID); err != nil {
				t.Fatalf("DisableNIC(%d): %s", nicID, err)
			}
			leaveCounter += uint64(len(test.multicastAddrs))
			if got := sentLeaveStat.Value(); got != leaveCounter {
				t.Errorf("got sentLeaveStat.Value() = %d, want = %d", got, leaveCounter)
			}
			for i := range test.multicastAddrs {
				if _, ok := e.Read(); !ok {
					t.Fatalf("expected (%d-th) leave message to be sent", i)
				}
			}
			for _, a := range test.multicastAddrs {
				if err := s.LeaveGroup(test.protoNum, nicID, a); err != nil {
					t.Fatalf("LeaveGroup(%d, nic, %s): %s", test.protoNum, a, err)
				}
				if got := sentLeaveStat.Value(); got != leaveCounter {
					t.Errorf("got sentLeaveStat.Value() = %d, want = %d", got, leaveCounter)
				}
				if p, ok := e.Read(); ok {
					t.Fatalf("leaving group %s on disabled NIC sent unexpected packet = %#v", a, p.Pkt)
				}
			}
			if err := s.JoinGroup(test.protoNum, nicID, test.finalMulticastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.finalMulticastAddr, err)
			}
			if got := sentReportStat.Value(); got != reportCounter {
				t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
			}
			if p, ok := e.Read(); ok {
				t.Fatalf("joining group %s on disabled NIC sent unexpected packet = %#v", test.finalMulticastAddr, p.Pkt)
			}

			// A report should only be sent for the group we last joined after
			// enabling the NIC since the original groups were all left.
			if err := s.EnableNIC(nicID); err != nil {
				t.Fatalf("EnableNIC(%d): %s", nicID, err)
			}
			reportCounter++
			if got := sentReportStat.Value(); got != reportCounter {
				t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
			}
			if p, ok := e.Read(); !ok {
				t.Fatal("expected a report message to be sent")
			} else {
				test.validateReport(t, p, test.finalMulticastAddr)
			}

			clock.Advance(test.maxUnsolicitedResponseDelay)
			reportCounter++
			if got := sentReportStat.Value(); got != reportCounter {
				t.Errorf("got sentReportStat.Value() = %d, want = %d", got, reportCounter)
			}
			if p, ok := e.Read(); !ok {
				t.Fatal("expected a report message to be sent")
			} else {
				test.validateReport(t, p, test.finalMulticastAddr)
			}

			// Should not send any more packets.
			clock.Advance(time.Hour)
			if p, ok := e.Read(); ok {
				t.Fatalf("sent unexpected packet = %#v", p)
			}
		})
	}
}

// TestMGPDisabledOnLoopback tests that the multicast group protocol is not
// performed on loopback interfaces since they have no neighbours.
func TestMGPDisabledOnLoopback(t *testing.T) {
	tests := []struct {
		name           string
		protoNum       tcpip.NetworkProtocolNumber
		multicastAddr  tcpip.Address
		sentReportStat func(*stack.Stack) *tcpip.StatCounter
	}{
		{
			name:          "IGMP",
			protoNum:      ipv4.ProtocolNumber,
			multicastAddr: ipv4MulticastAddr1,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsSent.V2MembershipReport
			},
		},
		{
			name:          "MLD",
			protoNum:      ipv6.ProtocolNumber,
			multicastAddr: ipv6MulticastAddr1,
			sentReportStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, clock := createStackWithLinkEndpoint(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */, loopback.New())

			sentReportStat := test.sentReportStat(s)
			if got := sentReportStat.Value(); got != 0 {
				t.Fatalf("got sentReportStat.Value() = %d, want = 0", got)
			}
			clock.Advance(time.Hour)
			if got := sentReportStat.Value(); got != 0 {
				t.Fatalf("got sentReportStat.Value() = %d, want = 0", got)
			}

			// Test joining a specific group explicitly and verify that no reports are
			// sent.
			if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
				t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
			}
			if got := sentReportStat.Value(); got != 0 {
				t.Fatalf("got sentReportStat.Value() = %d, want = 0", got)
			}
			clock.Advance(time.Hour)
			if got := sentReportStat.Value(); got != 0 {
				t.Fatalf("got sentReportStat.Value() = %d, want = 0", got)
			}
		})
	}
}
