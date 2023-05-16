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

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	iptestutil "gvisor.dev/gvisor/pkg/tcpip/network/internal/testutil"
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
func validateMLDPacket(t *testing.T, p stack.PacketBufferPtr, remoteAddress tcpip.Address, mldType uint8, maxRespTime byte, groupAddress tcpip.Address) {
	t.Helper()

	payload := stack.PayloadSince(p.NetworkHeader())
	defer payload.Release()
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

func validateMLDv2ReportPacket(t *testing.T, p stack.PacketBufferPtr, addrs []tcpip.Address, recordType header.MLDv2ReportRecordType) {
	t.Helper()
	payload := stack.PayloadSince(p.NetworkHeader())
	defer payload.Release()
	iptestutil.ValidateMLDv2Report(t, payload, linkLocalIPv6Addr1, addrs, recordType)
}

// validateIGMPPacket checks that a passed PacketInfo is an IPv4 IGMP packet
// sent to the provided address with the passed fields set.
func validateIGMPPacket(t *testing.T, p stack.PacketBufferPtr, remoteAddress tcpip.Address, igmpType uint8, maxRespTime byte, groupAddress tcpip.Address) {
	t.Helper()

	payload := stack.PayloadSince(p.NetworkHeader())
	defer payload.Release()
	checker.IPv4(t, payload,
		checker.SrcAddr(stackIPv4Addr),
		checker.DstAddr(remoteAddress),
		// TTL for an IGMP message must be 1 as per RFC 2236 section 2.
		checker.TTL(1),
		checker.IPv4RouterAlert(),
		checker.IGMP(
			checker.IGMPType(header.IGMPType(igmpType)),
			checker.IGMPMaxRespTime(header.DecisecondToDuration(uint16(maxRespTime))),
			checker.IGMPGroupAddress(groupAddress),
		),
	)
}

func validateIGMPv3ReportPacket(t *testing.T, p stack.PacketBufferPtr, addrs []tcpip.Address, recordType header.IGMPv3ReportRecordType) {
	t.Helper()

	payload := stack.PayloadSince(p.NetworkHeader())
	defer payload.Release()
	iptestutil.ValidateIGMPv3Report(t, payload, stackIPv4Addr, addrs, recordType)
}

type multicastTestContext struct {
	s     *stack.Stack
	e     *channel.Endpoint
	clock *faketime.ManualClock
}

func newMulticastTestContext(t *testing.T, v4, mgpEnabled bool) multicastTestContext {
	t.Helper()

	e := channel.New(maxUnsolicitedReports, header.IPv6MinimumMTU, linkAddr)
	s, clock := createStackWithLinkEndpoint(t, v4, mgpEnabled, e)
	return multicastTestContext{
		s:     s,
		e:     e,
		clock: clock,
	}
}

func (ctx *multicastTestContext) cleanup() {
	ctx.s.Close()
	ctx.s.Wait()
	ctx.e.Close()
	refs.DoRepeatedLeakCheck()
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
	addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   stackIPv4Addr,
			PrefixLen: defaultIPv4PrefixLength,
		},
	}
	if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, addr, err)
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: linkLocalIPv6Addr1.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
	}

	return s, clock
}

// checkInitialIPv6Groups checks the initial IPv6 groups that a NIC will join
// when it is created with an IPv6 address.
//
// To not interfere with tests, checkInitialIPv6Groups will leave the added
// address's solicited node multicast group so that the tests can all assume
// the NIC has not joined any IPv6 groups.
func checkInitialIPv6Groups(t *testing.T, e *channel.Endpoint, s *stack.Stack, clock *faketime.ManualClock) uint64 {
	t.Helper()

	var reportCounter uint64

	reportCounter++
	iptestutil.CheckMLDv2Stats(t, s, 0, 0, reportCounter)
	if p := e.Read(); p.IsNil() {
		t.Fatal("expected a report message to be sent")
	} else {
		v := stack.PayloadSince(p.NetworkHeader())
		iptestutil.ValidateMLDv2Report(t, v, linkLocalIPv6Addr1, []tcpip.Address{ipv6AddrSNMC}, header.MLDv2ReportRecordChangeToExcludeMode)
		v.Release()
		p.DecRef()
	}

	// Leave the group to not affect the tests. This is fine since we are not
	// testing DAD or the solicited node address specifically.
	if err := s.LeaveGroup(ipv6.ProtocolNumber, nicID, ipv6AddrSNMC); err != nil {
		t.Fatalf("LeaveGroup(%d, %d, %s): %s", ipv6.ProtocolNumber, nicID, ipv6AddrSNMC, err)
	}
	for i := 0; i < 2; i++ {
		reportCounter++
		iptestutil.CheckMLDv2Stats(t, s, 0, 0, reportCounter)
		if p := e.Read(); p.IsNil() {
			t.Fatal("expected a report message to be sent")
		} else {
			v := stack.PayloadSince(p.NetworkHeader())
			iptestutil.ValidateMLDv2Report(t, v, linkLocalIPv6Addr1, []tcpip.Address{ipv6AddrSNMC}, header.MLDv2ReportRecordChangeToIncludeMode)
			v.Release()
			p.DecRef()
		}

		clock.Advance(ipv6.UnsolicitedReportIntervalMax)
	}

	// Should not send any more packets.
	clock.Advance(time.Hour)
	if p := e.Read(); !p.IsNil() {
		t.Fatalf("sent unexpected packet = %#v", p)
	}

	return reportCounter
}

// createAndInjectIGMPPacket creates and injects an IGMP packet with the
// specified fields.
func createAndInjectIGMPPacket(e *channel.Endpoint, igmpType byte, maxRespTime byte, groupAddress tcpip.Address, extraLength int) {
	options := header.IPv4OptionsSerializer{
		&header.IPv4SerializableRouterAlertOption{},
	}
	buf := make([]byte, header.IPv4MinimumSize+int(options.Length())+header.IGMPQueryMinimumSize+extraLength)
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

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(buf),
	})
	e.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

// createAndInjectMLDPacket creates and injects an MLD packet with the
// specified fields.
func createAndInjectMLDPacket(e *channel.Endpoint, mldType uint8, maxRespDelay byte, groupAddress tcpip.Address, extraLength int) {
	extensionHeaders := header.IPv6ExtHdrSerializer{
		header.IPv6SerializableHopByHopExtHdr{
			&header.IPv6RouterAlertOption{Value: header.IPv6RouterAlertMLD},
		},
	}

	extensionHeadersLength := extensionHeaders.Length()
	payloadLength := extensionHeadersLength + header.ICMPv6HeaderSize + header.MLDMinimumSize + extraLength
	buf := make([]byte, header.IPv6MinimumSize+payloadLength)

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

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(buf),
	})
	e.InjectInbound(ipv6.ProtocolNumber, pkt)
	pkt.DecRef()
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
				createAndInjectIGMPPacket(e, igmpMembershipQuery, unsolicitedIGMPReportIntervalMaxTenthSec, header.IPv4Any, 0 /* extraLength */)
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
				createAndInjectMLDPacket(e, mldQuery, 0, header.IPv6Any, 0 /* extraLength */)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newMulticastTestContext(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, false /* mgpEnabled */)
			defer ctx.cleanup()
			s := ctx.s
			e := ctx.e
			clock := ctx.clock

			// This NIC may join multicast groups when it is enabled but since MGP is
			// disabled, no reports should be sent.
			sentReportStat := test.sentReportStat(s)
			if got := sentReportStat.Value(); got != 0 {
				t.Fatalf("got sentReportStat.Value() = %d, want = 0", got)
			}
			clock.Advance(time.Hour)
			if p := e.Read(); !p.IsNil() {
				t.Fatalf("sent unexpected packet, stack with disabled MGP sent packet = %#v", p)
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
			if p := e.Read(); !p.IsNil() {
				t.Fatalf("sent unexpected packet, stack with disabled IGMP sent packet = %#v", p)
			}

			// Inject a general query message. This should only trigger a report to be
			// sent if the MGP was enabled.
			test.rxQuery(e)
			if got := test.receivedQueryStat(s).Value(); got != 1 {
				t.Fatalf("got receivedQueryStat(_).Value() = %d, want = 1", got)
			}
			clock.Advance(time.Hour)
			if p := e.Read(); !p.IsNil() {
				t.Fatalf("sent unexpected packet, stack with disabled IGMP sent packet = %+v", p)
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
		rxMGPkt      func(*channel.Endpoint, byte, byte, tcpip.Address, int)
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
			ctx := newMulticastTestContext(t, test.groupAddress.Len() == header.IPv4AddressSize /* v4 */, true /* mgpEnabled */)
			defer ctx.cleanup()

			test.rxMGPkt(ctx.e, test.headerType, test.maxRespTime, test.groupAddress, 0 /* extraLength */)
			if got := test.statCounter(ctx.s).Value(); got != 1 {
				t.Fatalf("got %s received = %d, want = 1", test.name, got)
			}
		})
	}
}

// TestMGPJoinGroup tests that when explicitly joining a multicast group, the
// stack schedules and sends correct Membership Reports.
func TestMGPJoinGroup(t *testing.T) {
	type subTest struct {
		name           string
		enterVersion   func(e *channel.Endpoint)
		validateReport func(*testing.T, stack.PacketBufferPtr)
		checkStats     func(*testing.T, *stack.Stack, uint64, uint64, uint64)
	}

	tests := []struct {
		name                        string
		protoNum                    tcpip.NetworkProtocolNumber
		multicastAddr               tcpip.Address
		maxUnsolicitedResponseDelay time.Duration
		receivedQueryStat           func(*stack.Stack) *tcpip.StatCounter
		checkInitialGroups          func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) uint64
		subTests                    []subTest
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			multicastAddr:               ipv4MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.MembershipQuery
			},
			subTests: []subTest{
				{
					name: "V2",
					enterVersion: func(e *channel.Endpoint) {
						// V2 query for unrelated group.
						createAndInjectIGMPPacket(e, igmpMembershipQuery, 1, ipv4MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPPacket(t, p, ipv4MulticastAddr1, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
					},
					checkStats: iptestutil.CheckIGMPv2Stats,
				},
				{
					name:         "V3",
					enterVersion: func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPv3ReportPacket(t, p, []tcpip.Address{ipv4MulticastAddr1}, header.IGMPv3ReportRecordChangeToExcludeMode)
					},
					checkStats: iptestutil.CheckIGMPv3Stats,
				},
			},
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			multicastAddr:               ipv6MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerQuery
			},
			checkInitialGroups: checkInitialIPv6Groups,
			subTests: []subTest{
				{
					name: "V1",
					enterVersion: func(e *channel.Endpoint) {
						// V1 query for unrelated group.
						createAndInjectMLDPacket(e, mldQuery, 0, ipv6MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDPacket(t, p, ipv6MulticastAddr1, mldReport, 0, ipv6MulticastAddr1)
					},
					checkStats: iptestutil.CheckMLDv1Stats,
				},
				{
					name:         "V2",
					enterVersion: func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDv2ReportPacket(t, p, []tcpip.Address{ipv6MulticastAddr1}, header.MLDv2ReportRecordChangeToExcludeMode)
					},
					checkStats: iptestutil.CheckMLDv2Stats,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range test.subTests {
				t.Run(subTest.name, func(t *testing.T) {
					ctx := newMulticastTestContext(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)
					defer ctx.cleanup()
					s, e, clock := ctx.s, ctx.e, ctx.clock

					var reportCounter uint64
					var leaveCounter uint64
					var reportV2Counter uint64
					if test.checkInitialGroups != nil {
						reportV2Counter = test.checkInitialGroups(t, e, s, clock)
					}

					subTest.enterVersion(e)

					// Test joining a specific address explicitly and verify a Report is sent
					// immediately.
					if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
						t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
					}
					reportCounter++
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					if p := e.Read(); p.IsNil() {
						t.Fatal("expected a report message to be sent")
					} else {
						subTest.validateReport(t, p)
						p.DecRef()
					}
					if t.Failed() {
						t.FailNow()
					}

					// Verify the second report is sent by the maximum unsolicited response
					// interval.
					p := e.Read()
					if !p.IsNil() {
						t.Fatalf("sent unexpected packet, expected report only after advancing the clock = %#v", p)
					}
					clock.Advance(test.maxUnsolicitedResponseDelay)
					reportCounter++
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					if p := e.Read(); p.IsNil() {
						t.Fatal("expected a report message to be sent")
					} else {
						subTest.validateReport(t, p)
						p.DecRef()
					}

					// Should not send any more packets.
					clock.Advance(time.Hour)
					if p := e.Read(); !p.IsNil() {
						t.Fatalf("sent unexpected packet = %#v", p)
					}
				})
			}
		})
	}
}

// TestMGPLeaveGroup tests that when leaving a previously joined multicast
// group the stack sends a leave/done message.
func TestMGPLeaveGroup(t *testing.T) {
	type subTest struct {
		name           string
		enterVersion   func(e *channel.Endpoint)
		validateReport func(*testing.T, stack.PacketBufferPtr)
		validateLeave  func(*testing.T, stack.PacketBufferPtr)
		leaveCount     uint8
		checkStats     func(*testing.T, *stack.Stack, uint64, uint64, uint64)
	}

	tests := []struct {
		name                        string
		protoNum                    tcpip.NetworkProtocolNumber
		multicastAddr               tcpip.Address
		maxUnsolicitedResponseDelay time.Duration
		checkInitialGroups          func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) uint64
		subTests                    []subTest
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			multicastAddr:               ipv4MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			subTests: []subTest{
				{
					name: "V2",
					enterVersion: func(e *channel.Endpoint) {
						// V2 query for unrelated group.
						createAndInjectIGMPPacket(e, igmpMembershipQuery, 1, ipv4MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPPacket(t, p, ipv4MulticastAddr1, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
					},
					validateLeave: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPPacket(t, p, header.IPv4AllRoutersGroup, igmpLeaveGroup, 0, ipv4MulticastAddr1)
					},
					leaveCount: 1,
					checkStats: iptestutil.CheckIGMPv2Stats,
				},
				{
					name:         "V3",
					enterVersion: func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPv3ReportPacket(t, p, []tcpip.Address{ipv4MulticastAddr1}, header.IGMPv3ReportRecordChangeToExcludeMode)
					},
					validateLeave: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPv3ReportPacket(t, p, []tcpip.Address{ipv4MulticastAddr1}, header.IGMPv3ReportRecordChangeToIncludeMode)
					},
					leaveCount: 2,
					checkStats: iptestutil.CheckIGMPv3Stats,
				},
			},
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			multicastAddr:               ipv6MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			checkInitialGroups:          checkInitialIPv6Groups,
			subTests: []subTest{
				{
					name: "V1",
					enterVersion: func(e *channel.Endpoint) {
						// V1 query for unrelated group.
						createAndInjectMLDPacket(e, mldQuery, 0, ipv6MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDPacket(t, p, ipv6MulticastAddr1, mldReport, 0, ipv6MulticastAddr1)
					},
					validateLeave: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDPacket(t, p, header.IPv6AllRoutersLinkLocalMulticastAddress, mldDone, 0, ipv6MulticastAddr1)
					},
					leaveCount: 1,
					checkStats: iptestutil.CheckMLDv1Stats,
				},
				{
					name:         "V2",
					enterVersion: func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDv2ReportPacket(t, p, []tcpip.Address{ipv6MulticastAddr1}, header.MLDv2ReportRecordChangeToExcludeMode)
					},
					validateLeave: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDv2ReportPacket(t, p, []tcpip.Address{ipv6MulticastAddr1}, header.MLDv2ReportRecordChangeToIncludeMode)
					},
					leaveCount: 2,
					checkStats: iptestutil.CheckMLDv2Stats,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range test.subTests {
				t.Run(subTest.name, func(t *testing.T) {
					ctx := newMulticastTestContext(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)
					defer ctx.cleanup()
					s, e, clock := ctx.s, ctx.e, ctx.clock

					var reportCounter uint64
					var leaveCounter uint64
					var reportV2Counter uint64
					if test.checkInitialGroups != nil {
						reportV2Counter = test.checkInitialGroups(t, e, s, clock)
					}

					subTest.enterVersion(e)

					if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
						t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
					}
					reportCounter++
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					if p := e.Read(); p.IsNil() {
						t.Fatal("expected a report message to be sent")
					} else {
						subTest.validateReport(t, p)
						p.DecRef()
					}
					if t.Failed() {
						t.FailNow()
					}

					// Leaving the group should trigger an leave/done message to be sent.
					if err := s.LeaveGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
						t.Fatalf("LeaveGroup(%d, nic, %s): %s", test.protoNum, test.multicastAddr, err)
					}
					for i := subTest.leaveCount; i > 0; i-- {
						leaveCounter++
						subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
						if p := e.Read(); p.IsNil() {
							t.Fatal("expected a leave message to be sent")
						} else {
							subTest.validateLeave(t, p)
							p.DecRef()
						}
						clock.Advance(test.maxUnsolicitedResponseDelay)
					}

					// Should not send any more packets.
					clock.Advance(time.Hour)
					if p := e.Read(); !p.IsNil() {
						t.Fatalf("sent unexpected packet = %#v", p)
					}
				})
			}
		})
	}
}

// TestMGPQueryMessages tests that a report is sent in response to query
// messages.
func TestMGPQueryMessages(t *testing.T) {
	type subTest struct {
		name           string
		enterVersion   func(e *channel.Endpoint)
		validateReport func(*testing.T, stack.PacketBufferPtr, bool)
		checkStats     func(*testing.T, *stack.Stack, uint64, uint64, uint64)
		rxQuery        func(*channel.Endpoint, uint8, tcpip.Address)
	}

	tests := []struct {
		name                        string
		protoNum                    tcpip.NetworkProtocolNumber
		multicastAddr               tcpip.Address
		maxUnsolicitedResponseDelay time.Duration
		receivedQueryStat           func(*stack.Stack) *tcpip.StatCounter
		maxRespTimeToDuration       func(uint16) time.Duration
		checkInitialGroups          func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) uint64
		subTests                    []subTest
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			multicastAddr:               ipv4MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.MembershipQuery
			},
			maxRespTimeToDuration: header.DecisecondToDuration,
			subTests: []subTest{
				{
					name: "V2",
					enterVersion: func(e *channel.Endpoint) {
						// V2 query for unrelated group.
						createAndInjectIGMPPacket(e, igmpMembershipQuery, 1, ipv4MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr, _ bool) {
						t.Helper()

						validateIGMPPacket(t, p, ipv4MulticastAddr1, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
					},
					rxQuery: func(e *channel.Endpoint, maxRespTime uint8, groupAddress tcpip.Address) {
						createAndInjectIGMPPacket(e, igmpMembershipQuery, maxRespTime, groupAddress, 0 /* extraLength */)
					},
					checkStats: iptestutil.CheckIGMPv2Stats,
				},
				{
					name:         "V3",
					enterVersion: func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr, queryResponse bool) {
						t.Helper()

						recordType := header.IGMPv3ReportRecordChangeToExcludeMode
						if queryResponse {
							recordType = header.IGMPv3ReportRecordModeIsExclude
						}

						validateIGMPv3ReportPacket(t, p, []tcpip.Address{ipv4MulticastAddr1}, recordType)
					},
					rxQuery: func(e *channel.Endpoint, maxRespTime uint8, groupAddress tcpip.Address) {
						createAndInjectIGMPPacket(e, igmpMembershipQuery, maxRespTime, groupAddress, header.IGMPv3QueryMinimumSize-header.IGMPQueryMinimumSize /* extraLength */)
					},
					checkStats: iptestutil.CheckIGMPv3Stats,
				},
			},
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			multicastAddr:               ipv6MulticastAddr1,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerQuery
			},
			maxRespTimeToDuration: func(d uint16) time.Duration {
				return time.Duration(d) * time.Millisecond
			},
			checkInitialGroups: checkInitialIPv6Groups,
			subTests: []subTest{
				{
					name: "V1",
					enterVersion: func(e *channel.Endpoint) {
						// V1 query for unrelated group.
						createAndInjectMLDPacket(e, mldQuery, 0, ipv6MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr, _ bool) {
						t.Helper()

						validateMLDPacket(t, p, ipv6MulticastAddr1, mldReport, 0, ipv6MulticastAddr1)
					},
					rxQuery: func(e *channel.Endpoint, maxRespTime uint8, groupAddress tcpip.Address) {
						createAndInjectMLDPacket(e, mldQuery, maxRespTime, groupAddress, 0 /* extraLength */)
					},
					checkStats: iptestutil.CheckMLDv1Stats,
				},
				{
					name:         "V2",
					enterVersion: func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr, queryResponse bool) {
						t.Helper()

						recordType := header.MLDv2ReportRecordChangeToExcludeMode
						if queryResponse {
							recordType = header.MLDv2ReportRecordModeIsExclude
						}

						validateMLDv2ReportPacket(t, p, []tcpip.Address{ipv6MulticastAddr1}, recordType)
					},
					rxQuery: func(e *channel.Endpoint, maxRespTime uint8, groupAddress tcpip.Address) {
						createAndInjectMLDPacket(e, mldQuery, maxRespTime, groupAddress, header.MLDv2QueryMinimumSize-header.MLDMinimumSize /* extraLength */)
					},
					checkStats: iptestutil.CheckMLDv2Stats,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addrTests := []struct {
				name          string
				multicastAddr tcpip.Address
				expectReport  bool
			}{
				{
					name:          "Unspecified",
					multicastAddr: tcpip.AddrFromSlice([]byte(strings.Repeat("\x00", test.multicastAddr.Len()))),
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
						addrBytes := test.multicastAddr.AsSlice()
						addrBytes[len(addrBytes)-1]++
						return tcpip.AddrFromSlice(addrBytes)
					}(),
					expectReport: false,
				},
			}

			for _, addrTest := range addrTests {
				t.Run(addrTest.name, func(t *testing.T) {
					for _, subTest := range test.subTests {
						t.Run(subTest.name, func(t *testing.T) {
							ctx := newMulticastTestContext(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)
							defer ctx.cleanup()
							s, e, clock := ctx.s, ctx.e, ctx.clock

							var reportCounter uint64
							var leaveCounter uint64
							var reportV2Counter uint64
							if test.checkInitialGroups != nil {
								reportV2Counter = test.checkInitialGroups(t, e, s, clock)
							}

							subTest.enterVersion(e)

							if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
								t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
							}
							for i := 0; i < maxUnsolicitedReports; i++ {
								reportCounter++
								subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
								if p := e.Read(); p.IsNil() {
									t.Fatalf("expected %d-th report message to be sent", i)
								} else {
									subTest.validateReport(t, p, false /* queryResponse */)
									p.DecRef()
								}
								clock.Advance(test.maxUnsolicitedResponseDelay)
							}
							if t.Failed() {
								t.FailNow()
							}

							// Should not send any more packets until a query.
							clock.Advance(time.Hour)
							if p := e.Read(); !p.IsNil() {
								t.Fatalf("sent unexpected packet = %#v", p)
							}

							// Receive a query message which should trigger a report to be sent at
							// some time before the maximum response time if the report is
							// targeted at the host.
							const maxRespTime = 100
							subTest.rxQuery(e, maxRespTime, addrTest.multicastAddr)
							if p := e.Read(); !p.IsNil() {
								t.Fatalf("sent unexpected packet = %#v", p)
							}

							if addrTest.expectReport {
								clock.Advance(test.maxRespTimeToDuration(maxRespTime))
								reportCounter++
								subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
								if p := e.Read(); p.IsNil() {
									t.Fatal("expected a report message to be sent")
								} else {
									subTest.validateReport(t, p, true /* queryResponse */)
									p.DecRef()
								}
							}

							// Should not send any more packets.
							clock.Advance(time.Hour)
							if p := e.Read(); !p.IsNil() {
								t.Fatalf("sent unexpected packet = %#v", p)
							}
						})
					}
				})
			}
		})
	}
}

// TestMGPQueryMessages tests that no further reports or leave/done messages
// are sent after receiving a report.
func TestMGPReportMessages(t *testing.T) {
	type subTest struct {
		name           string
		enterVersion   func(e *channel.Endpoint)
		validateReport func(*testing.T, stack.PacketBufferPtr)
		validateLeave  func(*testing.T, stack.PacketBufferPtr)
		leaveCount     uint8
		checkStats     func(*testing.T, *stack.Stack, uint64, uint64, uint64)
	}

	tests := []struct {
		name                        string
		protoNum                    tcpip.NetworkProtocolNumber
		multicastAddr               tcpip.Address
		maxUnsolicitedResponseDelay time.Duration
		rxReport                    func(*channel.Endpoint)
		checkInitialGroups          func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) uint64
		subTests                    []subTest
	}{
		{
			name:          "IGMP",
			protoNum:      ipv4.ProtocolNumber,
			multicastAddr: ipv4MulticastAddr1,
			rxReport: func(e *channel.Endpoint) {
				createAndInjectIGMPPacket(e, igmpv2MembershipReport, 0, ipv4MulticastAddr1, 0 /* extraLength */)
			},
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			subTests: []subTest{
				{
					name: "V2",
					enterVersion: func(e *channel.Endpoint) {
						// V2 query for unrelated group.
						createAndInjectIGMPPacket(e, igmpMembershipQuery, 1, ipv4MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPPacket(t, p, ipv4MulticastAddr1, igmpv2MembershipReport, 0, ipv4MulticastAddr1)
					},
					leaveCount: 0,
					checkStats: iptestutil.CheckIGMPv2Stats,
				},
				{
					name:         "V3",
					enterVersion: func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPv3ReportPacket(t, p, []tcpip.Address{ipv4MulticastAddr1}, header.IGMPv3ReportRecordChangeToExcludeMode)
					},
					validateLeave: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateIGMPv3ReportPacket(t, p, []tcpip.Address{ipv4MulticastAddr1}, header.IGMPv3ReportRecordChangeToIncludeMode)
					},
					leaveCount: 2,
					checkStats: iptestutil.CheckIGMPv3Stats,
				},
			},
		},
		{
			name:          "MLD",
			protoNum:      ipv6.ProtocolNumber,
			multicastAddr: ipv6MulticastAddr1,
			rxReport: func(e *channel.Endpoint) {
				createAndInjectMLDPacket(e, mldReport, 0, ipv6MulticastAddr1, 0 /* extraLength */)
			},
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			checkInitialGroups:          checkInitialIPv6Groups,
			subTests: []subTest{
				{
					name: "V1",
					enterVersion: func(e *channel.Endpoint) {
						// V1 query for unrelated group.
						createAndInjectMLDPacket(e, mldQuery, 0, ipv6MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDPacket(t, p, ipv6MulticastAddr1, mldReport, 0, ipv6MulticastAddr1)
					},
					leaveCount: 0,
					checkStats: iptestutil.CheckMLDv1Stats,
				},
				{
					name:         "V2",
					enterVersion: func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDv2ReportPacket(t, p, []tcpip.Address{ipv6MulticastAddr1}, header.MLDv2ReportRecordChangeToExcludeMode)
					},
					validateLeave: func(t *testing.T, p stack.PacketBufferPtr) {
						t.Helper()

						validateMLDv2ReportPacket(t, p, []tcpip.Address{ipv6MulticastAddr1}, header.MLDv2ReportRecordChangeToIncludeMode)
					},
					leaveCount: 2,
					checkStats: iptestutil.CheckMLDv2Stats,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range test.subTests {
				t.Run(subTest.name, func(t *testing.T) {
					ctx := newMulticastTestContext(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)
					defer ctx.cleanup()
					s, e, clock := ctx.s, ctx.e, ctx.clock

					var reportCounter uint64
					var leaveCounter uint64
					var reportV2Counter uint64
					if test.checkInitialGroups != nil {
						reportV2Counter = test.checkInitialGroups(t, e, s, clock)
					}

					subTest.enterVersion(e)

					if err := s.JoinGroup(test.protoNum, nicID, test.multicastAddr); err != nil {
						t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.multicastAddr, err)
					}
					reportCounter++
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					if p := e.Read(); p.IsNil() {
						t.Fatal("expected a report message to be sent")
					} else {
						subTest.validateReport(t, p)
						p.DecRef()
					}
					if t.Failed() {
						t.FailNow()
					}

					// Receiving a report for a group we joined should cancel any further
					// reports.
					test.rxReport(e)
					clock.Advance(time.Hour)
					subTest.enterVersion(e)
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					if p := e.Read(); !p.IsNil() {
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
					for i := subTest.leaveCount; i > 0; i-- {
						leaveCounter++
						subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
						if p := e.Read(); p.IsNil() {
							t.Fatal("expected a leave message to be sent")
						} else {
							subTest.validateLeave(t, p)
							p.DecRef()
						}
						clock.Advance(test.maxUnsolicitedResponseDelay)
					}

					// Should not send any more packets.
					clock.Advance(time.Hour)
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					if p := e.Read(); !p.IsNil() {
						t.Fatalf("sent unexpected packet = %#v", p)
					}
				})
			}
		})
	}
}

func TestMGPWithNICLifecycle(t *testing.T) {
	type subTest struct {
		name            string
		v1Compatibility bool
		enterVersion    func(e *channel.Endpoint)
		validateReport  func(*testing.T, stack.PacketBufferPtr, tcpip.Address)
		validateLeave   func(*testing.T, *channel.Endpoint, []tcpip.Address)
		checkStats      func(*testing.T, *stack.Stack, uint64, uint64, uint64)
	}

	tests := []struct {
		name                        string
		protoNum                    tcpip.NetworkProtocolNumber
		multicastAddrs              []tcpip.Address
		finalMulticastAddr          tcpip.Address
		maxUnsolicitedResponseDelay time.Duration
		sentReportStat              func(*stack.Stack) *tcpip.StatCounter
		sentLeaveStat               func(*stack.Stack) *tcpip.StatCounter
		validateReport              func(*testing.T, *channel.Endpoint, []tcpip.Address)
		validateLeave               func(*testing.T, stack.PacketBufferPtr, tcpip.Address)
		checkInitialGroups          func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) uint64
		checkStats                  func(*testing.T, *stack.Stack, uint64, uint64, uint64)
		subTests                    []subTest
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
			validateReport: func(t *testing.T, e *channel.Endpoint, addrs []tcpip.Address) {
				t.Helper()
				iptestutil.ValidateIGMPv3RecordsAcrossReports(t, e, stackIPv4Addr, addrs, header.IGMPv3ReportRecordChangeToExcludeMode)
			},
			validateLeave: func(t *testing.T, p stack.PacketBufferPtr, addr tcpip.Address) {
				t.Helper()

				validateIGMPv3ReportPacket(t, p, []tcpip.Address{addr}, header.IGMPv3ReportRecordChangeToIncludeMode)
			},
			checkStats: iptestutil.CheckIGMPv3Stats,
			subTests: []subTest{
				{
					name:            "V2",
					v1Compatibility: true,
					enterVersion: func(e *channel.Endpoint) {
						// V2 query for unrelated group.
						createAndInjectIGMPPacket(e, igmpMembershipQuery, 1, ipv4MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr, addr tcpip.Address) {
						t.Helper()

						validateIGMPPacket(t, p, addr, igmpv2MembershipReport, 0, addr)
					},
					validateLeave: func(t *testing.T, e *channel.Endpoint, addrs []tcpip.Address) {
						t.Helper()
						iptestutil.ValidMultipleIGMPv2ReportLeaves(t, e, stackIPv4Addr, addrs, true /* leave */)
					},
					checkStats: iptestutil.CheckIGMPv2Stats,
				},
				{
					name:            "V3",
					v1Compatibility: false,
					enterVersion:    func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr, addr tcpip.Address) {
						t.Helper()

						validateIGMPv3ReportPacket(t, p, []tcpip.Address{addr}, header.IGMPv3ReportRecordChangeToExcludeMode)
					},
					validateLeave: func(t *testing.T, e *channel.Endpoint, addrs []tcpip.Address) {
						t.Helper()
						iptestutil.ValidateIGMPv3RecordsAcrossReports(t, e, stackIPv4Addr, addrs, header.IGMPv3ReportRecordChangeToIncludeMode)
					},
					checkStats: iptestutil.CheckIGMPv3Stats,
				},
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
			validateReport: func(t *testing.T, e *channel.Endpoint, addrs []tcpip.Address) {
				t.Helper()

				iptestutil.ValidateMLDv2RecordsAcrossReports(t, e, linkLocalIPv6Addr1, addrs, header.MLDv2ReportRecordChangeToExcludeMode)
			},
			validateLeave: func(t *testing.T, p stack.PacketBufferPtr, addr tcpip.Address) {
				t.Helper()

				validateMLDv2ReportPacket(t, p, []tcpip.Address{addr}, header.MLDv2ReportRecordChangeToIncludeMode)
			},
			checkInitialGroups: checkInitialIPv6Groups,
			checkStats:         iptestutil.CheckMLDv2Stats,
			subTests: []subTest{
				{
					name:            "V1",
					v1Compatibility: true,
					enterVersion: func(e *channel.Endpoint) {
						// V1 query for unrelated group.
						createAndInjectMLDPacket(e, mldQuery, 0, ipv6MulticastAddr3, 0 /* extraLength */)
					},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr, addr tcpip.Address) {
						t.Helper()

						validateMLDPacket(t, p, addr, mldReport, 0, addr)
					},
					validateLeave: func(t *testing.T, e *channel.Endpoint, addrs []tcpip.Address) {
						t.Helper()

						iptestutil.ValidMultipleMLDv1ReportLeaves(t, e, linkLocalIPv6Addr1, addrs, true /* leave */)
					},
					checkStats: iptestutil.CheckMLDv1Stats,
				},
				{
					name:            "V2",
					v1Compatibility: false,
					enterVersion:    func(*channel.Endpoint) {},
					validateReport: func(t *testing.T, p stack.PacketBufferPtr, addr tcpip.Address) {
						t.Helper()

						validateMLDv2ReportPacket(t, p, []tcpip.Address{addr}, header.MLDv2ReportRecordChangeToExcludeMode)
					},
					validateLeave: func(t *testing.T, e *channel.Endpoint, addrs []tcpip.Address) {
						t.Helper()

						iptestutil.ValidateMLDv2RecordsAcrossReports(t, e, linkLocalIPv6Addr1, addrs, header.MLDv2ReportRecordChangeToIncludeMode)
					},
					checkStats: iptestutil.CheckMLDv2Stats,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range test.subTests {
				t.Run(subTest.name, func(t *testing.T) {
					ctx := newMulticastTestContext(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)
					defer ctx.cleanup()
					s, e, clock := ctx.s, ctx.e, ctx.clock

					var reportCounter uint64
					var leaveCounter uint64
					var reportV2Counter uint64
					if test.checkInitialGroups != nil {
						reportV2Counter = test.checkInitialGroups(t, e, s, clock)
					}

					subTest.enterVersion(e)

					for _, a := range test.multicastAddrs {
						if err := s.JoinGroup(test.protoNum, nicID, a); err != nil {
							t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, a, err)
						}
						reportCounter++
						subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
						if p := e.Read(); p.IsNil() {
							t.Fatalf("expected a report message to be sent for %s", a)
						} else {
							subTest.validateReport(t, p, a)
							p.DecRef()
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
					{
						numMessages := 1
						if subTest.v1Compatibility {
							numMessages = len(test.multicastAddrs)
						}
						leaveCounter += uint64(numMessages)
						subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
						subTest.validateLeave(t, e, test.multicastAddrs)
					}
					if t.Failed() {
						t.FailNow()
					}

					// Reports should be sent for the joined groups when the NIC is enabled.
					if err := s.EnableNIC(nicID); err != nil {
						t.Fatalf("EnableNIC(%d): %s", nicID, err)
					}
					reportV2Counter++
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					test.validateReport(t, e, test.multicastAddrs)
					if t.Failed() {
						t.FailNow()
					}
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)

					// Joining/leaving a group while disabled should not send any messages.
					if err := s.DisableNIC(nicID); err != nil {
						t.Fatalf("DisableNIC(%d): %s", nicID, err)
					}
					reportV2Counter++
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					if p := e.Read(); p.IsNil() {
						t.Fatal("expected leave message to be sent")
					} else {
						p.DecRef()
					}
					for _, a := range test.multicastAddrs {
						if err := s.LeaveGroup(test.protoNum, nicID, a); err != nil {
							t.Fatalf("LeaveGroup(%d, nic, %s): %s", test.protoNum, a, err)
						}
						subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
						if p := e.Read(); !p.IsNil() {
							t.Fatalf("leaving group %s on disabled NIC sent unexpected packet = %#v", a, p)
						}
					}
					if err := s.JoinGroup(test.protoNum, nicID, test.finalMulticastAddr); err != nil {
						t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, test.finalMulticastAddr, err)
					}
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					if p := e.Read(); !p.IsNil() {
						t.Fatalf("joining group %s on disabled NIC sent unexpected packet = %#v", test.finalMulticastAddr, p)
					}

					// A report should only be sent for the group we last joined after
					// enabling the NIC since the original groups were all left.
					if err := s.EnableNIC(nicID); err != nil {
						t.Fatalf("EnableNIC(%d): %s", nicID, err)
					}
					reportV2Counter++
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					test.validateReport(t, e, []tcpip.Address{test.finalMulticastAddr})

					clock.Advance(test.maxUnsolicitedResponseDelay)
					reportV2Counter++
					subTest.checkStats(t, s, reportCounter, leaveCounter, reportV2Counter)
					test.validateReport(t, e, []tcpip.Address{test.finalMulticastAddr})

					// Should not send any more packets.
					clock.Advance(time.Hour)
					if p := e.Read(); !p.IsNil() {
						t.Fatalf("sent unexpected packet = %#v", p)
					}
				})
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
			defer func() {
				s.Close()
				s.Wait()
			}()
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

func TestMGPCoalescedQueryResponseRecords(t *testing.T) {
	const igmpv3MLDv2ReportRecordHeaderLen = 4

	type subTest struct {
		name           string
		enterVersion   func(e *channel.Endpoint)
		validateReport func(*testing.T, stack.PacketBufferPtr)
		checkStats     func(*testing.T, *stack.Stack, uint64, uint64, uint64)
	}

	genAddr := func(bytes []byte, i uint16) tcpip.Address {
		bytes[len(bytes)-1] = byte(i & 0xFF)
		bytes[len(bytes)-2] = byte(i >> 8)
		return tcpip.AddrFromSlice(bytes[:])
	}

	calcMaxRecordsPerMessage := func(hdrLen, recordLen uint16) uint16 {
		return (header.IPv6MinimumMTU - hdrLen) / recordLen
	}

	tests := []struct {
		name                              string
		protoNum                          tcpip.NetworkProtocolNumber
		maxUnsolicitedResponseDelay       time.Duration
		receivedQueryStat                 func(*stack.Stack) *tcpip.StatCounter
		checkInitialGroups                func(*testing.T, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) uint64
		validateReport                    func(*testing.T, stack.PacketBufferPtr, tcpip.Address)
		checkStats                        func(*testing.T, *stack.Stack, uint64)
		genAddr                           func(uint16) tcpip.Address
		maxRecordsPerMessage              uint16
		rxQuery                           func(*channel.Endpoint, uint8)
		validateReportWithMultipleRecords func(*testing.T, *channel.Endpoint, []tcpip.Address)
	}{
		{
			name:                        "IGMP",
			protoNum:                    ipv4.ProtocolNumber,
			maxUnsolicitedResponseDelay: ipv4.UnsolicitedReportIntervalMax,
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().IGMP.PacketsReceived.MembershipQuery
			},
			validateReport: func(t *testing.T, p stack.PacketBufferPtr, addr tcpip.Address) {
				t.Helper()

				validateIGMPv3ReportPacket(t, p, []tcpip.Address{addr}, header.IGMPv3ReportRecordChangeToExcludeMode)
			},
			checkStats: func(t *testing.T, s *stack.Stack, reports uint64) {
				t.Helper()
				iptestutil.CheckIGMPv3Stats(t, s, 0, 0, reports)
			},
			genAddr: func(i uint16) tcpip.Address {
				bytes := [header.IPv4AddressSize]byte{224, 1, 0, 0}
				return genAddr(bytes[:], i)
			},
			maxRecordsPerMessage: calcMaxRecordsPerMessage(header.IPv4MinimumSize+8 /* size of IGMPv3 report header */, igmpv3MLDv2ReportRecordHeaderLen+header.IPv4AddressSize),
			rxQuery: func(e *channel.Endpoint, maxRespTime uint8) {
				createAndInjectIGMPPacket(e, igmpMembershipQuery, maxRespTime, header.IPv4Any, header.IGMPv3QueryMinimumSize-header.IGMPQueryMinimumSize /* extraLength */)
			},
			validateReportWithMultipleRecords: func(t *testing.T, e *channel.Endpoint, addrs []tcpip.Address) {
				t.Helper()
				iptestutil.ValidateIGMPv3RecordsAcrossReports(t, e, stackIPv4Addr, addrs, header.IGMPv3ReportRecordModeIsExclude)
			},
		},
		{
			name:                        "MLD",
			protoNum:                    ipv6.ProtocolNumber,
			maxUnsolicitedResponseDelay: ipv6.UnsolicitedReportIntervalMax,
			receivedQueryStat: func(s *stack.Stack) *tcpip.StatCounter {
				return s.Stats().ICMP.V6.PacketsReceived.MulticastListenerQuery
			},
			checkInitialGroups: checkInitialIPv6Groups,
			validateReport: func(t *testing.T, p stack.PacketBufferPtr, addr tcpip.Address) {
				t.Helper()

				validateMLDv2ReportPacket(t, p, []tcpip.Address{addr}, header.MLDv2ReportRecordChangeToExcludeMode)
			},
			checkStats: func(t *testing.T, s *stack.Stack, reports uint64) {
				t.Helper()
				iptestutil.CheckMLDv2Stats(t, s, 0, 0, reports)
			},
			genAddr: func(i uint16) tcpip.Address {
				bytes := [header.IPv6AddressSize]byte{0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}
				return genAddr(bytes[:], i)
			},
			maxRecordsPerMessage: calcMaxRecordsPerMessage(header.IPv6MinimumSize+8 /* size of MLDv2 report header */, igmpv3MLDv2ReportRecordHeaderLen+header.IPv6AddressSize),
			rxQuery: func(e *channel.Endpoint, maxRespTime uint8) {
				createAndInjectMLDPacket(e, mldQuery, maxRespTime, header.IPv6Any, header.MLDv2QueryMinimumSize-header.MLDMinimumSize /* extraLength */)
			},
			validateReportWithMultipleRecords: func(t *testing.T, e *channel.Endpoint, addrs []tcpip.Address) {
				t.Helper()

				iptestutil.ValidateMLDv2RecordsAcrossReports(t, e, linkLocalIPv6Addr1, addrs, header.MLDv2ReportRecordModeIsExclude)
			},
		},
	}

	subTests := []struct {
		name            string
		extraRecords    uint16
		expectedReports uint64
	}{
		{
			name:            "No extra records",
			extraRecords:    0,
			expectedReports: 1,
		},
		{
			name:            "One extra record",
			extraRecords:    1,
			expectedReports: 2,
		},
		{
			name:            "Two extra records",
			extraRecords:    2,
			expectedReports: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					ctx := newMulticastTestContext(t, test.protoNum == ipv4.ProtocolNumber /* v4 */, true /* mgpEnabled */)
					defer ctx.cleanup()
					s, e, clock := ctx.s, ctx.e, ctx.clock

					var reportV2Counter uint64
					if test.checkInitialGroups != nil {
						reportV2Counter = test.checkInitialGroups(t, e, s, clock)
					}

					addrs := make([]tcpip.Address, test.maxRecordsPerMessage+subTest.extraRecords)
					for i := 0; i < len(addrs); i++ {
						addr := test.genAddr(uint16(i))
						addrs[i] = addr

						if err := s.JoinGroup(test.protoNum, nicID, addr); err != nil {
							t.Fatalf("JoinGroup(%d, %d, %s): %s", test.protoNum, nicID, addr, err)
						}
						reportV2Counter++
						test.checkStats(t, s, reportV2Counter)
						if p := e.Read(); p.IsNil() {
							t.Fatal("expected a report message to be sent")
						} else {
							test.validateReport(t, p, addr)
							p.DecRef()
						}
						if t.Failed() {
							t.FailNow()
						}

						// Verify the second report is sent by the maximum unsolicited response
						// interval.
						p := e.Read()
						if !p.IsNil() {
							t.Fatalf("sent unexpected packet, expected report only after advancing the clock = %#v", p)
						}
						clock.Advance(test.maxUnsolicitedResponseDelay)
						reportV2Counter++
						test.checkStats(t, s, reportV2Counter)
						if p := e.Read(); p.IsNil() {
							t.Fatal("expected a report message to be sent")
						} else {
							test.validateReport(t, p, addr)
							p.DecRef()
						}
					}

					// Should not send any more packets.
					clock.Advance(time.Hour)
					if p := e.Read(); !p.IsNil() {
						t.Fatalf("sent unexpected packet = %#v", p)
					}
					test.checkStats(t, s, reportV2Counter)

					// Receive a query which should send a few reports which together hold
					// records for all the groups we joined.
					test.rxQuery(e, 1)
					clock.Advance(time.Second)
					reportV2Counter += subTest.expectedReports
					test.checkStats(t, s, reportV2Counter)
					test.validateReportWithMultipleRecords(t, e, addrs)
				})
			}
		})
	}
}
