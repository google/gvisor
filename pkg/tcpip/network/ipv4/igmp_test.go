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

package ipv4_test

import (
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	linkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	// endpointAddr  = tcpip.Address("\x0a\x00\x00\x02")
	multicastAddr = tcpip.Address("\xe0\x00\x00\x03")
	nicID         = 1
)

var (
	// unsolicitedReportIntervalMaxTenthSec is the maximum amount of time the NIC
	// will wait before sending an unsolicited report after joining a multicast
	// group, in deciseconds.
	unsolicitedReportIntervalMaxTenthSec = func() uint8 {
		const decisecond = time.Second / 10
		if ipv4.UnsolicitedReportIntervalMax%decisecond != 0 {
			panic(fmt.Sprintf("UnsolicitedReportIntervalMax of %d is a lossy conversion to deciseconds", ipv4.UnsolicitedReportIntervalMax))
		}
		return uint8(ipv4.UnsolicitedReportIntervalMax / decisecond)
	}()
)

// validateIgmpPacket checks that a passed PacketInfo is an IPv4 IGMP packet
// sent to the provided address with the passed fields set. Raises a t.Error if
// any field does not match.
func validateIgmpPacket(t *testing.T, p channel.PacketInfo, remoteAddress tcpip.Address, igmpType header.IGMPType, maxRespTime byte, groupAddress tcpip.Address) {
	t.Helper()

	payload := header.IPv4(stack.PayloadSince(p.Pkt.NetworkHeader()))
	checker.IPv4(t, payload,
		checker.DstAddr(remoteAddress),
		checker.IGMP(
			checker.IGMPType(igmpType),
			checker.IGMPMaxRespTime(header.DecisecondToDuration(maxRespTime)),
			checker.IGMPGroupAddress(groupAddress),
		),
	)
}

func createStack(t *testing.T, igmpEnabled bool) (*channel.Endpoint, *stack.Stack, *faketime.ManualClock) {
	t.Helper()

	// Create an endpoint of queue size 1, since no more than 1 packets are ever
	// queued in the tests in this file.
	e := channel.New(1, 1280, linkAddr)
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{
			IGMPEnabled: igmpEnabled,
		})},
		Clock: clock,
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	return e, s, clock
}

func createAndInjectIGMPPacket(e *channel.Endpoint, igmpType header.IGMPType, maxRespTime byte, groupAddress tcpip.Address) {
	buf := buffer.NewView(header.IPv4MinimumSize + header.IGMPQueryMinimumSize)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         1,
		Protocol:    uint8(header.IGMPProtocolNumber),
		SrcAddr:     header.IPv4Any,
		DstAddr:     header.IPv4AllSystems,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	igmp := header.IGMP(buf[header.IPv4MinimumSize:])
	igmp.SetType(igmpType)
	igmp.SetMaxRespTime(maxRespTime)
	igmp.SetGroupAddress(groupAddress)
	igmp.SetChecksum(header.IGMPCalculateChecksum(igmp))

	e.InjectInbound(ipv4.ProtocolNumber, &stack.PacketBuffer{
		Data: buf.ToVectorisedView(),
	})
}

// TestIgmpDisabled tests that IGMP is not enabled with a default
// stack.Options. This also tests that this NIC does not send the IGMP Join
// Group for the All Hosts group it automatically joins when created.
func TestIgmpDisabled(t *testing.T) {
	e, s, _ := createStack(t, false)

	// This NIC will join the All Hosts group when created. Verify that does not
	// send a report.
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 0 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 0", got)
	}
	p, ok := e.Read()
	if ok {
		t.Fatalf("sent unexpected packet, stack with disabled IGMP sent packet = %+v", p.Pkt)
	}

	// Test joining a specific group explicitly and verify that no reports are
	// sent.
	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(ipv4.ProtocolNumber, %d, %s) = %s", nicID, multicastAddr, err)
	}

	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 0 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 0", got)
	}
	p, ok = e.Read()
	if ok {
		t.Fatalf("sent unexpected packet, stack with disabled IGMP sent packet = %+v", p.Pkt)
	}

	// Inject a General Membership Query, which is an IGMP Membership Query with
	// a zeroed Group Address (IPv4Any) to verify that it does not reach the
	// handler.
	createAndInjectIGMPPacket(e, header.IGMPMembershipQuery, unsolicitedReportIntervalMaxTenthSec, header.IPv4Any)

	if got := s.Stats().IGMP.PacketsReceived.MembershipQuery.Value(); got != 0 {
		t.Fatalf("got Membership Queries received = %d, want = 0", got)
	}
	p, ok = e.Read()
	if ok {
		t.Fatalf("sent unexpected packet, stack with disabled IGMP sent packet = %+v", p.Pkt)
	}
}

// TestIgmpReceivesIGMPMessages tests that the IGMP stack increments packet
// counters when it receives properly formatted Membership Queries, Membership
// Reports, and LeaveGroup Messages sent to this address. Note: test includes
// IGMP header fields that are not explicitly tested in order to inject proper
// IGMP packets.
func TestIgmpReceivesIGMPMessages(t *testing.T) {
	tests := []struct {
		name         string
		headerType   header.IGMPType
		maxRespTime  byte
		groupAddress tcpip.Address
		statCounter  func(tcpip.IGMPReceivedPacketStats) *tcpip.StatCounter
	}{
		{
			name:         "General Membership Query",
			headerType:   header.IGMPMembershipQuery,
			maxRespTime:  unsolicitedReportIntervalMaxTenthSec,
			groupAddress: header.IPv4Any,
			statCounter: func(stats tcpip.IGMPReceivedPacketStats) *tcpip.StatCounter {
				return stats.MembershipQuery
			},
		},
		{
			name:         "IGMPv1 Membership Report",
			headerType:   header.IGMPv1MembershipReport,
			maxRespTime:  0,
			groupAddress: header.IPv4AllSystems,
			statCounter: func(stats tcpip.IGMPReceivedPacketStats) *tcpip.StatCounter {
				return stats.V1MembershipReport
			},
		},
		{
			name:         "IGMPv2 Membership Report",
			headerType:   header.IGMPv2MembershipReport,
			maxRespTime:  0,
			groupAddress: header.IPv4AllSystems,
			statCounter: func(stats tcpip.IGMPReceivedPacketStats) *tcpip.StatCounter {
				return stats.V2MembershipReport
			},
		},
		{
			name:         "Leave Group",
			headerType:   header.IGMPLeaveGroup,
			maxRespTime:  0,
			groupAddress: header.IPv4AllRoutersGroup,
			statCounter: func(stats tcpip.IGMPReceivedPacketStats) *tcpip.StatCounter {
				return stats.LeaveGroup
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, _ := createStack(t, true)

			createAndInjectIGMPPacket(e, test.headerType, test.maxRespTime, test.groupAddress)

			if got := test.statCounter(s.Stats().IGMP.PacketsReceived).Value(); got != 1 {
				t.Fatalf("got %s received = %d, want = 1", test.name, got)
			}
		})
	}
}

// TestIgmpJoinGroup tests that when explicitly joining a multicast group, the
// IGMP stack schedules and sends correct Membership Reports.
func TestIgmpJoinGroup(t *testing.T) {
	e, s, clock := createStack(t, true)

	// Test joining a specific address explicitly and verify a Membership Report
	// is sent immediately.
	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	p, ok := e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 1 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 1", got)
	}

	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)
	if t.Failed() {
		t.FailNow()
	}

	// Verify the second Membership Report is sent after a random interval up to
	// the maximum unsolicited report interval.
	p, ok = e.Read()
	if ok {
		t.Fatalf("sent unexpected packet, expected V2MembershipReport only after advancing the clock = %+v", p.Pkt)
	}
	clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	p, ok = e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 2 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 2", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)
}

// TestIgmpLeaveGroup tests that when leaving a previously joined multicast
// group the IGMP enabled NIC sends the appropriate message.
func TestIgmpLeaveGroup(t *testing.T) {
	e, s, clock := createStack(t, true)

	// Join a group so that it can be left, validate the immediate Membership
	// Report is sent only to the multicast address joined.
	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}
	p, ok := e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 1 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 1", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)
	if t.Failed() {
		t.FailNow()
	}

	// Verify the second Membership Report is sent after a random interval up to
	// the maximum unsolicited report interval, and is sent to the multicast
	// address being joined.
	p, ok = e.Read()
	if ok {
		t.Fatalf("sent unexpected packet, expected V2MembershipReport only after advancing the clock = %+v", p.Pkt)
	}
	clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	p, ok = e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 2 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 2", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)
	if t.Failed() {
		t.FailNow()
	}

	// Now that there are no packets queued and none scheduled to be sent, leave
	// the group.
	if err := s.LeaveGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("LeaveGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	// Observe the Leave Group Message to verify that the Leave Group message is
	// sent to the All Routers group but that the message itself has the
	// multicast address being left.
	p, ok = e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected LeaveGroup")
	}
	if got := s.Stats().IGMP.PacketsSent.LeaveGroup.Value(); got != 1 {
		t.Fatalf("got LeaveGroup messages sent = %d, want = 1", got)
	}
	validateIgmpPacket(t, p, header.IPv4AllRoutersGroup, header.IGMPLeaveGroup, 0, multicastAddr)
}

// TestIgmpJoinLeaveGroup tests that when leaving a previously joined multicast
// group before the Unsolicited Report Interval cancels the second membership
// report.
func TestIgmpJoinLeaveGroup(t *testing.T) {
	_, s, clock := createStack(t, true)

	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	// Verify that this NIC sent a Membership Report for only the group just
	// joined.
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 1 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 1", got)
	}

	if err := s.LeaveGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("LeaveGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	// Wait for the standard IGMP Unsolicited Report Interval duration before
	// verifying that the unsolicited Membership Report was sent after leaving
	// the group.
	clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 1 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 1", got)
	}
}

// TestIgmpMembershipQueryReport tests the handling of both incoming IGMP
// Membership Queries and outgoing Membership Reports.
func TestIgmpMembershipQueryReport(t *testing.T) {
	e, s, clock := createStack(t, true)

	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	p, ok := e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 1 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 1", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)
	if t.Failed() {
		t.FailNow()
	}

	p, ok = e.Read()
	if ok {
		t.Fatalf("sent unexpected packet, expected V2MembershipReport only after advancing the clock = %+v", p.Pkt)
	}
	clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	p, ok = e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 2 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 2", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)

	// Inject a General Membership Query, which is an IGMP Membership Query with
	// a zeroed Group Address (IPv4Any) with the shortened Max Response Time.
	const maxRespTimeDS = 10
	createAndInjectIGMPPacket(e, header.IGMPMembershipQuery, maxRespTimeDS, header.IPv4Any)

	p, ok = e.Read()
	if ok {
		t.Fatalf("sent unexpected packet, expected V2MembershipReport only after advancing the clock = %+v", p.Pkt)
	}
	clock.Advance(header.DecisecondToDuration(maxRespTimeDS))
	p, ok = e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 3 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 3", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)
}

// TestIgmpMultipleHosts tests the handling of IGMP Leave when we are not the
// most recent IGMP host to join a multicast network.
func TestIgmpMultipleHosts(t *testing.T) {
	e, s, clock := createStack(t, true)

	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	p, ok := e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 1 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 1", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)
	if t.Failed() {
		t.FailNow()
	}

	// Inject another Host's Join Group message so that this host is not the
	// latest to send the report. Set Max Response Time to 0 for Membership
	// Reports.
	createAndInjectIGMPPacket(e, header.IGMPv2MembershipReport, 0, multicastAddr)

	if err := s.LeaveGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("LeaveGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	// Wait to be sure that no Leave Group messages were sent up to the max
	// unsolicited report interval since it was not the last host to join this
	// group.
	clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	if got := s.Stats().IGMP.PacketsSent.LeaveGroup.Value(); got != 0 {
		t.Fatalf("got LeaveGroup messages sent = %d, want = 0", got)
	}
}

// TestIgmpV1Present tests the handling of the case where an IGMPv1 router is
// present on the network. The IGMP stack will then send IGMPv1 Membership
// reports for backwards compatibility.
func TestIgmpV1Present(t *testing.T) {
	e, s, clock := createStack(t, true)

	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	// This NIC will send an IGMPv2 report immediately, before this test can get
	// the IGMPv1 General Membership Query in.
	p, ok := e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 1 {
		t.Fatalf("got V2MembershipReport messages sent = %d, want = 1", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv2MembershipReport, 0, multicastAddr)
	if t.Failed() {
		t.FailNow()
	}

	// Inject an IGMPv1 General Membership Query which is identical to a standard
	// membership query except the Max Response Time is set to 0, which will tell
	// the stack that this is a router using IGMPv1. Send it to the all systems
	// group which is the only group this host belongs to.
	createAndInjectIGMPPacket(e, header.IGMPMembershipQuery, 0, header.IPv4AllSystems)
	if got := s.Stats().IGMP.PacketsReceived.MembershipQuery.Value(); got != 1 {
		t.Fatalf("got Membership Queries received = %d, want = 1", got)
	}

	// Before advancing the clock, verify that this host has not sent a
	// V1MembershipReport yet.
	if got := s.Stats().IGMP.PacketsSent.V1MembershipReport.Value(); got != 0 {
		t.Fatalf("got V1MembershipReport messages sent = %d, want = 0", got)
	}

	// Verify the solicited Membership Report is sent. Now that this NIC has seen
	// an IGMPv1 query, it should send an IGMPv1 Membership Report.
	p, ok = e.Read()
	if ok {
		t.Fatalf("sent unexpected packet, expected V1MembershipReport only after advancing the clock = %+v", p.Pkt)
	}
	clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	p, ok = e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V1MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V1MembershipReport.Value(); got != 1 {
		t.Fatalf("got V1MembershipReport messages sent = %d, want = 1", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv1MembershipReport, 0, multicastAddr)
}
