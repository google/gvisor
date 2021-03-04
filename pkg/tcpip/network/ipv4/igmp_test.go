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
	linkAddr            = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	stackAddr           = tcpip.Address("\x0a\x00\x00\x01")
	remoteAddr          = tcpip.Address("\x0a\x00\x00\x02")
	multicastAddr       = tcpip.Address("\xe0\x00\x00\x03")
	nicID               = 1
	defaultTTL          = 1
	defaultPrefixLength = 24
)

// validateIgmpPacket checks that a passed PacketInfo is an IPv4 IGMP packet
// sent to the provided address with the passed fields set. Raises a t.Error if
// any field does not match.
func validateIgmpPacket(t *testing.T, p channel.PacketInfo, igmpType header.IGMPType, maxRespTime byte, srcAddr, dstAddr, groupAddress tcpip.Address) {
	t.Helper()

	payload := header.IPv4(stack.PayloadSince(p.Pkt.NetworkHeader()))
	checker.IPv4(t, payload,
		checker.SrcAddr(srcAddr),
		checker.DstAddr(dstAddr),
		// TTL for an IGMP message must be 1 as per RFC 2236 section 2.
		checker.TTL(1),
		checker.IPv4RouterAlert(),
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
			IGMP: ipv4.IGMPOptions{
				Enabled: igmpEnabled,
			},
		})},
		Clock: clock,
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}
	return e, s, clock
}

func createAndInjectIGMPPacket(e *channel.Endpoint, igmpType header.IGMPType, maxRespTime byte, ttl uint8, srcAddr, dstAddr, groupAddress tcpip.Address, hasRouterAlertOption bool) {
	var options header.IPv4OptionsSerializer
	if hasRouterAlertOption {
		options = header.IPv4OptionsSerializer{
			&header.IPv4SerializableRouterAlertOption{},
		}
	}
	buf := buffer.NewView(header.IPv4MinimumSize + int(options.Length()) + header.IGMPQueryMinimumSize)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         ttl,
		Protocol:    uint8(header.IGMPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Options:     options,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	igmp := header.IGMP(ip.Payload())
	igmp.SetType(igmpType)
	igmp.SetMaxRespTime(maxRespTime)
	igmp.SetGroupAddress(groupAddress)
	igmp.SetChecksum(header.IGMPCalculateChecksum(igmp))

	e.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buf.ToVectorisedView(),
	}))
}

// TestIGMPV1Present tests the node's ability to fallback to V1 when a V1
// router is detected. V1 present status is expected to be reset when the NIC
// cycles.
func TestIGMPV1Present(t *testing.T) {
	e, s, clock := createStack(t, true)
	addr := tcpip.AddressWithPrefix{Address: stackAddr, PrefixLen: defaultPrefixLength}
	if err := s.AddAddressWithPrefix(nicID, ipv4.ProtocolNumber, addr); err != nil {
		t.Fatalf("AddAddressWithPrefix(%d, %d, %s): %s", nicID, ipv4.ProtocolNumber, addr, err)
	}

	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr, err)
	}

	// This NIC will send an IGMPv2 report immediately, before this test can get
	// the IGMPv1 General Membership Query in.
	{
		p, ok := e.Read()
		if !ok {
			t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
		}
		if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 1 {
			t.Fatalf("got V2MembershipReport messages sent = %d, want = 1", got)
		}
		validateIgmpPacket(t, p, header.IGMPv2MembershipReport, 0, stackAddr, multicastAddr, multicastAddr)
	}
	if t.Failed() {
		t.FailNow()
	}

	// Inject an IGMPv1 General Membership Query which is identical to a standard
	// membership query except the Max Response Time is set to 0, which will tell
	// the stack that this is a router using IGMPv1. Send it to the all systems
	// group which is the only group this host belongs to.
	createAndInjectIGMPPacket(e, header.IGMPMembershipQuery, 0, defaultTTL, remoteAddr, stackAddr, header.IPv4AllSystems, true /* hasRouterAlertOption */)
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
	if p, ok := e.Read(); ok {
		t.Fatalf("sent unexpected packet, expected V1MembershipReport only after advancing the clock = %+v", p.Pkt)
	}
	clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	{
		p, ok := e.Read()
		if !ok {
			t.Fatal("unable to Read IGMP packet, expected V1MembershipReport")
		}
		if got := s.Stats().IGMP.PacketsSent.V1MembershipReport.Value(); got != 1 {
			t.Fatalf("got V1MembershipReport messages sent = %d, want = 1", got)
		}
		validateIgmpPacket(t, p, header.IGMPv1MembershipReport, 0, stackAddr, multicastAddr, multicastAddr)
	}

	// Cycling the interface should reset the V1 present flag.
	if err := s.DisableNIC(nicID); err != nil {
		t.Fatalf("s.DisableNIC(%d): %s", nicID, err)
	}
	if err := s.EnableNIC(nicID); err != nil {
		t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
	}
	{
		p, ok := e.Read()
		if !ok {
			t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
		}
		if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != 2 {
			t.Fatalf("got V2MembershipReport messages sent = %d, want = 2", got)
		}
		validateIgmpPacket(t, p, header.IGMPv2MembershipReport, 0, stackAddr, multicastAddr, multicastAddr)
	}
}

func TestSendQueuedIGMPReports(t *testing.T) {
	e, s, clock := createStack(t, true)

	// Joining a group without an assigned address should queue IGMP packets; none
	// should be sent without an assigned address.
	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
		t.Fatalf("JoinGroup(%d, %d, %s): %s", ipv4.ProtocolNumber, nicID, multicastAddr, err)
	}
	reportStat := s.Stats().IGMP.PacketsSent.V2MembershipReport
	if got := reportStat.Value(); got != 0 {
		t.Errorf("got reportStat.Value() = %d, want = 0", got)
	}
	clock.Advance(time.Hour)
	if p, ok := e.Read(); ok {
		t.Fatalf("got unexpected packet = %#v", p)
	}

	// The initial set of IGMP reports that were queued should be sent once an
	// address is assigned.
	if err := s.AddAddress(nicID, ipv4.ProtocolNumber, stackAddr); err != nil {
		t.Fatalf("AddAddress(%d, %d, %s): %s", nicID, ipv4.ProtocolNumber, stackAddr, err)
	}
	if got := reportStat.Value(); got != 1 {
		t.Errorf("got reportStat.Value() = %d, want = 1", got)
	}
	if p, ok := e.Read(); !ok {
		t.Error("expected to send an IGMP membership report")
	} else {
		validateIgmpPacket(t, p, header.IGMPv2MembershipReport, 0, stackAddr, multicastAddr, multicastAddr)
	}
	if t.Failed() {
		t.FailNow()
	}
	clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	if got := reportStat.Value(); got != 2 {
		t.Errorf("got reportStat.Value() = %d, want = 2", got)
	}
	if p, ok := e.Read(); !ok {
		t.Error("expected to send an IGMP membership report")
	} else {
		validateIgmpPacket(t, p, header.IGMPv2MembershipReport, 0, stackAddr, multicastAddr, multicastAddr)
	}
	if t.Failed() {
		t.FailNow()
	}

	// Should have no more packets to send after the initial set of unsolicited
	// reports.
	clock.Advance(time.Hour)
	if p, ok := e.Read(); ok {
		t.Fatalf("got unexpected packet = %#v", p)
	}
}

func TestIGMPPacketValidation(t *testing.T) {
	tests := []struct {
		name                     string
		messageType              header.IGMPType
		stackAddresses           []tcpip.AddressWithPrefix
		srcAddr                  tcpip.Address
		includeRouterAlertOption bool
		ttl                      uint8
		expectValidIGMP          bool
		getMessageTypeStatValue  func(tcpip.Stats) uint64
	}{
		{
			name:                     "valid",
			messageType:              header.IGMPLeaveGroup,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  remoteAddr,
			ttl:                      1,
			expectValidIGMP:          true,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.LeaveGroup.Value() },
		},
		{
			name:                     "bad ttl",
			messageType:              header.IGMPv1MembershipReport,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  remoteAddr,
			ttl:                      2,
			expectValidIGMP:          false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.V1MembershipReport.Value() },
		},
		{
			name:                     "missing router alert ip option",
			messageType:              header.IGMPv2MembershipReport,
			includeRouterAlertOption: false,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  remoteAddr,
			ttl:                      1,
			expectValidIGMP:          false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.V2MembershipReport.Value() },
		},
		{
			name:                     "igmp leave group and src ip does not belong to nic subnet",
			messageType:              header.IGMPLeaveGroup,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  tcpip.Address("\x0a\x00\x01\x02"),
			ttl:                      1,
			expectValidIGMP:          false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.LeaveGroup.Value() },
		},
		{
			name:                     "igmp query and src ip does not belong to nic subnet",
			messageType:              header.IGMPMembershipQuery,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  tcpip.Address("\x0a\x00\x01\x02"),
			ttl:                      1,
			expectValidIGMP:          true,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.MembershipQuery.Value() },
		},
		{
			name:                     "igmp report v1 and src ip does not belong to nic subnet",
			messageType:              header.IGMPv1MembershipReport,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  tcpip.Address("\x0a\x00\x01\x02"),
			ttl:                      1,
			expectValidIGMP:          false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.V1MembershipReport.Value() },
		},
		{
			name:                     "igmp report v2 and src ip does not belong to nic subnet",
			messageType:              header.IGMPv2MembershipReport,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  tcpip.Address("\x0a\x00\x01\x02"),
			ttl:                      1,
			expectValidIGMP:          false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.V2MembershipReport.Value() },
		},
		{
			name:                     "src ip belongs to the subnet of the nic's second address",
			messageType:              header.IGMPv2MembershipReport,
			includeRouterAlertOption: true,
			stackAddresses: []tcpip.AddressWithPrefix{
				{Address: tcpip.Address("\x0a\x00\x0f\x01"), PrefixLen: 24},
				{Address: stackAddr, PrefixLen: 24},
			},
			srcAddr:                 remoteAddr,
			ttl:                     1,
			expectValidIGMP:         true,
			getMessageTypeStatValue: func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.V2MembershipReport.Value() },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, s, _ := createStack(t, true)
			for _, address := range test.stackAddresses {
				if err := s.AddAddressWithPrefix(nicID, ipv4.ProtocolNumber, address); err != nil {
					t.Fatalf("AddAddressWithPrefix(%d, %d, %s): %s", nicID, ipv4.ProtocolNumber, address, err)
				}
			}
			stats := s.Stats()
			// Verify that every relevant stats is zero'd before we send a packet.
			if got := test.getMessageTypeStatValue(s.Stats()); got != 0 {
				t.Errorf("got test.getMessageTypeStatValue(s.Stats()) = %d, want = 0", got)
			}
			if got := stats.IGMP.PacketsReceived.Invalid.Value(); got != 0 {
				t.Errorf("got stats.IGMP.PacketsReceived.Invalid.Value() = %d, want = 0", got)
			}
			if got := stats.IP.PacketsDelivered.Value(); got != 0 {
				t.Fatalf("got stats.IP.PacketsDelivered.Value() = %d, want = 0", got)
			}
			createAndInjectIGMPPacket(e, test.messageType, 0, test.ttl, test.srcAddr, header.IPv4AllSystems, header.IPv4AllSystems, test.includeRouterAlertOption)
			// We always expect the packet to pass IP validation.
			if got := stats.IP.PacketsDelivered.Value(); got != 1 {
				t.Fatalf("got stats.IP.PacketsDelivered.Value() = %d, want = 1", got)
			}
			// Even when the IGMP-specific validation checks fail, we expect the
			// corresponding IGMP counter to be incremented.
			if got := test.getMessageTypeStatValue(s.Stats()); got != 1 {
				t.Errorf("got test.getMessageTypeStatValue(s.Stats()) = %d, want = 1", got)
			}
			var expectedInvalidCount uint64
			if !test.expectValidIGMP {
				expectedInvalidCount = 1
			}
			if got := stats.IGMP.PacketsReceived.Invalid.Value(); got != expectedInvalidCount {
				t.Errorf("got stats.IGMP.PacketsReceived.Invalid.Value() = %d, want = %d", got, expectedInvalidCount)
			}
		})
	}
}
