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

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	iptestutil "gvisor.dev/gvisor/pkg/tcpip/network/internal/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const (
	linkAddr            = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	nicID               = 1
	defaultTTL          = 1
	defaultPrefixLength = 24
)

var (
	stackAddr           = testutil.MustParse4("10.0.0.1")
	remoteAddr          = testutil.MustParse4("10.0.0.2")
	multicastAddr1      = testutil.MustParse4("224.0.0.3")
	multicastAddr2      = testutil.MustParse4("224.0.0.4")
	multicastAddr3      = testutil.MustParse4("224.0.0.5")
	multicastAddr4      = testutil.MustParse4("224.0.0.6")
	unusedMulticastAddr = testutil.MustParse4("224.0.0.7")
)

// validateIgmpPacket checks that a passed packet is an IPv4 IGMP packet sent
// to the provided address with the passed fields set. Raises a t.Error if any
// field does not match.
func validateIgmpPacket(t *testing.T, pkt stack.PacketBufferPtr, igmpType header.IGMPType, maxRespTime byte, srcAddr, dstAddr, groupAddress tcpip.Address) {
	t.Helper()

	payload := stack.PayloadSince(pkt.NetworkHeader())
	defer payload.Release()
	checker.IPv4(t, payload,
		checker.SrcAddr(srcAddr),
		checker.DstAddr(dstAddr),
		// TTL for an IGMP message must be 1 as per RFC 2236 section 2.
		checker.TTL(1),
		checker.IPv4RouterAlert(),
		checker.IGMP(
			checker.IGMPType(igmpType),
			checker.IGMPMaxRespTime(header.DecisecondToDuration(uint16(maxRespTime))),
			checker.IGMPGroupAddress(groupAddress),
		),
	)
}

func validateIgmpv3ReportPacket(t *testing.T, pkt stack.PacketBufferPtr, srcAddr, groupAddress tcpip.Address) {
	t.Helper()

	payload := stack.PayloadSince(pkt.NetworkHeader())
	defer payload.Release()
	iptestutil.ValidateIGMPv3Report(t, payload, srcAddr, []tcpip.Address{groupAddress}, header.IGMPv3ReportRecordChangeToExcludeMode)
}

type igmpTestContext struct {
	s     *stack.Stack
	ep    *channel.Endpoint
	clock *faketime.ManualClock
}

func (ctx igmpTestContext) cleanup() {
	ctx.s.Close()
	ctx.s.Wait()
	ctx.ep.Close()
	refs.DoRepeatedLeakCheck()
}

func newIGMPTestContext(t *testing.T, igmpEnabled bool) igmpTestContext {
	t.Helper()

	// Create an endpoint of queue size 2, since no more than 2 packets are ever
	// queued in the tests in this file.
	e := channel.New(2, 1280, linkAddr)
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

	return igmpTestContext{
		ep:    e,
		s:     s,
		clock: clock,
	}
}

func createAndInjectIGMPPacket(e *channel.Endpoint, igmpType header.IGMPType, maxRespTime byte, ttl uint8, srcAddr, dstAddr, groupAddress tcpip.Address, hasRouterAlertOption bool) {
	var options header.IPv4OptionsSerializer
	if hasRouterAlertOption {
		options = header.IPv4OptionsSerializer{
			&header.IPv4SerializableRouterAlertOption{},
		}
	}
	buf := make([]byte, header.IPv4MinimumSize+int(options.Length())+header.IGMPQueryMinimumSize)

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
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(buf),
	})
	e.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

// TestIGMPV1Present tests the node's ability to fallback to V1 when a V1
// router is detected. V1 present status is expected to be reset when the NIC
// cycles.
func TestIGMPV1Present(t *testing.T) {
	ctx := newIGMPTestContext(t, true /* igmpEnabled */)
	defer ctx.cleanup()
	s := ctx.s
	e := ctx.ep

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: stackAddr, PrefixLen: defaultPrefixLength},
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
	}

	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr1); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr1, err)
	}

	// This NIC will send an IGMPv3 report immediately, before this test can get
	// the IGMPv1 General Membership Query in.
	{
		p := e.Read()
		if p.IsNil() {
			t.Fatal("unable to Read IGMP packet, expected V3MembershipReport")
		}
		if got := s.Stats().IGMP.PacketsSent.V3MembershipReport.Value(); got != 1 {
			t.Fatalf("got V3MembershipReport messages sent = %d, want = 1", got)
		}
		validateIgmpv3ReportPacket(t, p, stackAddr, multicastAddr1)
		p.DecRef()
	}
	if t.Failed() {
		t.FailNow()
	}

	// Inject an IGMPv1 General Membership Query which is identical to a standard
	// membership query except the Max Response Time is set to 0, which will tell
	// the stack that this is a router using IGMPv1.
	createAndInjectIGMPPacket(e, header.IGMPMembershipQuery, 0, defaultTTL, remoteAddr, stackAddr, multicastAddr1, true /* hasRouterAlertOption */)
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
	if p := e.Read(); !p.IsNil() {
		t.Fatalf("sent unexpected packet, expected V1MembershipReport only after advancing the clock = %+v", p)
	}
	ctx.clock.Advance(ipv4.UnsolicitedReportIntervalMax)
	{
		p := e.Read()
		if p.IsNil() {
			t.Fatal("unable to Read IGMP packet, expected V1MembershipReport")
		}
		if got := s.Stats().IGMP.PacketsSent.V1MembershipReport.Value(); got != 1 {
			t.Fatalf("got V1MembershipReport messages sent = %d, want = 1", got)
		}
		validateIgmpPacket(t, p, header.IGMPv1MembershipReport, 0, stackAddr, multicastAddr1, multicastAddr1)
		p.DecRef()
	}

	// Cycling the interface should reset the V1 present flag.
	if err := s.DisableNIC(nicID); err != nil {
		t.Fatalf("s.DisableNIC(%d): %s", nicID, err)
	}
	if err := s.EnableNIC(nicID); err != nil {
		t.Fatalf("s.EnableNIC(%d): %s", nicID, err)
	}
	{
		p := e.Read()
		if p.IsNil() {
			t.Fatal("unable to Read IGMP packet, expected V2MembershipReport")
		}
		if got := s.Stats().IGMP.PacketsSent.V3MembershipReport.Value(); got != 2 {
			t.Fatalf("got V3MembershipReport messages sent = %d, want = 2", got)
		}
		validateIgmpv3ReportPacket(t, p, stackAddr, multicastAddr1)
		p.DecRef()
	}
}

func TestSendQueuedIGMPReports(t *testing.T) {
	tests := []struct {
		name            string
		v2Compatibility bool
		validate        func(t *testing.T, e *channel.Endpoint, localAddress tcpip.Address, groupAddresses []tcpip.Address)
		checkStats      func(*testing.T, *stack.Stack, uint64, uint64, uint64)
	}{
		{
			name:            "V2 Compatibility",
			v2Compatibility: true,
			validate: func(t *testing.T, e *channel.Endpoint, localAddress tcpip.Address, groupAddresses []tcpip.Address) {
				t.Helper()

				iptestutil.ValidMultipleIGMPv2ReportLeaves(t, e, localAddress, groupAddresses, false /* leave */)
			},
			checkStats: iptestutil.CheckIGMPv2Stats,
		},
		{
			name:            "V3",
			v2Compatibility: false,
			validate: func(t *testing.T, e *channel.Endpoint, localAddress tcpip.Address, groupAddresses []tcpip.Address) {
				t.Helper()

				iptestutil.ValidateIGMPv3RecordsAcrossReports(t, e, localAddress, groupAddresses, header.IGMPv3ReportRecordChangeToExcludeMode)
			},
			checkStats: iptestutil.CheckIGMPv3Stats,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newIGMPTestContext(t, true /* igmpEnabled */)
			defer ctx.cleanup()
			s := ctx.s
			e := ctx.ep
			clock := ctx.clock

			checkVersion := func() {
				if test.v2Compatibility {
					ep, err := s.GetNetworkEndpoint(nicID, header.IPv4ProtocolNumber)
					if err != nil {
						t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID, header.IPv4ProtocolNumber, err)
					}

					igmpEP, ok := ep.(ipv4.IGMPEndpoint)
					if !ok {
						t.Fatalf("got (%T).(%T) = (_, false), want = (_ true)", ep, igmpEP)
					}

					igmpEP.SetIGMPVersion(ipv4.IGMPVersion2)
				}
			}
			protocolAddr := tcpip.ProtocolAddress{
				Protocol: ipv4.ProtocolNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   stackAddr,
					PrefixLen: defaultPrefixLength,
				},
			}
			// Multicast traffic is not accepted unless we have an address so add an
			// address and check the version which receives a multicast packet.
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}
			checkVersion()
			if err := s.RemoveAddress(nicID, protocolAddr.AddressWithPrefix.Address); err != nil {
				t.Fatalf("RemoveAddress(%d, %s): %s", nicID, protocolAddr.AddressWithPrefix.Address, err)
			}

			var reportCounter uint64
			var doneCounter uint64
			var reportV2Counter uint64
			test.checkStats(t, s, reportCounter, doneCounter, reportV2Counter)

			// Joining groups without an assigned address should queue IGMP packets;
			// none should be sent without an assigned address.
			multicastAddrs := []tcpip.Address{multicastAddr1, multicastAddr2}
			for _, multicastAddr := range multicastAddrs {
				if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr); err != nil {
					t.Fatalf("JoinGroup(%d, %d, %s): %s", ipv4.ProtocolNumber, nicID, multicastAddr, err)
				}
			}
			test.checkStats(t, s, reportCounter, doneCounter, reportV2Counter)
			if p := e.Read(); !p.IsNil() {
				t.Fatalf("got unexpected packet = %#v", p)
			}

			// The initial set of IGMP reports that were queued should be sent once an
			// address is assigned.
			if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
			}

			// We expect two batches of reports to be sent (1 batch when the address
			// is assigned, and another after the maximum unsolicited report interval.
			for i := 0; i < 2; i++ {
				// IGMPv2 always sends a single message per group.
				//
				// IGMPv3 sends a single message per group when we first get an
				// address assigned, but later reports (sent by the state changed
				// timer) coalesce records for groups.
				if test.v2Compatibility || i == 0 {
					reportCounter += uint64(len(multicastAddrs))
				} else {
					reportCounter++
				}
				test.checkStats(t, s, reportCounter, doneCounter, reportV2Counter)
				test.validate(t, e, stackAddr, multicastAddrs)

				if t.Failed() {
					t.FailNow()
				}

				clock.Advance(ipv4.UnsolicitedReportIntervalMax)
			}

			// Should have no more packets to send after the initial set of unsolicited
			// reports.
			clock.Advance(time.Hour)
			if p := e.Read(); !p.IsNil() {
				t.Fatalf("got unexpected packet = %#v", p)
			}
		})
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
			srcAddr:                  testutil.MustParse4("10.0.1.2"),
			ttl:                      1,
			expectValidIGMP:          false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.LeaveGroup.Value() },
		},
		{
			name:                     "igmp query and src ip does not belong to nic subnet",
			messageType:              header.IGMPMembershipQuery,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  testutil.MustParse4("10.0.1.2"),
			ttl:                      1,
			expectValidIGMP:          true,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.MembershipQuery.Value() },
		},
		{
			name:                     "igmp report v1 and src ip does not belong to nic subnet",
			messageType:              header.IGMPv1MembershipReport,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  testutil.MustParse4("10.0.1.2"),
			ttl:                      1,
			expectValidIGMP:          false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.V1MembershipReport.Value() },
		},
		{
			name:                     "igmp report v2 and src ip does not belong to nic subnet",
			messageType:              header.IGMPv2MembershipReport,
			includeRouterAlertOption: true,
			stackAddresses:           []tcpip.AddressWithPrefix{{Address: stackAddr, PrefixLen: 24}},
			srcAddr:                  testutil.MustParse4("10.0.1.2"),
			ttl:                      1,
			expectValidIGMP:          false,
			getMessageTypeStatValue:  func(stats tcpip.Stats) uint64 { return stats.IGMP.PacketsReceived.V2MembershipReport.Value() },
		},
		{
			name:                     "src ip belongs to the subnet of the nic's second address",
			messageType:              header.IGMPv2MembershipReport,
			includeRouterAlertOption: true,
			stackAddresses: []tcpip.AddressWithPrefix{
				{Address: testutil.MustParse4("10.0.15.1"), PrefixLen: 24},
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
			ctx := newIGMPTestContext(t, true /* igmpEnabled */)
			defer ctx.cleanup()
			s := ctx.s
			e := ctx.ep

			for _, address := range test.stackAddresses {
				protocolAddr := tcpip.ProtocolAddress{
					Protocol:          ipv4.ProtocolNumber,
					AddressWithPrefix: address,
				}
				if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
					t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
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

func TestGetSetIGMPVersion(t *testing.T) {
	const nicID = 1

	c := newIGMPTestContext(t, true /* igmpEnabled */)
	defer c.cleanup()
	s := c.s
	e := c.ep

	ep, err := s.GetNetworkEndpoint(nicID, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatalf("s.GetNetworkEndpoint(%d, %d): %s", nicID, header.IPv4ProtocolNumber, err)
	}
	igmpEP, ok := ep.(ipv4.IGMPEndpoint)
	if !ok {
		t.Fatalf("got (%T).(%T) = (_, false), want = (_ true)", ep, igmpEP)
	}
	if got := igmpEP.GetIGMPVersion(); got != ipv4.IGMPVersion3 {
		t.Errorf("got igmpEP.GetIGMPVersion() = %d, want = %d", got, ipv4.IGMPVersion3)
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: stackAddr, PrefixLen: defaultPrefixLength},
	}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
	}

	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr1); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr1, err)
	}
	if p := e.Read(); p.IsNil() {
		t.Fatal("expected a report message to be sent")
	} else {
		validateIgmpv3ReportPacket(t, p, stackAddr, multicastAddr1)
		p.DecRef()
	}

	if got := igmpEP.SetIGMPVersion(ipv4.IGMPVersion2); got != ipv4.IGMPVersion3 {
		t.Errorf("got igmpEP.SetIGMPVersion(%d) = %d, want = %d", ipv4.IGMPVersion2, got, ipv4.IGMPVersion3)
	}
	if got := igmpEP.GetIGMPVersion(); got != ipv4.IGMPVersion2 {
		t.Errorf("got igmpEP.GetIGMPVersion() = %d, want = %d", got, ipv4.IGMPVersion2)
	}
	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr2); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr2, err)
	}
	if p := e.Read(); p.IsNil() {
		t.Fatal("expected a report message to be sent")
	} else {
		validateIgmpPacket(t, p, header.IGMPv2MembershipReport, 0, stackAddr, multicastAddr2, multicastAddr2)
		p.DecRef()
	}

	if got := igmpEP.SetIGMPVersion(ipv4.IGMPVersion1); got != ipv4.IGMPVersion2 {
		t.Errorf("got igmpEP.SetIGMPVersion(%d) = %d, want = %d", ipv4.IGMPVersion1, got, ipv4.IGMPVersion2)
	}
	if got := igmpEP.GetIGMPVersion(); got != ipv4.IGMPVersion1 {
		t.Errorf("got igmpEP.GetIGMPVersion() = %d, want = %d", got, ipv4.IGMPVersion1)
	}
	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr3); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr3, err)
	}
	if p := e.Read(); p.IsNil() {
		t.Fatal("expected a report message to be sent")
	} else {
		validateIgmpPacket(t, p, header.IGMPv1MembershipReport, 0, stackAddr, multicastAddr3, multicastAddr3)
		p.DecRef()
	}

	if got := igmpEP.SetIGMPVersion(ipv4.IGMPVersion3); got != ipv4.IGMPVersion1 {
		t.Errorf("got igmpEP.SetIGMPVersion(%d) = %d, want = %d", ipv4.IGMPVersion3, got, ipv4.IGMPVersion1)
	}
	if got := igmpEP.GetIGMPVersion(); got != ipv4.IGMPVersion3 {
		t.Errorf("got igmpEP.GetIGMPVersion() = %d, want = %d", got, ipv4.IGMPVersion3)
	}
	if err := s.JoinGroup(ipv4.ProtocolNumber, nicID, multicastAddr4); err != nil {
		t.Fatalf("JoinGroup(ipv4, nic, %s) = %s", multicastAddr4, err)
	}
	if p := e.Read(); p.IsNil() {
		t.Fatal("expected a report message to be sent")
	} else {
		validateIgmpv3ReportPacket(t, p, stackAddr, multicastAddr4)
		p.DecRef()
	}
}
