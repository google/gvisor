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

package ipv4

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	linkAddr      = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
	multicastAddr = tcpip.Address("\xe0\x00\x00\x03")
	nicID         = 1
)

// validateIgmpPacket checks that a passed PacketInfo is an IPv4 IGMP packet
// sent to the provided address with the passed fields set. Raises a t.Error if
// any field does not match.
func validateIgmpPacket(t *testing.T, p channel.PacketInfo, remoteAddress tcpip.Address, igmpType header.IGMPType, maxRespTime byte, groupAddress tcpip.Address) {
	t.Helper()

	payload := header.IPv4(stack.PayloadSince(p.Pkt.NetworkHeader()))
	checker.IPv4(t, payload,
		checker.DstAddr(remoteAddress),
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
		NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocolWithOptions(Options{
			IGMP: IGMPOptions{
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

	e.InjectInbound(ProtocolNumber, &stack.PacketBuffer{
		Data: buf.ToVectorisedView(),
	})
}

// TestIgmpV1Present tests the handling of the case where an IGMPv1 router is
// present on the network. The IGMP stack will then send IGMPv1 Membership
// reports for backwards compatibility.
func TestIgmpV1Present(t *testing.T) {
	e, s, clock := createStack(t, true)

	if err := s.JoinGroup(ProtocolNumber, nicID, multicastAddr); err != nil {
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
	clock.Advance(UnsolicitedReportIntervalMax)
	p, ok = e.Read()
	if !ok {
		t.Fatal("unable to Read IGMP packet, expected V1MembershipReport")
	}
	if got := s.Stats().IGMP.PacketsSent.V1MembershipReport.Value(); got != 1 {
		t.Fatalf("got V1MembershipReport messages sent = %d, want = 1", got)
	}
	validateIgmpPacket(t, p, multicastAddr, header.IGMPv1MembershipReport, 0, multicastAddr)
}
