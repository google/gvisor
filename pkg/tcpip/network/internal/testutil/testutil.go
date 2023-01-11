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

// Package testutil defines types and functions used to test Network Layer
// functionality such as IP fragmentation.
package testutil

import (
	"fmt"
	"math/rand"
	"testing"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// MockLinkEndpoint is an endpoint used for testing, it stores packets written
// to it and can mock errors.
type MockLinkEndpoint struct {
	// WrittenPackets is where packets written to the endpoint are stored.
	WrittenPackets []stack.PacketBufferPtr

	mtu          uint32
	err          tcpip.Error
	allowPackets int
}

// NewMockLinkEndpoint creates a new MockLinkEndpoint.
//
// err is the error that will be returned once allowPackets packets are written
// to the endpoint.
func NewMockLinkEndpoint(mtu uint32, err tcpip.Error, allowPackets int) *MockLinkEndpoint {
	return &MockLinkEndpoint{
		mtu:          mtu,
		err:          err,
		allowPackets: allowPackets,
	}
}

// MTU implements LinkEndpoint.MTU.
func (ep *MockLinkEndpoint) MTU() uint32 { return ep.mtu }

// Capabilities implements LinkEndpoint.Capabilities.
func (*MockLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }

// MaxHeaderLength implements LinkEndpoint.MaxHeaderLength.
func (*MockLinkEndpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress implements LinkEndpoint.LinkAddress.
func (*MockLinkEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

// WritePackets implements LinkEndpoint.WritePackets.
func (ep *MockLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, pkt := range pkts.AsSlice() {
		if ep.allowPackets == 0 {
			return n, ep.err
		}
		ep.allowPackets--
		ep.WrittenPackets = append(ep.WrittenPackets, pkt.IncRef())
		n++
	}
	return n, nil
}

// Attach implements LinkEndpoint.Attach.
func (*MockLinkEndpoint) Attach(stack.NetworkDispatcher) {}

// IsAttached implements LinkEndpoint.IsAttached.
func (*MockLinkEndpoint) IsAttached() bool { return false }

// Wait implements LinkEndpoint.Wait.
func (*MockLinkEndpoint) Wait() {}

// ARPHardwareType implements LinkEndpoint.ARPHardwareType.
func (*MockLinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

// AddHeader implements LinkEndpoint.AddHeader.
func (*MockLinkEndpoint) AddHeader(stack.PacketBufferPtr) {}

// Close releases all resources.
func (ep *MockLinkEndpoint) Close() {
	for _, pkt := range ep.WrittenPackets {
		pkt.DecRef()
	}
	ep.WrittenPackets = nil
}

// MakeRandPkt generates a randomized packet. transportHeaderLength indicates
// how many random bytes will be copied in the Transport Header.
// extraHeaderReserveLength indicates how much extra space will be reserved for
// the other headers. The payload is made from Views of the sizes listed in
// viewSizes.
func MakeRandPkt(transportHeaderLength int, extraHeaderReserveLength int, viewSizes []int, proto tcpip.NetworkProtocolNumber) stack.PacketBufferPtr {
	var buf bufferv2.Buffer

	for _, s := range viewSizes {
		newView := bufferv2.NewViewSize(s)
		if _, err := rand.Read(newView.AsSlice()); err != nil {
			panic(fmt.Sprintf("rand.Read: %s", err))
		}
		buf.Append(newView)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: transportHeaderLength + extraHeaderReserveLength,
		Payload:            buf,
	})
	pkt.NetworkProtocolNumber = proto
	if _, err := rand.Read(pkt.TransportHeader().Push(transportHeaderLength)); err != nil {
		panic(fmt.Sprintf("rand.Read: %s", err))
	}
	return pkt
}

func checkIGMPStats(t *testing.T, s *stack.Stack, reports, leaves, reportsV2 uint64) {
	t.Helper()

	if got := s.Stats().IGMP.PacketsSent.V2MembershipReport.Value(); got != reports {
		t.Errorf("got s.Stats().IGMP.PacketsSent.V2MembershipReport.Value() = %d, want = %d", got, reports)
	}
	if got := s.Stats().IGMP.PacketsSent.V3MembershipReport.Value(); got != reportsV2 {
		t.Errorf("got s.Stats().IGMP.PacketsSent.V3MembershipReport.Value() = %d, want = %d", got, reportsV2)
	}
	if got := s.Stats().IGMP.PacketsSent.LeaveGroup.Value(); got != leaves {
		t.Errorf("got s.Stats().IGMP.PacketsSent.LeaveGroup.Value() = %d, want = %d", got, leaves)
	}
}

// CheckIGMPv2Stats checks IGMPv2 stats.
func CheckIGMPv2Stats(t *testing.T, s *stack.Stack, reports, leaves, reportsV2 uint64) {
	t.Helper()
	// We still check V3 stats in V2 compatibility tests because the test may send
	// V3 reports before we drop into compatibility mode.
	checkIGMPStats(t, s, reports, leaves, reportsV2)
}

// CheckIGMPv3Stats checks IGMPv3 stats.
func CheckIGMPv3Stats(t *testing.T, s *stack.Stack, reports, leaves, reportsV2 uint64) {
	t.Helper()
	// In IGMPv3 tests, reports/leaves are just IGMPv3 reports.
	checkIGMPStats(t, s, 0 /* reports */, 0 /* leaves */, reports+leaves+reportsV2)
}

func checkMLDStats(t *testing.T, s *stack.Stack, reports, leaves, reportsV2 uint64) {
	t.Helper()

	if got := s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport.Value(); got != reports {
		t.Errorf("got s.Stats().ICMP.V6.PacketsSent.MulticastListenerReport.Value() = %d, want = %d", got, reports)
	}
	if got := s.Stats().ICMP.V6.PacketsSent.MulticastListenerReportV2.Value(); got != reportsV2 {
		t.Errorf("got s.Stats().ICMP.V6.PacketsSent.MulticastListenerReportV2.Value() = %d, want = %d", got, reportsV2)
	}
	if got := s.Stats().ICMP.V6.PacketsSent.MulticastListenerDone.Value(); got != leaves {
		t.Errorf("got s.Stats().ICMP.V6.PacketsSent.MulticastListenerDone.Value() = %d, want = %d", got, leaves)
	}
}

// CheckMLDv1Stats checks MLDv1 stats.
func CheckMLDv1Stats(t *testing.T, s *stack.Stack, reports, leaves, reportsV2 uint64) {
	t.Helper()
	// We still check V2 stats in V1 compatibility tests because the test may send
	// V2 reports before we drop into compatibility mode.
	checkMLDStats(t, s, reports, leaves, reportsV2)
}

// CheckMLDv2Stats checks MLDv2 stats.
func CheckMLDv2Stats(t *testing.T, s *stack.Stack, reports, leaves, reportsV2 uint64) {
	t.Helper()
	// In MLDv2 tests, reports/leaves are just MLDv2 reports.
	checkMLDStats(t, s, 0 /* reports */, 0 /* leaves */, reports+leaves+reportsV2)
}
