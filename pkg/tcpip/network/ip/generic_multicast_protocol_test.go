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
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/network/ip"
)

const (
	addr1 = tcpip.Address("\x01")
	addr2 = tcpip.Address("\x02")
	addr3 = tcpip.Address("\x03")
)

var _ ip.MulticastGroupProtocol = (*mockMulticastGroupProtocol)(nil)

type mockMulticastGroupProtocol struct {
	sendReportGroupAddrCount map[tcpip.Address]int
	sendLeaveGroupAddr       tcpip.Address
}

func (m *mockMulticastGroupProtocol) init() {
	m.sendReportGroupAddrCount = make(map[tcpip.Address]int)
	m.sendLeaveGroupAddr = ""
}

func (m *mockMulticastGroupProtocol) SendReport(groupAddress tcpip.Address) *tcpip.Error {
	m.sendReportGroupAddrCount[groupAddress]++
	return nil
}

func (m *mockMulticastGroupProtocol) SendLeave(groupAddress tcpip.Address) *tcpip.Error {
	m.sendLeaveGroupAddr = groupAddress
	return nil
}

func checkProtocol(mgp *mockMulticastGroupProtocol, sendReportGroupAddresses []tcpip.Address, sendLeaveGroupAddr tcpip.Address) string {
	sendReportGroupAddressesMap := make(map[tcpip.Address]int)
	for _, a := range sendReportGroupAddresses {
		sendReportGroupAddressesMap[a] = 1
	}

	diff := cmp.Diff(mockMulticastGroupProtocol{
		sendReportGroupAddrCount: sendReportGroupAddressesMap,
		sendLeaveGroupAddr:       sendLeaveGroupAddr,
	}, *mgp, cmp.AllowUnexported(mockMulticastGroupProtocol{}))
	mgp.init()
	return diff
}

func TestJoinGroup(t *testing.T) {
	const maxUnsolicitedReportDelay = time.Second

	var g ip.GenericMulticastProtocolState
	var mgp mockMulticastGroupProtocol
	mgp.init()
	clock := faketime.NewManualClock()
	g.Init(rand.New(rand.NewSource(0)), clock, &mgp, maxUnsolicitedReportDelay)

	// Joining a group should send a report immediately and another after
	// a random interval between 0 and the maximum unsolicited report delay.
	if !g.JoinGroup(addr1) {
		t.Errorf("got g.JoinGroup(%s) = false, want = true", addr1)
	}
	if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	clock.Advance(maxUnsolicitedReportDelay)
	if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should have no more messages to send.
	clock.Advance(time.Hour)
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
}

func TestLeaveGroup(t *testing.T) {
	const maxUnsolicitedReportDelay = time.Second

	var g ip.GenericMulticastProtocolState
	var mgp mockMulticastGroupProtocol
	mgp.init()
	clock := faketime.NewManualClock()
	g.Init(rand.New(rand.NewSource(1)), clock, &mgp, maxUnsolicitedReportDelay)

	if !g.JoinGroup(addr1) {
		t.Fatalf("got g.JoinGroup(%s) = false, want = true", addr1)
	}
	if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Leaving a group should send a leave report immediately and cancel any
	// delayed reports.
	g.LeaveGroup(addr1)
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, addr1 /* sendLeaveGroupAddr */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should have no more messages to send.
	clock.Advance(time.Hour)
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
}

func TestHandleReport(t *testing.T) {
	const maxUnsolicitedReportDelay = time.Second

	tests := []struct {
		name             string
		reportAddr       tcpip.Address
		expectReportsFor []tcpip.Address
	}{
		{
			name:             "Unpecified empty",
			reportAddr:       "",
			expectReportsFor: []tcpip.Address{addr1, addr2},
		},
		{
			name:             "Unpecified any",
			reportAddr:       "\x00",
			expectReportsFor: []tcpip.Address{addr1, addr2},
		},
		{
			name:             "Specified",
			reportAddr:       addr1,
			expectReportsFor: []tcpip.Address{addr2},
		},
		{
			name:             "Specified other",
			reportAddr:       addr3,
			expectReportsFor: []tcpip.Address{addr1, addr2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var g ip.GenericMulticastProtocolState
			var mgp mockMulticastGroupProtocol
			mgp.init()
			clock := faketime.NewManualClock()
			g.Init(rand.New(rand.NewSource(2)), clock, &mgp, maxUnsolicitedReportDelay)

			if !g.JoinGroup(addr1) {
				t.Fatalf("got g.JoinGroup(%s) = false, want = true", addr1)
			}
			if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			if !g.JoinGroup(addr2) {
				t.Fatalf("got g.JoinGroup(%s) = false, want = true", addr2)
			}
			if diff := checkProtocol(&mgp, []tcpip.Address{addr2} /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a report for a group we have a timer scheduled for should
			// cancel our delayed report timer for the group.
			g.HandleReport(test.reportAddr)
			if len(test.expectReportsFor) != 0 {
				clock.Advance(maxUnsolicitedReportDelay)
				if diff := checkProtocol(&mgp, test.expectReportsFor /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHandleQuery(t *testing.T) {
	const maxUnsolicitedReportDelay = time.Second

	tests := []struct {
		name             string
		queryAddr        tcpip.Address
		maxDelay         time.Duration
		expectReportsFor []tcpip.Address
	}{
		{
			name:             "Unpecified empty",
			queryAddr:        "",
			maxDelay:         0,
			expectReportsFor: []tcpip.Address{addr1, addr2},
		},
		{
			name:             "Unpecified any",
			queryAddr:        "\x00",
			maxDelay:         1,
			expectReportsFor: []tcpip.Address{addr1, addr2},
		},
		{
			name:             "Specified",
			queryAddr:        addr1,
			maxDelay:         2,
			expectReportsFor: []tcpip.Address{addr1},
		},
		{
			name:             "Specified other",
			queryAddr:        addr3,
			maxDelay:         3,
			expectReportsFor: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var g ip.GenericMulticastProtocolState
			var mgp mockMulticastGroupProtocol
			mgp.init()
			clock := faketime.NewManualClock()
			g.Init(rand.New(rand.NewSource(3)), clock, &mgp, maxUnsolicitedReportDelay)

			if !g.JoinGroup(addr1) {
				t.Fatalf("got g.JoinGroup(%s) = false, want = true", addr1)
			}
			if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			if !g.JoinGroup(addr2) {
				t.Fatalf("got g.JoinGroup(%s) = false, want = true", addr2)
			}
			if diff := checkProtocol(&mgp, []tcpip.Address{addr2} /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			clock.Advance(maxUnsolicitedReportDelay)
			if diff := checkProtocol(&mgp, []tcpip.Address{addr1, addr2} /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a query should make us schedule a new delayed report if it
			// is a query directed at us or a general query.
			g.HandleQuery(test.queryAddr, test.maxDelay)
			if len(test.expectReportsFor) != 0 {
				clock.Advance(test.maxDelay)
				if diff := checkProtocol(&mgp, test.expectReportsFor /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, "" /* sendLeaveGroupAddr */); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDoubleJoinGroup(t *testing.T) {
	var g ip.GenericMulticastProtocolState
	var mgp mockMulticastGroupProtocol
	mgp.init()
	clock := faketime.NewManualClock()
	g.Init(rand.New(rand.NewSource(4)), clock, &mgp, time.Second)

	if !g.JoinGroup(addr1) {
		t.Fatalf("got g.JoinGroup(%s) = false, want = true", addr1)
	}

	// Joining the same group twice should fail.
	if g.JoinGroup(addr1) {
		t.Errorf("got g.JoinGroup(%s) = true, want = false", addr1)
	}
}
