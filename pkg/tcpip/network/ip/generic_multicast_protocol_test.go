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
	addr4 = tcpip.Address("\x04")

	maxUnsolicitedReportDelay = time.Second
)

var _ ip.MulticastGroupProtocol = (*mockMulticastGroupProtocol)(nil)

type mockMulticastGroupProtocol struct {
	sendReportGroupAddrCount map[tcpip.Address]int
	sendLeaveGroupAddrCount  map[tcpip.Address]int
}

func (m *mockMulticastGroupProtocol) init() {
	m.sendReportGroupAddrCount = make(map[tcpip.Address]int)
	m.sendLeaveGroupAddrCount = make(map[tcpip.Address]int)
}

func (m *mockMulticastGroupProtocol) SendReport(groupAddress tcpip.Address) *tcpip.Error {
	m.sendReportGroupAddrCount[groupAddress]++
	return nil
}

func (m *mockMulticastGroupProtocol) SendLeave(groupAddress tcpip.Address) *tcpip.Error {
	m.sendLeaveGroupAddrCount[groupAddress]++
	return nil
}

func checkProtocol(mgp *mockMulticastGroupProtocol, sendReportGroupAddresses []tcpip.Address, sendLeaveGroupAddresses []tcpip.Address) string {
	sendReportGroupAddressesMap := make(map[tcpip.Address]int)
	for _, a := range sendReportGroupAddresses {
		sendReportGroupAddressesMap[a] = 1
	}

	sendLeaveGroupAddressesMap := make(map[tcpip.Address]int)
	for _, a := range sendLeaveGroupAddresses {
		sendLeaveGroupAddressesMap[a] = 1
	}

	diff := cmp.Diff(mockMulticastGroupProtocol{
		sendReportGroupAddrCount: sendReportGroupAddressesMap,
		sendLeaveGroupAddrCount:  sendLeaveGroupAddressesMap,
	}, *mgp, cmp.AllowUnexported(mockMulticastGroupProtocol{}))
	mgp.init()
	return diff
}

func TestJoinGroup(t *testing.T) {
	tests := []struct {
		name              string
		addr              tcpip.Address
		shouldSendReports bool
	}{
		{
			name:              "Normal group",
			addr:              addr1,
			shouldSendReports: true,
		},
		{
			name:              "All-nodes group",
			addr:              addr2,
			shouldSendReports: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var g ip.GenericMulticastProtocolState
			var mgp mockMulticastGroupProtocol
			mgp.init()
			clock := faketime.NewManualClock()
			g.Init(ip.GenericMulticastProtocolOptions{
				Enabled:                   true,
				Rand:                      rand.New(rand.NewSource(0)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
				AllNodesAddress:           addr2,
			})

			// Joining a group should send a report immediately and another after
			// a random interval between 0 and the maximum unsolicited report delay.
			g.JoinGroup(test.addr, false /* dontInitialize */)
			if test.shouldSendReports {
				if diff := checkProtocol(&mgp, []tcpip.Address{test.addr} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}

				clock.Advance(maxUnsolicitedReportDelay)
				if diff := checkProtocol(&mgp, []tcpip.Address{test.addr} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLeaveGroup(t *testing.T) {
	tests := []struct {
		name               string
		addr               tcpip.Address
		shouldSendMessages bool
	}{
		{
			name:               "Normal group",
			addr:               addr1,
			shouldSendMessages: true,
		},
		{
			name:               "All-nodes group",
			addr:               addr2,
			shouldSendMessages: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var g ip.GenericMulticastProtocolState
			var mgp mockMulticastGroupProtocol
			mgp.init()
			clock := faketime.NewManualClock()
			g.Init(ip.GenericMulticastProtocolOptions{
				Enabled:                   true,
				Rand:                      rand.New(rand.NewSource(1)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
				AllNodesAddress:           addr2,
			})

			g.JoinGroup(test.addr, false /* dontInitialize */)
			if test.shouldSendMessages {
				if diff := checkProtocol(&mgp, []tcpip.Address{test.addr} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Leaving a group should send a leave report immediately and cancel any
			// delayed reports.
			if !g.LeaveGroup(test.addr) {
				t.Fatalf("got g.LeaveGroup(%s) = false, want = true", test.addr)
			}
			if test.shouldSendMessages {
				if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, []tcpip.Address{test.addr} /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHandleReport(t *testing.T) {
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
			name:             "Specified all-nodes",
			reportAddr:       addr3,
			expectReportsFor: []tcpip.Address{addr1, addr2},
		},
		{
			name:             "Specified other",
			reportAddr:       addr4,
			expectReportsFor: []tcpip.Address{addr1, addr2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var g ip.GenericMulticastProtocolState
			var mgp mockMulticastGroupProtocol
			mgp.init()
			clock := faketime.NewManualClock()
			g.Init(ip.GenericMulticastProtocolOptions{
				Enabled:                   true,
				Rand:                      rand.New(rand.NewSource(2)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
				AllNodesAddress:           addr3,
			})

			g.JoinGroup(addr1, false /* dontInitialize */)
			if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			g.JoinGroup(addr2, false /* dontInitialize */)
			if diff := checkProtocol(&mgp, []tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			g.JoinGroup(addr3, false /* dontInitialize */)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a report for a group we have a timer scheduled for should
			// cancel our delayed report timer for the group.
			g.HandleReport(test.reportAddr)
			if len(test.expectReportsFor) != 0 {
				clock.Advance(maxUnsolicitedReportDelay)
				if diff := checkProtocol(&mgp, test.expectReportsFor /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHandleQuery(t *testing.T) {
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
			name:             "Specified all-nodes",
			queryAddr:        addr3,
			maxDelay:         3,
			expectReportsFor: nil,
		},
		{
			name:             "Specified other",
			queryAddr:        addr4,
			maxDelay:         4,
			expectReportsFor: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var g ip.GenericMulticastProtocolState
			var mgp mockMulticastGroupProtocol
			mgp.init()
			clock := faketime.NewManualClock()
			g.Init(ip.GenericMulticastProtocolOptions{
				Enabled:                   true,
				Rand:                      rand.New(rand.NewSource(3)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
				AllNodesAddress:           addr3,
			})

			g.JoinGroup(addr1, false /* dontInitialize */)
			if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			g.JoinGroup(addr2, false /* dontInitialize */)
			if diff := checkProtocol(&mgp, []tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			g.JoinGroup(addr3, false /* dontInitialize */)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			clock.Advance(maxUnsolicitedReportDelay)
			if diff := checkProtocol(&mgp, []tcpip.Address{addr1, addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a query should make us schedule a new delayed report if it
			// is a query directed at us or a general query.
			g.HandleQuery(test.queryAddr, test.maxDelay)
			if len(test.expectReportsFor) != 0 {
				clock.Advance(test.maxDelay)
				if diff := checkProtocol(&mgp, test.expectReportsFor /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestJoinCount(t *testing.T) {
	var g ip.GenericMulticastProtocolState
	var mgp mockMulticastGroupProtocol
	mgp.init()
	clock := faketime.NewManualClock()
	g.Init(ip.GenericMulticastProtocolOptions{
		Enabled:                   true,
		Rand:                      rand.New(rand.NewSource(4)),
		Clock:                     clock,
		Protocol:                  &mgp,
		MaxUnsolicitedReportDelay: time.Second,
	})

	// Set the join count to 2 for a group.
	g.JoinGroup(addr1, false /* dontInitialize */)
	if !g.IsLocallyJoined(addr1) {
		t.Fatalf("got g.IsLocallyJoined(%s) = false, want = true", addr1)
	}
	// Only the first join should trigger a report to be sent.
	if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	g.JoinGroup(addr1, false /* dontInitialize */)
	if !g.IsLocallyJoined(addr1) {
		t.Fatalf("got g.IsLocallyJoined(%s) = false, want = true", addr1)
	}
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Group should still be considered joined after leaving once.
	if !g.LeaveGroup(addr1) {
		t.Fatalf("got g.LeaveGroup(%s) = false, want = true", addr1)
	}
	if !g.IsLocallyJoined(addr1) {
		t.Fatalf("got g.IsLocallyJoined(%s) = false, want = true", addr1)
	}
	// A leave report should only be sent once the join count reaches 0.
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Leaving once more should actually remove us from the group.
	if !g.LeaveGroup(addr1) {
		t.Fatalf("got g.LeaveGroup(%s) = false, want = true", addr1)
	}
	if g.IsLocallyJoined(addr1) {
		t.Fatalf("got g.IsLocallyJoined(%s) = true, want = false", addr1)
	}
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, []tcpip.Address{addr1} /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Group should no longer be joined so we should not have anything to
	// leave.
	if g.LeaveGroup(addr1) {
		t.Fatalf("got g.LeaveGroup(%s) = true, want = false", addr1)
	}
	if g.IsLocallyJoined(addr1) {
		t.Fatalf("got g.IsLocallyJoined(%s) = true, want = false", addr1)
	}
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should have no more messages to send.
	clock.Advance(time.Hour)
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
}

func TestMakeAllNonMemberAndInitialize(t *testing.T) {
	var g ip.GenericMulticastProtocolState
	var mgp mockMulticastGroupProtocol
	mgp.init()
	clock := faketime.NewManualClock()
	g.Init(ip.GenericMulticastProtocolOptions{
		Enabled:                   true,
		Rand:                      rand.New(rand.NewSource(3)),
		Clock:                     clock,
		Protocol:                  &mgp,
		MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
		AllNodesAddress:           addr3,
	})

	g.JoinGroup(addr1, false /* dontInitialize */)
	if diff := checkProtocol(&mgp, []tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	g.JoinGroup(addr2, false /* dontInitialize */)
	if diff := checkProtocol(&mgp, []tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	g.JoinGroup(addr3, false /* dontInitialize */)
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should send the leave reports for each but still consider them locally
	// joined.
	g.MakeAllNonMember()
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, []tcpip.Address{addr1, addr2} /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	clock.Advance(time.Hour)
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	for _, group := range []tcpip.Address{addr1, addr2, addr3} {
		if !g.IsLocallyJoined(group) {
			t.Fatalf("got g.IsLocallyJoined(%s) = false, want = true", group)
		}
	}

	// Should send the initial set of unsolcited reports.
	g.InitializeGroups()
	if diff := checkProtocol(&mgp, []tcpip.Address{addr1, addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	clock.Advance(maxUnsolicitedReportDelay)
	if diff := checkProtocol(&mgp, []tcpip.Address{addr1, addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should have no more messages to send.
	clock.Advance(time.Hour)
	if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
}

// TestGroupStateNonMember tests that groups do not send packets when in the
// non-member state, but are still considered locally joined.
func TestGroupStateNonMember(t *testing.T) {
	tests := []struct {
		name           string
		enabled        bool
		dontInitialize bool
	}{
		{
			name:           "Disabled",
			enabled:        false,
			dontInitialize: false,
		},
		{
			name:           "Keep non-member",
			enabled:        true,
			dontInitialize: true,
		},
		{
			name:           "disabled and Keep non-member",
			enabled:        false,
			dontInitialize: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var g ip.GenericMulticastProtocolState
			var mgp mockMulticastGroupProtocol
			mgp.init()
			clock := faketime.NewManualClock()
			g.Init(ip.GenericMulticastProtocolOptions{
				Enabled:                   test.enabled,
				Rand:                      rand.New(rand.NewSource(3)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
			})

			g.JoinGroup(addr1, test.dontInitialize)
			if !g.IsLocallyJoined(addr1) {
				t.Fatalf("got g.IsLocallyJoined(%s) = false, want = true", addr1)
			}
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			g.JoinGroup(addr2, test.dontInitialize)
			if !g.IsLocallyJoined(addr2) {
				t.Fatalf("got g.IsLocallyJoined(%s) = false, want = true", addr2)
			}
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			g.HandleQuery(addr1, time.Nanosecond)
			clock.Advance(time.Nanosecond)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			if !g.LeaveGroup(addr2) {
				t.Errorf("got g.LeaveGroup(%s) = false, want = true", addr2)
			}
			if !g.IsLocallyJoined(addr1) {
				t.Fatalf("got g.IsLocallyJoined(%s) = false, want = true", addr1)
			}
			if g.IsLocallyJoined(addr2) {
				t.Fatalf("got g.IsLocallyJoined(%s) = true, want = false", addr2)
			}
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			clock.Advance(time.Hour)
			if diff := checkProtocol(&mgp, nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
