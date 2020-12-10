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
	"gvisor.dev/gvisor/pkg/sync"
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
	t *testing.T

	mu sync.RWMutex

	// Must only be accessed with mu held.
	sendReportGroupAddrCount map[tcpip.Address]int

	// Must only be accessed with mu held.
	sendLeaveGroupAddrCount map[tcpip.Address]int

	// Must only be accessed with mu held.
	makeQueuePackets bool
}

func (m *mockMulticastGroupProtocol) init() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initLocked()
}

func (m *mockMulticastGroupProtocol) initLocked() {
	m.sendReportGroupAddrCount = make(map[tcpip.Address]int)
	m.sendLeaveGroupAddrCount = make(map[tcpip.Address]int)
}

func (m *mockMulticastGroupProtocol) SendReport(groupAddress tcpip.Address) (bool, *tcpip.Error) {
	if m.mu.TryLock() {
		m.mu.Unlock()
		m.t.Fatalf("got write lock, expected to not take the lock; generic multicast protocol must take the write lock before sending report for %s", groupAddress)
	}
	if m.mu.TryRLock() {
		m.mu.RUnlock()
		m.t.Fatalf("got read lock, expected to not take the lock; generic multicast protocol must take the write lock before sending report for %s", groupAddress)
	}

	m.sendReportGroupAddrCount[groupAddress]++
	return !m.makeQueuePackets, nil
}

func (m *mockMulticastGroupProtocol) SendLeave(groupAddress tcpip.Address) *tcpip.Error {
	if m.mu.TryLock() {
		m.mu.Unlock()
		m.t.Fatalf("got write lock, expected to not take the lock; generic multicast protocol must take the write lock before sending leave for %s", groupAddress)
	}
	if m.mu.TryRLock() {
		m.mu.RUnlock()
		m.t.Fatalf("got read lock, expected to not take the lock; generic multicast protocol must take the write lock before sending leave for %s", groupAddress)
	}

	m.sendLeaveGroupAddrCount[groupAddress]++
	return nil
}

func (m *mockMulticastGroupProtocol) check(sendReportGroupAddresses []tcpip.Address, sendLeaveGroupAddresses []tcpip.Address) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	sendReportGroupAddrCount := make(map[tcpip.Address]int)
	for _, a := range sendReportGroupAddresses {
		sendReportGroupAddrCount[a] = 1
	}

	sendLeaveGroupAddrCount := make(map[tcpip.Address]int)
	for _, a := range sendLeaveGroupAddresses {
		sendLeaveGroupAddrCount[a] = 1
	}

	diff := cmp.Diff(
		&mockMulticastGroupProtocol{
			sendReportGroupAddrCount: sendReportGroupAddrCount,
			sendLeaveGroupAddrCount:  sendLeaveGroupAddrCount,
		},
		m,
		cmp.AllowUnexported(mockMulticastGroupProtocol{}),
		// ignore mockMulticastGroupProtocol.mu and mockMulticastGroupProtocol.t
		cmp.FilterPath(
			func(p cmp.Path) bool {
				return p.Last().String() == ".mu" || p.Last().String() == ".t" || p.Last().String() == ".makeQueuePackets"
			},
			cmp.Ignore(),
		),
	)
	m.initLocked()
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
			mgp := mockMulticastGroupProtocol{t: t}
			clock := faketime.NewManualClock()

			mgp.init()
			g.Init(&mgp.mu, ip.GenericMulticastProtocolOptions{
				Enabled:                   true,
				Rand:                      rand.New(rand.NewSource(0)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
				AllNodesAddress:           addr2,
			})

			// Joining a group should send a report immediately and another after
			// a random interval between 0 and the maximum unsolicited report delay.
			mgp.mu.Lock()
			g.JoinGroupLocked(test.addr, false /* dontInitialize */)
			mgp.mu.Unlock()
			if test.shouldSendReports {
				if diff := mgp.check([]tcpip.Address{test.addr} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}

				// Generic multicast protocol timers are expected to take the job mutex.
				clock.Advance(maxUnsolicitedReportDelay)
				if diff := mgp.check([]tcpip.Address{test.addr} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
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
			mgp := mockMulticastGroupProtocol{t: t}
			clock := faketime.NewManualClock()

			mgp.init()
			g.Init(&mgp.mu, ip.GenericMulticastProtocolOptions{
				Enabled:                   true,
				Rand:                      rand.New(rand.NewSource(1)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
				AllNodesAddress:           addr2,
			})

			mgp.mu.Lock()
			g.JoinGroupLocked(test.addr, false /* dontInitialize */)
			mgp.mu.Unlock()
			if test.shouldSendMessages {
				if diff := mgp.check([]tcpip.Address{test.addr} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Leaving a group should send a leave report immediately and cancel any
			// delayed reports.
			{
				mgp.mu.Lock()
				res := g.LeaveGroupLocked(test.addr)
				mgp.mu.Unlock()
				if !res {
					t.Fatalf("got g.LeaveGroupLocked(%s) = false, want = true", test.addr)
				}
			}
			if test.shouldSendMessages {
				if diff := mgp.check(nil /* sendReportGroupAddresses */, []tcpip.Address{test.addr} /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			//
			// Generic multicast protocol timers are expected to take the job mutex.
			clock.Advance(time.Hour)
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
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
			mgp := mockMulticastGroupProtocol{t: t}
			clock := faketime.NewManualClock()

			mgp.init()
			g.Init(&mgp.mu, ip.GenericMulticastProtocolOptions{
				Enabled:                   true,
				Rand:                      rand.New(rand.NewSource(2)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
				AllNodesAddress:           addr3,
			})

			mgp.mu.Lock()
			g.JoinGroupLocked(addr1, false /* dontInitialize */)
			mgp.mu.Unlock()
			if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.mu.Lock()
			g.JoinGroupLocked(addr2, false /* dontInitialize */)
			mgp.mu.Unlock()
			if diff := mgp.check([]tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.mu.Lock()
			g.JoinGroupLocked(addr3, false /* dontInitialize */)
			mgp.mu.Unlock()
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a report for a group we have a timer scheduled for should
			// cancel our delayed report timer for the group.
			mgp.mu.Lock()
			g.HandleReportLocked(test.reportAddr)
			mgp.mu.Unlock()
			if len(test.expectReportsFor) != 0 {
				// Generic multicast protocol timers are expected to take the job mutex.
				clock.Advance(maxUnsolicitedReportDelay)
				if diff := mgp.check(test.expectReportsFor /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
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
			mgp := mockMulticastGroupProtocol{t: t}
			clock := faketime.NewManualClock()

			mgp.init()
			g.Init(&mgp.mu, ip.GenericMulticastProtocolOptions{
				Enabled:                   true,
				Rand:                      rand.New(rand.NewSource(3)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
				AllNodesAddress:           addr3,
			})

			mgp.mu.Lock()
			g.JoinGroupLocked(addr1, false /* dontInitialize */)
			mgp.mu.Unlock()
			if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.mu.Lock()
			g.JoinGroupLocked(addr2, false /* dontInitialize */)
			mgp.mu.Unlock()
			if diff := mgp.check([]tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.mu.Lock()
			g.JoinGroupLocked(addr3, false /* dontInitialize */)
			mgp.mu.Unlock()
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			// Generic multicast protocol timers are expected to take the job mutex.
			clock.Advance(maxUnsolicitedReportDelay)
			if diff := mgp.check([]tcpip.Address{addr1, addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a query should make us schedule a new delayed report if it
			// is a query directed at us or a general query.
			mgp.mu.Lock()
			g.HandleQueryLocked(test.queryAddr, test.maxDelay)
			mgp.mu.Unlock()
			if len(test.expectReportsFor) != 0 {
				clock.Advance(test.maxDelay)
				if diff := mgp.check(test.expectReportsFor /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestJoinCount(t *testing.T) {
	var g ip.GenericMulticastProtocolState
	mgp := mockMulticastGroupProtocol{t: t}
	clock := faketime.NewManualClock()

	mgp.init()
	g.Init(&mgp.mu, ip.GenericMulticastProtocolOptions{
		Enabled:                   true,
		Rand:                      rand.New(rand.NewSource(4)),
		Clock:                     clock,
		Protocol:                  &mgp,
		MaxUnsolicitedReportDelay: time.Second,
	})

	// Set the join count to 2 for a group.
	{
		mgp.mu.Lock()
		g.JoinGroupLocked(addr1, false /* dontInitialize */)
		res := g.IsLocallyJoinedRLocked(addr1)
		mgp.mu.Unlock()
		if !res {
			t.Fatalf("got g.IsLocallyJoinedRLocked(%s) = false, want = true", addr1)
		}
	}
	// Only the first join should trigger a report to be sent.
	if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	{
		mgp.mu.Lock()
		g.JoinGroupLocked(addr1, false /* dontInitialize */)
		res := g.IsLocallyJoinedRLocked(addr1)
		mgp.mu.Unlock()
		if !res {
			t.Errorf("got g.IsLocallyJoinedRLocked(%s) = false, want = true", addr1)
		}
	}
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	if t.Failed() {
		t.FailNow()
	}

	// Group should still be considered joined after leaving once.
	{
		mgp.mu.Lock()
		leaveGroupRes := g.LeaveGroupLocked(addr1)
		isLocallyJoined := g.IsLocallyJoinedRLocked(addr1)
		mgp.mu.Unlock()
		if !leaveGroupRes {
			t.Errorf("got g.LeaveGroupLocked(%s) = false, want = true", addr1)
		}
		if !isLocallyJoined {
			t.Errorf("got g.IsLocallyJoinedRLocked(%s) = false, want = true", addr1)
		}
	}
	// A leave report should only be sent once the join count reaches 0.
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	if t.Failed() {
		t.FailNow()
	}

	// Leaving once more should actually remove us from the group.
	{
		mgp.mu.Lock()
		leaveGroupRes := g.LeaveGroupLocked(addr1)
		isLocallyJoined := g.IsLocallyJoinedRLocked(addr1)
		mgp.mu.Unlock()
		if !leaveGroupRes {
			t.Errorf("got g.LeaveGroupLocked(%s) = false, want = true", addr1)
		}
		if isLocallyJoined {
			t.Errorf("got g.IsLocallyJoinedRLocked(%s) = true, want = false", addr1)
		}
	}
	if diff := mgp.check(nil /* sendReportGroupAddresses */, []tcpip.Address{addr1} /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	if t.Failed() {
		t.FailNow()
	}

	// Group should no longer be joined so we should not have anything to
	// leave.
	{
		mgp.mu.Lock()
		leaveGroupRes := g.LeaveGroupLocked(addr1)
		isLocallyJoined := g.IsLocallyJoinedRLocked(addr1)
		mgp.mu.Unlock()
		if leaveGroupRes {
			t.Errorf("got g.LeaveGroupLocked(%s) = true, want = false", addr1)
		}
		if isLocallyJoined {
			t.Errorf("got g.IsLocallyJoinedRLocked(%s) = true, want = false", addr1)
		}
	}
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should have no more messages to send.
	//
	// Generic multicast protocol timers are expected to take the job mutex.
	clock.Advance(time.Hour)
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
}

func TestMakeAllNonMemberAndInitialize(t *testing.T) {
	var g ip.GenericMulticastProtocolState
	mgp := mockMulticastGroupProtocol{t: t}
	clock := faketime.NewManualClock()

	mgp.init()
	g.Init(&mgp.mu, ip.GenericMulticastProtocolOptions{
		Enabled:                   true,
		Rand:                      rand.New(rand.NewSource(3)),
		Clock:                     clock,
		Protocol:                  &mgp,
		MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
		AllNodesAddress:           addr3,
	})

	mgp.mu.Lock()
	g.JoinGroupLocked(addr1, false /* dontInitialize */)
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	mgp.mu.Lock()
	g.JoinGroupLocked(addr2, false /* dontInitialize */)
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	mgp.mu.Lock()
	g.JoinGroupLocked(addr3, false /* dontInitialize */)
	mgp.mu.Unlock()
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should send the leave reports for each but still consider them locally
	// joined.
	mgp.mu.Lock()
	g.MakeAllNonMemberLocked()
	mgp.mu.Unlock()
	if diff := mgp.check(nil /* sendReportGroupAddresses */, []tcpip.Address{addr1, addr2} /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	// Generic multicast protocol timers are expected to take the job mutex.
	clock.Advance(time.Hour)
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	for _, group := range []tcpip.Address{addr1, addr2, addr3} {
		mgp.mu.RLock()
		res := g.IsLocallyJoinedRLocked(group)
		mgp.mu.RUnlock()
		if !res {
			t.Fatalf("got g.IsLocallyJoinedRLocked(%s) = false, want = true", group)
		}
	}

	// Should send the initial set of unsolcited reports.
	mgp.mu.Lock()
	g.InitializeGroupsLocked()
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr1, addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	clock.Advance(maxUnsolicitedReportDelay)
	if diff := mgp.check([]tcpip.Address{addr1, addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should have no more messages to send.
	clock.Advance(time.Hour)
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
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
			mgp := mockMulticastGroupProtocol{t: t}
			clock := faketime.NewManualClock()

			mgp.init()
			g.Init(&mgp.mu, ip.GenericMulticastProtocolOptions{
				Enabled:                   test.enabled,
				Rand:                      rand.New(rand.NewSource(3)),
				Clock:                     clock,
				Protocol:                  &mgp,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
			})

			// Joining groups should not send any reports.
			{
				mgp.mu.Lock()
				g.JoinGroupLocked(addr1, test.dontInitialize)
				res := g.IsLocallyJoinedRLocked(addr1)
				mgp.mu.Unlock()
				if !res {
					t.Fatalf("got g.IsLocallyJoinedRLocked(%s) = false, want = true", addr1)
				}
			}
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			{
				mgp.mu.Lock()
				g.JoinGroupLocked(addr2, test.dontInitialize)
				res := g.IsLocallyJoinedRLocked(addr2)
				mgp.mu.Unlock()
				if !res {
					t.Fatalf("got g.IsLocallyJoinedRLocked(%s) = false, want = true", addr2)
				}
			}
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a query should not send any reports.
			mgp.mu.Lock()
			g.HandleQueryLocked(addr1, time.Nanosecond)
			mgp.mu.Unlock()
			// Generic multicast protocol timers are expected to take the job mutex.
			clock.Advance(time.Nanosecond)
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Leaving groups should not send any leave messages.
			{
				mgp.mu.Lock()
				addr2LeaveRes := g.LeaveGroupLocked(addr2)
				addr1IsJoined := g.IsLocallyJoinedRLocked(addr1)
				addr2IsJoined := g.IsLocallyJoinedRLocked(addr2)
				mgp.mu.Unlock()
				if !addr2LeaveRes {
					t.Errorf("got g.LeaveGroupLocked(%s) = false, want = true", addr2)
				}
				if !addr1IsJoined {
					t.Errorf("got g.IsLocallyJoinedRLocked(%s) = false, want = true", addr1)
				}
				if addr2IsJoined {
					t.Errorf("got g.IsLocallyJoinedRLocked(%s) = true, want = false", addr2)
				}
			}
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			clock.Advance(time.Hour)
			if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestQueuedPackets(t *testing.T) {
	var g ip.GenericMulticastProtocolState
	var mgp mockMulticastGroupProtocol
	mgp.init()
	clock := faketime.NewManualClock()
	g.Init(&mgp.mu, ip.GenericMulticastProtocolOptions{
		Enabled:                   true,
		Rand:                      rand.New(rand.NewSource(4)),
		Clock:                     clock,
		Protocol:                  &mgp,
		MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
	})

	// Joining should trigger a SendReport, but mgp should report that we did not
	// send the packet.
	mgp.mu.Lock()
	mgp.makeQueuePackets = true
	g.JoinGroupLocked(addr1, false /* dontInitialize */)
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// The delayed report timer should have been cancelled since we did not send
	// the initial report earlier.
	clock.Advance(time.Hour)
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Mock being able to successfully send the report.
	mgp.mu.Lock()
	mgp.makeQueuePackets = false
	g.SendQueuedReportsLocked()
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// The delayed report (sent after the initial report) should now be sent.
	clock.Advance(maxUnsolicitedReportDelay)
	if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should not have anything else to send (we should be idle).
	mgp.mu.Lock()
	g.SendQueuedReportsLocked()
	mgp.mu.Unlock()
	clock.Advance(time.Hour)
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Receive a query but mock being unable to send reports again.
	mgp.mu.Lock()
	mgp.makeQueuePackets = true
	g.HandleQueryLocked(addr1, time.Nanosecond)
	mgp.mu.Unlock()
	clock.Advance(time.Nanosecond)
	if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Mock being able to send reports again - we should have a packet queued to
	// send.
	mgp.mu.Lock()
	mgp.makeQueuePackets = false
	g.SendQueuedReportsLocked()
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should not have anything else to send.
	mgp.mu.Lock()
	g.SendQueuedReportsLocked()
	mgp.mu.Unlock()
	clock.Advance(time.Hour)
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Receive a query again, but mock being unable to send reports.
	mgp.mu.Lock()
	mgp.makeQueuePackets = true
	g.HandleQueryLocked(addr1, time.Nanosecond)
	mgp.mu.Unlock()
	clock.Advance(time.Nanosecond)
	if diff := mgp.check([]tcpip.Address{addr1} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Receiving a report should should transition us into the idle member state,
	// even if we had a packet queued. We should no longer have any packets to
	// send.
	mgp.mu.Lock()
	g.HandleReportLocked(addr1)
	g.SendQueuedReportsLocked()
	mgp.mu.Unlock()
	clock.Advance(time.Hour)
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// When we fail to send the initial set of reports, incoming reports should
	// not affect a newly joined group's reports from being sent.
	mgp.mu.Lock()
	mgp.makeQueuePackets = true
	g.JoinGroupLocked(addr2, false /* dontInitialize */)
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	mgp.mu.Lock()
	g.HandleReportLocked(addr2)
	// Attempting to send queued reports while still unable to send reports should
	// not change the host state.
	g.SendQueuedReportsLocked()
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	// Mock being able to successfully send the report.
	mgp.mu.Lock()
	mgp.makeQueuePackets = false
	g.SendQueuedReportsLocked()
	mgp.mu.Unlock()
	if diff := mgp.check([]tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
	// The delayed report (sent after the initial report) should now be sent.
	clock.Advance(maxUnsolicitedReportDelay)
	if diff := mgp.check([]tcpip.Address{addr2} /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	// Should not have anything else to send.
	mgp.mu.Lock()
	g.SendQueuedReportsLocked()
	mgp.mu.Unlock()
	clock.Advance(time.Hour)
	if diff := mgp.check(nil /* sendReportGroupAddresses */, nil /* sendLeaveGroupAddresses */); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
}
