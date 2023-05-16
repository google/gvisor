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
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
)

const maxUnsolicitedReportDelay = time.Second

var _ ip.MulticastGroupProtocol = (*mockMulticastGroupProtocol)(nil)

type mockMulticastGroupProtocolProtectedFields struct {
	sync.RWMutex

	genericMulticastGroup    ip.GenericMulticastProtocolState
	sendReportGroupAddrCount map[tcpip.Address]int
	sendLeaveGroupAddrCount  map[tcpip.Address]int
	makeQueuePackets         bool
	disabled                 bool
	sentV2Reports            map[tcpip.Address][]ip.MulticastGroupProtocolV2ReportRecordType
}

type mockMulticastGroupProtocol struct {
	t *testing.T

	skipProtocolAddress tcpip.Address

	mu mockMulticastGroupProtocolProtectedFields
}

func (m *mockMulticastGroupProtocol) init(opts ip.GenericMulticastProtocolOptions, v1Compatibility bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initLocked()
	opts.Protocol = m
	m.mu.genericMulticastGroup.Init(&m.mu.RWMutex, opts)

	if v1Compatibility {
		m.mu.genericMulticastGroup.SetV1ModeLocked(true)
	}
}

func (m *mockMulticastGroupProtocol) initLocked() {
	m.mu.sendReportGroupAddrCount = make(map[tcpip.Address]int)
	m.mu.sendLeaveGroupAddrCount = make(map[tcpip.Address]int)
	m.mu.sentV2Reports = make(map[tcpip.Address][]ip.MulticastGroupProtocolV2ReportRecordType)
}

func (m *mockMulticastGroupProtocol) setEnabled(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.disabled = !v
}

func (m *mockMulticastGroupProtocol) setQueuePackets(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.makeQueuePackets = v
}

func (m *mockMulticastGroupProtocol) setV1Mode(v bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.genericMulticastGroup.SetV1ModeLocked(v)
}

func (m *mockMulticastGroupProtocol) getV1Mode() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mu.genericMulticastGroup.GetV1ModeLocked()
}

func (m *mockMulticastGroupProtocol) joinGroup(addr tcpip.Address) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.genericMulticastGroup.JoinGroupLocked(addr)
}

func (m *mockMulticastGroupProtocol) leaveGroup(addr tcpip.Address) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.genericMulticastGroup.LeaveGroupLocked(addr)
}

func (m *mockMulticastGroupProtocol) handleReport(addr tcpip.Address) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.genericMulticastGroup.HandleReportLocked(addr)
}

func (m *mockMulticastGroupProtocol) handleQuery(addr tcpip.Address, maxRespTime time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.genericMulticastGroup.HandleQueryLocked(addr, maxRespTime)
}

func (m *mockMulticastGroupProtocol) handleQueryV2(addr tcpip.Address, maxResponseCode uint16, sources header.AddressIterator, robustnessVariable uint8, queryInterval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.genericMulticastGroup.HandleQueryV2Locked(addr, maxResponseCode, sources, robustnessVariable, queryInterval)
}

func (m *mockMulticastGroupProtocol) isLocallyJoined(addr tcpip.Address) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mu.genericMulticastGroup.IsLocallyJoinedRLocked(addr)
}

func (m *mockMulticastGroupProtocol) makeAllNonMember() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.genericMulticastGroup.MakeAllNonMemberLocked()
}

func (m *mockMulticastGroupProtocol) initializeGroups() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.genericMulticastGroup.InitializeGroupsLocked()
}

func (m *mockMulticastGroupProtocol) sendQueuedReports() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.genericMulticastGroup.SendQueuedReportsLocked()
}

// Enabled implements ip.MulticastGroupProtocol.
//
// Precondition: m.mu must be read locked.
func (m *mockMulticastGroupProtocol) Enabled() bool {
	if m.mu.TryLock() {
		m.mu.Unlock() // +checklocksforce: TryLock.
		m.t.Fatal("got write lock, expected to not take the lock; generic multicast protocol must take the read or write lock before calling Enabled")
	}

	return !m.mu.disabled
}

// SendReport implements ip.MulticastGroupProtocol.
//
// Precondition: m.mu must be locked.
func (m *mockMulticastGroupProtocol) SendReport(groupAddress tcpip.Address) (bool, tcpip.Error) {
	if m.mu.TryLock() {
		m.mu.Unlock() // +checklocksforce: TryLock.
		m.t.Fatalf("got write lock, expected to not take the lock; generic multicast protocol must take the write lock before sending report for %s", groupAddress)
	}
	if m.mu.TryRLock() {
		m.mu.RUnlock() // +checklocksforce: TryLock.
		m.t.Fatalf("got read lock, expected to not take the lock; generic multicast protocol must take the write lock before sending report for %s", groupAddress)
	}

	m.mu.sendReportGroupAddrCount[groupAddress]++
	return !m.mu.makeQueuePackets, nil
}

// SendLeave implements ip.MulticastGroupProtocol.
//
// Precondition: m.mu must be locked.
func (m *mockMulticastGroupProtocol) SendLeave(groupAddress tcpip.Address) tcpip.Error {
	if m.mu.TryLock() {
		m.mu.Unlock() // +checklocksforce: TryLock.
		m.t.Fatalf("got write lock, expected to not take the lock; generic multicast protocol must take the write lock before sending leave for %s", groupAddress)
	}
	if m.mu.TryRLock() {
		m.mu.RUnlock() // +checklocksforce: TryLock.
		m.t.Fatalf("got read lock, expected to not take the lock; generic multicast protocol must take the write lock before sending leave for %s", groupAddress)
	}

	m.mu.sendLeaveGroupAddrCount[groupAddress]++
	return nil
}

// ShouldPerformProtocol implements ip.MulticastGroupProtocol.
func (m *mockMulticastGroupProtocol) ShouldPerformProtocol(groupAddress tcpip.Address) bool {
	return groupAddress != m.skipProtocolAddress
}

type mockReportV2Record struct {
	recordType   ip.MulticastGroupProtocolV2ReportRecordType
	groupAddress tcpip.Address
}

type mockReportV2 struct {
	records []mockReportV2Record
}

type mockReportV2Builder struct {
	m      *mockMulticastGroupProtocol
	report mockReportV2
}

// AddRecord implements ip.MulticastGroupProtocolV2ReportBuilder.
func (b *mockReportV2Builder) AddRecord(recordType ip.MulticastGroupProtocolV2ReportRecordType, groupAddress tcpip.Address) {
	b.report.records = append(b.report.records, mockReportV2Record{recordType: recordType, groupAddress: groupAddress})
}

func recordsToMap(m map[tcpip.Address][]ip.MulticastGroupProtocolV2ReportRecordType, records []mockReportV2Record) {
	for _, record := range records {
		m[record.groupAddress] = append(m[record.groupAddress], record.recordType)
	}
}

// Send implements ip.MulticastGroupProtocolV2ReportBuilder.
func (b *mockReportV2Builder) Send() (sent bool, err tcpip.Error) {
	if b.m.mu.TryLock() {
		b.m.mu.Unlock() // +checklocksforce: TryLock.
		b.m.t.Fatal("got write lock, expected to not take the lock; generic multicast protocol must take the write lock before sending v2 report")
	}
	if b.m.mu.TryRLock() {
		b.m.mu.RUnlock() // +checklocksforce: TryLock.
		b.m.t.Fatal("got read lock, expected to not take the lock; generic multicast protocol must take the write lock before sending v2 report")
	}

	recordsToMap(b.m.mu.sentV2Reports, b.report.records)
	return !b.m.mu.makeQueuePackets, nil
}

// NewReportV2Builder implements ip.MulticastGroupProtocol.
func (m *mockMulticastGroupProtocol) NewReportV2Builder() ip.MulticastGroupProtocolV2ReportBuilder {
	return &mockReportV2Builder{m: m}
}

// V2QueryMaxRespCodeToV2Delay implements ip.MulticastGroupProtocol.
func (*mockMulticastGroupProtocol) V2QueryMaxRespCodeToV2Delay(code uint16) time.Duration {
	return time.Duration(code) * time.Millisecond
}

// V2QueryMaxRespCodeToV1Delay implements ip.MulticastGroupProtocol.
func (*mockMulticastGroupProtocol) V2QueryMaxRespCodeToV1Delay(code uint16) time.Duration {
	return time.Duration(code) * time.Millisecond
}

type checkFields struct {
	sendReportGroupAddresses []tcpip.Address
	sendLeaveGroupAddresses  []tcpip.Address
	sentV2Reports            []mockReportV2
}

func (m *mockMulticastGroupProtocol) check(fields checkFields) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	sendReportGroupAddrCount := make(map[tcpip.Address]int)
	for _, a := range fields.sendReportGroupAddresses {
		sendReportGroupAddrCount[a] = 1
	}

	sendLeaveGroupAddrCount := make(map[tcpip.Address]int)
	for _, a := range fields.sendLeaveGroupAddresses {
		sendLeaveGroupAddrCount[a] = 1
	}

	sentV2Reports := make(map[tcpip.Address][]ip.MulticastGroupProtocolV2ReportRecordType)
	for _, report := range fields.sentV2Reports {
		recordsToMap(sentV2Reports, report.records)
	}

	diff := cmp.Diff(
		&mockMulticastGroupProtocol{
			mu: mockMulticastGroupProtocolProtectedFields{
				sendReportGroupAddrCount: sendReportGroupAddrCount,
				sendLeaveGroupAddrCount:  sendLeaveGroupAddrCount,
				sentV2Reports:            sentV2Reports,
			},
		},
		m,
		cmp.AllowUnexported(mockMulticastGroupProtocol{}),
		cmp.AllowUnexported(mockMulticastGroupProtocolProtectedFields{}),
		cmp.AllowUnexported(mockReportV2{}),
		cmp.AllowUnexported(mockReportV2Record{}),
		// ignore mockMulticastGroupProtocol.mu and mockMulticastGroupProtocol.t
		cmp.FilterPath(
			func(p cmp.Path) bool {
				switch p.Last().String() {
				case ".RWMutex", ".t", ".makeQueuePackets", ".disabled", ".genericMulticastGroup", ".skipProtocolAddress":
					return true
				default:
					return false
				}
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

	subTests := []struct {
		name            string
		v1Compatibility bool
		checkFields     func(tcpip.Address) checkFields
	}{
		{
			name:            "V1 Compatibility",
			v1Compatibility: true,
			checkFields: func(addr tcpip.Address) checkFields {
				return checkFields{sendReportGroupAddresses: []tcpip.Address{addr}}
			},
		},
		{
			name:            "V2",
			v1Compatibility: false,
			checkFields: func(addr tcpip.Address) checkFields {
				return checkFields{sentV2Reports: []mockReportV2{{records: []mockReportV2Record{
					{
						recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
						groupAddress: addr,
					},
				}}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					mgp := mockMulticastGroupProtocol{t: t, skipProtocolAddress: addr2}
					clock := faketime.NewManualClock()

					mgp.init(ip.GenericMulticastProtocolOptions{
						Rand:                      rand.New(rand.NewSource(0)),
						Clock:                     clock,
						MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
					}, subTest.v1Compatibility)

					// Joining a group should send a report immediately and another after
					// a random interval between 0 and the maximum unsolicited report delay.
					mgp.joinGroup(test.addr)
					if test.shouldSendReports {
						expected := subTest.checkFields(test.addr)
						if diff := mgp.check(expected); diff != "" {
							t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
						}

						// Generic multicast protocol timers are expected to take the job mutex.
						clock.Advance(maxUnsolicitedReportDelay)
						if diff := mgp.check(expected); diff != "" {
							t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
						}
					}

					// Should have no more messages to send.
					clock.Advance(time.Hour)
					if diff := mgp.check(checkFields{}); diff != "" {
						t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}

func TestLeaveGroup(t *testing.T) {
	const maxRespCode = 1

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

	subTests := []struct {
		name            string
		v1Compatibility bool
		checkFields     func(tcpip.Address, bool) checkFields
		handleQuery     func(*mockMulticastGroupProtocol, tcpip.Address)
	}{
		{
			name:            "V1 Compatibility",
			v1Compatibility: true,
			checkFields: func(addr tcpip.Address, leave bool) checkFields {
				if leave {
					return checkFields{sendLeaveGroupAddresses: []tcpip.Address{addr}}
				}
				return checkFields{sendReportGroupAddresses: []tcpip.Address{addr}}
			},
			handleQuery: func(mgp *mockMulticastGroupProtocol, groupAddress tcpip.Address) {
				mgp.handleQuery(groupAddress, maxRespCode)
			},
		},
		{
			name:            "V2",
			v1Compatibility: false,
			checkFields: func(addr tcpip.Address, leave bool) checkFields {
				recordType := ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
				if leave {
					recordType = ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode
				}

				return checkFields{sentV2Reports: []mockReportV2{{records: []mockReportV2Record{
					{
						recordType:   recordType,
						groupAddress: addr,
					},
				}}}}
			},
			handleQuery: func(mgp *mockMulticastGroupProtocol, groupAddress tcpip.Address) {
				mgp.handleQueryV2(groupAddress, maxRespCode, header.MakeAddressIterator(addr1.Len(), bytes.NewBuffer(nil)), 0, 0)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					for _, queryAddr := range []tcpip.Address{test.addr, tcpip.Address{}} {
						t.Run(fmt.Sprintf("QueryAddr=%s", queryAddr), func(t *testing.T) {
							mgp := mockMulticastGroupProtocol{t: t, skipProtocolAddress: addr2}
							clock := faketime.NewManualClock()

							mgp.init(ip.GenericMulticastProtocolOptions{
								Rand:                      rand.New(rand.NewSource(1)),
								Clock:                     clock,
								MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
							}, subTest.v1Compatibility)

							mgp.joinGroup(test.addr)
							if test.shouldSendMessages {
								if diff := mgp.check(subTest.checkFields(test.addr, false /* leave */)); diff != "" {
									t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
								}
							}

							// The timer scheduled to send the query response should do
							// nothing since we will leave the group before the response is
							// sent.
							subTest.handleQuery(&mgp, queryAddr)

							// Leaving a group should send a leave report immediately and
							// cancel any delayed reports.
							if !mgp.leaveGroup(test.addr) {
								t.Fatalf("got mgp.leaveGroup(%s) = false, want = true", test.addr)
							}

							// A query should not do anything since we left the group.
							subTest.handleQuery(&mgp, queryAddr)

							if test.shouldSendMessages {
								if diff := mgp.check(subTest.checkFields(test.addr, true /* leave */)); diff != "" {
									t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
								}

								if !subTest.v1Compatibility {
									clock.Advance(maxUnsolicitedReportDelay)

									if diff := mgp.check(subTest.checkFields(test.addr, true /* leave */)); diff != "" {
										t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
									}
								}
							}

							// Should have no more messages to send.
							clock.Advance(time.Hour)
							if diff := mgp.check(checkFields{}); diff != "" {
								t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
							}
						})
					}
				})
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
			reportAddr:       tcpip.Address{},
			expectReportsFor: []tcpip.Address{addr1, addr2},
		},
		{
			name:             "Unpecified any",
			reportAddr:       tcpip.AddrFromSlice([]byte("\x00\x00\x00\x00")),
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

	subTests := []struct {
		name            string
		v1Compatibility bool
		checkFields     func([]tcpip.Address) checkFields
	}{
		{
			name:            "V1 Compatibility",
			v1Compatibility: true,
			checkFields: func(addrs []tcpip.Address) checkFields {
				return checkFields{sendReportGroupAddresses: addrs}
			},
		},
		{
			name:            "V2",
			v1Compatibility: false,
			checkFields: func(addrs []tcpip.Address) checkFields {
				var records []mockReportV2Record
				for _, addr := range addrs {
					records = append(records, mockReportV2Record{
						recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
						groupAddress: addr,
					})
				}

				return checkFields{sentV2Reports: []mockReportV2{{records: records}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					mgp := mockMulticastGroupProtocol{t: t, skipProtocolAddress: addr3}
					clock := faketime.NewManualClock()

					mgp.init(ip.GenericMulticastProtocolOptions{
						Rand:                      rand.New(rand.NewSource(2)),
						Clock:                     clock,
						MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
					}, subTest.v1Compatibility)

					mgp.joinGroup(addr1)
					if diff := mgp.check(subTest.checkFields([]tcpip.Address{addr1})); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
					mgp.joinGroup(addr2)
					if diff := mgp.check(subTest.checkFields([]tcpip.Address{addr2})); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
					mgp.joinGroup(addr3)
					if diff := mgp.check(checkFields{}); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}

					// Receiving a report for a group we have a timer scheduled for should
					// cancel our delayed report timer for the group.
					mgp.handleReport(test.reportAddr)
					if len(test.expectReportsFor) != 0 {
						// Generic multicast protocol timers are expected to take the job mutex.
						clock.Advance(maxUnsolicitedReportDelay)
						if diff := mgp.check(subTest.checkFields(test.expectReportsFor)); diff != "" {
							t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
						}
					}

					// Should have no more messages to send.
					clock.Advance(time.Hour)
					if diff := mgp.check(checkFields{}); diff != "" {
						t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}

func TestHandleQuery(t *testing.T) {
	tests := []struct {
		name                    string
		queryAddr               tcpip.Address
		maxDelay                time.Duration
		expectQueriedReportsFor []tcpip.Address
		expectDelayedReportsFor []tcpip.Address
	}{
		{
			name:                    "Unpecified empty",
			queryAddr:               tcpip.Address{},
			maxDelay:                0,
			expectQueriedReportsFor: []tcpip.Address{addr1, addr2},
			expectDelayedReportsFor: nil,
		},
		{
			name:                    "Unpecified any",
			queryAddr:               tcpip.AddrFromSlice([]byte("\x00\x00\x00\x00")),
			maxDelay:                1,
			expectQueriedReportsFor: []tcpip.Address{addr1, addr2},
			expectDelayedReportsFor: nil,
		},
		{
			name:                    "Specified",
			queryAddr:               addr1,
			maxDelay:                2,
			expectQueriedReportsFor: []tcpip.Address{addr1},
			expectDelayedReportsFor: []tcpip.Address{addr2},
		},
		{
			name:                    "Specified all-nodes",
			queryAddr:               addr3,
			maxDelay:                3,
			expectQueriedReportsFor: nil,
			expectDelayedReportsFor: []tcpip.Address{addr1, addr2},
		},
		{
			name:                    "Specified other",
			queryAddr:               addr4,
			maxDelay:                4,
			expectQueriedReportsFor: nil,
			expectDelayedReportsFor: []tcpip.Address{addr1, addr2},
		},
	}

	subTests := []struct {
		name            string
		v1Compatibility bool
		checkFields     func([]tcpip.Address) checkFields
	}{
		{
			name:            "V1 Compatibility",
			v1Compatibility: true,
			checkFields: func(addrs []tcpip.Address) checkFields {
				return checkFields{sendReportGroupAddresses: addrs}
			},
		},
		{
			name:            "V2",
			v1Compatibility: false,
			checkFields: func(addrs []tcpip.Address) checkFields {
				var records []mockReportV2Record
				for _, addr := range addrs {
					records = append(records, mockReportV2Record{
						recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
						groupAddress: addr,
					})
				}

				return checkFields{sentV2Reports: []mockReportV2{{records: records}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					mgp := mockMulticastGroupProtocol{t: t, skipProtocolAddress: addr3}
					clock := faketime.NewManualClock()

					mgp.init(ip.GenericMulticastProtocolOptions{
						Rand:                      rand.New(rand.NewSource(3)),
						Clock:                     clock,
						MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
					}, subTest.v1Compatibility)

					mgp.joinGroup(addr1)
					if diff := mgp.check(subTest.checkFields([]tcpip.Address{addr1})); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
					mgp.joinGroup(addr2)
					if diff := mgp.check(subTest.checkFields([]tcpip.Address{addr2})); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
					mgp.joinGroup(addr3)
					if diff := mgp.check(checkFields{}); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}

					// Receiving a query should make us reschedule our delayed report timer
					// to some time within the new max response delay.
					mgp.handleQuery(test.queryAddr, test.maxDelay)
					clock.Advance(test.maxDelay)
					if diff := mgp.check(checkFields{sendReportGroupAddresses: test.expectQueriedReportsFor}); diff != "" {
						t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}

					// The groups that were not affected by the query should still send a
					// report after the max unsolicited report delay.
					//
					// If we were in V2 mode, then we would have cancelled the interface's
					// state changed timer so we won't see any further reports after
					// receiving a V1 query.
					if subTest.v1Compatibility {
						clock.Advance(maxUnsolicitedReportDelay)
						if diff := mgp.check(subTest.checkFields(test.expectDelayedReportsFor)); diff != "" {
							t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
						}
					}

					// Should have no more messages to send.
					clock.Advance(time.Hour)
					if diff := mgp.check(checkFields{}); diff != "" {
						t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}

func TestHandleQueryV2Response(t *testing.T) {
	tests := []struct {
		name                    string
		queryAddr               tcpip.Address
		maxDelay                uint16
		expectQueriedReportsFor []tcpip.Address
		expectDelayedReportsFor []tcpip.Address
	}{
		{
			name:                    "Unpecified empty",
			queryAddr:               tcpip.Address{},
			maxDelay:                0,
			expectQueriedReportsFor: []tcpip.Address{addr1, addr2},
			expectDelayedReportsFor: nil,
		},
		{
			name:                    "Unpecified any",
			queryAddr:               tcpip.AddrFromSlice([]byte("\x00\x00\x00\x00")),
			maxDelay:                1,
			expectQueriedReportsFor: []tcpip.Address{addr1, addr2},
			expectDelayedReportsFor: nil,
		},
		{
			name:                    "Specified",
			queryAddr:               addr1,
			maxDelay:                2,
			expectQueriedReportsFor: []tcpip.Address{addr1},
			expectDelayedReportsFor: []tcpip.Address{addr2},
		},
		{
			name:                    "Specified all-nodes",
			queryAddr:               addr3,
			maxDelay:                3,
			expectQueriedReportsFor: nil,
			expectDelayedReportsFor: []tcpip.Address{addr1, addr2},
		},
		{
			name:                    "Specified other",
			queryAddr:               addr4,
			maxDelay:                4,
			expectQueriedReportsFor: nil,
			expectDelayedReportsFor: []tcpip.Address{addr1, addr2},
		},
	}

	subTests := []struct {
		name            string
		v1Compatibility bool
		checkFields     func([]tcpip.Address, bool) checkFields
	}{
		{
			name:            "V1 Compatibility",
			v1Compatibility: true,
			checkFields: func(addrs []tcpip.Address, _ bool) checkFields {
				return checkFields{sendReportGroupAddresses: addrs}
			},
		},
		{
			name:            "V2",
			v1Compatibility: false,
			checkFields: func(addrs []tcpip.Address, queryResponse bool) checkFields {
				var records []mockReportV2Record
				recordType := ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
				if queryResponse {
					recordType = ip.MulticastGroupProtocolV2ReportRecordModeIsExclude
				}

				for _, addr := range addrs {
					records = append(records, mockReportV2Record{
						recordType:   recordType,
						groupAddress: addr,
					})
				}

				return checkFields{sentV2Reports: []mockReportV2{{records: records}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					mgp := mockMulticastGroupProtocol{t: t, skipProtocolAddress: addr3}
					clock := faketime.NewManualClock()

					mgp.init(ip.GenericMulticastProtocolOptions{
						Rand:                      rand.New(rand.NewSource(3)),
						Clock:                     clock,
						MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
					}, subTest.v1Compatibility)

					mgp.joinGroup(addr1)
					if diff := mgp.check(subTest.checkFields([]tcpip.Address{addr1}, false /* queryResponse */)); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
					mgp.joinGroup(addr2)
					if diff := mgp.check(subTest.checkFields([]tcpip.Address{addr2}, false /* queryResponse */)); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
					mgp.joinGroup(addr3)
					if diff := mgp.check(checkFields{}); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
					clock.Advance(maxUnsolicitedReportDelay)
					if diff := mgp.check(subTest.checkFields([]tcpip.Address{addr1, addr2}, false /* queryResponse */)); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
					clock.Advance(maxUnsolicitedReportDelay)
					if diff := mgp.check(checkFields{}); diff != "" {
						t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}

					// Receiving a query should make us reschedule our delayed report
					// timer to some time within the new max response delay.
					//
					// Note that if we are in V1 compatbility mode, the V2 query will be
					// handled as a V1 query.
					mgp.handleQueryV2(test.queryAddr, test.maxDelay, header.MakeAddressIterator(addr1.Len(), bytes.NewBuffer(nil)), 0, 0)
					if subTest.v1Compatibility {
						clock.Advance(mgp.V2QueryMaxRespCodeToV1Delay(test.maxDelay))
					} else {
						clock.Advance(mgp.V2QueryMaxRespCodeToV2Delay(test.maxDelay))
					}
					if diff := mgp.check(subTest.checkFields(test.expectQueriedReportsFor, true /* queryResponse */)); diff != "" {
						t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}

					// Should have no more messages to send.
					clock.Advance(time.Hour)
					if diff := mgp.check(checkFields{}); diff != "" {
						t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}

func TestV1CompatbilityModeTimer(t *testing.T) {
	tests := []struct {
		name               string
		robustnessVariable uint8
		queryInterval      time.Duration
	}{
		{
			name:               "Unspecified Robustness variable and Query interval",
			robustnessVariable: 0,
			queryInterval:      0,
		},
		{
			name:               "Unspecified Robustness variable",
			robustnessVariable: 0,
			queryInterval:      ip.DefaultQueryInterval + time.Second,
		},
		{
			name:               "Unspecified Query interval",
			robustnessVariable: ip.DefaultRobustnessVariable + 1,
			queryInterval:      0,
		},
		{
			name:               "Default Robustness variable and Query interval",
			robustnessVariable: ip.DefaultRobustnessVariable,
			queryInterval:      ip.DefaultQueryInterval,
		},
		{
			name:               "Specified Robustness variable and Query interval",
			robustnessVariable: ip.DefaultRobustnessVariable + 1,
			queryInterval:      ip.DefaultQueryInterval + time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mgp := mockMulticastGroupProtocol{t: t, skipProtocolAddress: addr3}
			clock := faketime.NewManualClock()

			mgp.init(ip.GenericMulticastProtocolOptions{
				Rand:                      rand.New(rand.NewSource(3)),
				Clock:                     clock,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
			}, false /* v1Compatibiltiy */)

			v2Check := func(t *testing.T) {
				t.Helper()

				mgp.joinGroup(addr1)
				if diff := mgp.check(checkFields{sentV2Reports: []mockReportV2{{records: []mockReportV2Record{
					{
						recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
						groupAddress: addr1,
					},
				}}}}); diff != "" {
					t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
				if !mgp.leaveGroup(addr1) {
					t.Fatalf("got mgp.leaveGroup(%s) = false, want = true", addr1)
				}
				if diff := mgp.check(checkFields{sentV2Reports: []mockReportV2{{records: []mockReportV2Record{
					{
						recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode,
						groupAddress: addr1,
					},
				}}}}); diff != "" {
					t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}
			v2Check(t)

			subTests := []struct {
				name        string
				advanceTime time.Duration
			}{
				{
					name:        "Default",
					advanceTime: ip.DefaultRobustnessVariable * ip.DefaultQueryInterval,
				},
				{
					name: "After V2 Query",
					advanceTime: func() time.Duration {
						robustnessVariable := test.robustnessVariable
						if robustnessVariable == 0 {
							robustnessVariable = ip.DefaultRobustnessVariable
						}

						queryInterval := test.queryInterval
						if queryInterval == 0 {
							queryInterval = ip.DefaultQueryInterval
						}

						return time.Duration(robustnessVariable) * queryInterval
					}(),
				},
			}

			for _, subTest := range subTests {
				t.Run(subTest.name, func(t *testing.T) {
					mgp.handleQuery(addr3, time.Nanosecond)
					v1Check := func() {
						t.Helper()
						mgp.joinGroup(addr1)
						if diff := mgp.check(checkFields{sendReportGroupAddresses: []tcpip.Address{addr1}}); diff != "" {
							t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
						}
						if !mgp.leaveGroup(addr1) {
							t.Fatalf("got mgp.leaveGroup(%s) = false, want = true", addr1)
						}
						if diff := mgp.check(checkFields{sendLeaveGroupAddresses: []tcpip.Address{addr1}}); diff != "" {
							t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
						}
					}
					v1Check()
					const minDuration = time.Duration(1)
					clock.Advance(subTest.advanceTime - minDuration)
					v1Check()

					clock.Advance(minDuration)
					v2Check(t)
					// Should update the Robustness variable and Querier's Query interval.
					mgp.handleQueryV2(addr3, 0, header.MakeAddressIterator(addr1.Len(), bytes.NewBuffer(nil)), test.robustnessVariable, test.queryInterval)
				})
			}
		})
	}
}

func TestJoinCount(t *testing.T) {
	const maxUnsolicitedReportDelay = time.Second

	tests := []struct {
		name            string
		v1Compatibility bool
		checkFields     func(tcpip.Address, bool) checkFields
	}{
		{
			name:            "V1 Compatibility",
			v1Compatibility: true,
			checkFields: func(addr tcpip.Address, leave bool) checkFields {
				if leave {
					return checkFields{sendLeaveGroupAddresses: []tcpip.Address{addr}}
				}
				return checkFields{sendReportGroupAddresses: []tcpip.Address{addr}}
			},
		},
		{
			name:            "V2",
			v1Compatibility: false,
			checkFields: func(addr tcpip.Address, leave bool) checkFields {
				recordType := ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
				if leave {
					recordType = ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode
				}

				return checkFields{sentV2Reports: []mockReportV2{{records: []mockReportV2Record{
					{
						recordType:   recordType,
						groupAddress: addr,
					},
				}}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mgp := mockMulticastGroupProtocol{t: t}
			clock := faketime.NewManualClock()

			mgp.init(ip.GenericMulticastProtocolOptions{
				Rand:                      rand.New(rand.NewSource(4)),
				Clock:                     clock,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
			}, test.v1Compatibility)

			// Set the join count to 2 for a group.
			mgp.joinGroup(addr1)
			if !mgp.isLocallyJoined(addr1) {
				t.Fatalf("got mgp.isLocallyJoined(%s) = false, want = true", addr1)
			}
			// Only the first join should trigger a report to be sent.
			if diff := mgp.check(test.checkFields(addr1, false /* leave */)); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.joinGroup(addr1)
			if !mgp.isLocallyJoined(addr1) {
				t.Errorf("got mgp.isLocallyJoined(%s) = false, want = true", addr1)
			}
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			if t.Failed() {
				t.FailNow()
			}

			// Group should still be considered joined after leaving once.
			if !mgp.leaveGroup(addr1) {
				t.Errorf("got mgp.leaveGroup(%s) = false, want = true", addr1)
			}
			if !mgp.isLocallyJoined(addr1) {
				t.Errorf("got mgp.isLocallyJoined(%s) = false, want = true", addr1)
			}
			// A leave report should only be sent once the join count reaches 0.
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			if t.Failed() {
				t.FailNow()
			}

			// Leaving once more should actually remove us from the group.
			if !mgp.leaveGroup(addr1) {
				t.Errorf("got mgp.leaveGroup(%s) = false, want = true", addr1)
			}
			if mgp.isLocallyJoined(addr1) {
				t.Errorf("got mgp.isLocallyJoined(%s) = true, want = false", addr1)
			}
			if diff := mgp.check(test.checkFields(addr1, true /* leave */)); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			if !test.v1Compatibility {
				// V2 should still have a queued state-changed report.
				clock.Advance(maxUnsolicitedReportDelay)
				if diff := mgp.check(test.checkFields(addr1, true /* leave */)); diff != "" {
					t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
				}
			}
			if t.Failed() {
				t.FailNow()
			}

			// Group should no longer be joined so we should not have anything to
			// leave.
			if mgp.leaveGroup(addr1) {
				t.Errorf("got mgp.leaveGroup(%s) = true, want = false", addr1)
			}
			if mgp.isLocallyJoined(addr1) {
				t.Errorf("got mgp.isLocallyJoined(%s) = true, want = false", addr1)
			}
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Should have no more messages to send.
			//
			// Generic multicast protocol timers are expected to take the job mutex.
			clock.Advance(time.Hour)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMakeAllNonMemberAndInitialize(t *testing.T) {
	const unsolicitedTransmissionCount = 2

	tests := []struct {
		name            string
		v1              bool
		v1Compatibility bool
		checkFields     func([]tcpip.Address, bool) checkFields
	}{
		{
			name:            "V1",
			v1:              true,
			v1Compatibility: false,
			checkFields: func(addrs []tcpip.Address, leave bool) checkFields {
				if leave {
					return checkFields{sendLeaveGroupAddresses: addrs}
				}
				return checkFields{sendReportGroupAddresses: addrs}
			},
		},
		{
			name:            "V1 Compatibility",
			v1:              false,
			v1Compatibility: true,
			checkFields: func(addrs []tcpip.Address, leave bool) checkFields {
				if leave {
					return checkFields{sendLeaveGroupAddresses: addrs}
				}
				return checkFields{sendReportGroupAddresses: addrs}
			},
		},
		{
			name:            "V2",
			v1:              false,
			v1Compatibility: false,
			checkFields: func(addrs []tcpip.Address, leave bool) checkFields {
				recordType := ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
				if leave {
					recordType = ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode
				}
				var records []mockReportV2Record
				for _, addr := range addrs {
					records = append(records, mockReportV2Record{
						recordType:   recordType,
						groupAddress: addr,
					})
				}

				return checkFields{sentV2Reports: []mockReportV2{{records: records}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mgp := mockMulticastGroupProtocol{t: t, skipProtocolAddress: addr3}
			clock := faketime.NewManualClock()

			mgp.init(ip.GenericMulticastProtocolOptions{
				Rand:                      rand.New(rand.NewSource(3)),
				Clock:                     clock,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
			}, test.v1)

			if test.v1Compatibility {
				// V1 query targetting an unjoined group should drop us into V1
				// compatibility mode without sending any packets, affecting tests.
				mgp.handleQuery(addr3, 0)
			}

			mgp.joinGroup(addr1)
			if diff := mgp.check(test.checkFields([]tcpip.Address{addr1}, false /* leave */)); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.joinGroup(addr2)
			if diff := mgp.check(test.checkFields([]tcpip.Address{addr2}, false /* leave */)); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.joinGroup(addr3)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Should send the leave reports for each but still consider them locally
			// joined.
			mgp.makeAllNonMember()
			if diff := mgp.check(test.checkFields([]tcpip.Address{addr1, addr2}, true /* leave */)); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Generic multicast protocol timers are expected to take the job mutex.
			clock.Advance(time.Hour)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			for _, group := range []tcpip.Address{addr1, addr2, addr3} {
				if !mgp.isLocallyJoined(group) {
					t.Fatalf("got mgp.isLocallyJoined(%s) = false, want = true", group)
				}
			}

			// Should send the initial set of unsolcited V2 reports.
			mgp.initializeGroups()
			for i := 0; i < unsolicitedTransmissionCount; i++ {
				if test.v1 {
					if diff := mgp.check(test.checkFields([]tcpip.Address{addr1, addr2}, false /* leave */)); diff != "" {
						t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
				} else {
					if diff := mgp.check(checkFields{sentV2Reports: []mockReportV2{
						{
							records: []mockReportV2Record{
								{
									recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
									groupAddress: addr1,
								},
							},
						},
						{
							records: []mockReportV2Record{
								{
									recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
									groupAddress: addr2,
								},
							},
						},
					}}); diff != "" {
						t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
					}
				}
				clock.Advance(maxUnsolicitedReportDelay)
			}

			// Should have no more messages to send.
			clock.Advance(time.Hour)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			if got := mgp.getV1Mode(); got != test.v1 {
				t.Errorf("got mgp.getV1Mode() = %t, want = %t", got, test.v1)
			}
		})
	}
}

// TestGroupStateNonMember tests that groups do not send packets when in the
// non-member state, but are still considered locally joined.
func TestGroupStateNonMember(t *testing.T) {
	tests := []struct {
		name            string
		v1Compatibility bool
		checkFields     func([]tcpip.Address, bool) checkFields
	}{
		{
			name:            "V1 Compatibility",
			v1Compatibility: true,
			checkFields: func(addrs []tcpip.Address, leave bool) checkFields {
				if leave {
					return checkFields{sendLeaveGroupAddresses: addrs}
				}
				return checkFields{sendReportGroupAddresses: addrs}
			},
		},
		{
			name:            "V2",
			v1Compatibility: false,
			checkFields: func(addrs []tcpip.Address, leave bool) checkFields {
				recordType := ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
				if leave {
					recordType = ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode
				}
				var records []mockReportV2Record
				for _, addr := range addrs {
					records = append(records, mockReportV2Record{
						recordType:   recordType,
						groupAddress: addr,
					})
				}

				return checkFields{sentV2Reports: []mockReportV2{{records: records}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mgp := mockMulticastGroupProtocol{t: t}
			clock := faketime.NewManualClock()

			mgp.init(ip.GenericMulticastProtocolOptions{
				Rand:                      rand.New(rand.NewSource(3)),
				Clock:                     clock,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
			}, test.v1Compatibility)
			mgp.setEnabled(false)

			// Joining groups should not send any reports.
			mgp.joinGroup(addr1)
			if !mgp.isLocallyJoined(addr1) {
				t.Fatalf("got mgp.isLocallyJoined(%s) = false, want = true", addr1)
			}
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.joinGroup(addr2)
			if !mgp.isLocallyJoined(addr1) {
				t.Fatalf("got mgp.isLocallyJoined(%s) = false, want = true", addr2)
			}
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a query should not send any reports.
			mgp.handleQuery(addr1, time.Nanosecond)
			// Generic multicast protocol timers are expected to take the job mutex.
			clock.Advance(time.Nanosecond)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Leaving groups should not send any leave messages.
			if !mgp.leaveGroup(addr1) {
				t.Errorf("got mgp.leaveGroup(%s) = false, want = true", addr2)
			}
			if mgp.isLocallyJoined(addr1) {
				t.Errorf("got mgp.isLocallyJoined(%s) = true, want = false", addr2)
			}
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			clock.Advance(time.Hour)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestQueuedPackets(t *testing.T) {
	tests := []struct {
		name            string
		v1Compatibility bool
		checkFields     func(tcpip.Address) checkFields
	}{
		{
			name:            "V1 Compatibility",
			v1Compatibility: true,
			checkFields: func(addr tcpip.Address) checkFields {
				return checkFields{sendReportGroupAddresses: []tcpip.Address{addr}}
			},
		},
		{
			name:            "V2",
			v1Compatibility: false,
			checkFields: func(addr tcpip.Address) checkFields {
				return checkFields{sentV2Reports: []mockReportV2{{records: []mockReportV2Record{
					{
						recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
						groupAddress: addr,
					},
				}}}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			mgp := mockMulticastGroupProtocol{t: t}
			mgp.init(ip.GenericMulticastProtocolOptions{
				Rand:                      rand.New(rand.NewSource(4)),
				Clock:                     clock,
				MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
			}, test.v1Compatibility)

			// Joining should trigger a SendReport, but mgp should report that we did not
			// send the packet.
			mgp.setQueuePackets(true)
			mgp.joinGroup(addr1)
			if diff := mgp.check(test.checkFields(addr1)); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// The delayed report timer should have been cancelled since we did not send
			// the initial report earlier.
			clock.Advance(time.Hour)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Mock being able to successfully send the report.
			mgp.setQueuePackets(false)
			mgp.sendQueuedReports()
			if diff := mgp.check(test.checkFields(addr1)); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// The delayed report (sent after the initial report) should now be sent.
			clock.Advance(maxUnsolicitedReportDelay)
			if diff := mgp.check(test.checkFields(addr1)); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Should not have anything else to send (we should be idle).
			mgp.sendQueuedReports()
			clock.Advance(time.Hour)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receive a query but mock being unable to send reports again.
			mgp.setQueuePackets(true)
			mgp.handleQuery(addr1, time.Nanosecond)
			clock.Advance(time.Nanosecond)
			if diff := mgp.check(checkFields{sendReportGroupAddresses: []tcpip.Address{addr1}}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Mock being able to send reports again - we should have a packet queued to
			// send.
			mgp.setQueuePackets(false)
			mgp.sendQueuedReports()
			if diff := mgp.check(checkFields{sendReportGroupAddresses: []tcpip.Address{addr1}}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Should not have anything else to send.
			mgp.sendQueuedReports()
			clock.Advance(time.Hour)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receive a query again, but mock being unable to send reports.
			mgp.setQueuePackets(true)
			mgp.handleQuery(addr1, time.Nanosecond)
			clock.Advance(time.Nanosecond)
			if diff := mgp.check(checkFields{sendReportGroupAddresses: []tcpip.Address{addr1}}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// Receiving a report should should transition us into the idle member state,
			// even if we had a packet queued. We should no longer have any packets to
			// send.
			mgp.handleReport(addr1)
			mgp.sendQueuedReports()
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}

			// When we fail to send the initial set of reports, incoming reports should
			// prevent a newly joined group's reports from being sent.
			mgp.setQueuePackets(true)
			mgp.joinGroup(addr2)
			if diff := mgp.check(checkFields{sendReportGroupAddresses: []tcpip.Address{addr2}}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			mgp.handleReport(addr2)
			// Attempting to send queued reports while still unable to send reports should
			// not change the host state.
			mgp.sendQueuedReports()
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
			// Should not have any packets queued.
			mgp.setQueuePackets(false)
			mgp.sendQueuedReports()
			clock.Advance(time.Hour)
			if diff := mgp.check(checkFields{}); diff != "" {
				t.Errorf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetSetV1Mode(t *testing.T) {
	clock := faketime.NewManualClock()
	mgp := mockMulticastGroupProtocol{t: t}
	mgp.init(ip.GenericMulticastProtocolOptions{
		Rand:                      rand.New(rand.NewSource(4)),
		Clock:                     clock,
		MaxUnsolicitedReportDelay: maxUnsolicitedReportDelay,
	}, false /* v1Compatibility */)

	if mgp.getV1Mode() {
		t.Error("got mgp.getV1Mode() = true, want = false")
	}

	mgp.joinGroup(addr1)
	if diff := mgp.check(checkFields{sentV2Reports: []mockReportV2{{records: []mockReportV2Record{
		{
			recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
			groupAddress: addr1,
		},
	}}}}); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	if mgp.setV1Mode(true) {
		t.Error("got mgp.setV1Mode(true) = true, want = false")
	}
	if !mgp.getV1Mode() {
		t.Error("got mgp.getV1Mode() = false, want = true")
	}
	mgp.joinGroup(addr2)
	if diff := mgp.check(checkFields{sendReportGroupAddresses: []tcpip.Address{addr2}}); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}

	if !mgp.setV1Mode(false) {
		t.Error("got mgp.setV1Mode(false) = false, want = true")
	}
	if mgp.getV1Mode() {
		t.Error("got mgp.getV1Mode() = true, want = false")
	}
	mgp.joinGroup(addr3)
	if diff := mgp.check(checkFields{sentV2Reports: []mockReportV2{{records: []mockReportV2Record{
		{
			recordType:   ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode,
			groupAddress: addr3,
		},
	}}}}); diff != "" {
		t.Fatalf("mockMulticastGroupProtocol mismatch (-want +got):\n%s", diff)
	}
}
