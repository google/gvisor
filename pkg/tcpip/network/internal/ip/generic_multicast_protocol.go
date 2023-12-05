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

package ip

import (
	"fmt"
	"math/rand"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// As per RFC 2236 section 3,
	//
	//   When a host joins a multicast group, it should immediately transmit
	//   an unsolicited Version 2 Membership Report for that group, in case it
	//   is the first member of that group on the network.  To cover the
	//   possibility of the initial Membership Report being lost or damaged,
	//   it is recommended that it be repeated once or twice after short
	//   delays [Unsolicited Report Interval].  (A simple way to accomplish
	//   this is to send the initial Version 2 Membership Report and then act
	//   as if a Group-Specific Query was received for that group, and set a
	//   timer appropriately).
	//
	// As per RFC 2710 section 4,
	//
	//   When a node starts listening to a multicast address on an interface,
	//   it should immediately transmit an unsolicited Report for that address
	//   on that interface, in case it is the first listener on the link.  To
	//   cover the possibility of the initial Report being lost or damaged, it
	//   is recommended that it be repeated once or twice after short delays
	//   [Unsolicited Report Interval].  (A simple way to accomplish this is
	//   to send the initial Report and then act as if a Multicast-Address-
	//   Specific Query was received for that address, and set a timer
	//   appropriately).
	unsolicitedTransmissionCount = 2

	// Responses to queries may be delayed, but we only send a response to a
	// query once. A response to a query can be handled by any pending
	// unsolicited transmission count, but we should send at least one report
	// after sending a query.
	//
	// As per RFC 2236 section 3,
	//
	//   When a host receives a General Query, it sets delay timers for each
	//   group (excluding the all-systems group) of which it is a member on
	//   the interface from which it received the query.
	//
	// As per RFC 2710 section 4,
	//
	//   When a node receives a General Query, it sets a delay timer for each
	//   multicast address to which it is listening on the interface from
	//   which it received the Query, EXCLUDING the link-scope all-nodes
	//   address and any multicast addresses of scope 0 (reserved) or 1
	//   (node-local).
	minQueryResponseTransmissionCount = 1

	// DefaultRobustnessVariable is the default robustness variable
	//
	// As per RFC 3810 section 9.1 (for MLDv2),
	//
	//   The Robustness Variable allows tuning for the expected packet loss on
	//   a link.  If a link is expected to be lossy, the value of the
	//   Robustness Variable may be increased.  MLD is robust to [Robustness
	//   Variable] - 1 packet losses.  The value of the Robustness Variable
	//   MUST NOT be zero, and SHOULD NOT be one.  Default value: 2.
	//
	// As per RFC 3376 section 8.1 (for IGMPv3),
	//
	//   The Robustness Variable allows tuning for the expected packet loss on
	//   a network.  If a network is expected to be lossy, the Robustness
	//   Variable may be increased.  IGMP is robust to (Robustness Variable -
	//   1) packet losses.  The Robustness Variable MUST NOT be zero, and
	//   SHOULD NOT be one.  Default: 2
	DefaultRobustnessVariable = 2

	// DefaultQueryInterval is the default query interval.
	//
	// As per RFC 3810 section 9.2 (for MLDv2),
	//
	//   The Query Interval variable denotes the interval between General
	//   Queries sent by the Querier.  Default value: 125 seconds.
	//
	// As per RFC 3376 section 8.2 (for IGMPv3),
	//
	//   The Query Interval is the interval between General Queries sent by
	//   the Querier.  Default: 125 seconds.
	DefaultQueryInterval = 125 * time.Second
)

// multicastGroupState holds the Generic Multicast Protocol state for a
// multicast group.
type multicastGroupState struct {
	// joins is the number of times the group has been joined.
	joins uint64

	// transmissionLeft is the number of transmissions left to send.
	transmissionLeft uint8

	// lastToSendReport is true if we sent the last report for the group. It is
	// used to track whether there are other hosts on the subnet that are also
	// members of the group.
	//
	// Defined in RFC 2236 section 6 page 9 for IGMPv2 and RFC 2710 section 5 page
	// 8 for MLDv1.
	lastToSendReport bool

	// delayedReportJob is used to delay sending responses to membership report
	// messages in order to reduce duplicate reports from multiple hosts on the
	// interface.
	//
	// Must not be nil.
	delayedReportJob *tcpip.Job

	// delyedReportJobFiresAt is the time when the delayed report job will fire.
	//
	// A zero value indicates that the job is not scheduled.
	delayedReportJobFiresAt time.Time

	// queriedIncludeSources holds sources that were queried for.
	//
	// Indicates that there is a pending source-specific query response for the
	// multicast address.
	queriedIncludeSources map[tcpip.Address]struct{}

	deleteScheduled bool
}

func (m *multicastGroupState) cancelDelayedReportJob() {
	m.delayedReportJob.Cancel()
	m.delayedReportJobFiresAt = time.Time{}
	m.transmissionLeft = 0
}

func (m *multicastGroupState) clearQueriedIncludeSources() {
	for source := range m.queriedIncludeSources {
		delete(m.queriedIncludeSources, source)
	}
}

// GenericMulticastProtocolOptions holds options for the generic multicast
// protocol.
type GenericMulticastProtocolOptions struct {
	// Rand is the source of random numbers.
	Rand *rand.Rand

	// Clock is the clock used to create timers.
	Clock tcpip.Clock

	// Protocol is the implementation of the variant of multicast group protocol
	// in use.
	Protocol MulticastGroupProtocol

	// MaxUnsolicitedReportDelay is the maximum amount of time to wait between
	// transmitting unsolicited reports.
	//
	// Unsolicited reports are transmitted when a group is newly joined.
	MaxUnsolicitedReportDelay time.Duration
}

// MulticastGroupProtocolV2ReportRecordType is the type of a
// MulticastGroupProtocolv2 multicast address record.
type MulticastGroupProtocolV2ReportRecordType int

// MulticastGroupProtocolv2 multicast address record types.
const (
	_ MulticastGroupProtocolV2ReportRecordType = iota
	MulticastGroupProtocolV2ReportRecordModeIsInclude
	MulticastGroupProtocolV2ReportRecordModeIsExclude
	MulticastGroupProtocolV2ReportRecordChangeToIncludeMode
	MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
	MulticastGroupProtocolV2ReportRecordAllowNewSources
	MulticastGroupProtocolV2ReportRecordBlockOldSources
)

// MulticastGroupProtocolV2ReportBuilder is a builder for a V2 report.
type MulticastGroupProtocolV2ReportBuilder interface {
	// AddRecord adds a record to the report.
	AddRecord(recordType MulticastGroupProtocolV2ReportRecordType, groupAddress tcpip.Address)

	// Send sends the report.
	//
	// Does nothing if no records were added.
	//
	// It is invalid to use this builder after this method is called.
	Send() (sent bool, err tcpip.Error)
}

// MulticastGroupProtocol is a multicast group protocol whose core state machine
// can be represented by GenericMulticastProtocolState.
type MulticastGroupProtocol interface {
	// Enabled indicates whether the generic multicast protocol will be
	// performed.
	//
	// When enabled, the protocol may transmit report and leave messages when
	// joining and leaving multicast groups respectively, and handle incoming
	// packets.
	//
	// When disabled, the protocol will still keep track of locally joined groups,
	// it just won't transmit and handle packets, or update groups' state.
	Enabled() bool

	// SendReport sends a multicast report for the specified group address.
	//
	// Returns false if the caller should queue the report to be sent later. Note,
	// returning false does not mean that the receiver hit an error.
	SendReport(groupAddress tcpip.Address) (sent bool, err tcpip.Error)

	// SendLeave sends a multicast leave for the specified group address.
	SendLeave(groupAddress tcpip.Address) tcpip.Error

	// ShouldPerformProtocol returns true iff the protocol should be performed for
	// the specified group.
	ShouldPerformProtocol(tcpip.Address) bool

	// NewReportV2Builder creates a new V2 builder.
	NewReportV2Builder() MulticastGroupProtocolV2ReportBuilder

	// V2QueryMaxRespCodeToV2Delay takes a V2 query's maximum response code and
	// returns the V2 delay.
	V2QueryMaxRespCodeToV2Delay(code uint16) time.Duration

	// V2QueryMaxRespCodeToV1Delay takes a V2 query's maximum response code and
	// returns the V1 delay.
	V2QueryMaxRespCodeToV1Delay(code uint16) time.Duration
}

type protocolMode int

const (
	protocolModeV2 protocolMode = iota
	protocolModeV1
	protocolModeV1Compatibility
)

// GenericMulticastProtocolState is the per interface generic multicast protocol
// state.
//
// There is actually no protocol named "Generic Multicast Protocol". Instead,
// the term used to refer to a generic multicast protocol that applies to both
// IPv4 and IPv6. Specifically, Generic Multicast Protocol is the core state
// machine of IGMPv2 as defined by RFC 2236 and MLDv1 as defined by RFC 2710.
//
// Callers must synchronize accesses to the generic multicast protocol state;
// GenericMulticastProtocolState obtains no locks in any of its methods. The
// only exception to this is GenericMulticastProtocolState's timer/job callbacks
// which will obtain the lock provided to the GenericMulticastProtocolState when
// it is initialized.
//
// GenericMulticastProtocolState.Init MUST be called before calling any of
// the methods on GenericMulticastProtocolState.
//
// GenericMulticastProtocolState.MakeAllNonMemberLocked MUST be called when the
// multicast group protocol is disabled so that leave messages may be sent.
type GenericMulticastProtocolState struct {
	// Do not allow overwriting this state.
	_ sync.NoCopy

	opts GenericMulticastProtocolOptions

	// memberships holds group addresses and their associated state.
	memberships map[tcpip.Address]multicastGroupState

	// protocolMU is the mutex used to protect the protocol.
	protocolMU *sync.RWMutex

	// V2 state.
	robustnessVariable uint8
	queryInterval      time.Duration
	mode               protocolMode
	modeTimer          tcpip.Timer

	generalQueryV2Timer        tcpip.Timer
	generalQueryV2TimerFiresAt time.Time

	stateChangedReportV2Timer    tcpip.Timer
	stateChangedReportV2TimerSet bool
}

// GetV1ModeLocked returns the V1 configuration.
//
// Precondition: g.protocolMU must be read locked.
func (g *GenericMulticastProtocolState) GetV1ModeLocked() bool {
	switch g.mode {
	case protocolModeV2, protocolModeV1Compatibility:
		return false
	case protocolModeV1:
		return true
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}
}

func (g *GenericMulticastProtocolState) stopModeTimer() {
	if g.modeTimer != nil {
		g.modeTimer.Stop()
	}
}

// SetV1ModeLocked sets the V1 configuration.
//
// Returns the previous configuration.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) SetV1ModeLocked(v bool) bool {
	if g.GetV1ModeLocked() == v {
		return v
	}

	if v {
		g.stopModeTimer()
		g.cancelV2ReportTimers()
		g.mode = protocolModeV1
		return false
	}

	g.mode = protocolModeV2
	return true
}

func (g *GenericMulticastProtocolState) cancelV2ReportTimers() {
	if g.generalQueryV2Timer != nil {
		g.generalQueryV2Timer.Stop()
		g.generalQueryV2TimerFiresAt = time.Time{}
	}

	if g.stateChangedReportV2Timer != nil {
		g.stateChangedReportV2Timer.Stop()
		g.stateChangedReportV2TimerSet = false
	}
}

// Init initializes the Generic Multicast Protocol state.
//
// Must only be called once for the lifetime of g; Init will panic if it is
// called twice.
//
// The GenericMulticastProtocolState will only grab the lock when timers/jobs
// fire.
//
// Note: the methods on opts.Protocol will always be called while protocolMU is
// held.
func (g *GenericMulticastProtocolState) Init(protocolMU *sync.RWMutex, opts GenericMulticastProtocolOptions) {
	if g.memberships != nil {
		panic("attempted to initialize generic membership protocol state twice")
	}

	*g = GenericMulticastProtocolState{
		opts:               opts,
		memberships:        make(map[tcpip.Address]multicastGroupState),
		protocolMU:         protocolMU,
		robustnessVariable: DefaultRobustnessVariable,
		queryInterval:      DefaultQueryInterval,
		mode:               protocolModeV2,
	}
}

// MakeAllNonMemberLocked transitions all groups to the non-member state.
//
// The groups will still be considered joined locally.
//
// MUST be called when the multicast group protocol is disabled.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) MakeAllNonMemberLocked() {
	if !g.opts.Protocol.Enabled() {
		return
	}

	g.stopModeTimer()
	g.cancelV2ReportTimers()

	var v2ReportBuilder MulticastGroupProtocolV2ReportBuilder
	var handler func(tcpip.Address, *multicastGroupState)
	switch g.mode {
	case protocolModeV2:
		v2ReportBuilder = g.opts.Protocol.NewReportV2Builder()
		handler = func(groupAddress tcpip.Address, info *multicastGroupState) {
			info.cancelDelayedReportJob()

			// Send a report immediately to announce us leaving the group.
			v2ReportBuilder.AddRecord(
				MulticastGroupProtocolV2ReportRecordChangeToIncludeMode,
				groupAddress,
			)
		}
	case protocolModeV1Compatibility:
		g.mode = protocolModeV2
		fallthrough
	case protocolModeV1:
		handler = g.transitionToNonMemberLocked
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}

	for groupAddress, info := range g.memberships {
		if !g.shouldPerformForGroup(groupAddress) {
			continue
		}

		handler(groupAddress, &info)

		if info.deleteScheduled {
			delete(g.memberships, groupAddress)
		} else {
			info.transmissionLeft = 0
			g.memberships[groupAddress] = info
		}
	}

	if v2ReportBuilder != nil {
		// Nothing meaningful we can do with the error here - this method may be
		// called when an interface is being disabled when we expect sends to
		// fail.
		_, _ = v2ReportBuilder.Send()
	}
}

// InitializeGroupsLocked initializes each group, as if they were newly joined
// but without affecting the groups' join count.
//
// Must only be called after calling MakeAllNonMember as a group should not be
// initialized while it is not in the non-member state.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) InitializeGroupsLocked() {
	if !g.opts.Protocol.Enabled() {
		return
	}

	var v2ReportBuilder MulticastGroupProtocolV2ReportBuilder
	switch g.mode {
	case protocolModeV2:
		v2ReportBuilder = g.opts.Protocol.NewReportV2Builder()
	case protocolModeV1Compatibility, protocolModeV1:
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}

	for groupAddress, info := range g.memberships {
		g.initializeNewMemberLocked(groupAddress, &info, v2ReportBuilder)
		g.memberships[groupAddress] = info
	}

	if v2ReportBuilder == nil {
		return
	}

	if sent, err := v2ReportBuilder.Send(); sent && err == nil {
		g.scheduleStateChangedTimer()
	} else {
		// Nothing meaningful we could do with the error here - the interface may
		// not yet have an address. This is okay because we would either schedule a
		// report to be sent later or we will be notified when an address is added,
		// at which point we will try to send messages again.
		for groupAddress, info := range g.memberships {
			if !g.shouldPerformForGroup(groupAddress) {
				continue
			}

			// Revert the transmissions count since we did not successfully send.
			info.transmissionLeft++
			g.memberships[groupAddress] = info
		}
	}
}

// SendQueuedReportsLocked attempts to send reports for groups that failed to
// send reports during their last attempt.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) SendQueuedReportsLocked() {
	if g.stateChangedReportV2TimerSet {
		return
	}

	for groupAddress, info := range g.memberships {
		if info.delayedReportJobFiresAt.IsZero() {
			switch g.mode {
			case protocolModeV2:
				g.sendV2ReportAndMaybeScheduleChangedTimer(groupAddress, &info, MulticastGroupProtocolV2ReportRecordChangeToExcludeMode)
			case protocolModeV1Compatibility, protocolModeV1:
				g.maybeSendReportLocked(groupAddress, &info)
			default:
				panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
			}

			g.memberships[groupAddress] = info
		}
	}
}

// JoinGroupLocked handles joining a new group.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) JoinGroupLocked(groupAddress tcpip.Address) {
	info, ok := g.memberships[groupAddress]
	if ok {
		info.joins++
		if info.joins > 1 {
			// The group has already been joined.
			g.memberships[groupAddress] = info
			return
		}
	} else {
		info = multicastGroupState{
			// Since we just joined the group, its count is 1.
			joins:            1,
			lastToSendReport: false,
			delayedReportJob: tcpip.NewJob(g.opts.Clock, g.protocolMU, func() {
				if !g.opts.Protocol.Enabled() {
					panic(fmt.Sprintf("delayed report job fired for group %s while the multicast group protocol is disabled", groupAddress))
				}

				info, ok := g.memberships[groupAddress]
				if !ok {
					panic(fmt.Sprintf("expected to find group state for group = %s", groupAddress))
				}

				info.delayedReportJobFiresAt = time.Time{}

				switch g.mode {
				case protocolModeV2:
					reportBuilder := g.opts.Protocol.NewReportV2Builder()
					reportBuilder.AddRecord(MulticastGroupProtocolV2ReportRecordModeIsExclude, groupAddress)
					// Nothing meaningful we can do with the error here - we only try to
					// send a delayed report once.
					_, _ = reportBuilder.Send()
				case protocolModeV1Compatibility, protocolModeV1:
					g.maybeSendReportLocked(groupAddress, &info)
				default:
					panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
				}

				info.clearQueriedIncludeSources()
				g.memberships[groupAddress] = info
			}),
			queriedIncludeSources: make(map[tcpip.Address]struct{}),
		}
	}

	info.deleteScheduled = false
	info.clearQueriedIncludeSources()
	info.delayedReportJobFiresAt = time.Time{}
	info.lastToSendReport = false
	g.initializeNewMemberLocked(groupAddress, &info, nil /* callersV2ReportBuilder */)
	g.memberships[groupAddress] = info
}

// IsLocallyJoinedRLocked returns true if the group is locally joined.
//
// Precondition: g.protocolMU must be read locked.
func (g *GenericMulticastProtocolState) IsLocallyJoinedRLocked(groupAddress tcpip.Address) bool {
	info, ok := g.memberships[groupAddress]
	return ok && !info.deleteScheduled
}

func (g *GenericMulticastProtocolState) sendV2ReportAndMaybeScheduleChangedTimer(
	groupAddress tcpip.Address,
	info *multicastGroupState,
	recordType MulticastGroupProtocolV2ReportRecordType,
) bool {
	if info.transmissionLeft == 0 {
		return false
	}

	successfullySentAndHasMore := false

	// Send a report immediately to announce us leaving the group.
	reportBuilder := g.opts.Protocol.NewReportV2Builder()
	reportBuilder.AddRecord(recordType, groupAddress)
	if sent, err := reportBuilder.Send(); sent && err == nil {
		info.transmissionLeft--

		successfullySentAndHasMore = info.transmissionLeft != 0

		// Use the interface-wide state changed report for further transmissions.
		if successfullySentAndHasMore {
			g.scheduleStateChangedTimer()
		}
	}

	return successfullySentAndHasMore
}

func (g *GenericMulticastProtocolState) scheduleStateChangedTimer() {
	if g.stateChangedReportV2TimerSet {
		return
	}

	delay := g.calculateDelayTimerDuration(g.opts.MaxUnsolicitedReportDelay)
	if g.stateChangedReportV2Timer == nil {
		// TODO(https://issuetracker.google.com/264799098): Create timer on
		// initialization instead of lazily creating the timer since the timer
		// does not change after being created.
		g.stateChangedReportV2Timer = g.opts.Clock.AfterFunc(delay, func() {
			g.protocolMU.Lock()
			defer g.protocolMU.Unlock()

			reportBuilder := g.opts.Protocol.NewReportV2Builder()
			nonEmptyReport := false
			for groupAddress, info := range g.memberships {
				if info.transmissionLeft == 0 || !g.shouldPerformForGroup(groupAddress) {
					continue
				}

				info.transmissionLeft--
				nonEmptyReport = true

				mode := MulticastGroupProtocolV2ReportRecordChangeToExcludeMode
				if info.deleteScheduled {
					mode = MulticastGroupProtocolV2ReportRecordChangeToIncludeMode
				}
				reportBuilder.AddRecord(mode, groupAddress)

				if info.deleteScheduled && info.transmissionLeft == 0 {
					// No more transmissions left so we can actually delete the
					// membership.
					delete(g.memberships, groupAddress)
				} else {
					g.memberships[groupAddress] = info
				}
			}

			// Nothing meaningful we can do with the error here. We will retry
			// sending a state changed report again anyways.
			_, _ = reportBuilder.Send()

			if nonEmptyReport {
				g.stateChangedReportV2Timer.Reset(g.calculateDelayTimerDuration(g.opts.MaxUnsolicitedReportDelay))
			} else {
				g.stateChangedReportV2TimerSet = false
			}
		})
	} else {
		g.stateChangedReportV2Timer.Reset(delay)
	}
	g.stateChangedReportV2TimerSet = true
}

// LeaveGroupLocked handles leaving the group.
//
// Returns false if the group is not currently joined.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) LeaveGroupLocked(groupAddress tcpip.Address) bool {
	info, ok := g.memberships[groupAddress]
	if !ok || info.joins == 0 {
		return false
	}

	info.joins--
	if info.joins != 0 {
		// If we still have outstanding joins, then do nothing further.
		g.memberships[groupAddress] = info
		return true
	}

	info.deleteScheduled = true
	info.cancelDelayedReportJob()

	if !g.shouldPerformForGroup(groupAddress) {
		delete(g.memberships, groupAddress)
		return true
	}

	switch g.mode {
	case protocolModeV2:
		info.transmissionLeft = g.robustnessVariable
		if g.sendV2ReportAndMaybeScheduleChangedTimer(groupAddress, &info, MulticastGroupProtocolV2ReportRecordChangeToIncludeMode) {
			g.memberships[groupAddress] = info
		} else {
			delete(g.memberships, groupAddress)
		}
	case protocolModeV1Compatibility, protocolModeV1:
		g.transitionToNonMemberLocked(groupAddress, &info)
		delete(g.memberships, groupAddress)
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}

	return true
}

// HandleQueryV2Locked handles a V2 query.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) HandleQueryV2Locked(groupAddress tcpip.Address, maxResponseCode uint16, sources header.AddressIterator, robustnessVariable uint8, queryInterval time.Duration) {
	if !g.opts.Protocol.Enabled() {
		return
	}

	switch g.mode {
	case protocolModeV1Compatibility, protocolModeV1:
		g.handleQueryInnerLocked(groupAddress, g.opts.Protocol.V2QueryMaxRespCodeToV1Delay(maxResponseCode))
		return
	case protocolModeV2:
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}

	if robustnessVariable != 0 {
		g.robustnessVariable = robustnessVariable
	}

	if queryInterval != 0 {
		g.queryInterval = queryInterval
	}

	maxResponseTime := g.calculateDelayTimerDuration(g.opts.Protocol.V2QueryMaxRespCodeToV2Delay(maxResponseCode))

	// As per RFC 3376 section 5.2,
	//
	//   1. If there is a pending response to a previous General Query
	//      scheduled sooner than the selected delay, no additional response
	//      needs to be scheduled.
	//
	//   2. If the received Query is a General Query, the interface timer is
	//      used to schedule a response to the General Query after the
	//      selected delay.  Any previously pending response to a General
	//      Query is canceled.
	//
	//   3. If the received Query is a Group-Specific Query or a Group-and-
	//      Source-Specific Query and there is no pending response to a
	//      previous Query for this group, then the group timer is used to
	//      schedule a report.  If the received Query is a Group-and-Source-
	//      Specific Query, the list of queried sources is recorded to be used
	//      when generating a response.
	//
	//   4. If there already is a pending response to a previous Query
	//      scheduled for this group, and either the new Query is a Group-
	//      Specific Query or the recorded source-list associated with the
	//      group is empty, then the group source-list is cleared and a single
	//      response is scheduled using the group timer.  The new response is
	//      scheduled to be sent at the earliest of the remaining time for the
	//      pending report and the selected delay.
	//
	//   5. If the received Query is a Group-and-Source-Specific Query and
	//      there is a pending response for this group with a non-empty
	//      source-list, then the group source list is augmented to contain
	//      the list of sources in the new Query and a single response is
	//      scheduled using the group timer.  The new response is scheduled to
	//      be sent at the earliest of the remaining time for the pending
	//      report and the selected delay.
	//
	// As per RFC 3810 section 6.2,
	//
	//   1. If there is a pending response to a previous General Query
	//      scheduled sooner than the selected delay, no additional response
	//      needs to be scheduled.
	//
	//   2. If the received Query is a General Query, the Interface Timer is
	//      used to schedule a response to the General Query after the
	//      selected delay.  Any previously pending response to a General
	//      Query is canceled.
	//
	//   3. If the received Query is a Multicast Address Specific Query or a
	//      Multicast Address and Source Specific Query and there is no
	//      pending response to a previous Query for this multicast address,
	//      then the Multicast Address Timer is used to schedule a report.  If
	//      the received Query is a Multicast Address and Source Specific
	//      Query, the list of queried sources is recorded to be used when
	//      generating a response.
	//
	//   4. If there is already a pending response to a previous Query
	//      scheduled for this multicast address, and either the new Query is
	//      a Multicast Address Specific Query or the recorded source list
	//      associated with the multicast address is empty, then the multicast
	//      address source list is cleared and a single response is scheduled,
	//      using the Multicast Address Timer.  The new response is scheduled
	//      to be sent at the earliest of the remaining time for the pending
	//      report and the selected delay.
	//
	//   5. If the received Query is a Multicast Address and Source Specific
	//      Query and there is a pending response for this multicast address
	//      with a non-empty source list, then the multicast address source
	//      list is augmented to contain the list of sources in the new Query,
	//      and a single response is scheduled using the Multicast Address
	//      Timer.  The new response is scheduled to be sent at the earliest
	//      of the remaining time for the pending report and the selected
	//      delay.
	now := g.opts.Clock.Now()
	if !g.generalQueryV2TimerFiresAt.IsZero() && g.generalQueryV2TimerFiresAt.Sub(now) <= maxResponseTime {
		return
	}

	if groupAddress.Unspecified() {
		if g.generalQueryV2Timer == nil {
			// TODO(https://issuetracker.google.com/264799098): Create timer on
			// initialization instead of lazily creating the timer since the timer
			// does not change after being created.
			g.generalQueryV2Timer = g.opts.Clock.AfterFunc(maxResponseTime, func() {
				g.protocolMU.Lock()
				defer g.protocolMU.Unlock()

				g.generalQueryV2TimerFiresAt = time.Time{}

				// As per RFC 3810 section 6.3,
				//
				//      If the expired timer is the Interface Timer (i.e., there is a
				//      pending response to a General Query), then one Current State
				//      Record is sent for each multicast address for which the specified
				//      interface has listening state, as described in section 4.2.  The
				//      Current State Record carries the multicast address and its
				//      associated filter mode (MODE_IS_INCLUDE or MODE_IS_EXCLUDE) and
				//      Source list.  Multiple Current State Records are packed into
				//      individual Report messages, to the extent possible.
				//
				// As per RFC 3376 section 5.2,
				//
				//      If the expired timer is the interface timer (i.e., it is a pending
				//      response to a General Query), then one Current-State Record is
				//      sent for each multicast address for which the specified interface
				//      has reception state, as described in section 3.2.  The Current-
				//      State Record carries the multicast address and its associated
				//      filter mode (MODE_IS_INCLUDE or MODE_IS_EXCLUDE) and source list.
				//      Multiple Current-State Records are packed into individual Report
				//      messages, to the extent possible.
				reportBuilder := g.opts.Protocol.NewReportV2Builder()
				for groupAddress, info := range g.memberships {
					if info.deleteScheduled || !g.shouldPerformForGroup(groupAddress) {
						continue
					}

					// A MODE_IS_EXCLUDE record without any sources indicates that we are
					// interested in traffic from all sources for the group.
					//
					// We currently only hold groups if we have an active interest in the
					// group.
					reportBuilder.AddRecord(
						MulticastGroupProtocolV2ReportRecordModeIsExclude,
						groupAddress,
					)
				}

				_, _ = reportBuilder.Send()
			})
		} else {
			g.generalQueryV2Timer.Reset(maxResponseTime)
		}
		g.generalQueryV2TimerFiresAt = now.Add(maxResponseTime)
		return
	}

	if info, ok := g.memberships[groupAddress]; ok && !info.deleteScheduled && g.shouldPerformForGroup(groupAddress) {
		if info.delayedReportJobFiresAt.IsZero() || (!sources.Done() && len(info.queriedIncludeSources) != 0) {
			for {
				source, ok := sources.Next()
				if !ok {
					break
				}

				info.queriedIncludeSources[source] = struct{}{}
			}
		} else {
			info.clearQueriedIncludeSources()
		}
		g.setDelayTimerForAddressLocked(groupAddress, &info, maxResponseTime)
		g.memberships[groupAddress] = info
	}
}

// HandleQueryLocked handles a query message with the specified maximum response
// time.
//
// If the group address is unspecified, then reports will be scheduled for all
// joined groups.
//
// Report(s) will be scheduled to be sent after a random duration between 0 and
// the maximum response time.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) HandleQueryLocked(groupAddress tcpip.Address, maxResponseTime time.Duration) {
	if !g.opts.Protocol.Enabled() {
		return
	}

	switch g.mode {
	case protocolModeV2, protocolModeV1Compatibility:
		// As per 3376 section 8.12 (for IGMPv3),
		//
		//   The Older Version Querier Interval is the time-out for transitioning
		//   a host back to IGMPv3 mode once an older version query is heard.
		//   When an older version query is received, hosts set their Older
		//   Version Querier Present Timer to Older Version Querier Interval.
		//
		//   This value MUST be ((the Robustness Variable) times (the Query
		//   Interval in the last Query received)) plus (one Query Response
		//   Interval).
		//
		// As per RFC 3810 section 9.12 (for MLDv2),
		//
		//   The Older Version Querier Present Timeout is the time-out for
		//   transitioning a host back to MLDv2 Host Compatibility Mode.  When an
		//   MLDv1 query is received, MLDv2 hosts set their Older Version Querier
		//   Present Timer to [Older Version Querier Present Timeout].
		//
		//   This value MUST be ([Robustness Variable] times (the [Query Interval]
		//   in the last Query received)) plus ([Query Response Interval]).
		modeRevertDelay := time.Duration(g.robustnessVariable) * g.queryInterval
		if g.modeTimer == nil {
			// TODO(https://issuetracker.google.com/264799098): Create timer on
			// initialization instead of lazily creating the timer since the timer
			// does not change after being created.
			g.modeTimer = g.opts.Clock.AfterFunc(modeRevertDelay, func() {
				g.protocolMU.Lock()
				defer g.protocolMU.Unlock()
				g.mode = protocolModeV2
			})
		} else {
			g.modeTimer.Reset(modeRevertDelay)
		}
		g.mode = protocolModeV1Compatibility
		g.cancelV2ReportTimers()
	case protocolModeV1:
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}
	g.handleQueryInnerLocked(groupAddress, maxResponseTime)
}

func (g *GenericMulticastProtocolState) handleQueryInnerLocked(groupAddress tcpip.Address, maxResponseTime time.Duration) {
	maxResponseTime = g.calculateDelayTimerDuration(maxResponseTime)

	// As per RFC 2236 section 2.4 (for IGMPv2),
	//
	//   In a Membership Query message, the group address field is set to zero
	//   when sending a General Query, and set to the group address being
	//   queried when sending a Group-Specific Query.
	//
	// As per RFC 2710 section 3.6 (for MLDv1),
	//
	//   In a Query message, the Multicast Address field is set to zero when
	//   sending a General Query, and set to a specific IPv6 multicast address
	//   when sending a Multicast-Address-Specific Query.
	if groupAddress.Unspecified() {
		// This is a general query as the group address is unspecified.
		for groupAddress, info := range g.memberships {
			g.setDelayTimerForAddressLocked(groupAddress, &info, maxResponseTime)
			g.memberships[groupAddress] = info
		}
	} else if info, ok := g.memberships[groupAddress]; ok && !info.deleteScheduled {
		g.setDelayTimerForAddressLocked(groupAddress, &info, maxResponseTime)
		g.memberships[groupAddress] = info
	}
}

// HandleReportLocked handles a report message.
//
// If the report is for a joined group, any active delayed report will be
// cancelled and the host state for the group transitions to idle.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) HandleReportLocked(groupAddress tcpip.Address) {
	if !g.opts.Protocol.Enabled() {
		return
	}

	// As per RFC 2236 section 3 pages 3-4 (for IGMPv2),
	//
	//   If the host receives another host's Report (version 1 or 2) while it has
	//   a timer running, it stops its timer for the specified group and does not
	//   send a Report
	//
	// As per RFC 2710 section 4 page 6 (for MLDv1),
	//
	//   If a node receives another node's Report from an interface for a
	//   multicast address while it has a timer running for that same address
	//   on that interface, it stops its timer and does not send a Report for
	//   that address, thus suppressing duplicate reports on the link.
	if info, ok := g.memberships[groupAddress]; ok {
		info.cancelDelayedReportJob()
		info.lastToSendReport = false
		g.memberships[groupAddress] = info
	}
}

// initializeNewMemberLocked initializes a new group membership.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) initializeNewMemberLocked(groupAddress tcpip.Address, info *multicastGroupState, callersV2ReportBuilder MulticastGroupProtocolV2ReportBuilder) {
	if !g.shouldPerformForGroup(groupAddress) {
		return
	}

	info.lastToSendReport = false

	switch g.mode {
	case protocolModeV2:
		info.transmissionLeft = g.robustnessVariable
		if callersV2ReportBuilder == nil {
			g.sendV2ReportAndMaybeScheduleChangedTimer(groupAddress, info, MulticastGroupProtocolV2ReportRecordChangeToExcludeMode)
		} else {
			callersV2ReportBuilder.AddRecord(MulticastGroupProtocolV2ReportRecordChangeToExcludeMode, groupAddress)
			info.transmissionLeft--
		}
	case protocolModeV1Compatibility, protocolModeV1:
		info.transmissionLeft = unsolicitedTransmissionCount
		g.maybeSendReportLocked(groupAddress, info)
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", g.mode))
	}
}

func (g *GenericMulticastProtocolState) shouldPerformForGroup(groupAddress tcpip.Address) bool {
	return g.opts.Protocol.ShouldPerformProtocol(groupAddress) && g.opts.Protocol.Enabled()
}

// maybeSendReportLocked attempts to send a report for a group.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) maybeSendReportLocked(groupAddress tcpip.Address, info *multicastGroupState) {
	if info.transmissionLeft == 0 {
		return
	}

	// As per RFC 2236 section 3 page 5 (for IGMPv2),
	//
	//   When a host joins a multicast group, it should immediately transmit an
	//   unsolicited Version 2 Membership Report for that group" ... "it is
	//   recommended that it be repeated".
	//
	// As per RFC 2710 section 4 page 6 (for MLDv1),
	//
	//   When a node starts listening to a multicast address on an interface,
	//   it should immediately transmit an unsolicited Report for that address
	//   on that interface, in case it is the first listener on the link. To
	//   cover the possibility of the initial Report being lost or damaged, it
	//   is recommended that it be repeated once or twice after short delays
	//   [Unsolicited Report Interval].
	//
	// TODO(gvisor.dev/issue/4901): Support a configurable number of initial
	// unsolicited reports.
	sent, err := g.opts.Protocol.SendReport(groupAddress)
	if err == nil && sent {
		info.lastToSendReport = true

		info.transmissionLeft--
		if info.transmissionLeft > 0 {
			g.setDelayTimerForAddressLocked(
				groupAddress,
				info,
				g.calculateDelayTimerDuration(g.opts.MaxUnsolicitedReportDelay),
			)
		}
	}
}

// maybeSendLeave attempts to send a leave message.
func (g *GenericMulticastProtocolState) maybeSendLeave(groupAddress tcpip.Address, lastToSendReport bool) {
	if !g.shouldPerformForGroup(groupAddress) || !lastToSendReport {
		return
	}

	// Okay to ignore the error here as if packet write failed, the multicast
	// routers will eventually drop our membership anyways. If the interface is
	// being disabled or removed, the generic multicast protocol's should be
	// cleared eventually.
	//
	// As per RFC 2236 section 3 page 5 (for IGMPv2),
	//
	//   When a router receives a Report, it adds the group being reported to
	//   the list of multicast group memberships on the network on which it
	//   received the Report and sets the timer for the membership to the
	//   [Group Membership Interval]. Repeated Reports refresh the timer. If
	//   no Reports are received for a particular group before this timer has
	//   expired, the router assumes that the group has no local members and
	//   that it need not forward remotely-originated multicasts for that
	//   group onto the attached network.
	//
	// As per RFC 2710 section 4 page 5 (for MLDv1),
	//
	//   When a router receives a Report from a link, if the reported address
	//   is not already present in the router's list of multicast address
	//   having listeners on that link, the reported address is added to the
	//   list, its timer is set to [Multicast Listener Interval], and its
	//   appearance is made known to the router's multicast routing component.
	//   If a Report is received for a multicast address that is already
	//   present in the router's list, the timer for that address is reset to
	//   [Multicast Listener Interval]. If an address's timer expires, it is
	//   assumed that there are no longer any listeners for that address
	//   present on the link, so it is deleted from the list and its
	//   disappearance is made known to the multicast routing component.
	//
	// The requirement to send a leave message is also optional (it MAY be
	// skipped):
	//
	// As per RFC 2236 section 6 page 8 (for IGMPv2),
	//
	//  "send leave" for the group on the interface. If the interface
	//   state says the Querier is running IGMPv1, this action SHOULD be
	//   skipped. If the flag saying we were the last host to report is
	//   cleared, this action MAY be skipped. The Leave Message is sent to
	//   the ALL-ROUTERS group (224.0.0.2).
	//
	// As per RFC 2710 section 5 page 8 (for MLDv1),
	//
	//   "send done" for the address on the interface. If the flag saying
	//   we were the last node to report is cleared, this action MAY be
	//   skipped. The Done message is sent to the link-scope all-routers
	//   address (FF02::2).
	_ = g.opts.Protocol.SendLeave(groupAddress)
}

// transitionToNonMemberLocked transitions the given multicast group the the
// non-member/listener state.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) transitionToNonMemberLocked(groupAddress tcpip.Address, info *multicastGroupState) {
	info.cancelDelayedReportJob()
	g.maybeSendLeave(groupAddress, info.lastToSendReport)
	info.lastToSendReport = false
}

// setDelayTimerForAddressLocked sets timer to send a delayed report.
//
// Precondition: g.protocolMU MUST be locked.
func (g *GenericMulticastProtocolState) setDelayTimerForAddressLocked(groupAddress tcpip.Address, info *multicastGroupState, maxResponseTime time.Duration) {
	if !g.shouldPerformForGroup(groupAddress) {
		return
	}

	if info.transmissionLeft < minQueryResponseTransmissionCount {
		info.transmissionLeft = minQueryResponseTransmissionCount
	}

	// As per RFC 2236 section 3 page 3 (for IGMPv2),
	//
	//   If a timer for the group is already running, it is reset to the random
	//   value only if the requested Max Response Time is less than the remaining
	//   value of the running timer.
	//
	// As per RFC 2710 section 4 page 5 (for MLDv1),
	//
	//   If a timer for any address is already running, it is reset to the new
	//   random value only if the requested Maximum Response Delay is less than
	//   the remaining value of the running timer.
	now := g.opts.Clock.Now()
	if !info.delayedReportJobFiresAt.IsZero() && info.delayedReportJobFiresAt.Sub(now) <= maxResponseTime {
		// The timer is scheduled to fire before the maximum response time so we
		// leave our timer as is.
		return
	}

	info.delayedReportJob.Cancel()
	info.delayedReportJob.Schedule(maxResponseTime)
	info.delayedReportJobFiresAt = now.Add(maxResponseTime)
}

// calculateDelayTimerDuration returns a random time between (0, maxRespTime].
func (g *GenericMulticastProtocolState) calculateDelayTimerDuration(maxRespTime time.Duration) time.Duration {
	// As per RFC 2236 section 3 page 3 (for IGMPv2),
	//
	//   When a host receives a Group-Specific Query, it sets a delay timer to a
	//   random value selected from the range (0, Max Response Time]...
	//
	// As per RFC 2710 section 4 page 6 (for MLDv1),
	//
	//   When a node receives a Multicast-Address-Specific Query, if it is
	//   listening to the queried Multicast Address on the interface from
	//   which the Query was received, it sets a delay timer for that address
	//   to a random value selected from the range [0, Maximum Response Delay],
	//   as above.
	if maxRespTime == 0 {
		return 0
	}
	return time.Duration(g.opts.Rand.Int63n(int64(maxRespTime)))
}
