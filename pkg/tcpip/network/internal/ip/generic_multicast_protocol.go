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
)

// multicastGroupState holds the Generic Multicast Protocol state for a
// multicast group.
type multicastGroupState struct {
	// joins is the number of times the group has been joined.
	joins uint64

	// transmissionLeft is the number of transmissions left to send.
	transmissionLeft uint

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
}

func (m *multicastGroupState) cancelDelayedReportJob() {
	m.delayedReportJob.Cancel()
	m.delayedReportJobFiresAt = time.Time{}
	m.transmissionLeft = 0
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
}

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
		opts:        opts,
		memberships: make(map[tcpip.Address]multicastGroupState),
		protocolMU:  protocolMU,
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

	for groupAddress, info := range g.memberships {
		g.transitionToNonMemberLocked(groupAddress, &info)
		g.memberships[groupAddress] = info
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

	for groupAddress, info := range g.memberships {
		g.initializeNewMemberLocked(groupAddress, &info)
		g.memberships[groupAddress] = info
	}
}

// SendQueuedReportsLocked attempts to send reports for groups that failed to
// send reports during their last attempt.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) SendQueuedReportsLocked() {
	for groupAddress, info := range g.memberships {
		if info.delayedReportJobFiresAt.IsZero() {
			g.maybeSendReportLocked(groupAddress, &info)
			g.memberships[groupAddress] = info
		}
	}
}

// JoinGroupLocked handles joining a new group.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) JoinGroupLocked(groupAddress tcpip.Address) {
	if info, ok := g.memberships[groupAddress]; ok {
		// The group has already been joined.
		info.joins++
		g.memberships[groupAddress] = info
		return
	}

	info := multicastGroupState{
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
			g.maybeSendReportLocked(groupAddress, &info)
			g.memberships[groupAddress] = info
		}),
	}

	if g.opts.Protocol.Enabled() {
		g.initializeNewMemberLocked(groupAddress, &info)
	}

	g.memberships[groupAddress] = info
}

// IsLocallyJoinedRLocked returns true if the group is locally joined.
//
// Precondition: g.protocolMU must be read locked.
func (g *GenericMulticastProtocolState) IsLocallyJoinedRLocked(groupAddress tcpip.Address) bool {
	_, ok := g.memberships[groupAddress]
	return ok
}

// LeaveGroupLocked handles leaving the group.
//
// Returns false if the group is not currently joined.
//
// Precondition: g.protocolMU must be locked.
func (g *GenericMulticastProtocolState) LeaveGroupLocked(groupAddress tcpip.Address) bool {
	info, ok := g.memberships[groupAddress]
	if !ok {
		return false
	}

	if info.joins == 0 {
		panic(fmt.Sprintf("tried to leave group %s with a join count of 0", groupAddress))
	}
	info.joins--
	if info.joins != 0 {
		// If we still have outstanding joins, then do nothing further.
		g.memberships[groupAddress] = info
		return true
	}

	g.transitionToNonMemberLocked(groupAddress, &info)
	delete(g.memberships, groupAddress)
	return true
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
	} else if info, ok := g.memberships[groupAddress]; ok {
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
func (g *GenericMulticastProtocolState) initializeNewMemberLocked(groupAddress tcpip.Address, info *multicastGroupState) {
	info.lastToSendReport = false
	if g.shouldPerformForGroup(groupAddress) {
		info.transmissionLeft = unsolicitedTransmissionCount
		g.maybeSendReportLocked(groupAddress, info)
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
			g.setDelayTimerForAddressLocked(groupAddress, info, g.opts.MaxUnsolicitedReportDelay)
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
	if !g.shouldPerformForGroup(groupAddress) {
		return
	}

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

	maxResponseTime = g.calculateDelayTimerDuration(maxResponseTime)
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
