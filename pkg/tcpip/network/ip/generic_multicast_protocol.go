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

// Package ip holds IPv4/IPv6 common utilities.
package ip

import (
	"fmt"
	"math/rand"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// hostState is the state a host may be in for a multicast group.
type hostState int

// The states below are generic across IGMPv2 (RFC 2236 section 6) and MLDv1
// (RFC 2710 section 5). Even though the states are generic across both IGMPv2
// and MLDv1, IGMPv2 terminology will be used.
const (
	// "'Non-Member' state, when the host does not belong to the group on
	// the interface.  This is the initial state for all memberships on
	// all network interfaces; it requires no storage in the host."
	//
	// 'Non-Listener' is the MLDv1 term used to describe this state.
	_ hostState = iota

	// delayingMember is the "'Delaying Member' state, when the host belongs to
	// the group on the interface and has a report delay timer running for that
	// membership."
	//
	// 'Delaying Listener' is the MLDv1 term used to describe this state.
	delayingMember

	// idleMember is the "Idle Member" state, when the host belongs to the group
	// on the interface and does not have a report delay timer running for that
	// membership.
	//
	// 'Idle Listener' is the MLDv1 term used to describe this state.
	idleMember
)

// multicastGroupState holds the Generic Multicast Protocol state for a
// multicast group.
type multicastGroupState struct {
	// state contains the host's state for the group.
	state hostState

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
}

// MulticastGroupProtocol is a multicast group protocol whose core state machine
// can be represented by GenericMulticastProtocolState.
type MulticastGroupProtocol interface {
	// SendReport sends a multicast report for the specified group address.
	SendReport(groupAddress tcpip.Address) *tcpip.Error

	// SendLeave sends a multicast leave for the specified group address.
	SendLeave(groupAddress tcpip.Address) *tcpip.Error
}

// GenericMulticastProtocolState is the per interface generic multicast protocol
// state.
//
// There is actually no protocol named "Generic Multicast Protocol". Instead,
// the term used to refer to a generic multicast protocol that applies to both
// IPv4 and IPv6. Specifically, Generic Multicast Protocol is the core state
// machine of IGMPv2 as defined by RFC 2236 and MLDv1 as defined by RFC 2710.
//
// GenericMulticastProtocolState.Init MUST be called before calling any of
// the methods on GenericMulticastProtocolState.
type GenericMulticastProtocolState struct {
	rand                      *rand.Rand
	clock                     tcpip.Clock
	protocol                  MulticastGroupProtocol
	maxUnsolicitedReportDelay time.Duration

	mu struct {
		sync.Mutex

		// memberships holds group addresses and their associated state.
		memberships map[tcpip.Address]multicastGroupState
	}
}

// Init initializes the Generic Multicast Protocol state.
//
// maxUnsolicitedReportDelay is the maximum time between sending unsolicited
// reports after joining a group.
func (g *GenericMulticastProtocolState) Init(rand *rand.Rand, clock tcpip.Clock, protocol MulticastGroupProtocol, maxUnsolicitedReportDelay time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rand = rand
	g.clock = clock
	g.protocol = protocol
	g.maxUnsolicitedReportDelay = maxUnsolicitedReportDelay
	g.mu.memberships = make(map[tcpip.Address]multicastGroupState)
}

// JoinGroup handles joining a new group.
//
// Returns false if the group has already been joined.
func (g *GenericMulticastProtocolState) JoinGroup(groupAddress tcpip.Address) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.mu.memberships[groupAddress]; ok {
		// The group has already been joined.
		return false
	}

	info := multicastGroupState{
		// There isn't a job scheduled currently, so it's just idle.
		state: idleMember,
		// Joining a group immediately sends a report.
		lastToSendReport: true,
		delayedReportJob: tcpip.NewJob(g.clock, &g.mu, func() {
			info, ok := g.mu.memberships[groupAddress]
			if !ok {
				panic(fmt.Sprintf("expected to find group state for group = %s", groupAddress))
			}

			info.lastToSendReport = g.protocol.SendReport(groupAddress) == nil
			info.state = idleMember
			g.mu.memberships[groupAddress] = info
		}),
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
	info.lastToSendReport = g.protocol.SendReport(groupAddress) == nil
	g.setDelayTimerForAddressRLocked(groupAddress, &info, g.maxUnsolicitedReportDelay)
	g.mu.memberships[groupAddress] = info
	return true
}

// LeaveGroup handles leaving the group.
func (g *GenericMulticastProtocolState) LeaveGroup(groupAddress tcpip.Address) {
	g.mu.Lock()
	defer g.mu.Unlock()

	info, ok := g.mu.memberships[groupAddress]
	if !ok {
		return
	}

	info.delayedReportJob.Cancel()
	delete(g.mu.memberships, groupAddress)
	if info.lastToSendReport {
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
		_ = g.protocol.SendLeave(groupAddress)
	}
}

// HandleQuery handles a query message with the specified maximum response time.
//
// If the group address is unspecified, then reports will be scheduled for all
// joined groups.
//
// Report(s) will be scheduled to be sent after a random duration between 0 and
// the maximum response time.
func (g *GenericMulticastProtocolState) HandleQuery(groupAddress tcpip.Address, maxResponseTime time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()

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
		for groupAddress, info := range g.mu.memberships {
			g.setDelayTimerForAddressRLocked(groupAddress, &info, maxResponseTime)
			g.mu.memberships[groupAddress] = info
		}
	} else if info, ok := g.mu.memberships[groupAddress]; ok {
		g.setDelayTimerForAddressRLocked(groupAddress, &info, maxResponseTime)
		g.mu.memberships[groupAddress] = info
	}
}

// HandleReport handles a report message.
//
// If the report is for a joined group, any active delayed report will be
// cancelled and the host state for the group transitions to idle.
func (g *GenericMulticastProtocolState) HandleReport(groupAddress tcpip.Address) {
	g.mu.Lock()
	defer g.mu.Unlock()

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
	if info, ok := g.mu.memberships[groupAddress]; ok {
		info.delayedReportJob.Cancel()
		info.lastToSendReport = false
		info.state = idleMember
		g.mu.memberships[groupAddress] = info
	}
}

// setDelayTimerForAddressRLocked sets timer to send a delay report.
//
// Precondition: g.mu MUST be read locked.
func (g *GenericMulticastProtocolState) setDelayTimerForAddressRLocked(groupAddress tcpip.Address, info *multicastGroupState, maxResponseTime time.Duration) {
	// As per RFC 2236 section 3 page 3 (for IGMPv2),
	//
	//   If a timer for the group is already unning, it is reset to the random
	//   value only if the requested Max Response Time is less than the remaining
	//   value of the running timer.
	//
	// As per RFC 2710 section 4 page 5 (for MLDv1),
	//
	//   If a timer for any address is already running, it is reset to the new
	//   random value only if the requested Maximum Response Delay is less than
	//   the remaining value of the running timer.
	if info.state == delayingMember {
		// TODO: Reset the timer if time remaining is greater than maxResponseTime.
		return
	}
	info.state = delayingMember
	info.delayedReportJob.Cancel()
	info.delayedReportJob.Schedule(g.calculateDelayTimerDuration(maxResponseTime))
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
	return time.Duration(g.rand.Int63n(int64(maxRespTime)))
}
