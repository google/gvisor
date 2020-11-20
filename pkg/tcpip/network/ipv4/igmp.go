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
	"fmt"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// igmpV1PresentDefault is the initial state for igmpV1Present in the
	// igmpState. As per RFC 2236 Page 9 says "No IGMPv1 Router Present ... is
	// the initial state."
	igmpV1PresentDefault = false

	// v1RouterPresentTimeout from RFC 2236 Section 8.11, Page 18
	// See note on igmpState.igmpV1Present for more detail.
	v1RouterPresentTimeout = 400 * time.Second

	// v1MaxRespTimeTenthSec from RFC 2236 Section 4, Page 5. "The IGMPv1 router
	// will send General Queries with the Max Response Time set to 0. This MUST
	// be interpreted as a value of 100 (10 seconds)."
	v1MaxRespTimeTenthSec = 100

	// UnsolicitedReportIntervalMaxTenthSec from RFC 2236 Section 8.10, Page 19.
	// As all IGMP delay timers are set to a random value between 0 and the
	// interval, this is technically a maximum.
	UnsolicitedReportIntervalMaxTenthSec = 100
)

// igmpState is the per-interface IGMP state.
//
// igmpState.init() MUST be called after creating an IGMP state.
type igmpState struct {
	// The IPv4 endpoint this igmpState is for.
	ep *endpoint

	mu struct {
		sync.RWMutex

		// memberships contains the map of host groups to their state, timer, and
		// flag info.
		memberships map[tcpip.Address]membershipInfo

		// igmpV1Present is for maintaining compatibility with IGMPv1 Routers, from
		// RFC 2236 Section 4 Page 6: "The IGMPv1 router expects Version 1
		// Membership Reports in response to its Queries, and will not pay
		// attention to Version 2 Membership Reports.  Therefore, a state variable
		// MUST be kept for each interface, describing whether the multicast
		// Querier on that interface is running IGMPv1 or IGMPv2.  This variable
		// MUST be based upon whether or not an IGMPv1 query was heard in the last
		// [Version 1 Router Present Timeout] seconds"
		igmpV1Present bool

		// igmpV1Job is scheduled when this interface receives an IGMPv1 style
		// message, upon expiration the igmpV1Present flag is cleared.
		// igmpV1Job may not be nil once igmpState is initialized.
		igmpV1Job *tcpip.Job
	}
}

// membershipInfo holds the IGMPv2 state for a particular multicast address.
type membershipInfo struct {
	// state contains the current IGMP state for this member.
	state hostState

	// lastToSendReport is true if this was "the last host to send a report from
	// this group."
	// RFC 2236, Section 6, Page 9. This is used to track whether or not there
	// are other hosts on this subnet that belong to this group - RFC 2236
	// Section 3, Page 5.
	lastToSendReport bool

	// delayedReportJob is used to delay sending responses to IGMP messages in
	// order to reduce duplicate reports from multiple hosts on the interface.
	// Must not be nil.
	delayedReportJob *tcpip.Job
}

type hostState int

// From RFC 2236, Section 6, Page 7.
const (
	// "'Non-Member' state, when the host does not belong to the group on
	// the interface.  This is the initial state for all memberships on
	// all network interfaces; it requires no storage in the host."
	_ hostState = iota

	// delayingMember is the "'Delaying Member' state, when the host belongs to
	// the group on the interface and has a report delay timer running for that
	// membership."
	delayingMember

	// idleMember is the "Idle Member" state, when the host belongs to the group
	// on the interface and does not have a report delay timer running for that
	// membership.
	idleMember
)

// init sets up an igmpState struct, and is required to be called before using
// a new igmpState.
func (igmp *igmpState) init(ep *endpoint) {
	igmp.mu.Lock()
	defer igmp.mu.Unlock()
	igmp.ep = ep
	igmp.mu.memberships = make(map[tcpip.Address]membershipInfo)
	igmp.mu.igmpV1Present = igmpV1PresentDefault
	igmp.mu.igmpV1Job = igmp.ep.protocol.stack.NewJob(&igmp.mu, func() {
		igmp.mu.igmpV1Present = false
	})
}

func (igmp *igmpState) handleIGMP(pkt *stack.PacketBuffer) {
	stats := igmp.ep.protocol.stack.Stats()
	received := stats.IGMP.PacketsReceived
	headerView, ok := pkt.Data.PullUp(header.IGMPMinimumSize)
	if !ok {
		received.Invalid.Increment()
		return
	}
	h := header.IGMP(headerView)

	// Temporarily reset the checksum field to 0 in order to calculate the proper
	// checksum.
	wantChecksum := h.Checksum()
	h.SetChecksum(0)
	gotChecksum := ^header.ChecksumVV(pkt.Data, 0 /* initial */)
	h.SetChecksum(wantChecksum)

	if gotChecksum != wantChecksum {
		received.ChecksumErrors.Increment()
		return
	}

	switch h.Type() {
	case header.IGMPMembershipQuery:
		received.MembershipQuery.Increment()
		if len(headerView) < header.IGMPQueryMinimumSize {
			received.Invalid.Increment()
			return
		}
		igmp.handleMembershipQuery(h.GroupAddress(), h.MaxRespTime())
	case header.IGMPv1MembershipReport:
		received.V1MembershipReport.Increment()
		if len(headerView) < header.IGMPReportMinimumSize {
			received.Invalid.Increment()
			return
		}
		igmp.handleMembershipReport(h.GroupAddress())
	case header.IGMPv2MembershipReport:
		received.V2MembershipReport.Increment()
		if len(headerView) < header.IGMPReportMinimumSize {
			received.Invalid.Increment()
			return
		}
		igmp.handleMembershipReport(h.GroupAddress())
	case header.IGMPLeaveGroup:
		received.LeaveGroup.Increment()
		// As per RFC 2236 Section 6, Page 7: "IGMP messages other than Query or
		// Report, are ignored in all states"

	default:
		// As per RFC 2236 Section 2.1 Page 3: "Unrecognized message types should
		// be silently ignored. New message types may be used by newer versions of
		// IGMP, by multicast routing protocols, or other uses."
		received.Unrecognized.Increment()
	}
}

func (igmp *igmpState) handleMembershipQuery(groupAddress tcpip.Address, maxRespTime byte) {
	igmp.mu.Lock()
	defer igmp.mu.Unlock()

	// As per RFC 2236 Section 6, Page 10: If the maximum response time is zero
	// then change the state to note that an IGMPv1 router is present and
	// schedule the query received Job.
	if maxRespTime == 0 {
		igmp.mu.igmpV1Job.Cancel()
		igmp.mu.igmpV1Job.Schedule(v1RouterPresentTimeout)
		igmp.mu.igmpV1Present = true
		maxRespTime = v1MaxRespTimeTenthSec
	}

	// IPv4Any is the General Query Address.
	if groupAddress == header.IPv4Any {
		for membershipAddress, info := range igmp.mu.memberships {
			igmp.setDelayTimerForAddressRLocked(membershipAddress, &info, maxRespTime)
			igmp.mu.memberships[membershipAddress] = info
		}
	} else if info, ok := igmp.mu.memberships[groupAddress]; ok {
		igmp.setDelayTimerForAddressRLocked(groupAddress, &info, maxRespTime)
		igmp.mu.memberships[groupAddress] = info
	}
}

// setDelayTimerForAddressRLocked modifies the passed info only and does not
// modify IGMP state directly.
//
// Precondition: igmp.mu MUST be read locked.
func (igmp *igmpState) setDelayTimerForAddressRLocked(groupAddress tcpip.Address, info *membershipInfo, maxRespTime byte) {
	if info.state == delayingMember {
		// As per RFC 2236 Section 3, page 3: "If a timer for the group is already
		// running, it is reset to the random value only if the requested Max
		// Response Time is less than the remaining value of the running timer.
		// TODO: Reset the timer if time remaining is greater than maxRespTime.
		return
	}
	info.state = delayingMember
	info.delayedReportJob.Cancel()
	info.delayedReportJob.Schedule(igmp.calculateDelayTimerDuration(maxRespTime))
}

func (igmp *igmpState) handleMembershipReport(groupAddress tcpip.Address) {
	igmp.mu.Lock()
	defer igmp.mu.Unlock()

	// As per RFC 2236 Section 3, pages 3-4: "If the host receives another host's
	// Report (version 1 or 2) while it has a timer running, it stops its timer
	// for the specified group and does not send a Report"
	if info, ok := igmp.mu.memberships[groupAddress]; ok {
		info.delayedReportJob.Cancel()
		info.lastToSendReport = false
		igmp.mu.memberships[groupAddress] = info
	}
}

// writePacket assembles and sends an IGMP packet with the provided fields,
// incrementing the provided stat counter on success.
func (igmp *igmpState) writePacket(destAddress tcpip.Address, groupAddress tcpip.Address, igmpType header.IGMPType) {
	igmpData := header.IGMP(buffer.NewView(header.IGMPReportMinimumSize))
	igmpData.SetType(igmpType)
	igmpData.SetGroupAddress(groupAddress)
	igmpData.SetChecksum(header.IGMPCalculateChecksum(igmpData))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(igmp.ep.MaxHeaderLength()),
		Data:               buffer.View(igmpData).ToVectorisedView(),
	})

	// TODO(gvisor.dev/issue/4888): We should not use the unspecified address,
	// rather we should select an appropriate local address.
	r := stack.Route{
		LocalAddress:  header.IPv4Any,
		RemoteAddress: destAddress,
	}
	igmp.ep.addIPHeader(&r, pkt, stack.NetworkHeaderParams{
		Protocol: header.IGMPProtocolNumber,
		TTL:      header.IGMPTTL,
		TOS:      stack.DefaultTOS,
	})

	// TODO(b/162198658): set the ROUTER_ALERT option when sending Host
	// Membership Reports.
	sent := igmp.ep.protocol.stack.Stats().IGMP.PacketsSent
	if err := igmp.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv4Address(destAddress), nil /* gso */, header.IPv4ProtocolNumber, pkt); err != nil {
		sent.Dropped.Increment()
	} else {
		switch igmpType {
		case header.IGMPv1MembershipReport:
			sent.V1MembershipReport.Increment()
		case header.IGMPv2MembershipReport:
			sent.V2MembershipReport.Increment()
		case header.IGMPLeaveGroup:
			sent.LeaveGroup.Increment()
		default:
			panic(fmt.Sprintf("unrecognized igmp type = %d", igmpType))
		}
	}
}

// sendReport sends a Host Membership Report in response to a query or after
// this host joins a new group on this interface.
//
// Precondition: igmp.mu MUST be locked.
func (igmp *igmpState) sendReportLocked(groupAddress tcpip.Address) {
	igmpType := header.IGMPv2MembershipReport
	if igmp.mu.igmpV1Present {
		igmpType = header.IGMPv1MembershipReport
	}
	igmp.writePacket(groupAddress, groupAddress, igmpType)

	// Update the state of the membership for this group. If the group no longer
	// exists, do nothing since this report must have been a race with a remove
	// or is in the process of being added.
	info, ok := igmp.mu.memberships[groupAddress]
	if !ok {
		return
	}
	info.state = idleMember
	info.lastToSendReport = true
	igmp.mu.memberships[groupAddress] = info
}

// sendLeave sends a Leave Group report to the IPv4 All Routers Group.
//
// Precondition: igmp.mu MUST be read locked.
func (igmp *igmpState) sendLeaveRLocked(groupAddress tcpip.Address) {
	// As per RFC 2236 Section 6, Page 8: "If the interface state says the
	// Querier is running IGMPv1, this action SHOULD be skipped. If the flag
	// saying we were the last host to report is cleared, this action MAY be
	// skipped."
	if igmp.mu.igmpV1Present || !igmp.mu.memberships[groupAddress].lastToSendReport {
		return
	}

	igmp.writePacket(header.IPv4AllRoutersGroup, groupAddress, header.IGMPLeaveGroup)
}

// joinGroup handles adding a new group to the membership map, setting up the
// IGMP state for the group, and sending and scheduling the required
// messages.
//
// If the group already exists in the membership map, returns
// tcpip.ErrDuplicateAddress.
func (igmp *igmpState) joinGroup(groupAddress tcpip.Address) *tcpip.Error {
	igmp.mu.Lock()
	defer igmp.mu.Unlock()
	if _, ok := igmp.mu.memberships[groupAddress]; ok {
		// The group already exists in the membership map.
		return tcpip.ErrDuplicateAddress
	}

	info := membershipInfo{
		// There isn't a Job scheduled currently, so it's just idle.
		state: idleMember,
		// Joining a group immediately sends a report.
		lastToSendReport: true,
		delayedReportJob: igmp.ep.protocol.stack.NewJob(&igmp.mu, func() {
			igmp.sendReportLocked(groupAddress)
		}),
	}

	// As per RFC 2236 Section 3, Page 5: "When a host joins a multicast group,
	// it should immediately transmit an unsolicited Version 2 Membership Report
	// for that group" ... "it is recommended that it be repeated"
	igmp.sendReportLocked(groupAddress)
	igmp.setDelayTimerForAddressRLocked(groupAddress, &info, UnsolicitedReportIntervalMaxTenthSec)
	igmp.mu.memberships[groupAddress] = info

	return nil
}

// leaveGroup handles removing the group from the membership map, cancels any
// delay timers associated with that group, and sends the Leave Group message
// if required.
//
// If the group does not exist in the membership map, this function will
// silently return.
func (igmp *igmpState) leaveGroup(groupAddress tcpip.Address) {
	igmp.mu.Lock()
	defer igmp.mu.Unlock()
	info, ok := igmp.mu.memberships[groupAddress]
	if !ok {
		return
	}

	// Clean up the state of the group before sending the leave message and
	// removing it from the map.
	info.delayedReportJob.Cancel()
	info.state = idleMember
	igmp.mu.memberships[groupAddress] = info

	igmp.sendLeaveRLocked(groupAddress)
	delete(igmp.mu.memberships, groupAddress)
}

// RFC 2236 Section 3, Page 3: The response time is set to a "random value...
// selected from the range (0, Max Response Time]" where Max Resp Time is given
// in units of 1/10 of a second.
func (igmp *igmpState) calculateDelayTimerDuration(maxRespTime byte) time.Duration {
	maxRespTimeDuration := DecisecondToSecond(maxRespTime)
	return time.Duration(igmp.ep.protocol.stack.Rand().Int63n(int64(maxRespTimeDuration)))
}

// DecisecondToSecond converts a byte representing deci-seconds to a Duration
// type. This helper function exists because the IGMP stack sends and receives
// Max Response Times in deci-seconds.
func DecisecondToSecond(ds byte) time.Duration {
	return time.Duration(ds) * time.Second / 10
}
