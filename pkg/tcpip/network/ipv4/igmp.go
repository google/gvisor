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
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// v1RouterPresentTimeout from RFC 2236 Section 8.11, Page 18
	// See note on igmpState.igmpV1Present for more detail.
	v1RouterPresentTimeout = 400 * time.Second

	// v1MaxRespTime from RFC 2236 Section 4, Page 5. "The IGMPv1 router
	// will send General Queries with the Max Response Time set to 0. This MUST
	// be interpreted as a value of 100 (10 seconds)."
	//
	// Note that the Max Response Time field is a value in units of deciseconds.
	v1MaxRespTime = 10 * time.Second

	// UnsolicitedReportIntervalMax is the maximum delay between sending
	// unsolicited IGMP reports.
	//
	// Obtained from RFC 2236 Section 8.10, Page 19.
	UnsolicitedReportIntervalMax = 10 * time.Second
)

type protocolMode int

const (
	protocolModeV2OrV3 protocolMode = iota
	protocolModeV1
	// protocolModeV1Compatibility is for maintaining compatibility with IGMPv1
	// Routers.
	//
	// Per RFC 2236 Section 4 Page 6: "The IGMPv1 router expects Version 1
	// Membership Reports in response to its Queries, and will not pay
	// attention to Version 2 Membership Reports.  Therefore, a state variable
	// MUST be kept for each interface, describing whether the multicast
	// Querier on that interface is running IGMPv1 or IGMPv2.  This variable
	// MUST be based upon whether or not an IGMPv1 query was heard in the last
	// [Version 1 Router Present Timeout] seconds".
	protocolModeV1Compatibility
)

// IGMPVersion is the forced version of IGMP.
type IGMPVersion int

const (
	_ IGMPVersion = iota
	// IGMPVersion1 indicates IGMPv1.
	IGMPVersion1
	// IGMPVersion2 indicates IGMPv2. Note that IGMP may still fallback to V1
	// compatibility mode as required by IGMPv2.
	IGMPVersion2
	// IGMPVersion3 indicates IGMPv3. Note that IGMP may still fallback to V2
	// compatibility mode as required by IGMPv3.
	IGMPVersion3
)

// IGMPEndpoint is a network endpoint that supports IGMP.
type IGMPEndpoint interface {
	// SetIGMPVersion sets the IGMP version.
	//
	// Returns the previous IGMP version.
	SetIGMPVersion(IGMPVersion) IGMPVersion

	// GetIGMPVersion returns the IGMP version.
	GetIGMPVersion() IGMPVersion
}

// IGMPOptions holds options for IGMP.
type IGMPOptions struct {
	// Enabled indicates whether IGMP will be performed.
	//
	// When enabled, IGMP may transmit IGMP report and leave messages when
	// joining and leaving multicast groups respectively, and handle incoming
	// IGMP packets.
	//
	// This field is ignored and is always assumed to be false for interfaces
	// without neighbouring nodes (e.g. loopback).
	Enabled bool
}

var _ ip.MulticastGroupProtocol = (*igmpState)(nil)

// igmpState is the per-interface IGMP state.
//
// igmpState.init() MUST be called after creating an IGMP state.
type igmpState struct {
	// The IPv4 endpoint this igmpState is for.
	ep *endpoint

	genericMulticastProtocol ip.GenericMulticastProtocolState

	// mode is used to configure the version of IGMP to perform.
	mode protocolMode

	// igmpV1Job is scheduled when this interface receives an IGMPv1 style
	// message, upon expiration the igmpV1Present flag is cleared.
	// igmpV1Job may not be nil once igmpState is initialized.
	igmpV1Job *tcpip.Job
}

// Enabled implements ip.MulticastGroupProtocol.
func (igmp *igmpState) Enabled() bool {
	// No need to perform IGMP on loopback interfaces since they don't have
	// neighbouring nodes.
	return igmp.ep.protocol.options.IGMP.Enabled && !igmp.ep.nic.IsLoopback() && igmp.ep.Enabled()
}

// SendReport implements ip.MulticastGroupProtocol.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) SendReport(groupAddress tcpip.Address) (bool, tcpip.Error) {
	igmpType := header.IGMPv2MembershipReport
	switch igmp.mode {
	case protocolModeV2OrV3:
	case protocolModeV1, protocolModeV1Compatibility:
		igmpType = header.IGMPv1MembershipReport
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", igmp.mode))
	}
	return igmp.writePacket(groupAddress, groupAddress, igmpType)
}

// SendLeave implements ip.MulticastGroupProtocol.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) SendLeave(groupAddress tcpip.Address) tcpip.Error {
	// As per RFC 2236 Section 6, Page 8: "If the interface state says the
	// Querier is running IGMPv1, this action SHOULD be skipped. If the flag
	// saying we were the last host to report is cleared, this action MAY be
	// skipped."
	switch igmp.mode {
	case protocolModeV2OrV3:
		_, err := igmp.writePacket(header.IPv4AllRoutersGroup, groupAddress, header.IGMPLeaveGroup)
		return err
	case protocolModeV1, protocolModeV1Compatibility:
		return nil
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", igmp.mode))
	}
}

// ShouldPerformProtocol implements ip.MulticastGroupProtocol.
func (igmp *igmpState) ShouldPerformProtocol(groupAddress tcpip.Address) bool {
	// As per RFC 2236 section 6 page 10,
	//
	//   The all-systems group (address 224.0.0.1) is handled as a special
	//   case. The host starts in Idle Member state for that group on every
	//   interface, never transitions to another state, and never sends a
	//   report for that group.
	return groupAddress != header.IPv4AllSystems
}

type igmpv3ReportBuilder struct {
	igmp *igmpState

	records []header.IGMPv3ReportGroupAddressRecordSerializer
}

// AddRecord implements ip.MulticastGroupProtocolV2ReportBuilder.
func (b *igmpv3ReportBuilder) AddRecord(genericRecordType ip.MulticastGroupProtocolV2ReportRecordType, groupAddress tcpip.Address) {
	var recordType header.IGMPv3ReportRecordType
	switch genericRecordType {
	case ip.MulticastGroupProtocolV2ReportRecordModeIsInclude:
		recordType = header.IGMPv3ReportRecordModeIsInclude
	case ip.MulticastGroupProtocolV2ReportRecordModeIsExclude:
		recordType = header.IGMPv3ReportRecordModeIsExclude
	case ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode:
		recordType = header.IGMPv3ReportRecordChangeToIncludeMode
	case ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode:
		recordType = header.IGMPv3ReportRecordChangeToExcludeMode
	case ip.MulticastGroupProtocolV2ReportRecordAllowNewSources:
		recordType = header.IGMPv3ReportRecordAllowNewSources
	case ip.MulticastGroupProtocolV2ReportRecordBlockOldSources:
		recordType = header.IGMPv3ReportRecordBlockOldSources
	default:
		panic(fmt.Sprintf("unrecognied genericRecordType = %d", genericRecordType))
	}

	b.records = append(b.records, header.IGMPv3ReportGroupAddressRecordSerializer{
		RecordType:   recordType,
		GroupAddress: groupAddress,
		Sources:      nil,
	})
}

// Send implements ip.MulticastGroupProtocolV2ReportBuilder.
//
// +checklocksread:b.igmp.ep.mu
func (b *igmpv3ReportBuilder) Send() (sent bool, err tcpip.Error) {
	if len(b.records) == 0 {
		return false, err
	}

	options := header.IPv4OptionsSerializer{
		&header.IPv4SerializableRouterAlertOption{},
	}
	mtu := int(b.igmp.ep.MTU()) - int(options.Length())

	allSentWithSpecifiedAddress := true
	var firstErr tcpip.Error
	for records := b.records; len(records) != 0; {
		spaceLeft := mtu
		maxRecords := 0

		for ; maxRecords < len(records); maxRecords++ {
			tmp := spaceLeft - records[maxRecords].Length()
			if tmp > 0 {
				spaceLeft = tmp
			} else {
				break
			}
		}

		serializer := header.IGMPv3ReportSerializer{Records: records[:maxRecords]}
		records = records[maxRecords:]

		icmpView := buffer.NewViewSize(serializer.Length())
		serializer.SerializeInto(icmpView.AsSlice())
		if sentWithSpecifiedAddress, err := b.igmp.writePacketInner(
			icmpView,
			b.igmp.ep.stats.igmp.packetsSent.v3MembershipReport,
			options,
			header.IGMPv3RoutersAddress,
		); err != nil {
			if firstErr != nil {
				firstErr = nil
			}
			allSentWithSpecifiedAddress = false
		} else if !sentWithSpecifiedAddress {
			allSentWithSpecifiedAddress = false
		}
	}

	return allSentWithSpecifiedAddress, firstErr
}

// NewReportV2Builder implements ip.MulticastGroupProtocol.
func (igmp *igmpState) NewReportV2Builder() ip.MulticastGroupProtocolV2ReportBuilder {
	return &igmpv3ReportBuilder{igmp: igmp}
}

// V2QueryMaxRespCodeToV2Delay implements ip.MulticastGroupProtocol.
func (*igmpState) V2QueryMaxRespCodeToV2Delay(code uint16) time.Duration {
	if code > math.MaxUint8 {
		panic(fmt.Sprintf("got IGMPv3 MaxRespCode = %d, want <= %d", code, math.MaxUint8))
	}
	return header.IGMPv3MaximumResponseDelay(uint8(code))
}

// V2QueryMaxRespCodeToV1Delay implements ip.MulticastGroupProtocol.
func (*igmpState) V2QueryMaxRespCodeToV1Delay(code uint16) time.Duration {
	return time.Duration(code) * time.Millisecond
}

// init sets up an igmpState struct, and is required to be called before using
// a new igmpState.
//
// Must only be called once for the lifetime of igmp.
func (igmp *igmpState) init(ep *endpoint) {
	igmp.ep = ep
	igmp.genericMulticastProtocol.Init(&ep.mu, ip.GenericMulticastProtocolOptions{
		Rand:                      ep.protocol.stack.InsecureRNG(),
		Clock:                     ep.protocol.stack.Clock(),
		Protocol:                  igmp,
		MaxUnsolicitedReportDelay: UnsolicitedReportIntervalMax,
	})
	// As per RFC 2236 Page 9 says "No IGMPv1 Router Present ... is
	// the initial state.
	igmp.mode = protocolModeV2OrV3
	igmp.igmpV1Job = tcpip.NewJob(ep.protocol.stack.Clock(), &ep.mu, func() {
		igmp.mode = protocolModeV2OrV3
	})
}

// +checklocks:igmp.ep.mu
func (igmp *igmpState) isSourceIPValidLocked(src tcpip.Address, messageType header.IGMPType) bool {
	if messageType == header.IGMPMembershipQuery {
		// RFC 2236 does not require the IGMP implementation to check the source IP
		// for Membership Query messages.
		return true
	}

	// As per RFC 2236 section 10,
	//
	//   Ignore the Report if you cannot identify the source address of the
	//   packet as belonging to a subnet assigned to the interface on which the
	//   packet was received.
	//
	//   Ignore the Leave message if you cannot identify the source address of
	//   the packet as belonging to a subnet assigned to the interface on which
	//   the packet was received.
	//
	// Note: this rule applies to both V1 and V2 Membership Reports.
	var isSourceIPValid bool
	igmp.ep.addressableEndpointState.ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		if subnet := addressEndpoint.Subnet(); subnet.Contains(src) {
			isSourceIPValid = true
			return false
		}
		return true
	})

	return isSourceIPValid
}

// +checklocks:igmp.ep.mu
func (igmp *igmpState) isPacketValidLocked(pkt *stack.PacketBuffer, messageType header.IGMPType, hasRouterAlertOption bool) bool {
	// We can safely assume that the IP header is valid if we got this far.
	iph := header.IPv4(pkt.NetworkHeader().Slice())

	// As per RFC 2236 section 2,
	//
	//   All IGMP messages described in this document are sent with IP TTL 1, and
	//   contain the IP Router Alert option [RFC 2113] in their IP header.
	if !hasRouterAlertOption || iph.TTL() != header.IGMPTTL {
		return false
	}

	return igmp.isSourceIPValidLocked(iph.SourceAddress(), messageType)
}

// handleIGMP handles an IGMP packet.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) handleIGMP(pkt *stack.PacketBuffer, hasRouterAlertOption bool) {
	received := igmp.ep.stats.igmp.packetsReceived
	hdr, ok := pkt.Data().PullUp(pkt.Data().Size())
	if !ok {
		received.invalid.Increment()
		return
	}
	h := header.IGMP(hdr)
	if len(h) < header.IGMPMinimumSize {
		received.invalid.Increment()
		return
	}

	// As per RFC 1071 section 1.3,
	//
	//   To check a checksum, the 1's complement sum is computed over the
	//   same set of octets, including the checksum field. If the result
	//   is all 1 bits (-0 in 1's complement arithmetic), the check
	//   succeeds.
	if pkt.Data().Checksum() != 0xFFFF {
		received.checksumErrors.Increment()
		return
	}

	isValid := func(minimumSize int) bool {
		return len(hdr) >= minimumSize && igmp.isPacketValidLocked(pkt, h.Type(), hasRouterAlertOption)
	}

	switch h.Type() {
	case header.IGMPMembershipQuery:
		received.membershipQuery.Increment()
		if len(h) >= header.IGMPv3QueryMinimumSize {
			if isValid(header.IGMPv3QueryMinimumSize) {
				igmp.handleMembershipQueryV3(header.IGMPv3Query(h))
			} else {
				received.invalid.Increment()
			}
			return
		} else if !isValid(header.IGMPQueryMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipQuery(h.GroupAddress(), h.MaxRespTime())
	case header.IGMPv1MembershipReport:
		received.v1MembershipReport.Increment()
		if !isValid(header.IGMPReportMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipReport(h.GroupAddress())
	case header.IGMPv2MembershipReport:
		received.v2MembershipReport.Increment()
		if !isValid(header.IGMPReportMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipReport(h.GroupAddress())
	case header.IGMPLeaveGroup:
		received.leaveGroup.Increment()
		if !isValid(header.IGMPLeaveMessageMinimumSize) {
			received.invalid.Increment()
			return
		}
		// As per RFC 2236 Section 6, Page 7: "IGMP messages other than Query or
		// Report, are ignored in all states"

	default:
		// As per RFC 2236 Section 2.1 Page 3: "Unrecognized message types should
		// be silently ignored. New message types may be used by newer versions of
		// IGMP, by multicast routing protocols, or other uses."
		received.unrecognized.Increment()
	}
}

func (igmp *igmpState) resetV1Present() {
	igmp.igmpV1Job.Cancel()
	switch igmp.mode {
	case protocolModeV2OrV3, protocolModeV1:
	case protocolModeV1Compatibility:
		igmp.mode = protocolModeV2OrV3
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", igmp.mode))
	}
}

// handleMembershipQuery handles a membership query.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) handleMembershipQuery(groupAddress tcpip.Address, maxRespTime time.Duration) {
	// As per RFC 2236 Section 6, Page 10: If the maximum response time is zero
	// then change the state to note that an IGMPv1 router is present and
	// schedule the query received Job.
	if maxRespTime == 0 && igmp.Enabled() {
		switch igmp.mode {
		case protocolModeV2OrV3, protocolModeV1Compatibility:
			igmp.igmpV1Job.Cancel()
			igmp.igmpV1Job.Schedule(v1RouterPresentTimeout)
			igmp.mode = protocolModeV1Compatibility
		case protocolModeV1:
		default:
			panic(fmt.Sprintf("unrecognized mode = %d", igmp.mode))
		}

		maxRespTime = v1MaxRespTime
	}

	igmp.genericMulticastProtocol.HandleQueryLocked(groupAddress, maxRespTime)
}

// handleMembershipQueryV3 handles a membership query.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) handleMembershipQueryV3(igmpHdr header.IGMPv3Query) {
	sources, ok := igmpHdr.Sources()
	if !ok {
		return
	}

	igmp.genericMulticastProtocol.HandleQueryV2Locked(
		igmpHdr.GroupAddress(),
		uint16(igmpHdr.MaximumResponseCode()),
		sources,
		igmpHdr.QuerierRobustnessVariable(),
		igmpHdr.QuerierQueryInterval(),
	)
}

// handleMembershipReport handles a membership report.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) handleMembershipReport(groupAddress tcpip.Address) {
	igmp.genericMulticastProtocol.HandleReportLocked(groupAddress)
}

// writePacket assembles and sends an IGMP packet.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) writePacket(destAddress tcpip.Address, groupAddress tcpip.Address, igmpType header.IGMPType) (bool, tcpip.Error) {
	igmpView := buffer.NewViewSize(header.IGMPReportMinimumSize)
	igmpData := header.IGMP(igmpView.AsSlice())
	igmpData.SetType(igmpType)
	igmpData.SetGroupAddress(groupAddress)
	igmpData.SetChecksum(header.IGMPCalculateChecksum(igmpData))

	var reportType tcpip.MultiCounterStat
	sentStats := igmp.ep.stats.igmp.packetsSent
	switch igmpType {
	case header.IGMPv1MembershipReport:
		reportType = sentStats.v1MembershipReport
	case header.IGMPv2MembershipReport:
		reportType = sentStats.v2MembershipReport
	case header.IGMPLeaveGroup:
		reportType = sentStats.leaveGroup
	default:
		panic(fmt.Sprintf("unrecognized igmp type = %d", igmpType))
	}

	return igmp.writePacketInner(
		igmpView,
		reportType,
		header.IPv4OptionsSerializer{
			&header.IPv4SerializableRouterAlertOption{},
		},
		destAddress,
	)
}

// +checklocksread:igmp.ep.mu
func (igmp *igmpState) writePacketInner(buf *buffer.View, reportStat tcpip.MultiCounterStat, options header.IPv4OptionsSerializer, destAddress tcpip.Address) (bool, tcpip.Error) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(igmp.ep.MaxHeaderLength()),
		Payload:            buffer.MakeWithView(buf),
	})
	defer pkt.DecRef()

	addressEndpoint := igmp.ep.acquireOutgoingPrimaryAddressRLocked(destAddress, tcpip.Address{} /* srcHint */, false /* allowExpired */)
	if addressEndpoint == nil {
		return false, nil
	}
	localAddr := addressEndpoint.AddressWithPrefix().Address
	addressEndpoint.DecRef()
	addressEndpoint = nil
	if err := igmp.ep.addIPHeader(localAddr, destAddress, pkt, stack.NetworkHeaderParams{
		Protocol: header.IGMPProtocolNumber,
		TTL:      header.IGMPTTL,
		TOS:      stack.DefaultTOS,
	}, options); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}

	sentStats := igmp.ep.stats.igmp.packetsSent
	if err := igmp.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv4Address(destAddress), pkt); err != nil {
		sentStats.dropped.Increment()
		return false, err
	}
	reportStat.Increment()
	return true, nil
}

// joinGroup handles adding a new group to the membership map, setting up the
// IGMP state for the group, and sending and scheduling the required
// messages.
//
// If the group already exists in the membership map, returns
// *tcpip.ErrDuplicateAddress.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) joinGroup(groupAddress tcpip.Address) {
	igmp.genericMulticastProtocol.JoinGroupLocked(groupAddress)
}

// isInGroup returns true if the specified group has been joined locally.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) isInGroup(groupAddress tcpip.Address) bool {
	return igmp.genericMulticastProtocol.IsLocallyJoinedRLocked(groupAddress)
}

// leaveGroup handles removing the group from the membership map, cancels any
// delay timers associated with that group, and sends the Leave Group message
// if required.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) leaveGroup(groupAddress tcpip.Address) tcpip.Error {
	// LeaveGroup returns false only if the group was not joined.
	if igmp.genericMulticastProtocol.LeaveGroupLocked(groupAddress) {
		return nil
	}

	return &tcpip.ErrBadLocalAddress{}
}

// softLeaveAll leaves all groups from the perspective of IGMP, but remains
// joined locally.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) softLeaveAll() {
	igmp.genericMulticastProtocol.MakeAllNonMemberLocked()
}

// initializeAll attempts to initialize the IGMP state for each group that has
// been joined locally.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) initializeAll() {
	igmp.genericMulticastProtocol.InitializeGroupsLocked()
}

// sendQueuedReports attempts to send any reports that are queued for sending.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) sendQueuedReports() {
	igmp.genericMulticastProtocol.SendQueuedReportsLocked()
}

// setVersion sets the IGMP version.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) setVersion(v IGMPVersion) IGMPVersion {
	prev := igmp.mode
	igmp.igmpV1Job.Cancel()

	var prevGenericModeV1 bool
	switch v {
	case IGMPVersion3:
		prevGenericModeV1 = igmp.genericMulticastProtocol.SetV1ModeLocked(false)
		igmp.mode = protocolModeV2OrV3
	case IGMPVersion2:
		// IGMPv1 and IGMPv2 map to V1 of the generic multicast protocol.
		prevGenericModeV1 = igmp.genericMulticastProtocol.SetV1ModeLocked(true)
		igmp.mode = protocolModeV2OrV3
	case IGMPVersion1:
		// IGMPv1 and IGMPv2 map to V1 of the generic multicast protocol.
		prevGenericModeV1 = igmp.genericMulticastProtocol.SetV1ModeLocked(true)
		igmp.mode = protocolModeV1
	default:
		panic(fmt.Sprintf("unrecognized version = %d", v))
	}

	return toIGMPVersion(prev, prevGenericModeV1)
}

func toIGMPVersion(mode protocolMode, genericV1 bool) IGMPVersion {
	switch mode {
	case protocolModeV2OrV3, protocolModeV1Compatibility:
		if genericV1 {
			return IGMPVersion2
		}
		return IGMPVersion3
	case protocolModeV1:
		return IGMPVersion1
	default:
		panic(fmt.Sprintf("unrecognized mode = %d", mode))
	}
}

// getVersion returns the IGMP version.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) getVersion() IGMPVersion {
	return toIGMPVersion(igmp.mode, igmp.genericMulticastProtocol.GetV1ModeLocked())
}
