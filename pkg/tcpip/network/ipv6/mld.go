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

package ipv6

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// UnsolicitedReportIntervalMax is the maximum delay between sending
	// unsolicited MLD reports.
	//
	// Obtained from RFC 2710 Section 7.10.
	UnsolicitedReportIntervalMax = 10 * time.Second
)

// MLDVersion is the forced version of MLD.
type MLDVersion int

const (
	_ MLDVersion = iota
	// MLDVersion1 indicates MLDv1.
	MLDVersion1
	// MLDVersion2 indicates MLDv2. Note that MLD may still fallback to V1
	// compatibility mode as required by MLDv2.
	MLDVersion2
)

// MLDEndpoint is a network endpoint that supports MLD.
type MLDEndpoint interface {
	// SetMLDVersions sets the MLD version.
	//
	// Returns the previous MLD version.
	SetMLDVersion(MLDVersion) MLDVersion

	// GetMLDVersion returns the MLD version.
	GetMLDVersion() MLDVersion
}

// MLDOptions holds options for MLD.
type MLDOptions struct {
	// Enabled indicates whether MLD will be performed.
	//
	// When enabled, MLD may transmit MLD report and done messages when
	// joining and leaving multicast groups respectively, and handle incoming
	// MLD packets.
	//
	// This field is ignored and is always assumed to be false for interfaces
	// without neighbouring nodes (e.g. loopback).
	Enabled bool
}

var _ ip.MulticastGroupProtocol = (*mldState)(nil)

// mldState is the per-interface MLD state.
//
// mldState.init MUST be called to initialize the MLD state.
type mldState struct {
	// The IPv6 endpoint this mldState is for.
	ep *endpoint

	genericMulticastProtocol ip.GenericMulticastProtocolState
}

// Enabled implements ip.MulticastGroupProtocol.
func (mld *mldState) Enabled() bool {
	// No need to perform MLD on loopback interfaces since they don't have
	// neighbouring nodes.
	return mld.ep.protocol.options.MLD.Enabled && !mld.ep.nic.IsLoopback() && mld.ep.Enabled()
}

// SendReport implements ip.MulticastGroupProtocol.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) SendReport(groupAddress tcpip.Address) (bool, tcpip.Error) {
	return mld.writePacket(groupAddress, groupAddress, header.ICMPv6MulticastListenerReport)
}

// SendLeave implements ip.MulticastGroupProtocol.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) SendLeave(groupAddress tcpip.Address) tcpip.Error {
	_, err := mld.writePacket(header.IPv6AllRoutersLinkLocalMulticastAddress, groupAddress, header.ICMPv6MulticastListenerDone)
	return err
}

// ShouldPerformProtocol implements ip.MulticastGroupProtocol.
func (mld *mldState) ShouldPerformProtocol(groupAddress tcpip.Address) bool {
	// As per RFC 2710 section 5 page 10,
	//
	//   The link-scope all-nodes address (FF02::1) is handled as a special
	//   case. The node starts in Idle Listener state for that address on
	//   every interface, never transitions to another state, and never sends
	//   a Report or Done for that address.
	//
	//   MLD messages are never sent for multicast addresses whose scope is 0
	//   (reserved) or 1 (node-local).
	if groupAddress == header.IPv6AllNodesMulticastAddress {
		return false
	}

	scope := header.V6MulticastScope(groupAddress)
	return scope != header.IPv6Reserved0MulticastScope && scope != header.IPv6InterfaceLocalMulticastScope
}

type mldv2ReportBuilder struct {
	mld *mldState

	records []header.MLDv2ReportMulticastAddressRecordSerializer
}

// AddRecord implements ip.MulticastGroupProtocolV2ReportBuilder.
func (b *mldv2ReportBuilder) AddRecord(genericRecordType ip.MulticastGroupProtocolV2ReportRecordType, groupAddress tcpip.Address) {
	var recordType header.MLDv2ReportRecordType
	switch genericRecordType {
	case ip.MulticastGroupProtocolV2ReportRecordModeIsInclude:
		recordType = header.MLDv2ReportRecordModeIsInclude
	case ip.MulticastGroupProtocolV2ReportRecordModeIsExclude:
		recordType = header.MLDv2ReportRecordModeIsExclude
	case ip.MulticastGroupProtocolV2ReportRecordChangeToIncludeMode:
		recordType = header.MLDv2ReportRecordChangeToIncludeMode
	case ip.MulticastGroupProtocolV2ReportRecordChangeToExcludeMode:
		recordType = header.MLDv2ReportRecordChangeToExcludeMode
	case ip.MulticastGroupProtocolV2ReportRecordAllowNewSources:
		recordType = header.MLDv2ReportRecordAllowNewSources
	case ip.MulticastGroupProtocolV2ReportRecordBlockOldSources:
		recordType = header.MLDv2ReportRecordBlockOldSources
	default:
		panic(fmt.Sprintf("unrecognied genericRecordType = %d", genericRecordType))
	}

	b.records = append(b.records, header.MLDv2ReportMulticastAddressRecordSerializer{
		RecordType:       recordType,
		MulticastAddress: groupAddress,
		Sources:          nil,
	})
}

// Send implements ip.MulticastGroupProtocolV2ReportBuilder.
func (b *mldv2ReportBuilder) Send() (sent bool, err tcpip.Error) {
	if len(b.records) == 0 {
		return false, err
	}

	extensionHeaders := header.IPv6ExtHdrSerializer{
		header.IPv6SerializableHopByHopExtHdr{
			&header.IPv6RouterAlertOption{Value: header.IPv6RouterAlertMLD},
		},
	}
	mtu := int(b.mld.ep.MTU()) - extensionHeaders.Length()

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

		serializer := header.MLDv2ReportSerializer{Records: records[:maxRecords]}
		records = records[maxRecords:]

		icmpView := bufferv2.NewViewSize(header.ICMPv6HeaderSize + serializer.Length())
		icmp := header.ICMPv6(icmpView.AsSlice())
		serializer.SerializeInto(icmp.MessageBody())
		if sentWithSpecifiedAddress, err := b.mld.writePacketInner(
			icmpView,
			header.ICMPv6MulticastListenerV2Report,
			b.mld.ep.stats.icmp.packetsSent.multicastListenerReportV2,
			extensionHeaders,
			header.MLDv2RoutersAddress,
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
func (mld *mldState) NewReportV2Builder() ip.MulticastGroupProtocolV2ReportBuilder {
	return &mldv2ReportBuilder{mld: mld}
}

// V2QueryMaxRespCodeToV2Delay implements ip.MulticastGroupProtocol.
func (*mldState) V2QueryMaxRespCodeToV2Delay(code uint16) time.Duration {
	return header.MLDv2MaximumResponseDelay(code)
}

// V2QueryMaxRespCodeToV1Delay implements ip.MulticastGroupProtocol.
func (*mldState) V2QueryMaxRespCodeToV1Delay(code uint16) time.Duration {
	return time.Duration(code) * time.Millisecond
}

// init sets up an mldState struct, and is required to be called before using
// a new mldState.
//
// Must only be called once for the lifetime of mld.
func (mld *mldState) init(ep *endpoint) {
	mld.ep = ep
	mld.genericMulticastProtocol.Init(&ep.mu.RWMutex, ip.GenericMulticastProtocolOptions{
		Rand:                      ep.protocol.stack.Rand(),
		Clock:                     ep.protocol.stack.Clock(),
		Protocol:                  mld,
		MaxUnsolicitedReportDelay: UnsolicitedReportIntervalMax,
	})
}

// handleMulticastListenerQuery handles a query message.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) handleMulticastListenerQuery(mldHdr header.MLD) {
	mld.genericMulticastProtocol.HandleQueryLocked(mldHdr.MulticastAddress(), mldHdr.MaximumResponseDelay())
}

// handleMulticastListenerQueryV2 handles a V2 query message.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) handleMulticastListenerQueryV2(mldHdr header.MLDv2Query) {
	sources, ok := mldHdr.Sources()
	if !ok {
		return
	}

	mld.genericMulticastProtocol.HandleQueryV2Locked(
		mldHdr.MulticastAddress(),
		mldHdr.MaximumResponseCode(),
		sources,
		mldHdr.QuerierRobustnessVariable(),
		mldHdr.QuerierQueryInterval(),
	)
}

// handleMulticastListenerReport handles a report message.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) handleMulticastListenerReport(mldHdr header.MLD) {
	mld.genericMulticastProtocol.HandleReportLocked(mldHdr.MulticastAddress())
}

// joinGroup handles joining a new group and sending and scheduling the required
// messages.
//
// If the group is already joined, returns *tcpip.ErrDuplicateAddress.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) joinGroup(groupAddress tcpip.Address) {
	mld.genericMulticastProtocol.JoinGroupLocked(groupAddress)
}

// isInGroup returns true if the specified group has been joined locally.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) isInGroup(groupAddress tcpip.Address) bool {
	return mld.genericMulticastProtocol.IsLocallyJoinedRLocked(groupAddress)
}

// leaveGroup handles removing the group from the membership map, cancels any
// delay timers associated with that group, and sends the Done message, if
// required.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) leaveGroup(groupAddress tcpip.Address) tcpip.Error {
	// LeaveGroup returns false only if the group was not joined.
	if mld.genericMulticastProtocol.LeaveGroupLocked(groupAddress) {
		return nil
	}

	return &tcpip.ErrBadLocalAddress{}
}

// softLeaveAll leaves all groups from the perspective of MLD, but remains
// joined locally.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) softLeaveAll() {
	mld.genericMulticastProtocol.MakeAllNonMemberLocked()
}

// initializeAll attemps to initialize the MLD state for each group that has
// been joined locally.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) initializeAll() {
	mld.genericMulticastProtocol.InitializeGroupsLocked()
}

// sendQueuedReports attempts to send any reports that are queued for sending.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) sendQueuedReports() {
	mld.genericMulticastProtocol.SendQueuedReportsLocked()
}

// setVersion sets the MLD version.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) setVersion(v MLDVersion) MLDVersion {
	var prev bool
	switch v {
	case MLDVersion2:
		prev = mld.genericMulticastProtocol.SetV1ModeLocked(false)
	case MLDVersion1:
		prev = mld.genericMulticastProtocol.SetV1ModeLocked(true)
	default:
		panic(fmt.Sprintf("unrecognized version = %d", v))
	}

	return toMLDVersion(prev)
}

func toMLDVersion(v1Generic bool) MLDVersion {
	if v1Generic {
		return MLDVersion1
	}
	return MLDVersion2
}

// getVersion returns the MLD version.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) getVersion() MLDVersion {
	return toMLDVersion(mld.genericMulticastProtocol.GetV1ModeLocked())
}

// writePacket assembles and sends an MLD packet.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) writePacket(destAddress, groupAddress tcpip.Address, mldType header.ICMPv6Type) (bool, tcpip.Error) {
	sentStats := mld.ep.stats.icmp.packetsSent
	var mldStat tcpip.MultiCounterStat
	switch mldType {
	case header.ICMPv6MulticastListenerReport:
		mldStat = sentStats.multicastListenerReport
	case header.ICMPv6MulticastListenerDone:
		mldStat = sentStats.multicastListenerDone
	default:
		panic(fmt.Sprintf("unrecognized mld type = %d", mldType))
	}

	icmpView := bufferv2.NewViewSize(header.ICMPv6HeaderSize + header.MLDMinimumSize)

	icmp := header.ICMPv6(icmpView.AsSlice())
	header.MLD(icmp.MessageBody()).SetMulticastAddress(groupAddress)
	extensionHeaders := header.IPv6ExtHdrSerializer{
		header.IPv6SerializableHopByHopExtHdr{
			&header.IPv6RouterAlertOption{Value: header.IPv6RouterAlertMLD},
		},
	}

	return mld.writePacketInner(
		icmpView,
		mldType,
		mldStat,
		extensionHeaders,
		destAddress,
	)
}

func (mld *mldState) writePacketInner(buf *bufferv2.View, mldType header.ICMPv6Type, reportStat tcpip.MultiCounterStat, extensionHeaders header.IPv6ExtHdrSerializer, destAddress tcpip.Address) (bool, tcpip.Error) {
	icmp := header.ICMPv6(buf.AsSlice())
	icmp.SetType(mldType)

	// As per RFC 2710 section 3,
	//
	//   All MLD messages described in this document are sent with a link-local
	//   IPv6 Source Address, an IPv6 Hop Limit of 1, and an IPv6 Router Alert
	//   option in a Hop-by-Hop Options header.
	//
	// However, this would cause problems with Duplicate Address Detection with
	// the first address as MLD snooping switches may not send multicast traffic
	// that DAD depends on to the node performing DAD without the MLD report, as
	// documented in RFC 4816:
	//
	//   Note that when a node joins a multicast address, it typically sends a
	//   Multicast Listener Discovery (MLD) report message [RFC2710] [RFC3810]
	//   for the multicast address. In the case of Duplicate Address
	//   Detection, the MLD report message is required in order to inform MLD-
	//   snooping switches, rather than routers, to forward multicast packets.
	//   In the above description, the delay for joining the multicast address
	//   thus means delaying transmission of the corresponding MLD report
	//   message. Since the MLD specifications do not request a random delay
	//   to avoid race conditions, just delaying Neighbor Solicitation would
	//   cause congestion by the MLD report messages. The congestion would
	//   then prevent the MLD-snooping switches from working correctly and, as
	//   a result, prevent Duplicate Address Detection from working. The
	//   requirement to include the delay for the MLD report in this case
	//   avoids this scenario. [RFC3590] also talks about some interaction
	//   issues between Duplicate Address Detection and MLD, and specifies
	//   which source address should be used for the MLD report in this case.
	//
	// As per RFC 3590 section 4, we should still send out MLD reports with an
	// unspecified source address if we do not have an assigned link-local
	// address to use as the source address to ensure DAD works as expected on
	// networks with MLD snooping switches:
	//
	//   MLD Report and Done messages are sent with a link-local address as
	//   the IPv6 source address, if a valid address is available on the
	//   interface.  If a valid link-local address is not available (e.g., one
	//   has not been configured), the message is sent with the unspecified
	//   address (::) as the IPv6 source address.
	//
	//   Once a valid link-local address is available, a node SHOULD generate
	//   new MLD Report messages for all multicast addresses joined on the
	//   interface.
	//
	//   Routers receiving an MLD Report or Done message with the unspecified
	//   address as the IPv6 source address MUST silently discard the packet
	//   without taking any action on the packets contents.
	//
	//   Snooping switches MUST manage multicast forwarding state based on MLD
	//   Report and Done messages sent with the unspecified address as the
	//   IPv6 source address.
	localAddress := mld.ep.getLinkLocalAddressRLocked()
	if localAddress.BitLen() == 0 {
		localAddress = header.IPv6Any
	}

	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    localAddress,
		Dst:    destAddress,
	}))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(mld.ep.MaxHeaderLength()) + extensionHeaders.Length(),
		Payload:            bufferv2.MakeWithView(buf),
	})
	defer pkt.DecRef()

	if err := addIPHeader(localAddress, destAddress, pkt, stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      header.MLDHopLimit,
	}, extensionHeaders); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}
	if err := mld.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv6Address(destAddress), pkt); err != nil {
		mld.ep.stats.icmp.packetsSent.dropped.Increment()
		return false, err
	}
	reportStat.Increment()
	return localAddress != header.IPv6Any, nil
}
