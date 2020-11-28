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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// UnsolicitedReportIntervalMax is the maximum delay between sending
	// unsolicited MLD reports.
	//
	// Obtained from RFC 2710 Section 7.10.
	UnsolicitedReportIntervalMax = 10 * time.Second
)

// MLDOptions holds options for MLD.
type MLDOptions struct {
	// Enabled indicates whether MLD will be performed.
	//
	// When enabled, MLD may transmit MLD report and done messages when
	// joining and leaving multicast groups respectively, and handle incoming
	// MLD packets.
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

// SendReport implements ip.MulticastGroupProtocol.
func (mld *mldState) SendReport(groupAddress tcpip.Address) (bool, *tcpip.Error) {
	return mld.writePacket(groupAddress, groupAddress, header.ICMPv6MulticastListenerReport)
}

// SendLeave implements ip.MulticastGroupProtocol.
func (mld *mldState) SendLeave(groupAddress tcpip.Address) (bool, *tcpip.Error) {
	return mld.writePacket(header.IPv6AllRoutersMulticastAddress, groupAddress, header.ICMPv6MulticastListenerDone)
}

// init sets up an mldState struct, and is required to be called before using
// a new mldState.
func (mld *mldState) init(ep *endpoint, opts MLDOptions) {
	mld.ep = ep
	mld.genericMulticastProtocol.Init(ip.GenericMulticastProtocolOptions{
		Enabled:                   opts.Enabled,
		Rand:                      ep.protocol.stack.Rand(),
		Clock:                     ep.protocol.stack.Clock(),
		Protocol:                  mld,
		MaxUnsolicitedReportDelay: UnsolicitedReportIntervalMax,
		AllNodesAddress:           header.IPv6AllNodesMulticastAddress,
	})
}

func (mld *mldState) handleMulticastListenerQuery(mldHdr header.MLD) {
	mld.genericMulticastProtocol.HandleQuery(mldHdr.MulticastAddress(), mldHdr.MaximumResponseDelay())
}

func (mld *mldState) handleMulticastListenerReport(mldHdr header.MLD) {
	mld.genericMulticastProtocol.HandleReport(mldHdr.MulticastAddress())
}

// joinGroup handles joining a new group and sending and scheduling the required
// messages.
//
// If the group is already joined, returns tcpip.ErrDuplicateAddress.
func (mld *mldState) joinGroup(groupAddress tcpip.Address) {
	mld.genericMulticastProtocol.JoinGroup(groupAddress, !mld.ep.Enabled() /* dontInitialize */)
}

// isInGroup returns true if the specified group has been joined locally.
func (mld *mldState) isInGroup(groupAddress tcpip.Address) bool {
	return mld.genericMulticastProtocol.IsLocallyJoined(groupAddress)
}

// leaveGroup handles removing the group from the membership map, cancels any
// delay timers associated with that group, and sends the Done message, if
// required.
func (mld *mldState) leaveGroup(groupAddress tcpip.Address) *tcpip.Error {
	// LeaveGroup returns false only if the group was not joined.
	if mld.genericMulticastProtocol.LeaveGroup(groupAddress) {
		return nil
	}

	return tcpip.ErrBadLocalAddress
}

// softLeaveAll leaves all groups from the perspective of MLD, but remains
// joined locally.
func (mld *mldState) softLeaveAll() {
	mld.genericMulticastProtocol.MakeAllNonMember()
}

// initializeAll attemps to initialize the MLD state for each group that has
// been joined locally.
func (mld *mldState) initializeAll() {
	mld.genericMulticastProtocol.InitializeGroups()
}

func (mld *mldState) writePacket(destAddress, groupAddress tcpip.Address, mldType header.ICMPv6Type) (bool, *tcpip.Error) {
	sentStats := mld.ep.protocol.stack.Stats().ICMP.V6PacketsSent
	var mldStat *tcpip.StatCounter
	switch mldType {
	case header.ICMPv6MulticastListenerReport:
		mldStat = sentStats.MulticastListenerReport
	case header.ICMPv6MulticastListenerDone:
		mldStat = sentStats.MulticastListenerDone
	default:
		panic(fmt.Sprintf("unrecognized mld type = %d", mldType))
	}

	icmp := header.ICMPv6(buffer.NewView(header.ICMPv6HeaderSize + header.MLDMinimumSize))
	icmp.SetType(mldType)
	header.MLD(icmp.MessageBody()).SetMulticastAddress(groupAddress)
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
	localAddress := header.IPv6Any
	{
		addressEndpoint := mld.ep.acquireOutgoingPrimaryAddress(destAddress, false /* allowExpired */)
		if addressEndpoint != nil {
			address := addressEndpoint.AddressWithPrefix().Address
			addressEndpoint.DecRef()

			if header.IsV6LinkLocalAddress(address) {
				localAddress = addressEndpoint.AddressWithPrefix().Address
			}
		}
	}

	icmp.SetChecksum(header.ICMPv6Checksum(icmp, localAddress, destAddress, buffer.VectorisedView{}))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(mld.ep.MaxHeaderLength()),
		Data:               buffer.View(icmp).ToVectorisedView(),
	})

	mld.ep.addIPHeader(localAddress, destAddress, pkt, stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      header.MLDHopLimit,
	})
	// TODO(b/162198658): set the ROUTER_ALERT option when sending Host
	// Membership Reports.
	if err := mld.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv6Address(destAddress), nil /* gso */, ProtocolNumber, pkt); err != nil {
		sentStats.Dropped.Increment()
		return false, err
	}
	mldStat.Increment()
	return true /* localAddress != header.IPv6Any */, nil
}
