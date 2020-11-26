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
	ep   *endpoint
	opts MLDOptions

	genericMulticastProtocol ip.GenericMulticastProtocolState
}

// SendReport implements ip.MulticastGroupProtocol.
func (mld *mldState) SendReport(groupAddress tcpip.Address) *tcpip.Error {
	return mld.writePacket(groupAddress, groupAddress, header.ICMPv6MulticastListenerReport)
}

// SendLeave implements ip.MulticastGroupProtocol.
func (mld *mldState) SendLeave(groupAddress tcpip.Address) *tcpip.Error {
	return mld.writePacket(header.IPv6AllRoutersMulticastAddress, groupAddress, header.ICMPv6MulticastListenerDone)
}

// init sets up an mldState struct, and is required to be called before using
// a new mldState.
func (mld *mldState) init(ep *endpoint, opts MLDOptions) {
	mld.ep = ep
	mld.opts = opts
	mld.genericMulticastProtocol.Init(ep.protocol.stack.Rand(), ep.protocol.stack.Clock(), mld, UnsolicitedReportIntervalMax)
}

func (mld *mldState) handleMulticastListenerQuery(mldHdr header.MLD) {
	if !mld.opts.Enabled {
		return
	}

	mld.genericMulticastProtocol.HandleQuery(mldHdr.MulticastAddress(), mldHdr.MaximumResponseDelay())
}

func (mld *mldState) handleMulticastListenerReport(mldHdr header.MLD) {
	if !mld.opts.Enabled {
		return
	}

	mld.genericMulticastProtocol.HandleReport(mldHdr.MulticastAddress())
}

// joinGroup handles joining a new group and sending and scheduling the required
// messages.
//
// If the group is already joined, returns tcpip.ErrDuplicateAddress.
func (mld *mldState) joinGroup(groupAddress tcpip.Address) *tcpip.Error {
	if !mld.opts.Enabled {
		return nil
	}

	// As per RFC 2710 section 5 page 10,
	//
	//   The link-scope all-nodes address (FF02::1) is handled as a special
	//   case. The node starts in Idle Listener state for that address on
	//   every interface, never transitions to another state, and never sends
	//   a Report or Done for that address.
	//
	// This is equivalent to not performing MLD for the all-nodes multicast
	// address. Simply not performing MLD when the group is added will prevent
	// any work from being done on the all-nodes multicast group when leaving the
	// group or when query or report messages are received for it since the MGP
	// state will not know about it.
	if groupAddress == header.IPv6AllNodesMulticastAddress {
		return nil
	}

	// JoinGroup returns false if we have already joined the group.
	if !mld.genericMulticastProtocol.JoinGroup(groupAddress) {
		return tcpip.ErrDuplicateAddress
	}
	return nil
}

// leaveGroup handles removing the group from the membership map, cancels any
// delay timers associated with that group, and sends the Done message, if
// required.
//
// If the group is not joined, this function will do nothing.
func (mld *mldState) leaveGroup(groupAddress tcpip.Address) {
	if !mld.opts.Enabled {
		return
	}

	mld.genericMulticastProtocol.LeaveGroup(groupAddress)
}

func (mld *mldState) writePacket(destAddress, groupAddress tcpip.Address, mldType header.ICMPv6Type) *tcpip.Error {
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
	// TODO(gvisor.dev/issue/4888): We should not use the unspecified address,
	// rather we should select an appropriate local address.
	localAddress := header.IPv6Any
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
		return err
	}
	mldStat.Increment()
	return nil
}
