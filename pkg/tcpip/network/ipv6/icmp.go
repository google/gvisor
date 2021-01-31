// Copyright 2021 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// handleControl handles the case when an ICMP packet contains the headers of
// the original packet that caused the ICMP one to be sent. This information is
// used to find out which transport endpoint must be notified about the ICMP
// packet.
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, pkt *stack.PacketBuffer) {
	h, ok := pkt.Data.PullUp(header.IPv6MinimumSize)
	if !ok {
		return
	}
	hdr := header.IPv6(h)

	// We don't use IsValid() here because ICMP only requires that up to
	// 1280 bytes of the original packet be included. So it's likely that it
	// is truncated, which would cause IsValid to return false.
	//
	// Drop packet if it doesn't have the basic IPv6 header or if the
	// original source address doesn't match an address we own.
	src := hdr.SourceAddress()
	if e.protocol.stack.CheckLocalAddress(e.nic.ID(), ProtocolNumber, src) == 0 {
		return
	}

	// Skip the IP header, then handle the fragmentation header if there
	// is one.
	pkt.Data.TrimFront(header.IPv6MinimumSize)
	p := hdr.TransportProtocol()
	if p == header.IPv6FragmentHeader {
		f, ok := pkt.Data.PullUp(header.IPv6FragmentHeaderSize)
		if !ok {
			return
		}
		fragHdr := header.IPv6Fragment(f)
		if !fragHdr.IsValid() || fragHdr.FragmentOffset() != 0 {
			// We can't handle fragments that aren't at offset 0
			// because they don't have the transport headers.
			return
		}

		// Skip fragmentation header and find out the actual protocol
		// number.
		pkt.Data.TrimFront(header.IPv6FragmentHeaderSize)
		p = fragHdr.TransportProtocol()
	}

	// Deliver the control packet to the transport endpoint.
	e.dispatcher.DeliverTransportControlPacket(src, hdr.DestinationAddress(), ProtocolNumber, p, typ, extra, pkt)
}

// getLinkAddrOption searches NDP options for a given link address option using
// the provided getAddr function as a filter. Returns the link address if
// found; otherwise, returns the zero link address value. Also returns true if
// the options are valid as per the wire format, false otherwise.
func getLinkAddrOption(it header.NDPOptionIterator, getAddr func(header.NDPOption) tcpip.LinkAddress) (tcpip.LinkAddress, bool) {
	var linkAddr tcpip.LinkAddress
	for {
		opt, done, err := it.Next()
		if err != nil {
			return "", false
		}
		if done {
			break
		}
		if addr := getAddr(opt); len(addr) != 0 {
			// No RFCs define what to do when an NDP message has multiple Link-Layer
			// Address options. Since no interface can have multiple link-layer
			// addresses, we consider such messages invalid.
			if len(linkAddr) != 0 {
				return "", false
			}
			linkAddr = addr
		}
	}
	return linkAddr, true
}

// getSourceLinkAddr searches NDP options for the source link address option.
// Returns the link address if found; otherwise, returns the zero link address
// value. Also returns true if the options are valid as per the wire format,
// false otherwise.
func getSourceLinkAddr(it header.NDPOptionIterator) (tcpip.LinkAddress, bool) {
	return getLinkAddrOption(it, func(opt header.NDPOption) tcpip.LinkAddress {
		if src, ok := opt.(header.NDPSourceLinkLayerAddressOption); ok {
			return src.EthernetAddress()
		}
		return ""
	})
}

// getTargetLinkAddr searches NDP options for the target link address option.
// Returns the link address if found; otherwise, returns the zero link address
// value. Also returns true if the options are valid as per the wire format,
// false otherwise.
func getTargetLinkAddr(it header.NDPOptionIterator) (tcpip.LinkAddress, bool) {
	return getLinkAddrOption(it, func(opt header.NDPOption) tcpip.LinkAddress {
		if dst, ok := opt.(header.NDPTargetLinkLayerAddressOption); ok {
			return dst.EthernetAddress()
		}
		return ""
	})
}

func (e *endpoint) handleICMP(pkt *stack.PacketBuffer, hasFragmentHeader bool) {
	sent := e.stats.icmp.packetsSent
	received := e.stats.icmp.packetsReceived
	// TODO(gvisor.dev/issue/170): ICMP packets don't have their
	// TransportHeader fields set. See icmp/protocol.go:protocol.Parse for a
	// full explanation.
	v, ok := pkt.Data.PullUp(header.ICMPv6HeaderSize)
	if !ok {
		received.invalid.Increment()
		return
	}
	h := header.ICMPv6(v)
	iph := header.IPv6(pkt.NetworkHeader().View())
	srcAddr := iph.SourceAddress()
	dstAddr := iph.DestinationAddress()

	// Validate ICMPv6 checksum before processing the packet.
	//
	// This copy is used as extra payload during the checksum calculation.
	payload := pkt.Data.Clone(nil)
	payload.TrimFront(len(h))
	if got, want := h.Checksum(), header.ICMPv6Checksum(h, srcAddr, dstAddr, payload); got != want {
		received.invalid.Increment()
		return
	}

	isNDPValid := func() bool {
		// As per RFC 4861 sections 4.1 - 4.5, 6.1.1, 6.1.2, 7.1.1, 7.1.2 and
		// 8.1, nodes MUST silently drop NDP packets where the Hop Limit field
		// in the IPv6 header is not set to 255, or the ICMPv6 Code field is not
		// set to 0.
		//
		// As per RFC 6980 section 5, nodes MUST silently drop NDP messages if the
		// packet includes a fragmentation header.
		return !hasFragmentHeader && iph.HopLimit() == header.NDPHopLimit && h.Code() == 0
	}

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch icmpType := h.Type(); icmpType {
	case header.ICMPv6PacketTooBig:
		received.packetTooBig.Increment()
		hdr, ok := pkt.Data.PullUp(header.ICMPv6PacketTooBigMinimumSize)
		if !ok {
			received.invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6PacketTooBigMinimumSize)
		networkMTU, err := calculateNetworkMTU(header.ICMPv6(hdr).MTU(), header.IPv6MinimumSize)
		if err != nil {
			networkMTU = 0
		}
		e.handleControl(stack.ControlPacketTooBig, networkMTU, pkt)

	case header.ICMPv6DstUnreachable:
		received.dstUnreachable.Increment()
		hdr, ok := pkt.Data.PullUp(header.ICMPv6DstUnreachableMinimumSize)
		if !ok {
			received.invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6DstUnreachableMinimumSize)
		switch header.ICMPv6(hdr).Code() {
		case header.ICMPv6NetworkUnreachable:
			e.handleControl(stack.ControlNetworkUnreachable, 0, pkt)
		case header.ICMPv6PortUnreachable:
			e.handleControl(stack.ControlPortUnreachable, 0, pkt)
		}

	case header.ICMPv6NeighborSolicit:
		received.neighborSolicit.Increment()
		if !isNDPValid() || pkt.Data.Size() < header.ICMPv6NeighborSolicitMinimumSize {
			received.invalid.Increment()
			return
		}

		// The remainder of payload must be only the neighbor solicitation, so
		// payload.ToView() always returns the solicitation. Per RFC 6980 section 5,
		// NDP messages cannot be fragmented. Also note that in the common case NDP
		// datagrams are very small and ToView() will not incur allocations.
		ns := header.NDPNeighborSolicit(payload.ToView())
		targetAddr := ns.TargetAddress()

		// As per RFC 4861 section 4.3, the Target Address MUST NOT be a multicast
		// address.
		if header.IsV6MulticastAddress(targetAddr) {
			received.invalid.Increment()
			return
		}

		if e.hasTentativeAddr(targetAddr) {
			// If the target address is tentative and the source of the packet is a
			// unicast (specified) address, then the source of the packet is
			// attempting to perform address resolution on the target. In this case,
			// the solicitation is silently ignored, as per RFC 4862 section 5.4.3.
			//
			// If the target address is tentative and the source of the packet is the
			// unspecified address (::), then we know another node is also performing
			// DAD for the same address (since the target address is tentative for us,
			// we know we are also performing DAD on it). In this case we let the
			// stack know so it can handle such a scenario and do nothing further with
			// the NS.
			if srcAddr == header.IPv6Any {
				// We would get an error if the address no longer exists or the address
				// is no longer tentative (DAD resolved between the call to
				// hasTentativeAddr and this point). Both of these are valid scenarios:
				//   1) An address may be removed at any time.
				//   2) As per RFC 4862 section 5.4, DAD is not a perfect:
				//       "Note that the method for detecting duplicates
				//        is not completely reliable, and it is possible that duplicate
				//        addresses will still exist"
				//
				// TODO(gvisor.dev/issue/4046): Handle the scenario when a duplicate
				// address is detected for an assigned address.
				switch err := e.dupTentativeAddrDetected(targetAddr); err.(type) {
				case nil, *tcpip.ErrBadAddress, *tcpip.ErrInvalidEndpointState:
				default:
					panic(fmt.Sprintf("unexpected error handling duplicate tentative address: %s", err))
				}
			}

			// Do not handle neighbor solicitations targeted to an address that is
			// tentative on the NIC any further.
			return
		}

		// At this point we know that the target address is not tentative on the NIC
		// so the packet is processed as defined in RFC 4861, as per RFC 4862
		// section 5.4.3.

		// Is the NS targeting us?
		if e.protocol.stack.CheckLocalAddress(e.nic.ID(), ProtocolNumber, targetAddr) == 0 {
			return
		}

		var sourceLinkAddr tcpip.LinkAddress
		{
			it, err := ns.Options().Iter(false /* check */)
			if err != nil {
				// Options are not valid as per the wire format, silently drop the
				// packet.
				received.invalid.Increment()
				return
			}

			sourceLinkAddr, ok = getSourceLinkAddr(it)
			if !ok {
				received.invalid.Increment()
				return
			}
		}

		// As per RFC 4861 section 4.3, the Source Link-Layer Address Option MUST
		// NOT be included when the source IP address is the unspecified address.
		// Otherwise, on link layers that have addresses this option MUST be
		// included in multicast solicitations and SHOULD be included in unicast
		// solicitations.
		unspecifiedSource := srcAddr == header.IPv6Any
		if len(sourceLinkAddr) == 0 {
			if header.IsV6MulticastAddress(dstAddr) && !unspecifiedSource {
				received.invalid.Increment()
				return
			}
		} else if unspecifiedSource {
			received.invalid.Increment()
			return
		} else {
			e.nic.HandleNeighborProbe(srcAddr, sourceLinkAddr, e)
		}

		// As per RFC 4861 section 7.1.1:
		//   A node MUST silently discard any received Neighbor Solicitation
		//   messages that do not satisfy all of the following validity checks:
		//    ...
		//    - If the IP source address is the unspecified address, the IP
		//      destination address is a solicited-node multicast address.
		if unspecifiedSource && !header.IsSolicitedNodeAddr(dstAddr) {
			received.invalid.Increment()
			return
		}

		// As per RFC 4861 section 7.2.4:
		//
		//   If the source of the solicitation is the unspecified address, the node
		//   MUST [...] and multicast the advertisement to the all-nodes address.
		//
		remoteAddr := srcAddr
		if unspecifiedSource {
			remoteAddr = header.IPv6AllNodesMulticastAddress
		}

		// Even if we were able to receive a packet from some remote, we may not
		// have a route to it - the remote may be blocked via routing rules. We must
		// always consult our routing table and find a route to the remote before
		// sending any packet.
		r, err := e.protocol.stack.FindRoute(e.nic.ID(), targetAddr, remoteAddr, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		// If the NS has a source link-layer option, resolve the route immediately
		// to avoid querying the neighbor table when the neighbor entry was updated
		// as probing the neighbor table for a link address will transition the
		// entry's state from stale to delay.
		//
		// Note, if the source link address is unspecified and this is a unicast
		// solicitation, we may need to perform neighbor discovery to send the
		// neighbor advertisement response. This is expected as per RFC 4861 section
		// 7.2.4:
		//
		//   Because unicast Neighbor Solicitations are not required to include a
		//   Source Link-Layer Address, it is possible that a node sending a
		//   solicited Neighbor Advertisement does not have a corresponding link-
		//   layer address for its neighbor in its Neighbor Cache. In such
		//   situations, a node will first have to use Neighbor Discovery to
		//   determine the link-layer address of its neighbor (i.e., send out a
		//   multicast Neighbor Solicitation).
		//
		if len(sourceLinkAddr) != 0 {
			r.ResolveWith(sourceLinkAddr)
		}

		optsSerializer := header.NDPOptionsSerializer{
			header.NDPTargetLinkLayerAddressOption(e.nic.LinkAddress()),
		}
		neighborAdvertSize := header.ICMPv6NeighborAdvertMinimumSize + optsSerializer.Length()
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()) + neighborAdvertSize,
		})
		pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
		packet := header.ICMPv6(pkt.TransportHeader().Push(neighborAdvertSize))
		packet.SetType(header.ICMPv6NeighborAdvert)
		na := header.NDPNeighborAdvert(packet.MessageBody())

		// As per RFC 4861 section 7.2.4:
		//
		//   If the source of the solicitation is the unspecified address, the node
		//   MUST set the Solicited flag to zero and [..]. Otherwise, the node MUST
		//   set the Solicited flag to one and [..].
		//
		na.SetSolicitedFlag(!unspecifiedSource)
		na.SetOverrideFlag(true)
		na.SetTargetAddress(targetAddr)
		na.Options().Serialize(optsSerializer)
		packet.SetChecksum(header.ICMPv6Checksum(packet, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

		// RFC 4861 Neighbor Discovery for IP version 6 (IPv6)
		//
		// 7.1.2. Validation of Neighbor Advertisements
		//
		// The IP Hop Limit field has a value of 255, i.e., the packet
		// could not possibly have been forwarded by a router.
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: stack.DefaultTOS}, pkt); err != nil {
			sent.dropped.Increment()
			return
		}
		sent.neighborAdvert.Increment()

	case header.ICMPv6NeighborAdvert:
		received.neighborAdvert.Increment()
		if !isNDPValid() || pkt.Data.Size() < header.ICMPv6NeighborAdvertMinimumSize {
			received.invalid.Increment()
			return
		}

		// The remainder of payload must be only the neighbor advertisement, so
		// payload.ToView() always returns the advertisement. Per RFC 6980 section
		// 5, NDP messages cannot be fragmented. Also note that in the common case
		// NDP datagrams are very small and ToView() will not incur allocations.
		na := header.NDPNeighborAdvert(payload.ToView())
		targetAddr := na.TargetAddress()
		if e.hasTentativeAddr(targetAddr) {
			// We just got an NA from a node that owns an address we are performing
			// DAD on, implying the address is not unique. In this case we let the
			// stack know so it can handle such a scenario and do nothing furthur with
			// the NDP NA.
			//
			// We would get an error if the address no longer exists or the address
			// is no longer tentative (DAD resolved between the call to
			// hasTentativeAddr and this point). Both of these are valid scenarios:
			//   1) An address may be removed at any time.
			//   2) As per RFC 4862 section 5.4, DAD is not a perfect:
			//       "Note that the method for detecting duplicates
			//        is not completely reliable, and it is possible that duplicate
			//        addresses will still exist"
			//
			// TODO(gvisor.dev/issue/4046): Handle the scenario when a duplicate
			// address is detected for an assigned address.
			switch err := e.dupTentativeAddrDetected(targetAddr); err.(type) {
			case nil, *tcpip.ErrBadAddress, *tcpip.ErrInvalidEndpointState:
				return
			default:
				panic(fmt.Sprintf("unexpected error handling duplicate tentative address: %s", err))
			}
		}

		it, err := na.Options().Iter(false /* check */)
		if err != nil {
			// If we have a malformed NDP NA option, drop the packet.
			received.invalid.Increment()
			return
		}

		// At this point we know that the target address is not tentative on the
		// NIC. However, the target address may still be assigned to the NIC but not
		// tentative (it could be permanent). Such a scenario is beyond the scope of
		// RFC 4862. As such, we simply ignore such a scenario for now and proceed
		// as normal.
		//
		// TODO(b/143147598): Handle the scenario described above. Also inform the
		// netstack integration that a duplicate address was detected outside of
		// DAD.
		targetLinkAddr, ok := getTargetLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		// As per RFC 4861 section 7.1.2:
		//   A node MUST silently discard any received Neighbor Advertisement
		//   messages that do not satisfy all of the following validity checks:
		//    ...
		//    - If the IP Destination Address is a multicast address the
		// 	    Solicited flag is zero.
		if header.IsV6MulticastAddress(dstAddr) && na.SolicitedFlag() {
			received.invalid.Increment()
			return
		}

		// If the NA message has the target link layer option, update the link
		// address cache with the link address for the target of the message.
		e.nic.HandleNeighborConfirmation(targetAddr, targetLinkAddr, stack.ReachabilityConfirmationFlags{
			Solicited: na.SolicitedFlag(),
			Override:  na.OverrideFlag(),
			IsRouter:  na.RouterFlag(),
		})

	case header.ICMPv6EchoRequest:
		received.echoRequest.Increment()
		icmpHdr, ok := pkt.TransportHeader().Consume(header.ICMPv6EchoMinimumSize)
		if !ok {
			received.invalid.Increment()
			return
		}

		// As per RFC 4291 section 2.7, multicast addresses must not be used as
		// source addresses in IPv6 packets.
		localAddr := dstAddr
		if header.IsV6MulticastAddress(dstAddr) {
			localAddr = ""
		}

		r, err := e.protocol.stack.FindRoute(e.nic.ID(), localAddr, srcAddr, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize,
			Data:               pkt.Data,
		})
		packet := header.ICMPv6(replyPkt.TransportHeader().Push(header.ICMPv6EchoMinimumSize))
		pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
		copy(packet, icmpHdr)
		packet.SetType(header.ICMPv6EchoReply)
		packet.SetChecksum(header.ICMPv6Checksum(packet, r.LocalAddress, r.RemoteAddress, pkt.Data))
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{
			Protocol: header.ICMPv6ProtocolNumber,
			TTL:      r.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		}, replyPkt); err != nil {
			sent.dropped.Increment()
			return
		}
		sent.echoReply.Increment()

	case header.ICMPv6EchoReply:
		received.echoReply.Increment()
		if pkt.Data.Size() < header.ICMPv6EchoMinimumSize {
			received.invalid.Increment()
			return
		}
		e.dispatcher.DeliverTransportPacket(header.ICMPv6ProtocolNumber, pkt)

	case header.ICMPv6TimeExceeded:
		received.timeExceeded.Increment()

	case header.ICMPv6ParamProblem:
		received.paramProblem.Increment()

	case header.ICMPv6RouterSolicit:
		received.routerSolicit.Increment()

		//
		// Validate the RS as per RFC 4861 section 6.1.1.
		//

		// Is the NDP payload of sufficient size to hold a Router Solictation?
		if !isNDPValid() || pkt.Data.Size()-header.ICMPv6HeaderSize < header.NDPRSMinimumSize {
			received.invalid.Increment()
			return
		}

		stack := e.protocol.stack

		// Is the networking stack operating as a router?
		if !stack.Forwarding(ProtocolNumber) {
			// ... No, silently drop the packet.
			received.routerOnlyPacketsDroppedByHost.Increment()
			return
		}

		// Note that in the common case NDP datagrams are very small and ToView()
		// will not incur allocations.
		rs := header.NDPRouterSolicit(payload.ToView())
		it, err := rs.Options().Iter(false /* check */)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		// If the RS message has the source link layer option, update the link
		// address cache with the link address for the source of the message.
		if len(sourceLinkAddr) != 0 {
			// As per RFC 4861 section 4.1, the Source Link-Layer Address Option MUST
			// NOT be included when the source IP address is the unspecified address.
			// Otherwise, it SHOULD be included on link layers that have addresses.
			if srcAddr == header.IPv6Any {
				received.invalid.Increment()
				return
			}

			// A RS with a specified source IP address modifies the NUD state
			// machine in the same way a reachability probe would.
			e.nic.HandleNeighborProbe(srcAddr, sourceLinkAddr, e)
		}

	case header.ICMPv6RouterAdvert:
		received.routerAdvert.Increment()

		//
		// Validate the RA as per RFC 4861 section 6.1.2.
		//

		// Is the NDP payload of sufficient size to hold a Router Advertisement?
		if !isNDPValid() || pkt.Data.Size()-header.ICMPv6HeaderSize < header.NDPRAMinimumSize {
			received.invalid.Increment()
			return
		}

		routerAddr := srcAddr

		// Is the IP Source Address a link-local address?
		if !header.IsV6LinkLocalAddress(routerAddr) {
			// ...No, silently drop the packet.
			received.invalid.Increment()
			return
		}

		// Note that in the common case NDP datagrams are very small and ToView()
		// will not incur allocations.
		ra := header.NDPRouterAdvert(payload.ToView())
		it, err := ra.Options().Iter(false /* check */)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.invalid.Increment()
			return
		}

		//
		// At this point, we have a valid Router Advertisement, as far
		// as RFC 4861 section 6.1.2 is concerned.
		//

		// If the RA has the source link layer option, update the link address
		// cache with the link address for the advertised router.
		if len(sourceLinkAddr) != 0 {
			e.nic.HandleNeighborProbe(routerAddr, sourceLinkAddr, e)
		}

		e.mu.Lock()
		e.mu.ndp.handleRA(routerAddr, ra)
		e.mu.Unlock()

	case header.ICMPv6RedirectMsg:
		// TODO(gvisor.dev/issue/2285): Call `e.nud.HandleProbe` after validating
		// this redirect message, as per RFC 4871 section 7.3.3:
		//
		//    "A Neighbor Cache entry enters the STALE state when created as a
		//    result of receiving packets other than solicited Neighbor
		//    Advertisements (i.e., Router Solicitations, Router Advertisements,
		//    Redirects, and Neighbor Solicitations).  These packets contain the
		//    link-layer address of either the sender or, in the case of Redirect,
		//    the redirection target.  However, receipt of these link-layer
		//    addresses does not confirm reachability of the forward-direction path
		//    to that node.  Placing a newly created Neighbor Cache entry for which
		//    the link-layer address is known in the STALE state provides assurance
		//    that path failures are detected quickly. In addition, should a cached
		//    link-layer address be modified due to receiving one of the above
		//    messages, the state SHOULD also be set to STALE to provide prompt
		//    verification that the path to the new link-layer address is working."
		received.redirectMsg.Increment()
		if !isNDPValid() {
			received.invalid.Increment()
			return
		}

	case header.ICMPv6MulticastListenerQuery, header.ICMPv6MulticastListenerReport, header.ICMPv6MulticastListenerDone:
		switch icmpType {
		case header.ICMPv6MulticastListenerQuery:
			received.multicastListenerQuery.Increment()
		case header.ICMPv6MulticastListenerReport:
			received.multicastListenerReport.Increment()
		case header.ICMPv6MulticastListenerDone:
			received.multicastListenerDone.Increment()
		default:
			panic(fmt.Sprintf("unrecognized MLD message = %d", icmpType))
		}

		if pkt.Data.Size()-header.ICMPv6HeaderSize < header.MLDMinimumSize {
			received.invalid.Increment()
			return
		}

		switch icmpType {
		case header.ICMPv6MulticastListenerQuery:
			e.mu.Lock()
			e.mu.mld.handleMulticastListenerQuery(header.MLD(payload.ToView()))
			e.mu.Unlock()
		case header.ICMPv6MulticastListenerReport:
			e.mu.Lock()
			e.mu.mld.handleMulticastListenerReport(header.MLD(payload.ToView()))
			e.mu.Unlock()
		case header.ICMPv6MulticastListenerDone:
		default:
			panic(fmt.Sprintf("unrecognized MLD message = %d", icmpType))
		}

	default:
		received.unrecognized.Increment()
	}
}

// LinkAddressProtocol implements stack.LinkAddressResolver.
func (*endpoint) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.
func (e *endpoint) LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error {
	remoteAddr := targetAddr
	if len(remoteLinkAddr) == 0 {
		remoteAddr = header.SolicitedNodeAddr(targetAddr)
		remoteLinkAddr = header.EthernetAddressFromMulticastIPv6Address(remoteAddr)
	}

	if len(localAddr) == 0 {
		addressEndpoint := e.AcquireOutgoingPrimaryAddress(remoteAddr, false /* allowExpired */)
		if addressEndpoint == nil {
			return &tcpip.ErrNetworkUnreachable{}
		}

		localAddr = addressEndpoint.AddressWithPrefix().Address
	} else if e.protocol.stack.CheckLocalAddress(e.nic.ID(), ProtocolNumber, localAddr) == 0 {
		return &tcpip.ErrBadLocalAddress{}
	}

	optsSerializer := header.NDPOptionsSerializer{
		header.NDPSourceLinkLayerAddressOption(e.nic.LinkAddress()),
	}
	neighborSolicitSize := header.ICMPv6NeighborSolicitMinimumSize + optsSerializer.Length()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(e.nic.MaxHeaderLength()) + header.IPv6FixedHeaderSize + neighborSolicitSize,
	})
	pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	packet := header.ICMPv6(pkt.TransportHeader().Push(neighborSolicitSize))
	packet.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(packet.MessageBody())
	ns.SetTargetAddress(targetAddr)
	ns.Options().Serialize(optsSerializer)
	packet.SetChecksum(header.ICMPv6Checksum(packet, localAddr, remoteAddr, buffer.VectorisedView{}))

	if err := addIPHeader(localAddr, remoteAddr, pkt, stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      header.NDPHopLimit,
	}, header.IPv6ExtHdrSerializer{}); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}

	stat := e.stats.icmp.packetsSent

	if err := e.nic.WritePacketToRemote(remoteLinkAddr, nil /* gso */, ProtocolNumber, pkt); err != nil {
		stat.dropped.Increment()
		return err
	}

	stat.neighborSolicit.Increment()
	return nil
}

// ResolveStaticAddress implements stack.LinkAddressResolver.
func (*endpoint) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if header.IsV6MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv6Address(addr), true
	}
	return tcpip.LinkAddress([]byte(nil)), false
}

// ======= ICMP Error packet generation =========

// icmpReason is a marker interface for IPv6 specific ICMP errors.
type icmpReason interface {
	isICMPReason()
}

// icmpReasonParameterProblem is an error during processing of extension headers
// or the fixed header defined in RFC 4443 section 3.4.
type icmpReasonParameterProblem struct {
	code header.ICMPv6Code

	// respondToMulticast indicates that we are sending a packet that falls under
	// the exception outlined by RFC 4443 section 2.4 point e.3 exception 2:
	//
	//       (e.3) A packet destined to an IPv6 multicast address.  (There are
	//             two exceptions to this rule: (1) the Packet Too Big Message
	//             (Section 3.2) to allow Path MTU discovery to work for IPv6
	//             multicast, and (2) the Parameter Problem Message, Code 2
	//             (Section 3.4) reporting an unrecognized IPv6 option (see
	//             Section 4.2 of [IPv6]) that has the Option Type highest-
	//             order two bits set to 10).
	respondToMulticast bool

	// pointer is defined in the RFC 4443 setion 3.4 which reads:
	//
	//  Pointer         Identifies the octet offset within the invoking packet
	//                  where the error was detected.
	//
	//                  The pointer will point beyond the end of the ICMPv6
	//                  packet if the field in error is beyond what can fit
	//                  in the maximum size of an ICMPv6 error message.
	pointer uint32
}

func (*icmpReasonParameterProblem) isICMPReason() {}

// icmpReasonPortUnreachable is an error where the transport protocol has no
// listener and no alternative means to inform the sender.
type icmpReasonPortUnreachable struct{}

func (*icmpReasonPortUnreachable) isICMPReason() {}

// icmpReasonHopLimitExceeded is an error where a packet's hop limit exceeded in
// transit to its final destination, as per RFC 4443 section 3.3.
type icmpReasonHopLimitExceeded struct{}

func (*icmpReasonHopLimitExceeded) isICMPReason() {}

// icmpReasonReassemblyTimeout is an error where insufficient fragments are
// received to complete reassembly of a packet within a configured time after
// the reception of the first-arriving fragment of that packet.
type icmpReasonReassemblyTimeout struct{}

func (*icmpReasonReassemblyTimeout) isICMPReason() {}

// returnError takes an error descriptor and generates the appropriate ICMP
// error packet for IPv6 and sends it.
func (p *protocol) returnError(reason icmpReason, pkt *stack.PacketBuffer) tcpip.Error {
	origIPHdr := header.IPv6(pkt.NetworkHeader().View())
	origIPHdrSrc := origIPHdr.SourceAddress()
	origIPHdrDst := origIPHdr.DestinationAddress()

	// Only send ICMP error if the address is not a multicast v6
	// address and the source is not the unspecified address.
	//
	// There are exceptions to this rule.
	// See: point e.3) RFC 4443 section-2.4
	//
	//	 (e) An ICMPv6 error message MUST NOT be originated as a result of
	//       receiving the following:
	//
	//       (e.1) An ICMPv6 error message.
	//
	//       (e.2) An ICMPv6 redirect message [IPv6-DISC].
	//
	//       (e.3) A packet destined to an IPv6 multicast address.  (There are
	//             two exceptions to this rule: (1) the Packet Too Big Message
	//             (Section 3.2) to allow Path MTU discovery to work for IPv6
	//             multicast, and (2) the Parameter Problem Message, Code 2
	//             (Section 3.4) reporting an unrecognized IPv6 option (see
	//             Section 4.2 of [IPv6]) that has the Option Type highest-
	//             order two bits set to 10).
	//
	var allowResponseToMulticast bool
	if reason, ok := reason.(*icmpReasonParameterProblem); ok {
		allowResponseToMulticast = reason.respondToMulticast
	}

	isOrigDstMulticast := header.IsV6MulticastAddress(origIPHdrDst)
	if (!allowResponseToMulticast && isOrigDstMulticast) || origIPHdrSrc == header.IPv6Any {
		return nil
	}

	// If we hit a Hop Limit Exceeded error, then we know we are operating as a
	// router. As per RFC 4443 section 3.3:
	//
	//   If a router receives a packet with a Hop Limit of zero, or if a
	//   router decrements a packet's Hop Limit to zero, it MUST discard the
	//   packet and originate an ICMPv6 Time Exceeded message with Code 0 to
	//   the source of the packet.  This indicates either a routing loop or
	//   too small an initial Hop Limit value.
	//
	// If we are operating as a router, do not use the packet's destination
	// address as the response's source address as we should not own the
	// destination address of a packet we are forwarding.
	//
	// If the packet was originally destined to a multicast address, then do not
	// use the packet's destination address as the source for the response ICMP
	// packet as "multicast addresses must not be used as source addresses in IPv6
	// packets", as per RFC 4291 section 2.7.
	localAddr := origIPHdrDst
	if _, ok := reason.(*icmpReasonHopLimitExceeded); ok || isOrigDstMulticast {
		localAddr = ""
	}
	// Even if we were able to receive a packet from some remote, we may not have
	// a route to it - the remote may be blocked via routing rules. We must always
	// consult our routing table and find a route to the remote before sending any
	// packet.
	route, err := p.stack.FindRoute(pkt.NICID, localAddr, origIPHdrSrc, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer route.Release()

	p.mu.Lock()
	netEP, ok := p.mu.eps[pkt.NICID]
	p.mu.Unlock()
	if !ok {
		return &tcpip.ErrNotConnected{}
	}

	sent := netEP.stats.icmp.packetsSent

	if !p.stack.AllowICMPMessage() {
		sent.rateLimited.Increment()
		return nil
	}

	if pkt.TransportProtocolNumber == header.ICMPv6ProtocolNumber {
		// TODO(gvisor.dev/issues/3810): Sort this out when ICMP headers are stored.
		// Unfortunately at this time ICMP Packets do not have a transport
		// header separated out. It is in the Data part so we need to
		// separate it out now. We will just pretend it is a minimal length
		// ICMP packet as we don't really care if any later bits of a
		// larger ICMP packet are in the header view or in the Data view.
		transport, ok := pkt.TransportHeader().Consume(header.ICMPv6MinimumSize)
		if !ok {
			return nil
		}
		typ := header.ICMPv6(transport).Type()
		if typ.IsErrorType() || typ == header.ICMPv6RedirectMsg {
			return nil
		}
	}

	network, transport := pkt.NetworkHeader().View(), pkt.TransportHeader().View()

	// As per RFC 4443 section 2.4
	//
	//    (c) Every ICMPv6 error message (type < 128) MUST include
	//    as much of the IPv6 offending (invoking) packet (the
	//    packet that caused the error) as possible without making
	//    the error message packet exceed the minimum IPv6 MTU
	//    [IPv6].
	mtu := int(route.MTU())
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	if mtu > maxIPv6Data {
		mtu = maxIPv6Data
	}
	available := mtu - header.ICMPv6ErrorHeaderSize
	if available < header.IPv6MinimumSize {
		return nil
	}
	payloadLen := network.Size() + transport.Size() + pkt.Data.Size()
	if payloadLen > available {
		payloadLen = available
	}
	payload := network.ToVectorisedView()
	payload.AppendView(transport)
	payload.Append(pkt.Data)
	payload.CapLength(payloadLen)

	newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv6ErrorHeaderSize,
		Data:               payload,
	})
	newPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber

	icmpHdr := header.ICMPv6(newPkt.TransportHeader().Push(header.ICMPv6DstUnreachableMinimumSize))
	var counter tcpip.MultiCounterStat
	switch reason := reason.(type) {
	case *icmpReasonParameterProblem:
		icmpHdr.SetType(header.ICMPv6ParamProblem)
		icmpHdr.SetCode(reason.code)
		icmpHdr.SetTypeSpecific(reason.pointer)
		counter = sent.paramProblem
	case *icmpReasonPortUnreachable:
		icmpHdr.SetType(header.ICMPv6DstUnreachable)
		icmpHdr.SetCode(header.ICMPv6PortUnreachable)
		counter = sent.dstUnreachable
	case *icmpReasonHopLimitExceeded:
		icmpHdr.SetType(header.ICMPv6TimeExceeded)
		icmpHdr.SetCode(header.ICMPv6HopLimitExceeded)
		counter = sent.timeExceeded
	case *icmpReasonReassemblyTimeout:
		icmpHdr.SetType(header.ICMPv6TimeExceeded)
		icmpHdr.SetCode(header.ICMPv6ReassemblyTimeout)
		counter = sent.timeExceeded
	default:
		panic(fmt.Sprintf("unsupported ICMP type %T", reason))
	}
	icmpHdr.SetChecksum(header.ICMPv6Checksum(icmpHdr, route.LocalAddress, route.RemoteAddress, newPkt.Data))
	if err := route.WritePacket(
		nil, /* gso */
		stack.NetworkHeaderParams{
			Protocol: header.ICMPv6ProtocolNumber,
			TTL:      route.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		},
		newPkt,
	); err != nil {
		sent.dropped.Increment()
		return err
	}
	counter.Increment()
	return nil
}

// OnReassemblyTimeout implements fragmentation.TimeoutHandler.
func (p *protocol) OnReassemblyTimeout(pkt *stack.PacketBuffer) {
	// OnReassemblyTimeout sends a Time Exceeded Message as per RFC 2460 Section
	// 4.5:
	//
	//   If the first fragment (i.e., the one with a Fragment Offset of zero) has
	//   been received, an ICMP Time Exceeded -- Fragment Reassembly Time Exceeded
	//   message should be sent to the source of that fragment.
	if pkt != nil {
		p.returnError(&icmpReasonReassemblyTimeout{}, pkt)
	}
}
