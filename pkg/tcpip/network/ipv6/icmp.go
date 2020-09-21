// Copyright 2018 The gVisor Authors.
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
	if e.stack.CheckLocalAddress(e.NICID(), ProtocolNumber, src) == 0 {
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

func (e *endpoint) handleICMP(r *stack.Route, pkt *stack.PacketBuffer, hasFragmentHeader bool) {
	stats := r.Stats().ICMP
	sent := stats.V6PacketsSent
	received := stats.V6PacketsReceived
	// TODO(gvisor.dev/issue/170): ICMP packets don't have their
	// TransportHeader fields set. See icmp/protocol.go:protocol.Parse for a
	// full explanation.
	v, ok := pkt.Data.PullUp(header.ICMPv6HeaderSize)
	if !ok {
		received.Invalid.Increment()
		return
	}
	h := header.ICMPv6(v)
	iph := header.IPv6(pkt.NetworkHeader().View())

	// Validate ICMPv6 checksum before processing the packet.
	//
	// This copy is used as extra payload during the checksum calculation.
	payload := pkt.Data.Clone(nil)
	payload.TrimFront(len(h))
	if got, want := h.Checksum(), header.ICMPv6Checksum(h, iph.SourceAddress(), iph.DestinationAddress(), payload); got != want {
		received.Invalid.Increment()
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
	switch h.Type() {
	case header.ICMPv6PacketTooBig:
		received.PacketTooBig.Increment()
		hdr, ok := pkt.Data.PullUp(header.ICMPv6PacketTooBigMinimumSize)
		if !ok {
			received.Invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6PacketTooBigMinimumSize)
		mtu := header.ICMPv6(hdr).MTU()
		e.handleControl(stack.ControlPacketTooBig, calculateMTU(mtu), pkt)

	case header.ICMPv6DstUnreachable:
		received.DstUnreachable.Increment()
		hdr, ok := pkt.Data.PullUp(header.ICMPv6DstUnreachableMinimumSize)
		if !ok {
			received.Invalid.Increment()
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
		received.NeighborSolicit.Increment()
		if !isNDPValid() || pkt.Data.Size() < header.ICMPv6NeighborSolicitMinimumSize {
			received.Invalid.Increment()
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
			received.Invalid.Increment()
			return
		}

		s := r.Stack()
		if isTentative, err := s.IsAddrTentative(e.nicID, targetAddr); err != nil {
			// We will only get an error if the NIC is unrecognized, which should not
			// happen. For now, drop this packet.
			//
			// TODO(b/141002840): Handle this better?
			return
		} else if isTentative {
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
			if r.RemoteAddress == header.IPv6Any {
				s.DupTentativeAddrDetected(e.nicID, targetAddr)
			}

			// Do not handle neighbor solicitations targeted to an address that is
			// tentative on the NIC any further.
			return
		}

		// At this point we know that the target address is not tentative on the NIC
		// so the packet is processed as defined in RFC 4861, as per RFC 4862
		// section 5.4.3.

		// Is the NS targeting us?
		if s.CheckLocalAddress(e.nicID, ProtocolNumber, targetAddr) == 0 {
			return
		}

		it, err := ns.Options().Iter(false /* check */)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.Invalid.Increment()
			return
		}

		unspecifiedSource := r.RemoteAddress == header.IPv6Any

		// As per RFC 4861 section 4.3, the Source Link-Layer Address Option MUST
		// NOT be included when the source IP address is the unspecified address.
		// Otherwise, on link layers that have addresses this option MUST be
		// included in multicast solicitations and SHOULD be included in unicast
		// solicitations.
		if len(sourceLinkAddr) == 0 {
			if header.IsV6MulticastAddress(r.LocalAddress) && !unspecifiedSource {
				received.Invalid.Increment()
				return
			}
		} else if unspecifiedSource {
			received.Invalid.Increment()
			return
		} else if e.nud != nil {
			e.nud.HandleProbe(r.RemoteAddress, r.LocalAddress, header.IPv6ProtocolNumber, sourceLinkAddr, e.protocol)
		} else {
			e.linkAddrCache.AddLinkAddress(e.nicID, r.RemoteAddress, sourceLinkAddr)
		}

		// ICMPv6 Neighbor Solicit messages are always sent to
		// specially crafted IPv6 multicast addresses. As a result, the
		// route we end up with here has as its LocalAddress such a
		// multicast address. It would be nonsense to claim that our
		// source address is a multicast address, so we manually set
		// the source address to the target address requested in the
		// solicit message. Since that requires mutating the route, we
		// must first clone it.
		r := r.Clone()
		defer r.Release()
		r.LocalAddress = targetAddr

		// As per RFC 4861 section 7.2.4, if the the source of the solicitation is
		// the unspecified address, the node MUST set the Solicited flag to zero and
		// multicast the advertisement to the all-nodes address.
		solicited := true
		if unspecifiedSource {
			solicited = false
			r.RemoteAddress = header.IPv6AllNodesMulticastAddress
		}

		// If the NS has a source link-layer option, use the link address it
		// specifies as the remote link address for the response instead of the
		// source link address of the packet.
		//
		// TODO(#2401): As per RFC 4861 section 7.2.4 we should consult our link
		// address cache for the right destination link address instead of manually
		// patching the route with the remote link address if one is specified in a
		// Source Link-Layer Address option.
		if len(sourceLinkAddr) != 0 {
			r.RemoteLinkAddress = sourceLinkAddr
		}

		optsSerializer := header.NDPOptionsSerializer{
			header.NDPTargetLinkLayerAddressOption(r.LocalLinkAddress),
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()) + header.ICMPv6NeighborAdvertMinimumSize + int(optsSerializer.Length()),
		})
		packet := header.ICMPv6(pkt.TransportHeader().Push(header.ICMPv6NeighborAdvertSize))
		packet.SetType(header.ICMPv6NeighborAdvert)
		na := header.NDPNeighborAdvert(packet.NDPPayload())
		na.SetSolicitedFlag(solicited)
		na.SetOverrideFlag(true)
		na.SetTargetAddress(targetAddr)
		opts := na.Options()
		opts.Serialize(optsSerializer)
		packet.SetChecksum(header.ICMPv6Checksum(packet, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

		// RFC 4861 Neighbor Discovery for IP version 6 (IPv6)
		//
		// 7.1.2. Validation of Neighbor Advertisements
		//
		// The IP Hop Limit field has a value of 255, i.e., the packet
		// could not possibly have been forwarded by a router.
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: stack.DefaultTOS}, pkt); err != nil {
			sent.Dropped.Increment()
			return
		}
		sent.NeighborAdvert.Increment()

	case header.ICMPv6NeighborAdvert:
		received.NeighborAdvert.Increment()
		if !isNDPValid() || pkt.Data.Size() < header.ICMPv6NeighborAdvertSize {
			received.Invalid.Increment()
			return
		}

		// The remainder of payload must be only the neighbor advertisement, so
		// payload.ToView() always returns the advertisement. Per RFC 6980 section
		// 5, NDP messages cannot be fragmented. Also note that in the common case
		// NDP datagrams are very small and ToView() will not incur allocations.
		na := header.NDPNeighborAdvert(payload.ToView())
		targetAddr := na.TargetAddress()
		s := r.Stack()

		if isTentative, err := s.IsAddrTentative(e.nicID, targetAddr); err != nil {
			// We will only get an error if the NIC is unrecognized, which should not
			// happen. For now short-circuit this packet.
			//
			// TODO(b/141002840): Handle this better?
			return
		} else if isTentative {
			// We just got an NA from a node that owns an address we are performing
			// DAD on, implying the address is not unique. In this case we let the
			// stack know so it can handle such a scenario and do nothing furthur with
			// the NDP NA.
			s.DupTentativeAddrDetected(e.nicID, targetAddr)
			return
		}

		it, err := na.Options().Iter(false /* check */)
		if err != nil {
			// If we have a malformed NDP NA option, drop the packet.
			received.Invalid.Increment()
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
			received.Invalid.Increment()
			return
		}

		// If the NA message has the target link layer option, update the link
		// address cache with the link address for the target of the message.
		if len(targetLinkAddr) != 0 {
			if e.nud == nil {
				e.linkAddrCache.AddLinkAddress(e.nicID, targetAddr, targetLinkAddr)
				return
			}

			e.nud.HandleConfirmation(targetAddr, targetLinkAddr, stack.ReachabilityConfirmationFlags{
				Solicited: na.SolicitedFlag(),
				Override:  na.OverrideFlag(),
				IsRouter:  na.RouterFlag(),
			})
		}

	case header.ICMPv6EchoRequest:
		received.EchoRequest.Increment()
		icmpHdr, ok := pkt.TransportHeader().Consume(header.ICMPv6EchoMinimumSize)
		if !ok {
			received.Invalid.Increment()
			return
		}

		remoteLinkAddr := r.RemoteLinkAddress

		// As per RFC 4291 section 2.7, multicast addresses must not be used as
		// source addresses in IPv6 packets.
		localAddr := r.LocalAddress
		if header.IsV6MulticastAddress(r.LocalAddress) {
			localAddr = ""
		}

		r, err := r.Stack().FindRoute(e.NICID(), localAddr, r.RemoteAddress, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		// Use the link address from the source of the original packet.
		r.ResolveWith(remoteLinkAddr)

		replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize,
			Data:               pkt.Data,
		})
		packet := header.ICMPv6(replyPkt.TransportHeader().Push(header.ICMPv6EchoMinimumSize))
		copy(packet, icmpHdr)
		packet.SetType(header.ICMPv6EchoReply)
		packet.SetChecksum(header.ICMPv6Checksum(packet, r.LocalAddress, r.RemoteAddress, pkt.Data))
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: r.DefaultTTL(), TOS: stack.DefaultTOS}, replyPkt); err != nil {
			sent.Dropped.Increment()
			return
		}
		sent.EchoReply.Increment()

	case header.ICMPv6EchoReply:
		received.EchoReply.Increment()
		if pkt.Data.Size() < header.ICMPv6EchoMinimumSize {
			received.Invalid.Increment()
			return
		}
		e.dispatcher.DeliverTransportPacket(r, header.ICMPv6ProtocolNumber, pkt)

	case header.ICMPv6TimeExceeded:
		received.TimeExceeded.Increment()

	case header.ICMPv6ParamProblem:
		received.ParamProblem.Increment()

	case header.ICMPv6RouterSolicit:
		received.RouterSolicit.Increment()

		//
		// Validate the RS as per RFC 4861 section 6.1.1.
		//

		// Is the NDP payload of sufficient size to hold a Router Solictation?
		if !isNDPValid() || pkt.Data.Size()-header.ICMPv6HeaderSize < header.NDPRSMinimumSize {
			received.Invalid.Increment()
			return
		}

		stack := r.Stack()

		// Is the networking stack operating as a router?
		if !stack.Forwarding(ProtocolNumber) {
			// ... No, silently drop the packet.
			received.RouterOnlyPacketsDroppedByHost.Increment()
			return
		}

		// Note that in the common case NDP datagrams are very small and ToView()
		// will not incur allocations.
		rs := header.NDPRouterSolicit(payload.ToView())
		it, err := rs.Options().Iter(false /* check */)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.Invalid.Increment()
			return
		}

		// If the RS message has the source link layer option, update the link
		// address cache with the link address for the source of the message.
		if len(sourceLinkAddr) != 0 {
			// As per RFC 4861 section 4.1, the Source Link-Layer Address Option MUST
			// NOT be included when the source IP address is the unspecified address.
			// Otherwise, it SHOULD be included on link layers that have addresses.
			if r.RemoteAddress == header.IPv6Any {
				received.Invalid.Increment()
				return
			}

			if e.nud != nil {
				// A RS with a specified source IP address modifies the NUD state
				// machine in the same way a reachability probe would.
				e.nud.HandleProbe(r.RemoteAddress, r.LocalAddress, header.IPv6ProtocolNumber, sourceLinkAddr, e.protocol)
			}
		}

	case header.ICMPv6RouterAdvert:
		received.RouterAdvert.Increment()

		//
		// Validate the RA as per RFC 4861 section 6.1.2.
		//

		// Is the NDP payload of sufficient size to hold a Router Advertisement?
		if !isNDPValid() || pkt.Data.Size()-header.ICMPv6HeaderSize < header.NDPRAMinimumSize {
			received.Invalid.Increment()
			return
		}

		routerAddr := iph.SourceAddress()

		// Is the IP Source Address a link-local address?
		if !header.IsV6LinkLocalAddress(routerAddr) {
			// ...No, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		// Note that in the common case NDP datagrams are very small and ToView()
		// will not incur allocations.
		ra := header.NDPRouterAdvert(payload.ToView())
		it, err := ra.Options().Iter(false /* check */)
		if err != nil {
			// Options are not valid as per the wire format, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		sourceLinkAddr, ok := getSourceLinkAddr(it)
		if !ok {
			received.Invalid.Increment()
			return
		}

		//
		// At this point, we have a valid Router Advertisement, as far
		// as RFC 4861 section 6.1.2 is concerned.
		//

		// If the RA has the source link layer option, update the link address
		// cache with the link address for the advertised router.
		if len(sourceLinkAddr) != 0 && e.nud != nil {
			e.nud.HandleProbe(routerAddr, r.LocalAddress, header.IPv6ProtocolNumber, sourceLinkAddr, e.protocol)
		}

		// Tell the NIC to handle the RA.
		stack := r.Stack()
		stack.HandleNDPRA(e.nicID, routerAddr, ra)

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
		received.RedirectMsg.Increment()
		if !isNDPValid() {
			received.Invalid.Increment()
			return
		}

	default:
		received.Invalid.Increment()
	}
}

const (
	ndpSolicitedFlag = 1 << 6
	ndpOverrideFlag  = 1 << 5

	ndpOptSrcLinkAddr = 1
	ndpOptDstLinkAddr = 2

	icmpV6FlagOffset   = 4
	icmpV6OptOffset    = 24
	icmpV6LengthOffset = 25
)

var _ stack.LinkAddressResolver = (*protocol)(nil)

// LinkAddressProtocol implements stack.LinkAddressResolver.
func (*protocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.
func (*protocol) LinkAddressRequest(addr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress, linkEP stack.LinkEndpoint) *tcpip.Error {
	snaddr := header.SolicitedNodeAddr(addr)

	// TODO(b/148672031): Use stack.FindRoute instead of manually creating the
	// route here. Note, we would need the nicID to do this properly so the right
	// NIC (associated to linkEP) is used to send the NDP NS message.
	r := &stack.Route{
		LocalAddress:      localAddr,
		RemoteAddress:     snaddr,
		RemoteLinkAddress: remoteLinkAddr,
	}
	if len(r.RemoteLinkAddress) == 0 {
		r.RemoteLinkAddress = header.EthernetAddressFromMulticastIPv6Address(snaddr)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(linkEP.MaxHeaderLength()) + header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize,
	})
	icmpHdr := header.ICMPv6(pkt.TransportHeader().Push(header.ICMPv6NeighborAdvertSize))
	icmpHdr.SetType(header.ICMPv6NeighborSolicit)
	copy(icmpHdr[icmpV6OptOffset-len(addr):], addr)
	icmpHdr[icmpV6OptOffset] = ndpOptSrcLinkAddr
	icmpHdr[icmpV6LengthOffset] = 1
	copy(icmpHdr[icmpV6LengthOffset+1:], linkEP.LinkAddress())
	icmpHdr.SetChecksum(header.ICMPv6Checksum(icmpHdr, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

	length := uint16(pkt.Size())
	ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: length,
		NextHeader:    uint8(header.ICMPv6ProtocolNumber),
		HopLimit:      header.NDPHopLimit,
		SrcAddr:       r.LocalAddress,
		DstAddr:       r.RemoteAddress,
	})

	// TODO(stijlist): count this in ICMP stats.
	return linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, pkt)
}

// ResolveStaticAddress implements stack.LinkAddressResolver.
func (*protocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if header.IsV6MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv6Address(addr), true
	}
	return tcpip.LinkAddress([]byte(nil)), false
}
