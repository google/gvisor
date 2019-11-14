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
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, pkt tcpip.PacketBuffer) {
	h := header.IPv6(pkt.Data.First())

	// We don't use IsValid() here because ICMP only requires that up to
	// 1280 bytes of the original packet be included. So it's likely that it
	// is truncated, which would cause IsValid to return false.
	//
	// Drop packet if it doesn't have the basic IPv6 header or if the
	// original source address doesn't match the endpoint's address.
	if len(h) < header.IPv6MinimumSize || h.SourceAddress() != e.id.LocalAddress {
		return
	}

	// Skip the IP header, then handle the fragmentation header if there
	// is one.
	pkt.Data.TrimFront(header.IPv6MinimumSize)
	p := h.TransportProtocol()
	if p == header.IPv6FragmentHeader {
		f := header.IPv6Fragment(pkt.Data.First())
		if !f.IsValid() || f.FragmentOffset() != 0 {
			// We can't handle fragments that aren't at offset 0
			// because they don't have the transport headers.
			return
		}

		// Skip fragmentation header and find out the actual protocol
		// number.
		pkt.Data.TrimFront(header.IPv6FragmentHeaderSize)
		p = f.TransportProtocol()
	}

	// Deliver the control packet to the transport endpoint.
	e.dispatcher.DeliverTransportControlPacket(e.id.LocalAddress, h.DestinationAddress(), ProtocolNumber, p, typ, extra, pkt)
}

func (e *endpoint) handleICMP(r *stack.Route, netHeader buffer.View, pkt tcpip.PacketBuffer) {
	stats := r.Stats().ICMP
	sent := stats.V6PacketsSent
	received := stats.V6PacketsReceived
	v := pkt.Data.First()
	if len(v) < header.ICMPv6MinimumSize {
		received.Invalid.Increment()
		return
	}
	h := header.ICMPv6(v)
	iph := header.IPv6(netHeader)

	// Validate ICMPv6 checksum before processing the packet.
	//
	// Only the first view in vv is accounted for by h. To account for the
	// rest of vv, a shallow copy is made and the first view is removed.
	// This copy is used as extra payload during the checksum calculation.
	payload := pkt.Data
	payload.RemoveFirst()
	if got, want := h.Checksum(), header.ICMPv6Checksum(h, iph.SourceAddress(), iph.DestinationAddress(), payload); got != want {
		received.Invalid.Increment()
		return
	}

	// As per RFC 4861 sections 4.1 - 4.5, 6.1.1, 6.1.2, 7.1.1, 7.1.2 and
	// 8.1, nodes MUST silently drop NDP packets where the Hop Limit field
	// in the IPv6 header is not set to 255, or the ICMPv6 Code field is not
	// set to 0.
	switch h.Type() {
	case header.ICMPv6NeighborSolicit,
		header.ICMPv6NeighborAdvert,
		header.ICMPv6RouterSolicit,
		header.ICMPv6RouterAdvert,
		header.ICMPv6RedirectMsg:
		if iph.HopLimit() != header.NDPHopLimit {
			received.Invalid.Increment()
			return
		}

		if h.Code() != 0 {
			received.Invalid.Increment()
			return
		}
	}

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch h.Type() {
	case header.ICMPv6PacketTooBig:
		received.PacketTooBig.Increment()
		if len(v) < header.ICMPv6PacketTooBigMinimumSize {
			received.Invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6PacketTooBigMinimumSize)
		mtu := h.MTU()
		e.handleControl(stack.ControlPacketTooBig, calculateMTU(mtu), pkt)

	case header.ICMPv6DstUnreachable:
		received.DstUnreachable.Increment()
		if len(v) < header.ICMPv6DstUnreachableMinimumSize {
			received.Invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6DstUnreachableMinimumSize)
		switch h.Code() {
		case header.ICMPv6PortUnreachable:
			e.handleControl(stack.ControlPortUnreachable, 0, pkt)
		}

	case header.ICMPv6NeighborSolicit:
		received.NeighborSolicit.Increment()
		if len(v) < header.ICMPv6NeighborSolicitMinimumSize {
			received.Invalid.Increment()
			return
		}

		ns := header.NDPNeighborSolicit(h.NDPPayload())
		targetAddr := ns.TargetAddress()
		s := r.Stack()
		rxNICID := r.NICID()

		isTentative, err := s.IsAddrTentative(rxNICID, targetAddr)
		if err != nil {
			// We will only get an error if rxNICID is unrecognized,
			// which should not happen. For now short-circuit this
			// packet.
			//
			// TODO(b/141002840): Handle this better?
			return
		}

		if isTentative {
			// If the target address is tentative and the source
			// of the packet is a unicast (specified) address, then
			// the source of the packet is attempting to perform
			// address resolution on the target. In this case, the
			// solicitation is silently ignored, as per RFC 4862
			// section 5.4.3.
			//
			// If the target address is tentative and the source of
			// the packet is the unspecified address (::), then we
			// know another node is also performing DAD for the
			// same address (since targetAddr is tentative for us,
			// we know we are also performing DAD on it). In this
			// case we let the stack know so it can handle such a
			// scenario and do nothing further with the NDP NS.
			if iph.SourceAddress() == header.IPv6Any {
				s.DupTentativeAddrDetected(rxNICID, targetAddr)
			}

			// Do not handle neighbor solicitations targeted
			// to an address that is tentative on the received
			// NIC any further.
			return
		}

		// At this point we know that targetAddr is not tentative on
		// rxNICID so the packet is processed as defined in RFC 4861,
		// as per RFC 4862 section 5.4.3.

		if e.linkAddrCache.CheckLocalAddress(e.nicID, ProtocolNumber, targetAddr) == 0 {
			// We don't have a useful answer; the best we can do is ignore the request.
			return
		}

		optsSerializer := header.NDPOptionsSerializer{
			header.NDPTargetLinkLayerAddressOption(r.LocalLinkAddress[:]),
		}
		hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6NeighborAdvertMinimumSize + int(optsSerializer.Length()))
		packet := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
		packet.SetType(header.ICMPv6NeighborAdvert)
		na := header.NDPNeighborAdvert(packet.NDPPayload())
		na.SetSolicitedFlag(true)
		na.SetOverrideFlag(true)
		na.SetTargetAddress(targetAddr)
		opts := na.Options()
		opts.Serialize(optsSerializer)

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
		packet.SetChecksum(header.ICMPv6Checksum(packet, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

		// TODO(tamird/ghanan): there exists an explicit NDP option that is
		// used to update the neighbor table with link addresses for a
		// neighbor from an NS (see the Source Link Layer option RFC
		// 4861 section 4.6.1 and section 7.2.3).
		//
		// Furthermore, the entirety of NDP handling here seems to be
		// contradicted by RFC 4861.
		e.linkAddrCache.AddLinkAddress(e.nicID, r.RemoteAddress, r.RemoteLinkAddress)

		// RFC 4861 Neighbor Discovery for IP version 6 (IPv6)
		//
		// 7.1.2. Validation of Neighbor Advertisements
		//
		// The IP Hop Limit field has a value of 255, i.e., the packet
		// could not possibly have been forwarded by a router.
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: header.NDPHopLimit, TOS: stack.DefaultTOS}, tcpip.PacketBuffer{
			Header: hdr,
		}); err != nil {
			sent.Dropped.Increment()
			return
		}
		sent.NeighborAdvert.Increment()

	case header.ICMPv6NeighborAdvert:
		received.NeighborAdvert.Increment()
		if len(v) < header.ICMPv6NeighborAdvertSize {
			received.Invalid.Increment()
			return
		}

		na := header.NDPNeighborAdvert(h.NDPPayload())
		targetAddr := na.TargetAddress()
		stack := r.Stack()
		rxNICID := r.NICID()

		isTentative, err := stack.IsAddrTentative(rxNICID, targetAddr)
		if err != nil {
			// We will only get an error if rxNICID is unrecognized,
			// which should not happen. For now short-circuit this
			// packet.
			//
			// TODO(b/141002840): Handle this better?
			return
		}

		if isTentative {
			// We just got an NA from a node that owns an address we
			// are performing DAD on, implying the address is not
			// unique. In this case we let the stack know so it can
			// handle such a scenario and do nothing furthur with
			// the NDP NA.
			stack.DupTentativeAddrDetected(rxNICID, targetAddr)
			return
		}

		// At this point we know that the targetAddress is not tentative
		// on rxNICID. However, targetAddr may still be assigned to
		// rxNICID but not tentative (it could be permanent). Such a
		// scenario is beyond the scope of RFC 4862. As such, we simply
		// ignore such a scenario for now and proceed as normal.
		//
		// TODO(b/143147598): Handle the scenario described above. Also
		// inform the netstack integration that a duplicate address was
		// detected outside of DAD.

		e.linkAddrCache.AddLinkAddress(e.nicID, targetAddr, r.RemoteLinkAddress)
		if targetAddr != r.RemoteAddress {
			e.linkAddrCache.AddLinkAddress(e.nicID, r.RemoteAddress, r.RemoteLinkAddress)
		}

	case header.ICMPv6EchoRequest:
		received.EchoRequest.Increment()
		if len(v) < header.ICMPv6EchoMinimumSize {
			received.Invalid.Increment()
			return
		}
		pkt.Data.TrimFront(header.ICMPv6EchoMinimumSize)
		hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize)
		packet := header.ICMPv6(hdr.Prepend(header.ICMPv6EchoMinimumSize))
		copy(packet, h)
		packet.SetType(header.ICMPv6EchoReply)
		packet.SetChecksum(header.ICMPv6Checksum(packet, r.LocalAddress, r.RemoteAddress, pkt.Data))
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: r.DefaultTTL(), TOS: stack.DefaultTOS}, tcpip.PacketBuffer{
			Header: hdr,
			Data:   pkt.Data,
		}); err != nil {
			sent.Dropped.Increment()
			return
		}
		sent.EchoReply.Increment()

	case header.ICMPv6EchoReply:
		received.EchoReply.Increment()
		if len(v) < header.ICMPv6EchoMinimumSize {
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

	case header.ICMPv6RouterAdvert:
		routerAddr := iph.SourceAddress()

		//
		// Validate the RA as per RFC 4861 section 6.1.2.
		//

		// Is the IP Source Address a link-local address?
		if !header.IsV6LinkLocalAddress(routerAddr) {
			// ...No, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		p := h.NDPPayload()

		// Is the NDP payload of sufficient size to hold a Router
		// Advertisement?
		if len(p) < header.NDPRAMinimumSize {
			// ...No, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		ra := header.NDPRouterAdvert(p)
		opts := ra.Options()

		// Are options valid as per the wire format?
		if _, err := opts.Iter(true); err != nil {
			// ...No, silently drop the packet.
			received.Invalid.Increment()
			return
		}

		//
		// At this point, we have a valid Router Advertisement, as far
		// as RFC 4861 section 6.1.2 is concerned.
		//

		received.RouterAdvert.Increment()

		// Tell the NIC to handle the RA.
		stack := r.Stack()
		rxNICID := r.NICID()
		stack.HandleNDPRA(rxNICID, routerAddr, ra)

	case header.ICMPv6RedirectMsg:
		received.RedirectMsg.Increment()

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

var broadcastMAC = tcpip.LinkAddress([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

var _ stack.LinkAddressResolver = (*protocol)(nil)

// LinkAddressProtocol implements stack.LinkAddressResolver.
func (*protocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv6ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.
func (*protocol) LinkAddressRequest(addr, localAddr tcpip.Address, linkEP stack.LinkEndpoint) *tcpip.Error {
	snaddr := header.SolicitedNodeAddr(addr)
	r := &stack.Route{
		LocalAddress:      localAddr,
		RemoteAddress:     snaddr,
		RemoteLinkAddress: broadcastMAC,
	}
	hdr := buffer.NewPrependable(int(linkEP.MaxHeaderLength()) + header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
	pkt.SetType(header.ICMPv6NeighborSolicit)
	copy(pkt[icmpV6OptOffset-len(addr):], addr)
	pkt[icmpV6OptOffset] = ndpOptSrcLinkAddr
	pkt[icmpV6LengthOffset] = 1
	copy(pkt[icmpV6LengthOffset+1:], linkEP.LinkAddress())
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

	length := uint16(hdr.UsedLength())
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: length,
		NextHeader:    uint8(header.ICMPv6ProtocolNumber),
		HopLimit:      header.NDPHopLimit,
		SrcAddr:       r.LocalAddress,
		DstAddr:       r.RemoteAddress,
	})

	// TODO(stijlist): count this in ICMP stats.
	return linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, tcpip.PacketBuffer{
		Header: hdr,
	})
}

// ResolveStaticAddress implements stack.LinkAddressResolver.
func (*protocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if header.IsV6MulticastAddress(addr) {
		// RFC 2464 Transmission of IPv6 Packets over Ethernet Networks
		//
		// 7. Address Mapping -- Multicast
		//
		// An IPv6 packet with a multicast destination address DST,
		// consisting of the sixteen octets DST[1] through DST[16], is
		// transmitted to the Ethernet multicast address whose first
		// two octets are the value 3333 hexadecimal and whose last
		// four octets are the last four octets of DST.
		return tcpip.LinkAddress([]byte{
			0x33,
			0x33,
			addr[header.IPv6AddressSize-4],
			addr[header.IPv6AddressSize-3],
			addr[header.IPv6AddressSize-2],
			addr[header.IPv6AddressSize-1],
		}), true
	}
	return "", false
}
