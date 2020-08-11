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

package ipv4

import (
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// handleControl handles the case when an ICMP packet contains the headers of
// the original packet that caused the ICMP one to be sent. This information is
// used to find out which transport endpoint must be notified about the ICMP
// packet.
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, pkt *stack.PacketBuffer) {
	h, ok := pkt.Data.PullUp(header.IPv4MinimumSize)
	if !ok {
		return
	}
	hdr := header.IPv4(h)

	// We don't use IsValid() here because ICMP only requires that the IP
	// header plus 8 bytes of the transport header be included. So it's
	// likely that it is truncated, which would cause IsValid to return
	// false.
	//
	// Drop packet if it doesn't have the basic IPv4 header or if the
	// original source address doesn't match the endpoint's address.
	if hdr.SourceAddress() != e.id.LocalAddress {
		return
	}

	hlen := int(hdr.HeaderLength())
	if pkt.Data.Size() < hlen || hdr.FragmentOffset() != 0 {
		// We won't be able to handle this if it doesn't contain the
		// full IPv4 header, or if it's a fragment not at offset 0
		// (because it won't have the transport header).
		return
	}

	// Skip the ip header, then deliver control message.
	pkt.Data.TrimFront(hlen)
	p := hdr.TransportProtocol()
	e.dispatcher.DeliverTransportControlPacket(e.id.LocalAddress, hdr.DestinationAddress(), ProtocolNumber, p, typ, extra, pkt)
}

func (e *endpoint) handleICMP(r *stack.Route, pkt *stack.PacketBuffer) {
	stats := r.Stats()
	received := stats.ICMP.V4PacketsReceived
	// TODO(gvisor.dev/issue/170): ICMP packets don't have their
	// TransportHeader fields set. See icmp/protocol.go:protocol.Parse for a
	// full explanation.
	v, ok := pkt.Data.PullUp(header.ICMPv4MinimumSize)
	if !ok {
		received.Invalid.Increment()
		return
	}
	h := header.ICMPv4(v)

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch h.Type() {
	case header.ICMPv4Echo:
		received.Echo.Increment()

		// Only send a reply if the checksum is valid.
		wantChecksum := h.Checksum()
		// Reset the checksum field to 0 to can calculate the proper
		// checksum. We'll have to reset this before we hand the packet
		// off.
		h.SetChecksum(0)
		gotChecksum := ^header.ChecksumVV(pkt.Data, 0 /* initial */)
		if gotChecksum != wantChecksum {
			// It's possible that a raw socket expects to receive this.
			h.SetChecksum(wantChecksum)
			e.dispatcher.DeliverTransportPacket(r, header.ICMPv4ProtocolNumber, pkt)
			received.Invalid.Increment()
			return
		}

		// It's possible that a raw socket expects to receive this.
		h.SetChecksum(wantChecksum)
		e.dispatcher.DeliverTransportPacket(r, header.ICMPv4ProtocolNumber, &stack.PacketBuffer{
			Data:          pkt.Data.Clone(nil),
			NetworkHeader: append(buffer.View(nil), pkt.NetworkHeader...),
		})

		remoteLinkAddr := r.RemoteLinkAddress

		// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
		// source address MUST be one of its own IP addresses (but not a broadcast
		// or multicast address).
		localAddr := r.LocalAddress
		if r.IsInboundBroadcast() || header.IsV4MulticastAddress(r.LocalAddress) {
			localAddr = ""
		}

		r, err := r.Stack().FindRoute(e.NICID(), localAddr, r.RemoteAddress, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		// Use the remote link address from the incoming packet.
		r.ResolveWith(remoteLinkAddr)

		vv := pkt.Data.Clone(nil)
		vv.TrimFront(header.ICMPv4MinimumSize)
		hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv4MinimumSize)
		pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
		copy(pkt, h)
		pkt.SetType(header.ICMPv4EchoReply)
		pkt.SetChecksum(0)
		pkt.SetChecksum(^header.Checksum(pkt, header.ChecksumVV(vv, 0)))
		sent := stats.ICMP.V4PacketsSent
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{
			Protocol: header.ICMPv4ProtocolNumber,
			TTL:      r.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		}, &stack.PacketBuffer{
			Header:          hdr,
			Data:            vv,
			TransportHeader: buffer.View(pkt),
		}); err != nil {
			sent.Dropped.Increment()
			return
		}
		sent.EchoReply.Increment()

	case header.ICMPv4EchoReply:
		received.EchoReply.Increment()

		e.dispatcher.DeliverTransportPacket(r, header.ICMPv4ProtocolNumber, pkt)

	case header.ICMPv4DstUnreachable:
		received.DstUnreachable.Increment()

		pkt.Data.TrimFront(header.ICMPv4MinimumSize)
		switch h.Code() {
		case header.ICMPv4HostUnreachable:
			e.handleControl(stack.ControlNoRoute, 0, pkt)

		case header.ICMPv4PortUnreachable:
			e.handleControl(stack.ControlPortUnreachable, 0, pkt)

		case header.ICMPv4FragmentationNeeded:
			mtu := uint32(h.MTU())
			e.handleControl(stack.ControlPacketTooBig, calculateMTU(mtu), pkt)
		}

	case header.ICMPv4SrcQuench:
		received.SrcQuench.Increment()

	case header.ICMPv4Redirect:
		received.Redirect.Increment()

	case header.ICMPv4TimeExceeded:
		received.TimeExceeded.Increment()

	case header.ICMPv4ParamProblem:
		received.ParamProblem.Increment()

	case header.ICMPv4Timestamp:
		received.Timestamp.Increment()

	case header.ICMPv4TimestampReply:
		received.TimestampReply.Increment()

	case header.ICMPv4InfoRequest:
		received.InfoRequest.Increment()

	case header.ICMPv4InfoReply:
		received.InfoReply.Increment()

	default:
		received.Invalid.Increment()
	}
}

// ReturnError sends an ICMP error report back to the remote device that sent
// the problematic packet. It will incorporate as much of that packet as
// possible as well as any error metadata as is available. This may be called
// from transport protocols or from within the Network stack.
func (p *protocol) ReturnError(r *stack.Route, reason int, aux int, pkt *stack.PacketBuffer) bool {
	return IPv4ReturnError(r,
		header.ICMPv4ReasonType(reason),
		header.ICMPv4ReasonCode(reason), aux, pkt)
}

// IPv4ReturnError can only be called from within code that is knowledgeable about
// IPv4 ICMP For Protocol agnostic code, call protocol.ReturnError above.
func IPv4ReturnError(r *stack.Route, eType header.ICMPv4Type, eCode header.ICMPv4Code, aux int, pkt *stack.PacketBuffer) bool {
	// Only send ICMP error if the address is not a multicast/broadcast v4
	// address or the source is not the unspecified address.
	//
	// See: point e) in https://tools.ietf.org/html/rfc4443#section-2.4
	if r.LocalAddress == header.IPv4Broadcast || header.IsV4MulticastAddress(r.LocalAddress) || r.RemoteAddress == header.IPv4Any {
		return true
	}

	if !r.Stack().AllowICMPMessage() {
		r.Stack().Stats().ICMP.V4PacketsSent.RateLimited.Increment()
		return true
	}

	// As per RFC 1812 Section 4.3.2.3
	//
	//   ICMP datagram SHOULD contain as much of the original
	//   datagram as possible without the length of the ICMP
	//   datagram exceeding 576 bytes
	//
	// NOTE: The above RFC referenced is different from the original
	// recommendation in RFC 1122 where it mentioned that at least 8
	// bytes of the payload must be included. Today linux and other
	// systems implement the RFC1812 definition and not the original
	// RFC 1122 requirement.
	mtu := int(r.MTU())
	if mtu > header.IPv4MinimumProcessableDatagramSize {
		mtu = header.IPv4MinimumProcessableDatagramSize
	}
	headerLen := int(r.MaxHeaderLength()) + header.ICMPv4MinimumSize
	available := int(mtu) - headerLen

	// If the headers have not yet been parsed they will have length 0 but their
	// data will be in the Data part. Probably this can only be the case of a
	// transport header on receiving an unknown transport protocol.
	payloadLen := len(pkt.NetworkHeader) + len(pkt.TransportHeader) + pkt.Data.Size()
	if payloadLen > available {
		payloadLen = available
	}

	// The buffers used by pkt may be used elsewhere in the system.
	// For example, a raw or packet socket may use what UDP
	// considers an unreachable destination. Thus we deep copy pkt
	// to prevent multiple ownership and SR errors.
	newHeader := append(buffer.View(nil), pkt.NetworkHeader...)
	newHeader = append(newHeader, pkt.TransportHeader...)
	payload := newHeader.ToVectorisedView()
	payload.AppendView(pkt.Data.ToView())
	payload.CapLength(payloadLen)

	hdr := buffer.NewPrependable(headerLen)
	newpkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
	newpkt.SetType(eType)

	// We know that ParamProblem messages need special help. As we support
	// more types of messages we may need to add more support here.
	if eType == header.ICMPv4ParamProblem {
		newpkt.SetPointer(byte(aux))
	} else {
		newpkt.SetCode(eCode)
	}
	newpkt.SetChecksum(header.ICMPv4Checksum(newpkt, payload))
	r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{
		Protocol: header.ICMPv4ProtocolNumber,
		TTL:      r.DefaultTTL(),
		TOS:      stack.DefaultTOS,
	}, &stack.PacketBuffer{
		Header:          hdr,
		TransportHeader: buffer.View(newpkt),
		Data:            payload,
	})
	return true
}
