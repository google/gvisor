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
	// original source address doesn't match an address we own.
	src := hdr.SourceAddress()
	if e.protocol.stack.CheckLocalAddress(e.nic.ID(), ProtocolNumber, src) == 0 {
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
	e.dispatcher.DeliverTransportControlPacket(src, hdr.DestinationAddress(), ProtocolNumber, p, typ, extra, pkt)
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

		// Make a copy of data before pkt gets sent to raw socket.
		// DeliverTransportPacket will take ownership of pkt.
		replyData := pkt.Data.Clone(nil)
		replyData.TrimFront(header.ICMPv4MinimumSize)

		// It's possible that a raw socket expects to receive this.
		h.SetChecksum(wantChecksum)
		e.dispatcher.DeliverTransportPacket(r, header.ICMPv4ProtocolNumber, pkt)

		remoteLinkAddr := r.RemoteLinkAddress

		// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
		// source address MUST be one of its own IP addresses (but not a broadcast
		// or multicast address).
		localAddr := r.LocalAddress
		if r.IsInboundBroadcast() || header.IsV4MulticastAddress(localAddr) {
			localAddr = ""
		}

		r, err := r.Stack().FindRoute(e.nic.ID(), localAddr, r.RemoteAddress, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		// Use the remote link address from the incoming packet.
		r.ResolveWith(remoteLinkAddr)

		// Prepare a reply packet.
		icmpHdr := make(header.ICMPv4, header.ICMPv4MinimumSize)
		copy(icmpHdr, h)
		icmpHdr.SetType(header.ICMPv4EchoReply)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(^header.Checksum(icmpHdr, header.ChecksumVV(replyData, 0)))
		dataVV := buffer.View(icmpHdr).ToVectorisedView()
		dataVV.Append(replyData)
		replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()),
			Data:               dataVV,
		})
		// TODO(gvisor.dev/issue/3810): When adding protocol numbers into the header
		// information we will have to change this code to handle the ICMP header
		// no longer being in the data buffer.
		replyPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
		// Send out the reply packet.
		sent := stats.ICMP.V4PacketsSent
		if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{
			Protocol: header.ICMPv4ProtocolNumber,
			TTL:      r.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		}, replyPkt); err != nil {
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

// ======= ICMP Error packet generation =========

// icmpReason is a marker interface for IPv4 specific ICMP errors.
type icmpReason interface {
	isICMPReason()
}

// icmpReasonPortUnreachable is an error where the transport protocol has no
// listener and no alternative means to inform the sender.
type icmpReasonPortUnreachable struct{}

func (*icmpReasonPortUnreachable) isICMPReason() {}

// returnError takes an error descriptor and generates the appropriate ICMP
// error packet for IPv4 and sends it back to the remote device that sent
// the problematic packet. It incorporates as much of that packet as
// possible as well as any error metadata as is available. returnError
// expects pkt to hold a valid IPv4 packet as per the wire format.
func returnError(r *stack.Route, reason icmpReason, pkt *stack.PacketBuffer) *tcpip.Error {
	sent := r.Stats().ICMP.V4PacketsSent
	if !r.Stack().AllowICMPMessage() {
		sent.RateLimited.Increment()
		return nil
	}

	// We check we are responding only when we are allowed to.
	// See RFC 1812 section 4.3.2.7 (shown below).
	//
	// =========
	// 4.3.2.7 When Not to Send ICMP Errors
	//
	//  An ICMP error message MUST NOT be sent as the result of receiving:
	//
	//  o An ICMP error message, or
	//
	//  o A packet which fails the IP header validation tests described in
	//    Section [5.2.2] (except where that section specifically permits
	//    the sending of an ICMP error message), or
	//
	//  o A packet destined to an IP broadcast or IP multicast address, or
	//
	//  o A packet sent as a Link Layer broadcast or multicast, or
	//
	//  o Any fragment of a datagram other then the first fragment (i.e., a
	// packet for which the fragment offset in the IP header is nonzero).
	//
	// TODO(gvisor.dev/issues/4058): Make sure we don't send ICMP errors in
	// response to a non-initial fragment, but it currently can not happen.

	if r.IsInboundBroadcast() || header.IsV4MulticastAddress(r.LocalAddress) || r.RemoteAddress == header.IPv4Any {
		return nil
	}

	networkHeader := pkt.NetworkHeader().View()
	transportHeader := pkt.TransportHeader().View()

	// Don't respond to icmp error packets.
	if header.IPv4(networkHeader).Protocol() == uint8(header.ICMPv4ProtocolNumber) {
		// TODO(gvisor.dev/issue/3810):
		// Unfortunately the current stack pretty much always has ICMPv4 headers
		// in the Data section of the packet but there is no guarantee that is the
		// case. If this is the case grab the header to make it like all other
		// packet types. When this is cleaned up the Consume should be removed.
		if transportHeader.IsEmpty() {
			var ok bool
			transportHeader, ok = pkt.TransportHeader().Consume(header.ICMPv4MinimumSize)
			if !ok {
				return nil
			}
		} else if transportHeader.Size() < header.ICMPv4MinimumSize {
			return nil
		}
		// We need to decide to explicitly name the packets we can respond to or
		// the ones we can not respond to. The decision is somewhat arbitrary and
		// if problems arise this could be reversed. It was judged less of a breach
		// of protocol to not respond to unknown non-error packets than to respond
		// to unknown error packets so we take the first approach.
		switch header.ICMPv4(transportHeader).Type() {
		case
			header.ICMPv4EchoReply,
			header.ICMPv4Echo,
			header.ICMPv4Timestamp,
			header.ICMPv4TimestampReply,
			header.ICMPv4InfoRequest,
			header.ICMPv4InfoReply:
		default:
			// Assume any type we don't know about may be an error type.
			return nil
		}
	} else if transportHeader.IsEmpty() {
		return nil
	}

	// Now work out how much of the triggering packet we should return.
	// As per RFC 1812 Section 4.3.2.3
	//
	//   ICMP datagram SHOULD contain as much of the original
	//   datagram as possible without the length of the ICMP
	//   datagram exceeding 576 bytes.
	//
	// NOTE: The above RFC referenced is different from the original
	// recommendation in RFC 1122 and RFC 792 where it mentioned that at
	// least 8 bytes of the payload must be included. Today linux and other
	// systems implement the RFC 1812 definition and not the original
	// requirement. We treat 8 bytes as the minimum but will try send more.
	mtu := int(r.MTU())
	if mtu > header.IPv4MinimumProcessableDatagramSize {
		mtu = header.IPv4MinimumProcessableDatagramSize
	}
	headerLen := int(r.MaxHeaderLength()) + header.ICMPv4MinimumSize
	available := int(mtu) - headerLen

	if available < header.IPv4MinimumSize+header.ICMPv4MinimumErrorPayloadSize {
		return nil
	}

	payloadLen := networkHeader.Size() + transportHeader.Size() + pkt.Data.Size()
	if payloadLen > available {
		payloadLen = available
	}

	// The buffers used by pkt may be used elsewhere in the system.
	// For example, an AF_RAW or AF_PACKET socket may use what the transport
	// protocol considers an unreachable destination. Thus we deep copy pkt to
	// prevent multiple ownership and SR errors. The new copy is a vectorized
	// view with the entire incoming IP packet reassembled and truncated as
	// required. This is now the payload of the new ICMP packet and no longer
	// considered a packet in its own right.
	newHeader := append(buffer.View(nil), networkHeader...)
	newHeader = append(newHeader, transportHeader...)
	payload := newHeader.ToVectorisedView()
	payload.AppendView(pkt.Data.ToView())
	payload.CapLength(payloadLen)

	icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: headerLen,
		Data:               payload,
	})
	icmpPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

	icmpHdr := header.ICMPv4(icmpPkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(header.ICMPv4PortUnreachable)
	counter := sent.DstUnreachable
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, icmpPkt.Data))

	if err := r.WritePacket(
		nil, /* gso */
		stack.NetworkHeaderParams{
			Protocol: header.ICMPv4ProtocolNumber,
			TTL:      r.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		},
		icmpPkt,
	); err != nil {
		sent.Dropped.Increment()
		return err
	}
	counter.Increment()
	return nil
}
