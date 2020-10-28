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
	"errors"
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// handleControl handles the case when an ICMP error packet contains the headers
// of the original packet that caused the ICMP one to be sent. This information
// is used to find out which transport endpoint must be notified about the ICMP
// packet. We only expect the payload, not the enclosing ICMP packet.
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
	srcAddr := hdr.SourceAddress()
	if e.protocol.stack.CheckLocalAddress(e.nic.ID(), ProtocolNumber, srcAddr) == 0 {
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
	e.dispatcher.DeliverTransportControlPacket(srcAddr, hdr.DestinationAddress(), ProtocolNumber, p, typ, extra, pkt)
}

func (e *endpoint) handleICMP(pkt *stack.PacketBuffer) {
	stats := e.protocol.stack.Stats()
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

	// Only do in-stack processing if the checksum is correct.
	if header.ChecksumVV(pkt.Data, 0 /* initial */) != 0xffff {
		received.Invalid.Increment()
		// It's possible that a raw socket expects to receive this regardless
		// of checksum errors. If it's an echo request we know it's safe because
		// we are the only handler, however other types do not cope well with
		// packets with checksum errors.
		switch h.Type() {
		case header.ICMPv4Echo:
			e.dispatcher.DeliverTransportPacket(header.ICMPv4ProtocolNumber, pkt)
		}
		return
	}

	iph := header.IPv4(pkt.NetworkHeader().View())
	var newOptions header.IPv4Options
	if len(iph) > header.IPv4MinimumSize {
		// RFC 1122 section 3.2.2.6 (page 43) (and similar for other round trip
		// type ICMP packets):
		//    If a Record Route and/or Time Stamp option is received in an
		//    ICMP Echo Request, this option (these options) SHOULD be
		//    updated to include the current host and included in the IP
		//    header of the Echo Reply message, without "truncation".
		//    Thus, the recorded route will be for the entire round trip.
		//
		// So we need to let the option processor know how it should handle them.
		var op optionsUsage
		if h.Type() == header.ICMPv4Echo {
			op = &optionUsageEcho{}
		} else {
			op = &optionUsageReceive{}
		}
		aux, tmp, err := e.processIPOptions(pkt, iph.Options(), op)
		if err != nil {
			switch {
			case
				errors.Is(err, header.ErrIPv4OptDuplicate),
				errors.Is(err, errIPv4RecordRouteOptInvalidLength),
				errors.Is(err, errIPv4RecordRouteOptInvalidPointer),
				errors.Is(err, errIPv4TimestampOptInvalidLength),
				errors.Is(err, errIPv4TimestampOptInvalidPointer),
				errors.Is(err, errIPv4TimestampOptOverflow):
				_ = e.protocol.returnError(&icmpReasonParamProblem{pointer: aux}, pkt)
				stats.MalformedRcvdPackets.Increment()
				stats.IP.MalformedPacketsReceived.Increment()
			}
			return
		}
		newOptions = tmp
	}

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch h.Type() {
	case header.ICMPv4Echo:
		received.Echo.Increment()

		sent := stats.ICMP.V4PacketsSent
		if !e.protocol.stack.AllowICMPMessage() {
			sent.RateLimited.Increment()
			return
		}

		// DeliverTransportPacket will take ownership of pkt so don't use it beyond
		// this point. Make a deep copy of the data before pkt gets sent as we will
		// be modifying fields.
		//
		// TODO(gvisor.dev/issue/4399): The copy may not be needed if there are no
		// waiting endpoints. Consider moving responsibility for doing the copy to
		// DeliverTransportPacket so that is is only done when needed.
		replyData := pkt.Data.ToOwnedView()
		ipHdr := header.IPv4(pkt.NetworkHeader().View())
		localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

		// It's possible that a raw socket expects to receive this.
		e.dispatcher.DeliverTransportPacket(header.ICMPv4ProtocolNumber, pkt)
		pkt = nil

		// Take the base of the incoming request IP header but replace the options.
		replyHeaderLength := uint8(header.IPv4MinimumSize + len(newOptions))
		replyIPHdr := header.IPv4(append(iph[:header.IPv4MinimumSize:header.IPv4MinimumSize], newOptions...))
		replyIPHdr.SetHeaderLength(replyHeaderLength)

		// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
		// source address MUST be one of its own IP addresses (but not a broadcast
		// or multicast address).
		localAddr := ipHdr.DestinationAddress()
		if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
			localAddr = ""
		}

		r, err := e.protocol.stack.FindRoute(e.nic.ID(), localAddr, ipHdr.SourceAddress(), ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return
		}
		defer r.Release()

		// TODO(gvisor.dev/issue/3810:) When adding protocol numbers into the
		// header information, we may have to change this code to handle the
		// ICMP header no longer being in the data buffer.

		// Because IP and ICMP are so closely intertwined, we need to handcraft our
		// IP header to be able to follow RFC 792. The wording on page 13 is as
		// follows:
		//   IP Fields:
		//   Addresses
		//     The address of the source in an echo message will be the
		//     destination of the echo reply message.  To form an echo reply
		//     message, the source and destination addresses are simply reversed,
		//     the type code changed to 0, and the checksum recomputed.
		//
		// This was interpreted by early implementors to mean that all options must
		// be copied from the echo request IP header to the echo reply IP header
		// and this behaviour is still relied upon by some applications.
		//
		// Create a copy of the IP header we received, options and all, and change
		// The fields we need to alter.
		//
		// We need to produce the entire packet in the data segment in order to
		// use WriteHeaderIncludedPacket(). WriteHeaderIncludedPacket sets the
		// total length and the header checksum so we don't need to set those here.
		replyIPHdr.SetSourceAddress(r.LocalAddress)
		replyIPHdr.SetDestinationAddress(r.RemoteAddress)
		replyIPHdr.SetTTL(r.DefaultTTL())

		replyICMPHdr := header.ICMPv4(replyData)
		replyICMPHdr.SetType(header.ICMPv4EchoReply)
		replyICMPHdr.SetChecksum(0)
		replyICMPHdr.SetChecksum(^header.Checksum(replyData, 0))

		replyVV := buffer.View(replyIPHdr).ToVectorisedView()
		replyVV.AppendView(replyData)
		replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(r.MaxHeaderLength()),
			Data:               replyVV,
		})
		replyPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

		if err := r.WriteHeaderIncludedPacket(replyPkt); err != nil {
			sent.Dropped.Increment()
			return
		}
		sent.EchoReply.Increment()

	case header.ICMPv4EchoReply:
		received.EchoReply.Increment()

		e.dispatcher.DeliverTransportPacket(header.ICMPv4ProtocolNumber, pkt)

	case header.ICMPv4DstUnreachable:
		received.DstUnreachable.Increment()

		pkt.Data.TrimFront(header.ICMPv4MinimumSize)
		switch h.Code() {
		case header.ICMPv4HostUnreachable:
			e.handleControl(stack.ControlNoRoute, 0, pkt)

		case header.ICMPv4PortUnreachable:
			e.handleControl(stack.ControlPortUnreachable, 0, pkt)

		case header.ICMPv4FragmentationNeeded:
			networkMTU, err := calculateNetworkMTU(uint32(h.MTU()), header.IPv4MinimumSize)
			if err != nil {
				networkMTU = 0
			}
			e.handleControl(stack.ControlPacketTooBig, networkMTU, pkt)
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

// icmpReasonProtoUnreachable is an error where the transport protocol is
// not supported.
type icmpReasonProtoUnreachable struct{}

func (*icmpReasonProtoUnreachable) isICMPReason() {}

// icmpReasonReassemblyTimeout is an error where insufficient fragments are
// received to complete reassembly of a packet within a configured time after
// the reception of the first-arriving fragment of that packet.
type icmpReasonReassemblyTimeout struct{}

func (*icmpReasonReassemblyTimeout) isICMPReason() {}

// icmpReasonParamProblem is an error to use to request a Parameter Problem
// message to be sent.
type icmpReasonParamProblem struct {
	pointer byte
}

func (*icmpReasonParamProblem) isICMPReason() {}

// returnError takes an error descriptor and generates the appropriate ICMP
// error packet for IPv4 and sends it back to the remote device that sent
// the problematic packet. It incorporates as much of that packet as
// possible as well as any error metadata as is available. returnError
// expects pkt to hold a valid IPv4 packet as per the wire format.
func (p *protocol) returnError(reason icmpReason, pkt *stack.PacketBuffer) *tcpip.Error {
	origIPHdr := header.IPv4(pkt.NetworkHeader().View())
	origIPHdrSrc := origIPHdr.SourceAddress()
	origIPHdrDst := origIPHdr.DestinationAddress()

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
	if pkt.NetworkPacketInfo.LocalAddressBroadcast || header.IsV4MulticastAddress(origIPHdrDst) || origIPHdrSrc == header.IPv4Any {
		return nil
	}

	// Even if we were able to receive a packet from some remote, we may not have
	// a route to it - the remote may be blocked via routing rules. We must always
	// consult our routing table and find a route to the remote before sending any
	// packet.
	route, err := p.stack.FindRoute(pkt.NICID, origIPHdrDst, origIPHdrSrc, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer route.Release()

	sent := p.stack.Stats().ICMP.V4PacketsSent
	if !p.stack.AllowICMPMessage() {
		sent.RateLimited.Increment()
		return nil
	}

	transportHeader := pkt.TransportHeader().View()

	// Don't respond to icmp error packets.
	if origIPHdr.Protocol() == uint8(header.ICMPv4ProtocolNumber) {
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
	mtu := int(route.MTU())
	if mtu > header.IPv4MinimumProcessableDatagramSize {
		mtu = header.IPv4MinimumProcessableDatagramSize
	}
	headerLen := int(route.MaxHeaderLength()) + header.ICMPv4MinimumSize
	available := int(mtu) - headerLen

	if available < header.IPv4MinimumSize+header.ICMPv4MinimumErrorPayloadSize {
		return nil
	}

	payloadLen := len(origIPHdr) + transportHeader.Size() + pkt.Data.Size()
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
	newHeader := append(buffer.View(nil), origIPHdr...)
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
	var counter *tcpip.StatCounter
	switch reason := reason.(type) {
	case *icmpReasonPortUnreachable:
		icmpHdr.SetType(header.ICMPv4DstUnreachable)
		icmpHdr.SetCode(header.ICMPv4PortUnreachable)
		counter = sent.DstUnreachable
	case *icmpReasonProtoUnreachable:
		icmpHdr.SetType(header.ICMPv4DstUnreachable)
		icmpHdr.SetCode(header.ICMPv4ProtoUnreachable)
		counter = sent.DstUnreachable
	case *icmpReasonReassemblyTimeout:
		icmpHdr.SetType(header.ICMPv4TimeExceeded)
		icmpHdr.SetCode(header.ICMPv4ReassemblyTimeout)
		counter = sent.TimeExceeded
	case *icmpReasonParamProblem:
		icmpHdr.SetType(header.ICMPv4ParamProblem)
		icmpHdr.SetCode(header.ICMPv4UnusedCode)
		icmpHdr.SetPointer(reason.pointer)
		counter = sent.ParamProblem
	default:
		panic(fmt.Sprintf("unsupported ICMP type %T", reason))
	}
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, icmpPkt.Data))

	if err := route.WritePacket(
		nil, /* gso */
		stack.NetworkHeaderParams{
			Protocol: header.ICMPv4ProtocolNumber,
			TTL:      route.DefaultTTL(),
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
