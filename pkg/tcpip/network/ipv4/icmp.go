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

package ipv4

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// icmpv4DestinationUnreachableSockError is a general ICMPv4 Destination
// Unreachable error.
//
// +stateify savable
type icmpv4DestinationUnreachableSockError struct{}

// Origin implements tcpip.SockErrorCause.
func (*icmpv4DestinationUnreachableSockError) Origin() tcpip.SockErrOrigin {
	return tcpip.SockExtErrorOriginICMP
}

// Type implements tcpip.SockErrorCause.
func (*icmpv4DestinationUnreachableSockError) Type() uint8 {
	return uint8(header.ICMPv4DstUnreachable)
}

// Info implements tcpip.SockErrorCause.
func (*icmpv4DestinationUnreachableSockError) Info() uint32 {
	return 0
}

var _ stack.TransportError = (*icmpv4DestinationHostUnreachableSockError)(nil)

// icmpv4DestinationHostUnreachableSockError is an ICMPv4 Destination Host
// Unreachable error.
//
// It indicates that a packet was not able to reach the destination host.
//
// +stateify savable
type icmpv4DestinationHostUnreachableSockError struct {
	icmpv4DestinationUnreachableSockError
}

// Code implements tcpip.SockErrorCause.
func (*icmpv4DestinationHostUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv4HostUnreachable)
}

// Kind implements stack.TransportError.
func (*icmpv4DestinationHostUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationHostUnreachableTransportError
}

var _ stack.TransportError = (*icmpv4DestinationPortUnreachableSockError)(nil)

// icmpv4DestinationPortUnreachableSockError is an ICMPv4 Destination Port
// Unreachable error.
//
// It indicates that a packet reached the destination host, but the transport
// protocol was not active on the destination port.
//
// +stateify savable
type icmpv4DestinationPortUnreachableSockError struct {
	icmpv4DestinationUnreachableSockError
}

// Code implements tcpip.SockErrorCause.
func (*icmpv4DestinationPortUnreachableSockError) Code() uint8 {
	return uint8(header.ICMPv4PortUnreachable)
}

// Kind implements stack.TransportError.
func (*icmpv4DestinationPortUnreachableSockError) Kind() stack.TransportErrorKind {
	return stack.DestinationPortUnreachableTransportError
}

var _ stack.TransportError = (*icmpv4FragmentationNeededSockError)(nil)

// icmpv4FragmentationNeededSockError is an ICMPv4 Destination Unreachable error
// due to fragmentation being required but the packet was set to not be
// fragmented.
//
// It indicates that a link exists on the path to the destination with an MTU
// that is too small to carry the packet.
//
// +stateify savable
type icmpv4FragmentationNeededSockError struct {
	icmpv4DestinationUnreachableSockError

	mtu uint32
}

// Code implements tcpip.SockErrorCause.
func (*icmpv4FragmentationNeededSockError) Code() uint8 {
	return uint8(header.ICMPv4FragmentationNeeded)
}

// Info implements tcpip.SockErrorCause.
func (e *icmpv4FragmentationNeededSockError) Info() uint32 {
	return e.mtu
}

// Kind implements stack.TransportError.
func (*icmpv4FragmentationNeededSockError) Kind() stack.TransportErrorKind {
	return stack.PacketTooBigTransportError
}

func (e *endpoint) checkLocalAddress(addr tcpip.Address) bool {
	if e.nic.Spoofing() {
		return true
	}

	if addressEndpoint := e.AcquireAssignedAddress(addr, false, stack.NeverPrimaryEndpoint); addressEndpoint != nil {
		addressEndpoint.DecRef()
		return true
	}
	return false
}

// handleControl handles the case when an ICMP error packet contains the headers
// of the original packet that caused the ICMP one to be sent. This information
// is used to find out which transport endpoint must be notified about the ICMP
// packet. We only expect the payload, not the enclosing ICMP packet.
func (e *endpoint) handleControl(errInfo stack.TransportError, pkt *stack.PacketBuffer) {
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
	if !e.checkLocalAddress(srcAddr) {
		return
	}

	hlen := int(hdr.HeaderLength())
	if pkt.Data.Size() < hlen || hdr.FragmentOffset() != 0 {
		// We won't be able to handle this if it doesn't contain the
		// full IPv4 header, or if it's a fragment not at offset 0
		// (because it won't have the transport header).
		return
	}

	// Skip the ip header, then deliver the error.
	pkt.Data.TrimFront(hlen)
	p := hdr.TransportProtocol()
	e.dispatcher.DeliverTransportError(srcAddr, hdr.DestinationAddress(), ProtocolNumber, p, errInfo, pkt)
}

func (e *endpoint) handleICMP(pkt *stack.PacketBuffer) {
	received := e.stats.icmp.packetsReceived
	// TODO(gvisor.dev/issue/170): ICMP packets don't have their
	// TransportHeader fields set. See icmp/protocol.go:protocol.Parse for a
	// full explanation.
	v, ok := pkt.Data.PullUp(header.ICMPv4MinimumSize)
	if !ok {
		received.invalid.Increment()
		return
	}
	h := header.ICMPv4(v)

	// Only do in-stack processing if the checksum is correct.
	if header.ChecksumVV(pkt.Data, 0 /* initial */) != 0xffff {
		received.invalid.Increment()
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
	if opts := iph.Options(); len(opts) != 0 {
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
		var optProblem *header.IPv4OptParameterProblem
		newOptions, optProblem = e.processIPOptions(pkt, opts, op)
		if optProblem != nil {
			if optProblem.NeedICMP {
				_ = e.protocol.returnError(&icmpReasonParamProblem{
					pointer: optProblem.Pointer,
				}, pkt)
				e.protocol.stack.Stats().MalformedRcvdPackets.Increment()
				e.stats.ip.MalformedPacketsReceived.Increment()
			}
			return
		}
		copied := copy(opts, newOptions)
		if copied != len(newOptions) {
			panic(fmt.Sprintf("copied %d bytes of new options, expected %d bytes", copied, len(newOptions)))
		}
		for i := copied; i < len(opts); i++ {
			// Pad with 0 (EOL). RFC 791 page 23 says "The padding is zero".
			opts[i] = byte(header.IPv4OptionListEndType)
		}
	}

	// TODO(b/112892170): Meaningfully handle all ICMP types.
	switch h.Type() {
	case header.ICMPv4Echo:
		received.echo.Increment()

		sent := e.stats.icmp.packetsSent
		if !e.protocol.stack.AllowICMPMessage() {
			sent.rateLimited.Increment()
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
			sent.dropped.Increment()
			return
		}
		sent.echoReply.Increment()

	case header.ICMPv4EchoReply:
		received.echoReply.Increment()

		e.dispatcher.DeliverTransportPacket(header.ICMPv4ProtocolNumber, pkt)

	case header.ICMPv4DstUnreachable:
		received.dstUnreachable.Increment()

		pkt.Data.TrimFront(header.ICMPv4MinimumSize)
		switch h.Code() {
		case header.ICMPv4HostUnreachable:
			e.handleControl(&icmpv4DestinationHostUnreachableSockError{}, pkt)
		case header.ICMPv4PortUnreachable:
			e.handleControl(&icmpv4DestinationPortUnreachableSockError{}, pkt)
		case header.ICMPv4FragmentationNeeded:
			networkMTU, err := calculateNetworkMTU(uint32(h.MTU()), header.IPv4MinimumSize)
			if err != nil {
				networkMTU = 0
			}
			e.handleControl(&icmpv4FragmentationNeededSockError{mtu: networkMTU}, pkt)
		}
	case header.ICMPv4SrcQuench:
		received.srcQuench.Increment()

	case header.ICMPv4Redirect:
		received.redirect.Increment()

	case header.ICMPv4TimeExceeded:
		received.timeExceeded.Increment()

	case header.ICMPv4ParamProblem:
		received.paramProblem.Increment()

	case header.ICMPv4Timestamp:
		received.timestamp.Increment()

	case header.ICMPv4TimestampReply:
		received.timestampReply.Increment()

	case header.ICMPv4InfoRequest:
		received.infoRequest.Increment()

	case header.ICMPv4InfoReply:
		received.infoReply.Increment()

	default:
		received.invalid.Increment()
	}
}

// ======= ICMP Error packet generation =========

// icmpReason is a marker interface for IPv4 specific ICMP errors.
type icmpReason interface {
	isICMPReason()
	isForwarding() bool
}

// icmpReasonPortUnreachable is an error where the transport protocol has no
// listener and no alternative means to inform the sender.
type icmpReasonPortUnreachable struct{}

func (*icmpReasonPortUnreachable) isICMPReason() {}
func (*icmpReasonPortUnreachable) isForwarding() bool {
	return false
}

// icmpReasonProtoUnreachable is an error where the transport protocol is
// not supported.
type icmpReasonProtoUnreachable struct{}

func (*icmpReasonProtoUnreachable) isICMPReason() {}
func (*icmpReasonProtoUnreachable) isForwarding() bool {
	return false
}

// icmpReasonTTLExceeded is an error where a packet's time to live exceeded in
// transit to its final destination, as per RFC 792 page 6, Time Exceeded
// Message.
type icmpReasonTTLExceeded struct{}

func (*icmpReasonTTLExceeded) isICMPReason() {}
func (*icmpReasonTTLExceeded) isForwarding() bool {
	// If we hit a TTL Exceeded error, then we know we are operating as a router.
	// As per RFC 792 page 6, Time Exceeded Message,
	//
	//   If the gateway processing a datagram finds the time to live field
	//   is zero it must discard the datagram.  The gateway may also notify
	//   the source host via the time exceeded message.
	return true
}

// icmpReasonReassemblyTimeout is an error where insufficient fragments are
// received to complete reassembly of a packet within a configured time after
// the reception of the first-arriving fragment of that packet.
type icmpReasonReassemblyTimeout struct{}

func (*icmpReasonReassemblyTimeout) isICMPReason() {}
func (*icmpReasonReassemblyTimeout) isForwarding() bool {
	return false
}

// icmpReasonParamProblem is an error to use to request a Parameter Problem
// message to be sent.
type icmpReasonParamProblem struct {
	pointer    byte
	forwarding bool
}

func (*icmpReasonParamProblem) isICMPReason() {}
func (r *icmpReasonParamProblem) isForwarding() bool {
	return r.forwarding
}

// returnError takes an error descriptor and generates the appropriate ICMP
// error packet for IPv4 and sends it back to the remote device that sent
// the problematic packet. It incorporates as much of that packet as
// possible as well as any error metadata as is available. returnError
// expects pkt to hold a valid IPv4 packet as per the wire format.
func (p *protocol) returnError(reason icmpReason, pkt *stack.PacketBuffer) tcpip.Error {
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

	// If we are operating as a router/gateway, don't use the packet's destination
	// address as the response's source address as we should not not own the
	// destination address of a packet we are forwarding.
	localAddr := origIPHdrDst
	if reason.isForwarding() {
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
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize

	if available < len(origIPHdr)+header.ICMPv4MinimumErrorPayloadSize {
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
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv4MinimumSize,
		Data:               payload,
	})

	icmpPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber

	icmpHdr := header.ICMPv4(icmpPkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	var counter tcpip.MultiCounterStat
	switch reason := reason.(type) {
	case *icmpReasonPortUnreachable:
		icmpHdr.SetType(header.ICMPv4DstUnreachable)
		icmpHdr.SetCode(header.ICMPv4PortUnreachable)
		counter = sent.dstUnreachable
	case *icmpReasonProtoUnreachable:
		icmpHdr.SetType(header.ICMPv4DstUnreachable)
		icmpHdr.SetCode(header.ICMPv4ProtoUnreachable)
		counter = sent.dstUnreachable
	case *icmpReasonTTLExceeded:
		icmpHdr.SetType(header.ICMPv4TimeExceeded)
		icmpHdr.SetCode(header.ICMPv4TTLExceeded)
		counter = sent.timeExceeded
	case *icmpReasonReassemblyTimeout:
		icmpHdr.SetType(header.ICMPv4TimeExceeded)
		icmpHdr.SetCode(header.ICMPv4ReassemblyTimeout)
		counter = sent.timeExceeded
	case *icmpReasonParamProblem:
		icmpHdr.SetType(header.ICMPv4ParamProblem)
		icmpHdr.SetCode(header.ICMPv4UnusedCode)
		icmpHdr.SetPointer(reason.pointer)
		counter = sent.paramProblem
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
		sent.dropped.Increment()
		return err
	}
	counter.Increment()
	return nil
}

// OnReassemblyTimeout implements fragmentation.TimeoutHandler.
func (p *protocol) OnReassemblyTimeout(pkt *stack.PacketBuffer) {
	// OnReassemblyTimeout sends a Time Exceeded Message, as per RFC 792:
	//
	//   If a host reassembling a fragmented datagram cannot complete the
	//   reassembly due to missing fragments within its time limit it discards the
	//   datagram, and it may send a time exceeded message.
	//
	//   If fragment zero is not available then no time exceeded need be sent at
	//   all.
	if pkt != nil {
		p.returnError(&icmpReasonReassemblyTimeout{}, pkt)
	}
}
