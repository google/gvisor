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
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, pkt tcpip.PacketBuffer) {
	h := header.IPv4(pkt.Data.First())

	// We don't use IsValid() here because ICMP only requires that the IP
	// header plus 8 bytes of the transport header be included. So it's
	// likely that it is truncated, which would cause IsValid to return
	// false.
	//
	// Drop packet if it doesn't have the basic IPv4 header or if the
	// original source address doesn't match the endpoint's address.
	if len(h) < header.IPv4MinimumSize || h.SourceAddress() != e.id.LocalAddress {
		return
	}

	hlen := int(h.HeaderLength())
	if pkt.Data.Size() < hlen || h.FragmentOffset() != 0 {
		// We won't be able to handle this if it doesn't contain the
		// full IPv4 header, or if it's a fragment not at offset 0
		// (because it won't have the transport header).
		return
	}

	// Skip the ip header, then deliver control message.
	pkt.Data.TrimFront(hlen)
	p := h.TransportProtocol()
	e.dispatcher.DeliverTransportControlPacket(e.id.LocalAddress, h.DestinationAddress(), ProtocolNumber, p, typ, extra, pkt)
}

func (e *endpoint) handleICMP(r *stack.Route, pkt tcpip.PacketBuffer) {
	stats := r.Stats()
	received := stats.ICMP.V4PacketsReceived
	v := pkt.Data.First()
	if len(v) < header.ICMPv4MinimumSize {
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
		e.dispatcher.DeliverTransportPacket(r, header.ICMPv4ProtocolNumber, tcpip.PacketBuffer{
			Data:          pkt.Data.Clone(nil),
			NetworkHeader: append(buffer.View(nil), pkt.NetworkHeader...),
		})

		vv := pkt.Data.Clone(nil)
		vv.TrimFront(header.ICMPv4MinimumSize)
		hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv4MinimumSize)
		pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))
		copy(pkt, h)
		pkt.SetType(header.ICMPv4EchoReply)
		pkt.SetChecksum(0)
		pkt.SetChecksum(^header.Checksum(pkt, header.ChecksumVV(vv, 0)))
		sent := stats.ICMP.V4PacketsSent
		if err := r.WritePacket(nil /* gso */, hdr, vv, stack.NetworkHeaderParams{Protocol: header.ICMPv4ProtocolNumber, TTL: r.DefaultTTL(), TOS: stack.DefaultTOS}); err != nil {
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

func (e *endpoint) ParamProblem(r *stack.Route, netHeader buffer.View, vv buffer.VectorisedView) {
	vv = vv.Clone(nil)

	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv4MinimumSize + header.IPv4MinimumSize + header.ICMPv4MinimumSize)
	transportHdr := hdr.Prepend(header.ICMPv4MinimumSize)
	copy(transportHdr, vv.First())
	vv.TrimFront(header.ICMPv4MinimumSize)

	ipHdr := hdr.Prepend(header.IPv4MinimumSize + len(options))
	copy(ipHdr, netHeader)

	pkt := header.ICMPv4(hdr.Prepend(header.ICMPv4MinimumSize))

	pkt.SetType(header.ICMPv4ParamProblem)
	pkt.SetCode(0)

	pointer := make([]byte, 1)
	if len(options) != int(options[1]) {
		pointer = []byte{20}
	} else if len(options) <= int(options[3]) {
		pointer = []byte{22}
	}

	pkt.SetPointer(pointer)
	pkt.SetChecksum(0)
	pkt.SetChecksum(^header.Checksum(pkt, header.ChecksumVV(vv, 0)))

	options = nil

	if err := r.WritePacket(nil /* gso */, hdr, vv, stack.NetworkHeaderParams{Protocol: header.ICMPv4ProtocolNumber, TTL: r.DefaultTTL(), TOS: stack.DefaultTOS}); err != nil {
		return
	}
}
