// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4

import (
	"encoding/binary"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

// handleControl handles the case when an ICMP packet contains the headers of
// the original packet that caused the ICMP one to be sent. This information is
// used to find out which transport endpoint must be notified about the ICMP
// packet.
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, vv *buffer.VectorisedView) {
	h := header.IPv4(vv.First())

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
	if vv.Size() < hlen || h.FragmentOffset() != 0 {
		// We won't be able to handle this if it doesn't contain the
		// full IPv4 header, or if it's a fragment not at offset 0
		// (because it won't have the transport header).
		return
	}

	// Skip the ip header, then deliver control message.
	vv.TrimFront(hlen)
	p := h.TransportProtocol()
	e.dispatcher.DeliverTransportControlPacket(e.id.LocalAddress, h.DestinationAddress(), ProtocolNumber, p, typ, extra, vv)
}

func (e *endpoint) handleICMP(r *stack.Route, vv *buffer.VectorisedView) {
	v := vv.First()
	if len(v) < header.ICMPv4MinimumSize {
		return
	}
	h := header.ICMPv4(v)

	switch h.Type() {
	case header.ICMPv4Echo:
		if len(v) < header.ICMPv4EchoMinimumSize {
			return
		}
		vv.TrimFront(header.ICMPv4MinimumSize)
		req := echoRequest{r: r.Clone(), v: vv.ToView()}
		select {
		case e.echoRequests <- req:
		default:
			req.r.Release()
		}

	case header.ICMPv4EchoReply:
		if len(v) < header.ICMPv4EchoMinimumSize {
			return
		}
		e.dispatcher.DeliverTransportPacket(r, header.ICMPv4ProtocolNumber, vv)

	case header.ICMPv4DstUnreachable:
		if len(v) < header.ICMPv4DstUnreachableMinimumSize {
			return
		}
		vv.TrimFront(header.ICMPv4DstUnreachableMinimumSize)
		switch h.Code() {
		case header.ICMPv4PortUnreachable:
			e.handleControl(stack.ControlPortUnreachable, 0, vv)

		case header.ICMPv4FragmentationNeeded:
			mtu := uint32(binary.BigEndian.Uint16(v[header.ICMPv4DstUnreachableMinimumSize-2:]))
			e.handleControl(stack.ControlPacketTooBig, calculateMTU(mtu), vv)
		}
	}
	// TODO: Handle other ICMP types.
}

type echoRequest struct {
	r stack.Route
	v buffer.View
}

func (e *endpoint) echoReplier() {
	for req := range e.echoRequests {
		sendPing4(&req.r, 0, req.v)
		req.r.Release()
	}
}

func sendPing4(r *stack.Route, code byte, data buffer.View) *tcpip.Error {
	hdr := buffer.NewPrependable(header.ICMPv4EchoMinimumSize + int(r.MaxHeaderLength()))

	icmpv4 := header.ICMPv4(hdr.Prepend(header.ICMPv4EchoMinimumSize))
	icmpv4.SetType(header.ICMPv4EchoReply)
	icmpv4.SetCode(code)
	copy(icmpv4[header.ICMPv4MinimumSize:], data)
	data = data[header.ICMPv4EchoMinimumSize-header.ICMPv4MinimumSize:]
	icmpv4.SetChecksum(^header.Checksum(icmpv4, header.Checksum(data, 0)))

	return r.WritePacket(&hdr, data, header.ICMPv4ProtocolNumber)
}
