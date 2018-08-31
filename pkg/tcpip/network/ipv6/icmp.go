// Copyright 2018 Google Inc.
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
	"encoding/binary"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

// handleControl handles the case when an ICMP packet contains the headers of
// the original packet that caused the ICMP one to be sent. This information is
// used to find out which transport endpoint must be notified about the ICMP
// packet.
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, vv *buffer.VectorisedView) {
	h := header.IPv6(vv.First())

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
	vv.TrimFront(header.IPv6MinimumSize)
	p := h.TransportProtocol()
	if p == header.IPv6FragmentHeader {
		f := header.IPv6Fragment(vv.First())
		if !f.IsValid() || f.FragmentOffset() != 0 {
			// We can't handle fragments that aren't at offset 0
			// because they don't have the transport headers.
			return
		}

		// Skip fragmentation header and find out the actual protocol
		// number.
		vv.TrimFront(header.IPv6FragmentHeaderSize)
		p = f.TransportProtocol()
	}

	// Deliver the control packet to the transport endpoint.
	e.dispatcher.DeliverTransportControlPacket(e.id.LocalAddress, h.DestinationAddress(), ProtocolNumber, p, typ, extra, vv)
}

func (e *endpoint) handleICMP(r *stack.Route, vv *buffer.VectorisedView) {
	v := vv.First()
	if len(v) < header.ICMPv6MinimumSize {
		return
	}
	h := header.ICMPv6(v)

	switch h.Type() {
	case header.ICMPv6PacketTooBig:
		if len(v) < header.ICMPv6PacketTooBigMinimumSize {
			return
		}
		vv.TrimFront(header.ICMPv6PacketTooBigMinimumSize)
		mtu := binary.BigEndian.Uint32(v[header.ICMPv6MinimumSize:])
		e.handleControl(stack.ControlPacketTooBig, calculateMTU(mtu), vv)

	case header.ICMPv6DstUnreachable:
		if len(v) < header.ICMPv6DstUnreachableMinimumSize {
			return
		}
		vv.TrimFront(header.ICMPv6DstUnreachableMinimumSize)
		switch h.Code() {
		case header.ICMPv6PortUnreachable:
			e.handleControl(stack.ControlPortUnreachable, 0, vv)
		}
	}
}
