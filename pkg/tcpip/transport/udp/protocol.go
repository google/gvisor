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

// Package udp contains the implementation of the UDP transport protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing udp.NewProtocol() as one of the
// transport protocols when calling stack.New(). Then endpoints can be created
// by passing udp.ProtocolNumber as the transport protocol number when calling
// Stack.NewEndpoint().
package udp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// ProtocolNumber is the udp protocol number.
	ProtocolNumber = header.UDPProtocolNumber

	// MinBufferSize is the smallest size of a receive or send buffer.
	MinBufferSize = 4 << 10 // 4KiB bytes.

	// DefaultSendBufferSize is the default size of the send buffer for
	// an endpoint.
	DefaultSendBufferSize = 32 << 10 // 32KiB

	// DefaultReceiveBufferSize is the default size of the receive buffer
	// for an endpoint.
	DefaultReceiveBufferSize = 32 << 10 // 32KiB

	// MaxBufferSize is the largest size a receive/send buffer can grow to.
	MaxBufferSize = 4 << 20 // 4MiB
)

type protocol struct {
}

// Number returns the udp protocol number.
func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

// NewEndpoint creates a new udp endpoint.
func (*protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newEndpoint(stack, netProto, waiterQueue), nil
}

// NewRawEndpoint creates a new raw UDP endpoint. It implements
// stack.TransportProtocol.NewRawEndpoint.
func (p *protocol) NewRawEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return raw.NewEndpoint(stack, netProto, header.UDPProtocolNumber, waiterQueue)
}

// MinimumPacketSize returns the minimum valid udp packet size.
func (*protocol) MinimumPacketSize() int {
	return header.UDPMinimumSize
}

// ParsePorts returns the source and destination ports stored in the given udp
// packet.
func (*protocol) ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error) {
	h := header.UDP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

// HandleUnknownDestinationPacket handles packets targeted at this protocol but
// that don't match any existing endpoint.
func (p *protocol) HandleUnknownDestinationPacket(r *stack.Route, id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	hdr := header.UDP(pkt.TransportHeader().View())
	if int(hdr.Length()) > pkt.Data.Size()+header.UDPMinimumSize {
		// Malformed packet.
		r.Stack().Stats().UDP.MalformedPacketsReceived.Increment()
		return true
	}

	if !verifyChecksum(r, hdr, pkt) {
		// Checksum Error.
		r.Stack().Stats().UDP.ChecksumErrors.Increment()
		return true
	}

	// Only send ICMP error if the address is not a multicast/broadcast
	// v4/v6 address or the source is not the unspecified address.
	//
	// See: point e) in https://tools.ietf.org/html/rfc4443#section-2.4
	if id.LocalAddress == header.IPv4Broadcast || header.IsV4MulticastAddress(id.LocalAddress) || header.IsV6MulticastAddress(id.LocalAddress) || id.RemoteAddress == header.IPv6Any || id.RemoteAddress == header.IPv4Any {
		return true
	}

	// As per RFC: 1122 Section 3.2.2.1 A host SHOULD generate Destination
	//   Unreachable messages with code:
	//
	//     2 (Protocol Unreachable), when the designated transport protocol
	//     is not supported; or
	//
	//     3 (Port Unreachable), when the designated transport protocol
	//     (e.g., UDP) is unable to demultiplex the datagram but has no
	//     protocol mechanism to inform the sender.
	switch len(id.LocalAddress) {
	case header.IPv4AddressSize:
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
		// systems implement the] RFC1812 definition and not the original
		// RFC 1122 requirement.
		mtu := int(r.MTU())
		if mtu > header.IPv4MinimumProcessableDatagramSize {
			mtu = header.IPv4MinimumProcessableDatagramSize
		}
		headerLen := int(r.MaxHeaderLength()) + header.ICMPv4MinimumSize
		available := int(mtu) - headerLen
		payloadLen := pkt.NetworkHeader().View().Size() + pkt.TransportHeader().View().Size() + pkt.Data.Size()
		if payloadLen > available {
			payloadLen = available
		}

		// The buffers used by pkt may be used elsewhere in the system.
		// For example, a raw or packet socket may use what UDP
		// considers an unreachable destination. Thus we deep copy pkt
		// to prevent multiple ownership and SR errors.
		newHeader := append(buffer.View(nil), pkt.NetworkHeader().View()...)
		newHeader = append(newHeader, pkt.TransportHeader().View()...)
		payload := newHeader.ToVectorisedView()
		payload.AppendView(pkt.Data.ToView())
		payload.CapLength(payloadLen)

		icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: headerLen,
			Data:               payload,
		})
		icmpHdr := header.ICMPv4(icmpPkt.TransportHeader().Push(header.ICMPv4MinimumSize))
		icmpHdr.SetType(header.ICMPv4DstUnreachable)
		icmpHdr.SetCode(header.ICMPv4PortUnreachable)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, icmpPkt.Data))
		r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv4ProtocolNumber, TTL: r.DefaultTTL(), TOS: stack.DefaultTOS}, icmpPkt)

	case header.IPv6AddressSize:
		if !r.Stack().AllowICMPMessage() {
			r.Stack().Stats().ICMP.V6PacketsSent.RateLimited.Increment()
			return true
		}

		// As per RFC 4443 section 2.4
		//
		//    (c) Every ICMPv6 error message (type < 128) MUST include
		//    as much of the IPv6 offending (invoking) packet (the
		//    packet that caused the error) as possible without making
		//    the error message packet exceed the minimum IPv6 MTU
		//    [IPv6].
		mtu := int(r.MTU())
		if mtu > header.IPv6MinimumMTU {
			mtu = header.IPv6MinimumMTU
		}
		headerLen := int(r.MaxHeaderLength()) + header.ICMPv6DstUnreachableMinimumSize
		available := int(mtu) - headerLen
		network, transport := pkt.NetworkHeader().View(), pkt.TransportHeader().View()
		payloadLen := len(network) + len(transport) + pkt.Data.Size()
		if payloadLen > available {
			payloadLen = available
		}
		payload := buffer.NewVectorisedView(len(network)+len(transport), []buffer.View{network, transport})
		payload.Append(pkt.Data)
		payload.CapLength(payloadLen)

		icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: headerLen,
			Data:               payload,
		})
		icmpHdr := header.ICMPv6(icmpPkt.TransportHeader().Push(header.ICMPv6DstUnreachableMinimumSize))
		icmpHdr.SetType(header.ICMPv6DstUnreachable)
		icmpHdr.SetCode(header.ICMPv6PortUnreachable)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(icmpHdr, r.LocalAddress, r.RemoteAddress, icmpPkt.Data))
		r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: r.DefaultTTL(), TOS: stack.DefaultTOS}, icmpPkt)
	}
	return true
}

// SetOption implements stack.TransportProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Option implements stack.TransportProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// Parse implements stack.TransportProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.TransportHeader().Consume(header.UDPMinimumSize)
	return ok
}

// NewProtocol returns a UDP transport protocol.
func NewProtocol() stack.TransportProtocol {
	return &protocol{}
}
