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

// Package ipv6 contains the implementation of the ipv6 network protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing ipv6.ProtocolName (or "ipv6") as one of the
// network protocols when calling stack.New(). Then endpoints can be created
// by passing ipv6.ProtocolNumber as the network protocol number when calling
// Stack.NewEndpoint().
package ipv6

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

const (
	// ProtocolName is the string representation of the ipv6 protocol name.
	ProtocolName = "ipv6"

	// ProtocolNumber is the ipv6 protocol number.
	ProtocolNumber = header.IPv6ProtocolNumber

	// maxTotalSize is maximum size that can be encoded in the 16-bit
	// PayloadLength field of the ipv6 header.
	maxPayloadSize = 0xffff

	// defaultIPv6HopLimit is the default hop limit for IPv6 Packets
	// egressed by Netstack.
	defaultIPv6HopLimit = 255
)

type address [header.IPv6AddressSize]byte

type endpoint struct {
	nicid         tcpip.NICID
	id            stack.NetworkEndpointID
	address       address
	linkEP        stack.LinkEndpoint
	linkAddrCache stack.LinkAddressCache
	dispatcher    stack.TransportDispatcher
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
func (e *endpoint) MTU() uint32 {
	return calculateMTU(e.linkEP.MTU())
}

// NICID returns the ID of the NIC this endpoint belongs to.
func (e *endpoint) NICID() tcpip.NICID {
	return e.nicid
}

// ID returns the ipv6 endpoint ID.
func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &e.id
}

// Capabilities implements stack.NetworkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.linkEP.Capabilities()
}

// MaxHeaderLength returns the maximum length needed by ipv6 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.IPv6MinimumSize
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.TransportProtocolNumber) *tcpip.Error {
	length := uint16(hdr.UsedLength() + payload.Size())
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: length,
		NextHeader:    uint8(protocol),
		HopLimit:      defaultIPv6HopLimit,
		SrcAddr:       tcpip.Address(e.address[:]),
		DstAddr:       r.RemoteAddress,
	})
	r.Stats().IP.PacketsSent.Increment()

	return e.linkEP.WritePacket(r, hdr, payload, ProtocolNumber)
}

// HandlePacket is called by the link layer when new ipv6 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, vv *buffer.VectorisedView) {
	h := header.IPv6(vv.First())
	if !h.IsValid(vv.Size()) {
		return
	}

	vv.TrimFront(header.IPv6MinimumSize)
	vv.CapLength(int(h.PayloadLength()))

	p := h.TransportProtocol()
	if p == header.ICMPv6ProtocolNumber {
		e.handleICMP(r, vv)
		return
	}

	r.Stats().IP.PacketsDelivered.Increment()
	e.dispatcher.DeliverTransportPacket(r, p, vv)
}

// Close cleans up resources associated with the endpoint.
func (*endpoint) Close() {}

type protocol struct{}

// NewProtocol creates a new protocol ipv6 protocol descriptor. This is exported
// only for tests that short-circuit the stack. Regular use of the protocol is
// done via the stack, which gets a protocol descriptor from the init() function
// below.
func NewProtocol() stack.NetworkProtocol {
	return &protocol{}
}

// Number returns the ipv6 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv6 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv6MinimumSize
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv6(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// NewEndpoint creates a new ipv6 endpoint.
func (p *protocol) NewEndpoint(nicid tcpip.NICID, addr tcpip.Address, linkAddrCache stack.LinkAddressCache, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	e := &endpoint{
		nicid:         nicid,
		linkEP:        linkEP,
		linkAddrCache: linkAddrCache,
		dispatcher:    dispatcher,
	}
	copy(e.address[:], addr)
	e.id = stack.NetworkEndpointID{LocalAddress: tcpip.Address(e.address[:])}
	return e, nil
}

// SetOption implements NetworkProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Option implements NetworkProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// calculateMTU calculates the network-layer payload MTU based on the link-layer
// payload mtu.
func calculateMTU(mtu uint32) uint32 {
	mtu -= header.IPv6MinimumSize
	if mtu <= maxPayloadSize {
		return mtu
	}
	return maxPayloadSize
}

func init() {
	stack.RegisterNetworkProtocolFactory(ProtocolName, func() stack.NetworkProtocol {
		return &protocol{}
	})
}
