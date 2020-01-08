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

// Package ipv6 contains the implementation of the ipv6 network protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing ipv6.NewProtocol() as one of the network
// protocols when calling stack.New(). Then endpoints can be created by passing
// ipv6.ProtocolNumber as the network protocol number when calling
// Stack.NewEndpoint().
package ipv6

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// ProtocolNumber is the ipv6 protocol number.
	ProtocolNumber = header.IPv6ProtocolNumber

	// maxTotalSize is maximum size that can be encoded in the 16-bit
	// PayloadLength field of the ipv6 header.
	maxPayloadSize = 0xffff

	// DefaultTTL is the default hop limit for IPv6 Packets egressed by
	// Netstack.
	DefaultTTL = 64
)

type endpoint struct {
	nicID         tcpip.NICID
	id            stack.NetworkEndpointID
	prefixLen     int
	linkEP        stack.LinkEndpoint
	linkAddrCache stack.LinkAddressCache
	dispatcher    stack.TransportDispatcher
	protocol      *protocol
}

// DefaultTTL is the default hop limit for this endpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
func (e *endpoint) MTU() uint32 {
	return calculateMTU(e.linkEP.MTU())
}

// NICID returns the ID of the NIC this endpoint belongs to.
func (e *endpoint) NICID() tcpip.NICID {
	return e.nicID
}

// ID returns the ipv6 endpoint ID.
func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &e.id
}

// PrefixLen returns the ipv6 endpoint subnet prefix length in bits.
func (e *endpoint) PrefixLen() int {
	return e.prefixLen
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

// GSOMaxSize returns the maximum GSO packet size.
func (e *endpoint) GSOMaxSize() uint32 {
	if gso, ok := e.linkEP.(stack.GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

func (e *endpoint) addIPHeader(r *stack.Route, hdr *buffer.Prependable, payloadSize int, params stack.NetworkHeaderParams) header.IPv6 {
	length := uint16(hdr.UsedLength() + payloadSize)
	ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: length,
		NextHeader:    uint8(params.Protocol),
		HopLimit:      params.TTL,
		TrafficClass:  params.TOS,
		SrcAddr:       r.LocalAddress,
		DstAddr:       r.RemoteAddress,
	})
	return ip
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, params stack.NetworkHeaderParams, pkt tcpip.PacketBuffer) *tcpip.Error {
	ip := e.addIPHeader(r, &pkt.Header, pkt.Data.Size(), params)
	pkt.NetworkHeader = buffer.View(ip)

	if r.Loop&stack.PacketLoop != 0 {
		// The inbound path expects the network header to still be in
		// the PacketBuffer's Data field.
		views := make([]buffer.View, 1, 1+len(pkt.Data.Views()))
		views[0] = pkt.Header.View()
		views = append(views, pkt.Data.Views()...)
		loopedR := r.MakeLoopedRoute()

		e.HandlePacket(&loopedR, tcpip.PacketBuffer{
			Data: buffer.NewVectorisedView(len(views[0])+pkt.Data.Size(), views),
		})

		loopedR.Release()
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}

	r.Stats().IP.PacketsSent.Increment()
	return e.linkEP.WritePacket(r, gso, ProtocolNumber, pkt)
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts []tcpip.PacketBuffer, params stack.NetworkHeaderParams) (int, *tcpip.Error) {
	if r.Loop&stack.PacketLoop != 0 {
		panic("not implemented")
	}
	if r.Loop&stack.PacketOut == 0 {
		return len(pkts), nil
	}

	for i := range pkts {
		hdr := &pkts[i].Header
		size := pkts[i].DataSize
		ip := e.addIPHeader(r, hdr, size, params)
		pkts[i].NetworkHeader = buffer.View(ip)
	}

	n, err := e.linkEP.WritePackets(r, gso, pkts, ProtocolNumber)
	r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
	return n, err
}

// WriteHeaderIncludedPacker implements stack.NetworkEndpoint. It is not yet
// supported by IPv6.
func (*endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt tcpip.PacketBuffer) *tcpip.Error {
	// TODO(b/146666412): Support IPv6 header-included packets.
	return tcpip.ErrNotSupported
}

// HandlePacket is called by the link layer when new ipv6 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, pkt tcpip.PacketBuffer) {
	headerView := pkt.Data.First()
	h := header.IPv6(headerView)
	if !h.IsValid(pkt.Data.Size()) {
		return
	}

	pkt.NetworkHeader = headerView[:header.IPv6MinimumSize]
	pkt.Data.TrimFront(header.IPv6MinimumSize)
	pkt.Data.CapLength(int(h.PayloadLength()))

	p := h.TransportProtocol()
	if p == header.ICMPv6ProtocolNumber {
		e.handleICMP(r, headerView, pkt)
		return
	}

	r.Stats().IP.PacketsDelivered.Increment()
	e.dispatcher.DeliverTransportPacket(r, p, pkt)
}

// Close cleans up resources associated with the endpoint.
func (*endpoint) Close() {}

type protocol struct {
	// defaultTTL is the current default TTL for the protocol. Only the
	// uint8 portion of it is meaningful and it must be accessed
	// atomically.
	defaultTTL uint32
}

// Number returns the ipv6 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv6 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv6MinimumSize
}

// DefaultPrefixLen returns the IPv6 default prefix length.
func (p *protocol) DefaultPrefixLen() int {
	return header.IPv6AddressSize * 8
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv6(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// NewEndpoint creates a new ipv6 endpoint.
func (p *protocol) NewEndpoint(nicID tcpip.NICID, addrWithPrefix tcpip.AddressWithPrefix, linkAddrCache stack.LinkAddressCache, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	return &endpoint{
		nicID:         nicID,
		id:            stack.NetworkEndpointID{LocalAddress: addrWithPrefix.Address},
		prefixLen:     addrWithPrefix.PrefixLen,
		linkEP:        linkEP,
		linkAddrCache: linkAddrCache,
		dispatcher:    dispatcher,
		protocol:      p,
	}, nil
}

// SetOption implements NetworkProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case tcpip.DefaultTTLOption:
		p.SetDefaultTTL(uint8(v))
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Option implements NetworkProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		*v = tcpip.DefaultTTLOption(p.DefaultTTL())
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// SetDefaultTTL sets the default TTL for endpoints created with this protocol.
func (p *protocol) SetDefaultTTL(ttl uint8) {
	atomic.StoreUint32(&p.defaultTTL, uint32(ttl))
}

// DefaultTTL returns the default TTL for endpoints created with this protocol.
func (p *protocol) DefaultTTL() uint8 {
	return uint8(atomic.LoadUint32(&p.defaultTTL))
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

// NewProtocol returns an IPv6 network protocol.
func NewProtocol() stack.NetworkProtocol {
	return &protocol{defaultTTL: DefaultTTL}
}
