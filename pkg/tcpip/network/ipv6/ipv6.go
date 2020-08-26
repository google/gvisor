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
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/fragmentation"
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
	linkEP        stack.LinkEndpoint
	linkAddrCache stack.LinkAddressCache
	nud           stack.NUDHandler
	dispatcher    stack.TransportDispatcher
	protocol      *protocol
	stack         *stack.Stack
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

func (e *endpoint) addIPHeader(r *stack.Route, pkt *stack.PacketBuffer, params stack.NetworkHeaderParams) {
	length := uint16(pkt.Size())
	ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		PayloadLength: length,
		NextHeader:    uint8(params.Protocol),
		HopLimit:      params.TTL,
		TrafficClass:  params.TOS,
		SrcAddr:       r.LocalAddress,
		DstAddr:       r.RemoteAddress,
	})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) *tcpip.Error {
	e.addIPHeader(r, pkt, params)

	if r.Loop&stack.PacketLoop != 0 {
		loopedR := r.MakeLoopedRoute()

		e.HandlePacket(&loopedR, stack.NewPacketBuffer(stack.PacketBufferOptions{
			// The inbound path expects an unparsed packet.
			Data: buffer.NewVectorisedView(pkt.Size(), pkt.Views()),
		}))

		loopedR.Release()
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}

	r.Stats().IP.PacketsSent.Increment()
	return e.linkEP.WritePacket(r, gso, ProtocolNumber, pkt)
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, params stack.NetworkHeaderParams) (int, *tcpip.Error) {
	if r.Loop&stack.PacketLoop != 0 {
		panic("not implemented")
	}
	if r.Loop&stack.PacketOut == 0 {
		return pkts.Len(), nil
	}

	for pb := pkts.Front(); pb != nil; pb = pb.Next() {
		e.addIPHeader(r, pb, params)
	}

	n, err := e.linkEP.WritePackets(r, gso, pkts, ProtocolNumber)
	r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
	return n, err
}

// WriteHeaderIncludedPacker implements stack.NetworkEndpoint. It is not yet
// supported by IPv6.
func (*endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) *tcpip.Error {
	// TODO(b/146666412): Support IPv6 header-included packets.
	return tcpip.ErrNotSupported
}

// HandlePacket is called by the link layer when new ipv6 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, pkt *stack.PacketBuffer) {
	h := header.IPv6(pkt.NetworkHeader().View())
	if !h.IsValid(pkt.Data.Size() + pkt.NetworkHeader().View().Size() + pkt.TransportHeader().View().Size()) {
		r.Stats().IP.MalformedPacketsReceived.Increment()
		return
	}

	// vv consists of:
	// - Any IPv6 header bytes after the first 40 (i.e. extensions).
	// - The transport header, if present.
	// - Any other payload data.
	vv := pkt.NetworkHeader().View()[header.IPv6MinimumSize:].ToVectorisedView()
	vv.AppendView(pkt.TransportHeader().View())
	vv.Append(pkt.Data)
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(h.NextHeader()), vv)
	hasFragmentHeader := false

	for firstHeader := true; ; firstHeader = false {
		extHdr, done, err := it.Next()
		if err != nil {
			r.Stats().IP.MalformedPacketsReceived.Increment()
			return
		}
		if done {
			break
		}

		switch extHdr := extHdr.(type) {
		case header.IPv6HopByHopOptionsExtHdr:
			// As per RFC 8200 section 4.1, the Hop By Hop extension header is
			// restricted to appear immediately after an IPv6 fixed header.
			//
			// TODO(b/152019344): Send an ICMPv6 Parameter Problem, Code 1
			// (unrecognized next header) error in response to an extension header's
			// Next Header field with the Hop By Hop extension header identifier.
			if !firstHeader {
				return
			}

			optsIt := extHdr.Iter()

			for {
				opt, done, err := optsIt.Next()
				if err != nil {
					r.Stats().IP.MalformedPacketsReceived.Increment()
					return
				}
				if done {
					break
				}

				// We currently do not support any IPv6 Hop By Hop extension header
				// options.
				switch opt.UnknownAction() {
				case header.IPv6OptionUnknownActionSkip:
				case header.IPv6OptionUnknownActionDiscard:
					return
				case header.IPv6OptionUnknownActionDiscardSendICMP:
					// TODO(b/152019344): Send an ICMPv6 Parameter Problem Code 2 for
					// unrecognized IPv6 extension header options.
					return
				case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
					// TODO(b/152019344): Send an ICMPv6 Parameter Problem Code 2 for
					// unrecognized IPv6 extension header options.
					return
				default:
					panic(fmt.Sprintf("unrecognized action for an unrecognized Hop By Hop extension header option = %d", opt))
				}
			}

		case header.IPv6RoutingExtHdr:
			// As per RFC 8200 section 4.4, if a node encounters a routing header with
			// an unrecognized routing type value, with a non-zero Segments Left
			// value, the node must discard the packet and send an ICMP Parameter
			// Problem, Code 0. If the Segments Left is 0, the node must ignore the
			// Routing extension header and process the next header in the packet.
			//
			// Note, the stack does not yet handle any type of routing extension
			// header, so we just make sure Segments Left is zero before processing
			// the next extension header.
			//
			// TODO(b/152019344): Send an ICMPv6 Parameter Problem Code 0 for
			// unrecognized routing types with a non-zero Segments Left value.
			if extHdr.SegmentsLeft() != 0 {
				return
			}

		case header.IPv6FragmentExtHdr:
			hasFragmentHeader = true

			if extHdr.IsAtomic() {
				// This fragment extension header indicates that this packet is an
				// atomic fragment. An atomic fragment is a fragment that contains
				// all the data required to reassemble a full packet. As per RFC 6946,
				// atomic fragments must not interfere with "normal" fragmented traffic
				// so we skip processing the fragment instead of feeding it through the
				// reassembly process below.
				continue
			}

			// Don't consume the iterator if we have the first fragment because we
			// will use it to validate that the first fragment holds the upper layer
			// header.
			rawPayload := it.AsRawHeader(extHdr.FragmentOffset() != 0 /* consume */)

			if extHdr.FragmentOffset() == 0 {
				// Check that the iterator ends with a raw payload as the first fragment
				// should include all headers up to and including any upper layer
				// headers, as per RFC 8200 section 4.5; only upper layer data
				// (non-headers) should follow the fragment extension header.
				var lastHdr header.IPv6PayloadHeader

				for {
					it, done, err := it.Next()
					if err != nil {
						r.Stats().IP.MalformedPacketsReceived.Increment()
						r.Stats().IP.MalformedPacketsReceived.Increment()
						return
					}
					if done {
						break
					}

					lastHdr = it
				}

				// If the last header is a raw header, then the last portion of the IPv6
				// payload is not a known IPv6 extension header. Note, this does not
				// mean that the last portion is an upper layer header or not an
				// extension header because:
				//  1) we do not yet support all extension headers
				//  2) we do not validate the upper layer header before reassembling.
				//
				// This check makes sure that a known IPv6 extension header is not
				// present after the Fragment extension header in a non-initial
				// fragment.
				//
				// TODO(#2196): Support IPv6 Authentication and Encapsulated
				// Security Payload extension headers.
				// TODO(#2333): Validate that the upper layer header is valid.
				switch lastHdr.(type) {
				case header.IPv6RawPayloadHeader:
				default:
					r.Stats().IP.MalformedPacketsReceived.Increment()
					r.Stats().IP.MalformedFragmentsReceived.Increment()
					return
				}
			}

			fragmentPayloadLen := rawPayload.Buf.Size()
			if fragmentPayloadLen == 0 {
				// Drop the packet as it's marked as a fragment but has no payload.
				r.Stats().IP.MalformedPacketsReceived.Increment()
				r.Stats().IP.MalformedFragmentsReceived.Increment()
				return
			}

			// The packet is a fragment, let's try to reassemble it.
			start := extHdr.FragmentOffset() * header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit
			last := start + uint16(fragmentPayloadLen) - 1

			// Drop the packet if the fragmentOffset is incorrect. i.e the
			// combination of fragmentOffset and pkt.Data.size() causes a
			// wrap around resulting in last being less than the offset.
			if last < start {
				r.Stats().IP.MalformedPacketsReceived.Increment()
				r.Stats().IP.MalformedFragmentsReceived.Increment()
				return
			}

			// Note that pkt doesn't have its transport header set after reassembly,
			// and won't until DeliverNetworkPacket sets it.
			data, proto, ready, err := e.protocol.fragmentation.Process(
				// IPv6 ignores the Protocol field since the ID only needs to be unique
				// across source-destination pairs, as per RFC 8200 section 4.5.
				fragmentation.FragmentID{
					Source:      h.SourceAddress(),
					Destination: h.DestinationAddress(),
					ID:          extHdr.ID(),
				},
				start,
				last,
				extHdr.More(),
				uint8(rawPayload.Identifier),
				rawPayload.Buf,
			)
			if err != nil {
				r.Stats().IP.MalformedPacketsReceived.Increment()
				r.Stats().IP.MalformedFragmentsReceived.Increment()
				return
			}
			pkt.Data = data

			if ready {
				// We create a new iterator with the reassembled packet because we could
				// have more extension headers in the reassembled payload, as per RFC
				// 8200 section 4.5. We also use the NextHeader value from the first
				// fragment.
				it = header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(proto), pkt.Data)
			}

		case header.IPv6DestinationOptionsExtHdr:
			optsIt := extHdr.Iter()

			for {
				opt, done, err := optsIt.Next()
				if err != nil {
					r.Stats().IP.MalformedPacketsReceived.Increment()
					return
				}
				if done {
					break
				}

				// We currently do not support any IPv6 Destination extension header
				// options.
				switch opt.UnknownAction() {
				case header.IPv6OptionUnknownActionSkip:
				case header.IPv6OptionUnknownActionDiscard:
					return
				case header.IPv6OptionUnknownActionDiscardSendICMP:
					// TODO(b/152019344): Send an ICMPv6 Parameter Problem Code 2 for
					// unrecognized IPv6 extension header options.
					return
				case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
					// TODO(b/152019344): Send an ICMPv6 Parameter Problem Code 2 for
					// unrecognized IPv6 extension header options.
					return
				default:
					panic(fmt.Sprintf("unrecognized action for an unrecognized Destination extension header option = %d", opt))
				}
			}

		case header.IPv6RawPayloadHeader:
			// If the last header in the payload isn't a known IPv6 extension header,
			// handle it as if it is transport layer data.

			// For unfragmented packets, extHdr still contains the transport header.
			// Get rid of it.
			//
			// For reassembled fragments, pkt.TransportHeader is unset, so this is a
			// no-op and pkt.Data begins with the transport header.
			extHdr.Buf.TrimFront(pkt.TransportHeader().View().Size())
			pkt.Data = extHdr.Buf

			if p := tcpip.TransportProtocolNumber(extHdr.Identifier); p == header.ICMPv6ProtocolNumber {
				pkt.TransportProtocolNumber = p
				e.handleICMP(r, pkt, hasFragmentHeader)
			} else {
				r.Stats().IP.PacketsDelivered.Increment()
				// TODO(b/152019344): Send an ICMPv6 Parameter Problem, Code 1 error
				// in response to unrecognized next header values.
				e.dispatcher.DeliverTransportPacket(r, p, pkt)
			}

		default:
			// If we receive a packet for an extension header we do not yet handle,
			// drop the packet for now.
			//
			// TODO(b/152019344): Send an ICMPv6 Parameter Problem, Code 1 error
			// in response to unrecognized next header values.
			r.Stats().UnknownProtocolRcvdPackets.Increment()
			return
		}
	}
}

// Close cleans up resources associated with the endpoint.
func (*endpoint) Close() {}

// NetworkProtocolNumber implements stack.NetworkEndpoint.NetworkProtocolNumber.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

type protocol struct {
	// defaultTTL is the current default TTL for the protocol. Only the
	// uint8 portion of it is meaningful and it must be accessed
	// atomically.
	defaultTTL    uint32
	fragmentation *fragmentation.Fragmentation
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
func (p *protocol) NewEndpoint(nicID tcpip.NICID, linkAddrCache stack.LinkAddressCache, nud stack.NUDHandler, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint, st *stack.Stack) stack.NetworkEndpoint {
	return &endpoint{
		nicID:         nicID,
		linkEP:        linkEP,
		linkAddrCache: linkAddrCache,
		nud:           nud,
		dispatcher:    dispatcher,
		protocol:      p,
		stack:         st,
	}
}

// SetOption implements NetworkProtocol.SetOption.
func (p *protocol) SetOption(option tcpip.SettableNetworkProtocolOption) *tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		p.SetDefaultTTL(uint8(*v))
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Option implements NetworkProtocol.Option.
func (p *protocol) Option(option tcpip.GettableNetworkProtocolOption) *tcpip.Error {
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

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// Parse implements stack.TransportProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	hdr, ok := pkt.Data.PullUp(header.IPv6MinimumSize)
	if !ok {
		return 0, false, false
	}
	ipHdr := header.IPv6(hdr)

	// dataClone consists of:
	// - Any IPv6 header bytes after the first 40 (i.e. extensions).
	// - The transport header, if present.
	// - Any other payload data.
	views := [8]buffer.View{}
	dataClone := pkt.Data.Clone(views[:])
	dataClone.TrimFront(header.IPv6MinimumSize)
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(ipHdr.NextHeader()), dataClone)

	// Iterate over the IPv6 extensions to find their length.
	//
	// Parsing occurs again in HandlePacket because we don't track the
	// extensions in PacketBuffer. Unfortunately, that means HandlePacket
	// has to do the parsing work again.
	var nextHdr tcpip.TransportProtocolNumber
	foundNext := true
	extensionsSize := 0
traverseExtensions:
	for extHdr, done, err := it.Next(); ; extHdr, done, err = it.Next() {
		if err != nil {
			break
		}
		// If we exhaust the extension list, the entire packet is the IPv6 header
		// and (possibly) extensions.
		if done {
			extensionsSize = dataClone.Size()
			foundNext = false
			break
		}

		switch extHdr := extHdr.(type) {
		case header.IPv6FragmentExtHdr:
			// If this is an atomic fragment, we don't have to treat it specially.
			if !extHdr.More() && extHdr.FragmentOffset() == 0 {
				continue
			}
			// This is a non-atomic fragment and has to be re-assembled before we can
			// examine the payload for a transport header.
			foundNext = false

		case header.IPv6RawPayloadHeader:
			// We've found the payload after any extensions.
			extensionsSize = dataClone.Size() - extHdr.Buf.Size()
			nextHdr = tcpip.TransportProtocolNumber(extHdr.Identifier)
			break traverseExtensions

		default:
			// Any other extension is a no-op, keep looping until we find the payload.
		}
	}

	// Put the IPv6 header with extensions in pkt.NetworkHeader().
	hdr, ok = pkt.NetworkHeader().Consume(header.IPv6MinimumSize + extensionsSize)
	if !ok {
		panic(fmt.Sprintf("pkt.Data should have at least %d bytes, but only has %d.", header.IPv6MinimumSize+extensionsSize, pkt.Data.Size()))
	}
	ipHdr = header.IPv6(hdr)
	pkt.Data.CapLength(int(ipHdr.PayloadLength()))
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber

	return nextHdr, foundNext, true
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
	return &protocol{
		defaultTTL:    DefaultTTL,
		fragmentation: fragmentation.NewFragmentation(header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, fragmentation.DefaultReassembleTimeout),
	}
}
