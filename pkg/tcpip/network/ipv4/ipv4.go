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

// Package ipv4 contains the implementation of the ipv4 network protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing ipv4.NewProtocol() as one of the network
// protocols when calling stack.New(). Then endpoints can be created by passing
// ipv4.ProtocolNumber as the network protocol number when calling
// Stack.NewEndpoint().
package ipv4

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/fragmentation"
	"gvisor.dev/gvisor/pkg/tcpip/network/hash"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// ProtocolNumber is the ipv4 protocol number.
	ProtocolNumber = header.IPv4ProtocolNumber

	// MaxTotalSize is maximum size that can be encoded in the 16-bit
	// TotalLength field of the ipv4 header.
	MaxTotalSize = 0xffff

	// DefaultTTL is the default time-to-live value for this endpoint.
	DefaultTTL = 64

	// buckets is the number of identifier buckets.
	buckets = 2048
)

type endpoint struct {
	nicID         tcpip.NICID
	id            stack.NetworkEndpointID
	prefixLen     int
	linkEP        stack.LinkEndpoint
	dispatcher    stack.TransportDispatcher
	fragmentation *fragmentation.Fragmentation
	protocol      *protocol
	stack         *stack.Stack
}

// NewEndpoint creates a new ipv4 endpoint.
func (p *protocol) NewEndpoint(nicID tcpip.NICID, addrWithPrefix tcpip.AddressWithPrefix, linkAddrCache stack.LinkAddressCache, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint, st *stack.Stack) (stack.NetworkEndpoint, *tcpip.Error) {
	e := &endpoint{
		nicID:         nicID,
		id:            stack.NetworkEndpointID{LocalAddress: addrWithPrefix.Address},
		prefixLen:     addrWithPrefix.PrefixLen,
		linkEP:        linkEP,
		dispatcher:    dispatcher,
		fragmentation: fragmentation.NewFragmentation(fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, fragmentation.DefaultReassembleTimeout),
		protocol:      p,
		stack:         st,
	}

	return e, nil
}

// DefaultTTL is the default time-to-live value for this endpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
func (e *endpoint) MTU() uint32 {
	return calculateMTU(e.linkEP.MTU())
}

// Capabilities implements stack.NetworkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.linkEP.Capabilities()
}

// NICID returns the ID of the NIC this endpoint belongs to.
func (e *endpoint) NICID() tcpip.NICID {
	return e.nicID
}

// ID returns the ipv4 endpoint ID.
func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &e.id
}

// PrefixLen returns the ipv4 endpoint subnet prefix length in bits.
func (e *endpoint) PrefixLen() int {
	return e.prefixLen
}

// MaxHeaderLength returns the maximum length needed by ipv4 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.IPv4MinimumSize
}

// GSOMaxSize returns the maximum GSO packet size.
func (e *endpoint) GSOMaxSize() uint32 {
	if gso, ok := e.linkEP.(stack.GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

// NetworkProtocolNumber implements stack.NetworkEndpoint.NetworkProtocolNumber.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

// writePacketFragments calls e.linkEP.WritePacket with each packet fragment to
// write. It assumes that the IP header is entirely in pkt.Header but does not
// assume that only the IP header is in pkt.Header. It assumes that the input
// packet's stated length matches the length of the header+payload. mtu
// includes the IP header and options. This does not support the DontFragment
// IP flag.
func (e *endpoint) writePacketFragments(r *stack.Route, gso *stack.GSO, mtu int, pkt stack.PacketBuffer) *tcpip.Error {
	// This packet is too big, it needs to be fragmented.
	ip := header.IPv4(pkt.Header.View())
	flags := ip.Flags()

	// Update mtu to take into account the header, which will exist in all
	// fragments anyway.
	innerMTU := mtu - int(ip.HeaderLength())

	// Round the MTU down to align to 8 bytes. Then calculate the number of
	// fragments. Calculate fragment sizes as in RFC791.
	innerMTU &^= 7
	n := (int(ip.PayloadLength()) + innerMTU - 1) / innerMTU

	outerMTU := innerMTU + int(ip.HeaderLength())
	offset := ip.FragmentOffset()
	originalAvailableLength := pkt.Header.AvailableLength()
	for i := 0; i < n; i++ {
		// Where possible, the first fragment that is sent has the same
		// pkt.Header.UsedLength() as the input packet. The link-layer
		// endpoint may depend on this for looking at, eg, L4 headers.
		h := ip
		if i > 0 {
			pkt.Header = buffer.NewPrependable(int(ip.HeaderLength()) + originalAvailableLength)
			h = header.IPv4(pkt.Header.Prepend(int(ip.HeaderLength())))
			copy(h, ip[:ip.HeaderLength()])
		}
		if i != n-1 {
			h.SetTotalLength(uint16(outerMTU))
			h.SetFlagsFragmentOffset(flags|header.IPv4FlagMoreFragments, offset)
		} else {
			h.SetTotalLength(uint16(h.HeaderLength()) + uint16(pkt.Data.Size()))
			h.SetFlagsFragmentOffset(flags, offset)
		}
		h.SetChecksum(0)
		h.SetChecksum(^h.CalculateChecksum())
		offset += uint16(innerMTU)
		if i > 0 {
			newPayload := pkt.Data.Clone(nil)
			newPayload.CapLength(innerMTU)
			if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, stack.PacketBuffer{
				Header:        pkt.Header,
				Data:          newPayload,
				NetworkHeader: buffer.View(h),
			}); err != nil {
				return err
			}
			r.Stats().IP.PacketsSent.Increment()
			pkt.Data.TrimFront(newPayload.Size())
			continue
		}
		// Special handling for the first fragment because it comes
		// from the header.
		if outerMTU >= pkt.Header.UsedLength() {
			// This fragment can fit all of pkt.Header and possibly
			// some of pkt.Data, too.
			newPayload := pkt.Data.Clone(nil)
			newPayloadLength := outerMTU - pkt.Header.UsedLength()
			newPayload.CapLength(newPayloadLength)
			if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, stack.PacketBuffer{
				Header:        pkt.Header,
				Data:          newPayload,
				NetworkHeader: buffer.View(h),
			}); err != nil {
				return err
			}
			r.Stats().IP.PacketsSent.Increment()
			pkt.Data.TrimFront(newPayloadLength)
		} else {
			// The fragment is too small to fit all of pkt.Header.
			startOfHdr := pkt.Header
			startOfHdr.TrimBack(pkt.Header.UsedLength() - outerMTU)
			emptyVV := buffer.NewVectorisedView(0, []buffer.View{})
			if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, stack.PacketBuffer{
				Header:        startOfHdr,
				Data:          emptyVV,
				NetworkHeader: buffer.View(h),
			}); err != nil {
				return err
			}
			r.Stats().IP.PacketsSent.Increment()
			// Add the unused bytes of pkt.Header into the pkt.Data
			// that remains to be sent.
			restOfHdr := pkt.Header.View()[outerMTU:]
			tmp := buffer.NewVectorisedView(len(restOfHdr), []buffer.View{buffer.NewViewFromBytes(restOfHdr)})
			tmp.Append(pkt.Data)
			pkt.Data = tmp
		}
	}
	return nil
}

func (e *endpoint) addIPHeader(r *stack.Route, hdr *buffer.Prependable, payloadSize int, params stack.NetworkHeaderParams) header.IPv4 {
	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	length := uint16(hdr.UsedLength() + payloadSize)
	id := uint32(0)
	if length > header.IPv4MaximumHeaderSize+8 {
		// Packets of 68 bytes or less are required by RFC 791 to not be
		// fragmented, so we only assign ids to larger packets.
		id = atomic.AddUint32(&e.protocol.ids[hashRoute(r, params.Protocol, e.protocol.hashIV)%buckets], 1)
	}
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: length,
		ID:          uint16(id),
		TTL:         params.TTL,
		TOS:         params.TOS,
		Protocol:    uint8(params.Protocol),
		SrcAddr:     r.LocalAddress,
		DstAddr:     r.RemoteAddress,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return ip
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, params stack.NetworkHeaderParams, pkt stack.PacketBuffer) *tcpip.Error {
	ip := e.addIPHeader(r, &pkt.Header, pkt.Data.Size(), params)
	pkt.NetworkHeader = buffer.View(ip)

	nicName := e.stack.FindNICNameFromID(e.NICID())
	// iptables filtering. All packets that reach here are locally
	// generated.
	ipt := e.stack.IPTables()
	if ok := ipt.Check(stack.Output, &pkt, gso, r, "", nicName); !ok {
		// iptables is telling us to drop the packet.
		return nil
	}

	if pkt.NatDone {
		// If the packet is manipulated as per NAT Ouput rules, handle packet
		// based on destination address and do not send the packet to link layer.
		netHeader := header.IPv4(pkt.NetworkHeader)
		ep, err := e.stack.FindNetworkEndpoint(header.IPv4ProtocolNumber, netHeader.DestinationAddress())
		if err == nil {
			src := netHeader.SourceAddress()
			dst := netHeader.DestinationAddress()
			route := r.ReverseRoute(src, dst)

			views := make([]buffer.View, 1, 1+len(pkt.Data.Views()))
			views[0] = pkt.Header.View()
			views = append(views, pkt.Data.Views()...)
			packet := stack.PacketBuffer{
				Data: buffer.NewVectorisedView(len(views[0])+pkt.Data.Size(), views)}
			ep.HandlePacket(&route, packet)
			return nil
		}
	}

	if r.Loop&stack.PacketLoop != 0 {
		// The inbound path expects the network header to still be in
		// the PacketBuffer's Data field.
		views := make([]buffer.View, 1, 1+len(pkt.Data.Views()))
		views[0] = pkt.Header.View()
		views = append(views, pkt.Data.Views()...)
		loopedR := r.MakeLoopedRoute()

		e.HandlePacket(&loopedR, stack.PacketBuffer{
			Data: buffer.NewVectorisedView(len(views[0])+pkt.Data.Size(), views),
		})

		loopedR.Release()
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}
	if pkt.Header.UsedLength()+pkt.Data.Size() > int(e.linkEP.MTU()) && (gso == nil || gso.Type == stack.GSONone) {
		return e.writePacketFragments(r, gso, int(e.linkEP.MTU()), pkt)
	}
	if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
		return err
	}
	r.Stats().IP.PacketsSent.Increment()
	return nil
}

// WritePackets implements stack.NetworkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, params stack.NetworkHeaderParams) (int, *tcpip.Error) {
	if r.Loop&stack.PacketLoop != 0 {
		panic("multiple packets in local loop")
	}
	if r.Loop&stack.PacketOut == 0 {
		return pkts.Len(), nil
	}

	for pkt := pkts.Front(); pkt != nil; {
		ip := e.addIPHeader(r, &pkt.Header, pkt.Data.Size(), params)
		pkt.NetworkHeader = buffer.View(ip)
		pkt = pkt.Next()
	}

	nicName := e.stack.FindNICNameFromID(e.NICID())
	// iptables filtering. All packets that reach here are locally
	// generated.
	ipt := e.stack.IPTables()
	dropped, natPkts := ipt.CheckPackets(stack.Output, pkts, gso, r, nicName)
	if len(dropped) == 0 && len(natPkts) == 0 {
		// Fast path: If no packets are to be dropped then we can just invoke the
		// faster WritePackets API directly.
		n, err := e.linkEP.WritePackets(r, gso, pkts, ProtocolNumber)
		r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
		return n, err
	}

	// Slow Path as we are dropping some packets in the batch degrade to
	// emitting one packet at a time.
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if _, ok := dropped[pkt]; ok {
			continue
		}
		if _, ok := natPkts[pkt]; ok {
			netHeader := header.IPv4(pkt.NetworkHeader)
			ep, err := e.stack.FindNetworkEndpoint(header.IPv4ProtocolNumber, netHeader.DestinationAddress())
			if err == nil {
				src := netHeader.SourceAddress()
				dst := netHeader.DestinationAddress()
				route := r.ReverseRoute(src, dst)

				views := make([]buffer.View, 1, 1+len(pkt.Data.Views()))
				views[0] = pkt.Header.View()
				views = append(views, pkt.Data.Views()...)
				packet := stack.PacketBuffer{
					Data: buffer.NewVectorisedView(len(views[0])+pkt.Data.Size(), views)}
				ep.HandlePacket(&route, packet)
				n++
				continue
			}
		}
		if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, *pkt); err != nil {
			r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
			return n, err
		}
		n++
	}
	r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
	return n, nil
}

// WriteHeaderIncludedPacket writes a packet already containing a network
// header through the given route.
func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt stack.PacketBuffer) *tcpip.Error {
	// The packet already has an IP header, but there are a few required
	// checks.
	h, ok := pkt.Data.PullUp(header.IPv4MinimumSize)
	if !ok {
		return tcpip.ErrInvalidOptionValue
	}
	ip := header.IPv4(h)
	if !ip.IsValid(pkt.Data.Size()) {
		return tcpip.ErrInvalidOptionValue
	}

	// Always set the total length.
	ip.SetTotalLength(uint16(pkt.Data.Size()))

	// Set the source address when zero.
	if ip.SourceAddress() == tcpip.Address(([]byte{0, 0, 0, 0})) {
		ip.SetSourceAddress(r.LocalAddress)
	}

	// Set the destination. If the packet already included a destination,
	// it will be part of the route.
	ip.SetDestinationAddress(r.RemoteAddress)

	// Set the packet ID when zero.
	if ip.ID() == 0 {
		id := uint32(0)
		if pkt.Data.Size() > header.IPv4MaximumHeaderSize+8 {
			// Packets of 68 bytes or less are required by RFC 791 to not be
			// fragmented, so we only assign ids to larger packets.
			id = atomic.AddUint32(&e.protocol.ids[hashRoute(r, 0 /* protocol */, e.protocol.hashIV)%buckets], 1)
		}
		ip.SetID(uint16(id))
	}

	// Always set the checksum.
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	if r.Loop&stack.PacketLoop != 0 {
		e.HandlePacket(r, pkt.Clone())
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}

	r.Stats().IP.PacketsSent.Increment()

	ip = ip[:ip.HeaderLength()]
	pkt.Header = buffer.NewPrependableFromView(buffer.View(ip))
	pkt.Data.TrimFront(int(ip.HeaderLength()))
	return e.linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, pkt)
}

// HandlePacket is called by the link layer when new ipv4 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, pkt stack.PacketBuffer) {
	headerView, ok := pkt.Data.PullUp(header.IPv4MinimumSize)
	if !ok {
		r.Stats().IP.MalformedPacketsReceived.Increment()
		return
	}
	h := header.IPv4(headerView)
	if !h.IsValid(pkt.Data.Size()) {
		r.Stats().IP.MalformedPacketsReceived.Increment()
		return
	}
	pkt.NetworkHeader = headerView[:h.HeaderLength()]

	hlen := int(h.HeaderLength())
	tlen := int(h.TotalLength())
	pkt.Data.TrimFront(hlen)
	pkt.Data.CapLength(tlen - hlen)

	// iptables filtering. All packets that reach here are intended for
	// this machine and will not be forwarded.
	ipt := e.stack.IPTables()
	if ok := ipt.Check(stack.Input, &pkt, nil, nil, "", ""); !ok {
		// iptables is telling us to drop the packet.
		return
	}

	more := (h.Flags() & header.IPv4FlagMoreFragments) != 0
	if more || h.FragmentOffset() != 0 {
		if pkt.Data.Size() == 0 {
			// Drop the packet as it's marked as a fragment but has
			// no payload.
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}
		// The packet is a fragment, let's try to reassemble it.
		last := h.FragmentOffset() + uint16(pkt.Data.Size()) - 1
		// Drop the packet if the fragmentOffset is incorrect. i.e the
		// combination of fragmentOffset and pkt.Data.size() causes a
		// wrap around resulting in last being less than the offset.
		if last < h.FragmentOffset() {
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}
		var ready bool
		var err error
		pkt.Data, ready, err = e.fragmentation.Process(hash.IPv4FragmentHash(h), h.FragmentOffset(), last, more, pkt.Data)
		if err != nil {
			r.Stats().IP.MalformedPacketsReceived.Increment()
			r.Stats().IP.MalformedFragmentsReceived.Increment()
			return
		}
		if !ready {
			return
		}
	}
	p := h.TransportProtocol()
	if p == header.ICMPv4ProtocolNumber {
		headerView.CapLength(hlen)
		e.handleICMP(r, pkt)
		return
	}
	r.Stats().IP.PacketsDelivered.Increment()
	e.dispatcher.DeliverTransportPacket(r, p, pkt)
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {}

type protocol struct {
	ids    []uint32
	hashIV uint32

	// defaultTTL is the current default TTL for the protocol. Only the
	// uint8 portion of it is meaningful and it must be accessed
	// atomically.
	defaultTTL uint32
}

// Number returns the ipv4 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv4 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv4MinimumSize
}

// DefaultPrefixLen returns the IPv4 default prefix length.
func (p *protocol) DefaultPrefixLen() int {
	return header.IPv4AddressSize * 8
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv4(v)
	return h.SourceAddress(), h.DestinationAddress()
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

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// calculateMTU calculates the network-layer payload MTU based on the link-layer
// payload mtu.
func calculateMTU(mtu uint32) uint32 {
	if mtu > MaxTotalSize {
		mtu = MaxTotalSize
	}
	return mtu - header.IPv4MinimumSize
}

// hashRoute calculates a hash value for the given route. It uses the source &
// destination address, the transport protocol number, and a random initial
// value (generated once on initialization) to generate the hash.
func hashRoute(r *stack.Route, protocol tcpip.TransportProtocolNumber, hashIV uint32) uint32 {
	t := r.LocalAddress
	a := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = r.RemoteAddress
	b := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return hash.Hash3Words(a, b, uint32(protocol), hashIV)
}

// NewProtocol returns an IPv4 network protocol.
func NewProtocol() stack.NetworkProtocol {
	ids := make([]uint32, buckets)

	// Randomly initialize hashIV and the ids.
	r := hash.RandN32(1 + buckets)
	for i := range ids {
		ids[i] = r[i]
	}
	hashIV := r[buckets]

	return &protocol{ids: ids, hashIV: hashIV, defaultTTL: DefaultTTL}
}
