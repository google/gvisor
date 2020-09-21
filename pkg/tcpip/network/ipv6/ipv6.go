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
	"sort"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
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

var _ stack.GroupAddressableEndpoint = (*endpoint)(nil)
var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)
var _ stack.NDPEndpoint = (*endpoint)(nil)
var _ NDPEndpoint = (*endpoint)(nil)

type endpoint struct {
	nic           stack.NetworkInterface
	linkEP        stack.LinkEndpoint
	linkAddrCache stack.LinkAddressCache
	nud           stack.NUDHandler
	dispatcher    stack.TransportDispatcher
	protocol      *protocol
	stack         *stack.Stack

	mu struct {
		sync.RWMutex

		enabled bool

		addressableEndpoint      *stack.AddressableEndpointState
		groupAddressableEndpoint *stack.GroupAddressableEndpointState
		ndp                      ndpState
	}
}

// NICNameFromID is a function that returns a stable name for the specified NIC,
// even if different NIC IDs are used to refer to the same NIC in different
// program runs. It is used when generating opaque interface identifiers (IIDs).
// If the NIC was created with a name, it will be passed to NICNameFromID.
//
// NICNameFromID SHOULD return unique NIC names so unique opaque IIDs are
// generated for the same prefix on differnt NICs.
type NICNameFromID func(tcpip.NICID, string) string

// OpaqueInterfaceIdentifierOptions holds the options related to the generation
// of opaque interface indentifiers (IIDs) as defined by RFC 7217.
type OpaqueInterfaceIdentifierOptions struct {
	// NICNameFromID is a function that returns a stable name for a specified NIC,
	// even if the NIC ID changes over time.
	//
	// Must be specified to generate the opaque IID.
	NICNameFromID NICNameFromID

	// SecretKey is a pseudo-random number used as the secret key when generating
	// opaque IIDs as defined by RFC 7217. The key SHOULD be at least
	// header.OpaqueIIDSecretKeyMinBytes bytes and MUST follow minimum randomness
	// requirements for security as outlined by RFC 4086. SecretKey MUST NOT
	// change between program runs, unless explicitly changed.
	//
	// OpaqueInterfaceIdentifierOptions takes ownership of SecretKey. SecretKey
	// MUST NOT be modified after Stack is created.
	//
	// May be nil, but a nil value is highly discouraged to maintain
	// some level of randomness between nodes.
	SecretKey []byte
}

// InvalidateDefaultRouter implements stack.NDPEndpoint.
func (e *endpoint) InvalidateDefaultRouter(rtr tcpip.Address) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mu.ndp.invalidateDefaultRouter(rtr)
}

// SetNDPConfigurations implements NDPEndpoint.
func (e *endpoint) SetNDPConfigurations(c NDPConfigurations) {
	c.validate()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mu.ndp.configs = c
}

// isAddrTentative returns true if addr is tentative on e.
//
// Note that if addr is not associated with e, then this function will return
// false. It will only return true if the address is associated with the NIC
// AND it is tentative.
func (e *endpoint) isAddrTentative(addr tcpip.Address) bool {
	e.mu.RLock()
	nep := e.getAddressRLocked(addr)
	e.mu.RUnlock()
	if nep == nil {
		return false
	}
	kind := nep.GetKind()
	return kind == stack.PermanentTentative
}

// dupTentativeAddrDetected attempts to inform e that a tentative addr is a
// duplicate on a link.
//
// dupTentativeAddrDetected will remove the tentative address if it exists. If
// the address was generated via SLAAC, an attempt will be made to generate a
// new address.
func (e *endpoint) dupTentativeAddrDetected(addr tcpip.Address) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	nep := e.getAddressRLocked(addr)
	if nep == nil {
		return tcpip.ErrBadAddress
	}

	if nep.GetKind() != stack.PermanentTentative {
		return tcpip.ErrInvalidEndpointState
	}

	// If the address is a SLAAC address, do not invalidate its SLAAC prefix as a
	// new address will be generated for it.
	if err := e.removePermanentEndpointLocked(nep, false /* allowSLAACInvalidation */); err != nil {
		return err
	}

	prefix := nep.AddressWithPrefix().Subnet()

	switch nep.ConfigType() {
	case stack.AddressConfigSlaac:
		e.mu.ndp.regenerateSLAACAddr(prefix)
	case stack.AddressConfigSlaacTemp:
		// Do not reset the generation attempts counter for the prefix as the
		// temporary address is being regenerated in response to a DAD conflict.
		e.mu.ndp.regenerateTempSLAACAddr(prefix, false /* resetGenAttempts */)
	}

	return nil
}

func (e *endpoint) setForwarding(forwarding bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if forwarding {
		// When transitioning into an IPv6 router, host-only state (NDP discovered
		// routers, discovered on-link prefixes, and auto-generated addresses) will
		// be cleaned up/invalidated and NDP router solicitations will be stopped.
		e.mu.ndp.stopSolicitingRouters()
		e.mu.ndp.cleanupState(true /* hostOnly */)
	} else {
		// When transitioning into an IPv6 host, NDP router solicitations will be
		// started.
		e.mu.ndp.startSolicitingRouters()
	}
}

// Enable implements stack.NetworkEndpoint.
func (e *endpoint) Enable() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.mu.enabled {
		return nil
	}

	e.mu.enabled = true

	// Join the IPv6 All-Nodes Multicast group if the stack is configured to
	// use IPv6. This is required to ensure that this node properly receives
	// and responds to the various NDP messages that are destined to the
	// all-nodes multicast address. An example is the Neighbor Advertisement
	// when we perform Duplicate Address Detection, or Router Advertisement
	// when we do Router Discovery. See RFC 4862, section 5.4.2 and RFC 4861
	// section 4.2 for more information.
	//
	// Also auto-generate an IPv6 link-local address based on the NIC's
	// link address if it is configured to do so. Note, each interface is
	// required to have IPv6 link-local unicast address, as per RFC 4291
	// section 2.1.

	// Join the All-Nodes multicast group before starting DAD as responses to DAD
	// (NDP NS) messages may be sent to the All-Nodes multicast group if the
	// source address of the NDP NS is the unspecified address, as per RFC 4861
	// section 7.2.4.
	if _, err := e.mu.groupAddressableEndpoint.JoinGroup(header.IPv6AllNodesMulticastAddress); err != nil {
		return err
	}

	// Perform DAD on the all the unicast IPv6 endpoints that are in the permanent
	// state.
	//
	// Addresses may have aleady completed DAD but in the time since the NIC was
	// last enabled, other devices may have acquired the same addresses.
	var err *tcpip.Error
	eps := e.mu.addressableEndpoint.ReadonlyAllEndpoints()
	eps.ForEach(func(_ tcpip.Address, r stack.AddressEndpoint) bool {
		addr := r.AddressWithPrefix().Address
		if k := r.GetKind(); (k != stack.Permanent && k != stack.PermanentTentative) || !header.IsV6UnicastAddress(addr) {
			return true
		}

		r.SetKind(stack.PermanentTentative)
		err = e.mu.ndp.startDuplicateAddressDetection(addr, r)
		return err == nil
	})
	eps.Release()
	if err != nil {
		return err
	}

	// Do not auto-generate an IPv6 link-local address for loopback devices.
	if e.protocol.autoGenIPv6LinkLocal /* && !e.nic.IsLoopback() */ {
		// The valid and preferred lifetime is infinite for the auto-generated
		// link-local address.
		e.mu.ndp.doSLAAC(header.IPv6LinkLocalPrefix.Subnet(), header.NDPInfiniteLifetime, header.NDPInfiniteLifetime)
	}

	// If we are operating as a router, then do not solicit routers since we
	// won't process the RAs anyways.
	//
	// Routers do not process Router Advertisements (RA) the same way a host
	// does. That is, routers do not learn from RAs (e.g. on-link prefixes
	// and default routers). Therefore, soliciting RAs from other routers on
	// a link is unnecessary for routers.
	if !e.protocol.Forwarding() {
		e.mu.ndp.startSolicitingRouters()
	}

	return nil
}

// Disable implements stack.NetworkEndpoint.
func (e *endpoint) Disable() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.disableLocked()
}

func (e *endpoint) disableLocked() *tcpip.Error {
	if !e.mu.enabled {
		return nil
	}

	e.mu.enabled = false

	e.mu.ndp.stopSolicitingRouters()
	e.mu.ndp.cleanupState(false /* hostOnly */)
	e.stopDADForAllPermanentAddressesLocked()

	// The NIC may have already left the multicast group.
	if _, err := e.mu.groupAddressableEndpoint.LeaveGroup(header.IPv6AllNodesMulticastAddress); err != nil && err != tcpip.ErrBadLocalAddress {
		return err
	}

	return nil
}

// stopDADForAllPermanentAddressesLocked stops DAD for all permaneent addresses.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) stopDADForAllPermanentAddressesLocked() {
	// Stop DAD for all the unicast IPv6 endpoints that are in the
	// permanentTentative state.
	eps := e.mu.addressableEndpoint.ReadonlyAllEndpoints()
	defer eps.Release()
	eps.ForEach(func(_ tcpip.Address, r stack.AddressEndpoint) bool {
		if addr := r.AddressWithPrefix().Address; r.GetKind() == stack.PermanentTentative && header.IsV6UnicastAddress(addr) {
			e.mu.ndp.stopDuplicateAddressDetection(addr)
		}

		return true
	})
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
	return e.nic.ID()
}

// Capabilities implements stack.NetworkEndpoint.
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

	// iptables filtering. All packets that reach here are locally
	// generated.
	nicName := e.stack.FindNICNameFromID(e.NICID())
	ipt := e.stack.IPTables()
	if ok := ipt.Check(stack.Output, pkt, gso, r, "", nicName); !ok {
		// iptables is telling us to drop the packet.
		r.Stats().IP.IPTablesOutputDropped.Increment()
		return nil
	}

	// If the packet is manipulated as per NAT Output rules, handle packet
	// based on destination address and do not send the packet to link
	// layer.
	//
	// TODO(gvisor.dev/issue/170): We should do this for every
	// packet, rather than only NATted packets, but removing this check
	// short circuits broadcasts before they are sent out to other hosts.
	if pkt.NatDone {
		netHeader := header.IPv6(pkt.NetworkHeader().View())
		if ep, err := e.stack.FindNetworkEndpoint(header.IPv6ProtocolNumber, netHeader.DestinationAddress()); err == nil {
			route := r.ReverseRoute(netHeader.SourceAddress(), netHeader.DestinationAddress())
			ep.HandlePacket(&route, pkt)
			return nil
		}
	}

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

	if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
		return err
	}
	r.Stats().IP.PacketsSent.Increment()
	return nil
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

	// iptables filtering. All packets that reach here are locally
	// generated.
	nicName := e.stack.FindNICNameFromID(e.NICID())
	ipt := e.stack.IPTables()
	dropped, natPkts := ipt.CheckPackets(stack.Output, pkts, gso, r, nicName)
	if len(dropped) == 0 && len(natPkts) == 0 {
		// Fast path: If no packets are to be dropped then we can just invoke the
		// faster WritePackets API directly.
		n, err := e.linkEP.WritePackets(r, gso, pkts, ProtocolNumber)
		r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
		return n, err
	}
	r.Stats().IP.IPTablesOutputDropped.IncrementBy(uint64(len(dropped)))

	// Slow path as we are dropping some packets in the batch degrade to
	// emitting one packet at a time.
	n := 0
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if _, ok := dropped[pkt]; ok {
			continue
		}
		if _, ok := natPkts[pkt]; ok {
			netHeader := header.IPv6(pkt.NetworkHeader().View())
			if ep, err := e.stack.FindNetworkEndpoint(header.IPv6ProtocolNumber, netHeader.DestinationAddress()); err == nil {
				src := netHeader.SourceAddress()
				dst := netHeader.DestinationAddress()
				route := r.ReverseRoute(src, dst)
				ep.HandlePacket(&route, pkt)
				n++
				continue
			}
		}
		if err := e.linkEP.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
			r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
			// Dropped packets aren't errors, so include them in
			// the return value.
			return n + len(dropped), err
		}
		n++
	}

	r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
	// Dropped packets aren't errors, so include them in the return value.
	return n + len(dropped), nil
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

	// iptables filtering. All packets that reach here are intended for
	// this machine and will not be forwarded.
	ipt := e.stack.IPTables()
	if ok := ipt.Check(stack.Input, pkt, nil, nil, "", ""); !ok {
		// iptables is telling us to drop the packet.
		r.Stats().IP.IPTablesInputDropped.Increment()
		return
	}

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

			// Drop the fragment if the size of the reassembled payload would exceed
			// the maximum payload size.
			if int(start)+fragmentPayloadLen > header.IPv6MaximumPayloadSize {
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
				start+uint16(fragmentPayloadLen)-1,
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
func (e *endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	_ = e.disableLocked()
	_ = e.mu.groupAddressableEndpoint.LeaveAllGroups()
	_ = e.removeAllPermanentAddressesLocked()

	e.protocol.forgetEndpoint(e)
}

// NetworkProtocolNumber implements stack.NetworkEndpoint.NetworkProtocolNumber.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

// AddPermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) AddPermanentAddress(addr tcpip.AddressWithPrefix, peb stack.PrimaryEndpointBehavior, configType stack.AddressConfigType, deprecated bool) (stack.AddressEndpoint, *tcpip.Error) {
	// TODO: add checks here after making sure we will no longer receive an empty
	// address (b/140943433).
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.addPermanentAddressLocked(addr, peb, configType, deprecated)
}

// addPermanentAddressLocked is like AddPermanentAddress but with locking
// requirements.
//
// addPermanentAddressLocked will also join the passed address's solicited-node
// multicast group and start duplicate address detection.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) addPermanentAddressLocked(addr tcpip.AddressWithPrefix, peb stack.PrimaryEndpointBehavior, configType stack.AddressConfigType, deprecated bool) (stack.AddressEndpoint, *tcpip.Error) {
	nep, err := e.mu.addressableEndpoint.AddPermanentAddress(addr, peb, configType, deprecated)
	if err != nil {
		return nil, err
	}

	if !header.IsV6UnicastAddress(addr.Address) {
		return nep, nil
	}

	snmc := header.SolicitedNodeAddr(addr.Address)
	if _, err := e.mu.groupAddressableEndpoint.JoinGroup(snmc); err != nil {
		return nil, err
	}

	nep.SetKind(stack.PermanentTentative)

	if e.mu.enabled {
		if err := e.mu.ndp.startDuplicateAddressDetection(addr.Address, nep); err != nil {
			return nil, err
		}
	}

	return nep, nil
}

// RemovePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) RemovePermanentAddress(addr tcpip.Address) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.removePermanentAddressLocked(addr)
}

// removePermanentAddressLocked is like RemovePermanentAddress but with locking
// requirements.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) removePermanentAddressLocked(addr tcpip.Address) *tcpip.Error {
	r := e.getAddressRLocked(addr)
	if r == nil || !r.GetKind().IsPermanent() {
		return tcpip.ErrBadLocalAddress
	}

	return e.removePermanentEndpointLocked(r, true)
}

// removePermanentEndpointLocked is like removePermanentAddressLocked except
// it works with a stack.AddressEndpoint.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) removePermanentEndpointLocked(r stack.AddressEndpoint, allowSLAACInvalidation bool) *tcpip.Error {
	addr := r.AddressWithPrefix()
	unicast := header.IsV6UnicastAddress(addr.Address)
	if unicast {
		e.mu.ndp.stopDuplicateAddressDetection(addr.Address)

		// If we are removing an address generated via SLAAC, cleanup
		// its SLAAC resources and notify the integrator.
		switch r.ConfigType() {
		case stack.AddressConfigSlaac:
			e.mu.ndp.cleanupSLAACAddrResourcesAndNotify(addr, allowSLAACInvalidation)
		case stack.AddressConfigSlaacTemp:
			e.mu.ndp.cleanupTempSLAACAddrResourcesAndNotify(addr, allowSLAACInvalidation)
		}
	}

	if err := e.mu.addressableEndpoint.RemovePermanentEndpoint(r); err != nil {
		return err
	}

	if !unicast {
		return nil
	}

	snmc := header.SolicitedNodeAddr(addr.Address)
	if _, err := e.mu.groupAddressableEndpoint.LeaveGroup(snmc); err != nil && err != tcpip.ErrBadLocalAddress {
		return err
	}

	return nil
}

// hasPermanentAddressLocked returns true if the endpoint has a permanent
// address equal to the passed address.
//
// Precondition: e.mu must be read or write locked.
func (e *endpoint) hasPermanentAddressRLocked(addr tcpip.Address) bool {
	r := e.getAddressRLocked(addr)
	if r == nil {
		return false
	}

	return r.GetKind().IsPermanent()
}

// getAddressRLocked returns the endpoint for the passed address.
//
// Precondition: e.mu must be read or write locked.
func (e *endpoint) getAddressRLocked(localAddr tcpip.Address) stack.AddressEndpoint {
	eps := e.mu.addressableEndpoint.ReadonlyAllEndpoints()
	defer eps.Release()
	return eps.Lookup(localAddr)
}

// AcquireAssignedAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior) stack.AddressEndpoint {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.getRefOrCreateTempLocked(localAddr, allowTemp, tempPEB)
}

func (e *endpoint) getRefOrCreateTempLocked(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior) stack.AddressEndpoint {
	return e.mu.addressableEndpoint.AcquireAssignedAddress(localAddr, allowTemp, tempPEB)
}

// AcquirePrimaryAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquirePrimaryAddress(remoteAddr tcpip.Address, spoofingOrPromiscuous bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.primaryEndpointRLocked(remoteAddr, spoofingOrPromiscuous)
}

func (e *endpoint) primaryEndpointRLocked(remoteAddr tcpip.Address, spoofingOrPromiscuous bool) stack.AddressEndpoint {
	// ipv6AddrCandidate is an IPv6 candidate for Source Address Selection (RFC
	// 6724 section 5).
	type ipv6AddrCandidate struct {
		ref   stack.AddressEndpoint
		scope header.IPv6AddressScope
	}

	if len(remoteAddr) == 0 {
		return e.mu.addressableEndpoint.AcquirePrimaryAddress(remoteAddr, spoofingOrPromiscuous)
	}

	// Create a candidate set of available addresses we can potentially use as a
	// source address.
	var cs []ipv6AddrCandidate
	e.mu.addressableEndpoint.ForEachPrimaryEndpoint(func(r stack.AddressEndpoint) {
		// If r is not valid for outgoing connections, it is not a valid endpoint.
		if !r.IsAssigned(spoofingOrPromiscuous) {
			return
		}

		addr := r.AddressWithPrefix().Address
		scope, err := header.ScopeForIPv6Address(addr)
		if err != nil {
			// Should never happen as we got r from the primary IPv6 endpoint list and
			// ScopeForIPv6Address only returns an error if addr is not an IPv6
			// address.
			panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", addr, err))
		}

		cs = append(cs, ipv6AddrCandidate{
			ref:   r,
			scope: scope,
		})
	})

	remoteScope, err := header.ScopeForIPv6Address(remoteAddr)
	if err != nil {
		// primaryIPv6Endpoint should never be called with an invalid IPv6 address.
		panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", remoteAddr, err))
	}

	// Sort the addresses as per RFC 6724 section 5 rules 1-3.
	//
	// TODO(b/146021396): Implement rules 4-8 of RFC 6724 section 5.
	sort.Slice(cs, func(i, j int) bool {
		sa := cs[i]
		sb := cs[j]

		// Prefer same address as per RFC 6724 section 5 rule 1.
		if sa.ref.AddressWithPrefix().Address == remoteAddr {
			return true
		}
		if sb.ref.AddressWithPrefix().Address == remoteAddr {
			return false
		}

		// Prefer appropriate scope as per RFC 6724 section 5 rule 2.
		if sa.scope < sb.scope {
			return sa.scope >= remoteScope
		} else if sb.scope < sa.scope {
			return sb.scope < remoteScope
		}

		// Avoid deprecated addresses as per RFC 6724 section 5 rule 3.
		if saDep, sbDep := sa.ref.Deprecated(), sb.ref.Deprecated(); saDep != sbDep {
			// If sa is not deprecated, it is preferred over sb.
			return sbDep
		}

		// Prefer temporary addresses as per RFC 6724 section 5 rule 7.
		if saTemp, sbTemp := sa.ref.ConfigType() == stack.AddressConfigSlaacTemp, sb.ref.ConfigType() == stack.AddressConfigSlaacTemp; saTemp != sbTemp {
			return saTemp
		}

		// sa and sb are equal, return the endpoint that is closest to the front of
		// the primary endpoint list.
		return i < j
	})

	// Return the most preferred address that can have its reference count
	// incremented.
	for _, c := range cs {
		if r := c.ref; r.IncRef() {
			return r
		}
	}

	return nil
}

// PrimaryAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpoint.PrimaryAddresses()
}

// AllPermanentAddresses implements stack.AddressableEndpoint.
func (e *endpoint) AllPermanentAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpoint.AllPermanentAddresses()
}

// RemoveAllPermanentAddresses implements stack.AddressableEndpoint.
func (e *endpoint) RemoveAllPermanentAddresses() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.removeAllPermanentAddressesLocked()
}

func (e *endpoint) removeAllPermanentAddressesLocked() *tcpip.Error {
	e.mu.ndp.removeSLAACAddresses(false /* keepLinkLocal */)
	e.stopDADForAllPermanentAddressesLocked()
	return e.mu.addressableEndpoint.RemoveAllPermanentAddresses()
}

// JoinGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) JoinGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	if !header.IsV6MulticastAddress(addr) {
		return false, tcpip.ErrBadAddress
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.groupAddressableEndpoint.JoinGroup(addr)
}

// LeaveGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) LeaveGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.groupAddressableEndpoint.LeaveGroup(addr)
}

// IsInGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) IsInGroup(addr tcpip.Address) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.groupAddressableEndpoint.IsInGroup(addr)
}

// LeaveAllGroups implements stack.GroupAddressableEndpoint.
func (e *endpoint) LeaveAllGroups() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.groupAddressableEndpoint.LeaveAllGroups()
}

var _ stack.ForwardingNetworkProtocol = (*protocol)(nil)
var _ stack.NetworkProtocol = (*protocol)(nil)

type protocol struct {
	mu struct {
		sync.RWMutex

		eps map[*endpoint]struct{}
	}

	// atomics hold fields that must be accessed using atomic operations.
	atomics struct {
		// defaultTTL is the current default TTL for the protocol. Only the
		// uint8 portion of it is meaningful.
		defaultTTL uint32

		// forwarding is set to 1 when the protocol has forwarding enabled and 0
		// when it is disabled.
		//
		// May only be updated while mu is write locked. This is so that we can read
		// the forwarding status without worrying about currently held locks and
		// synchronize writes when enabling/disabling forwarding for the protocol.
		forwarding uint32
	}

	fragmentation *fragmentation.Fragmentation

	// ndpDisp is the NDP event dispatcher that is used to send the netstack
	// integrator NDP related events.
	ndpDisp NDPDispatcher

	// ndpConfigs is the default NDP configurations used by an IPv6 endpoint.
	ndpConfigs NDPConfigurations

	// opaqueIIDOpts hold the options for generating opaque interface identifiers
	// (IIDs) as outlined by RFC 7217.
	opaqueIIDOpts OpaqueInterfaceIdentifierOptions

	// tempIIDSeed is used to seed the initial temporary interface identifier
	// history value used to generate IIDs for temporary SLAAC addresses.
	tempIIDSeed []byte

	// autoGenIPv6LinkLocal determines whether or not the stack will attempt
	// to auto-generate an IPv6 link-local address for newly enabled non-loopback
	// NICs. See the AutoGenIPv6LinkLocal field of Options for more details.
	autoGenIPv6LinkLocal bool
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
func (p *protocol) NewEndpoint(nic stack.NetworkInterface, linkAddrCache stack.LinkAddressCache, nud stack.NUDHandler, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint, st *stack.Stack) stack.NetworkEndpoint {
	e := &endpoint{
		nic:           nic,
		linkEP:        linkEP,
		linkAddrCache: linkAddrCache,
		nud:           nud,
		dispatcher:    dispatcher,
		protocol:      p,
		stack:         st,
	}
	e.mu.addressableEndpoint = stack.NewAddressableEndpointState()
	e.mu.groupAddressableEndpoint = stack.NewGroupAddressableEndpointState(e.mu.addressableEndpoint)
	e.mu.ndp = ndpState{
		ep:             e,
		configs:        p.ndpConfigs,
		dad:            make(map[tcpip.Address]dadState),
		defaultRouters: make(map[tcpip.Address]defaultRouterState),
		onLinkPrefixes: make(map[tcpip.Subnet]onLinkPrefixState),
		slaacPrefixes:  make(map[tcpip.Subnet]slaacPrefixState),
	}
	e.mu.ndp.initializeTempAddrState()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.mu.eps[e] = struct{}{}
	return e
}

func (p *protocol) forgetEndpoint(e *endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.mu.eps, e)
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
	atomic.StoreUint32(&p.atomics.defaultTTL, uint32(ttl))
}

// DefaultTTL returns the default TTL for endpoints created with this protocol.
func (p *protocol) DefaultTTL() uint8 {
	return uint8(atomic.LoadUint32(&p.atomics.defaultTTL))
}

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {

}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// Parse implements stack.NetworkProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	proto, _, fragOffset, fragMore, ok := parse.IPv6(pkt)
	if !ok {
		return 0, false, false
	}

	return proto, !fragMore && fragOffset == 0, true
}

// Forwarding implements stack.ForwardingNetworkProtocol.
func (p *protocol) Forwarding() bool {
	return uint8(atomic.LoadUint32(&p.atomics.forwarding)) == 1
}

// SetForwarding implements stack.ForwardingNetworkProtocol.
func (p *protocol) SetForwarding(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Forwarding() == v {
		return
	}

	if v {
		atomic.StoreUint32(&p.atomics.forwarding, 1)
	} else {
		atomic.StoreUint32(&p.atomics.forwarding, 0)
	}

	for ep := range p.mu.eps {
		ep.setForwarding(v)
	}
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

// Options holds options to configure a new protocol.
type Options struct {
	// NDPConfigs is the default NDP configurations used by interfaces.
	//
	// By default, NDPConfigs will have a zero value for its
	// DupAddrDetectTransmits field, implying that DAD will not be performed
	// before assigning an address to a NIC.
	NDPConfigs NDPConfigurations

	// AutoGenIPv6LinkLocal determines whether or not the stack will attempt to
	// auto-generate an IPv6 link-local address for newly enabled non-loopback
	// NICs.
	//
	// Note, setting this to true does not mean that a link-local address
	// will be assigned right away, or at all. If Duplicate Address Detection
	// is enabled, an address will only be assigned if it successfully resolves.
	// If it fails, no further attempt will be made to auto-generate an IPv6
	// link-local address.
	//
	// The generated link-local address will follow RFC 4291 Appendix A
	// guidelines.
	AutoGenIPv6LinkLocal bool

	// NDPDisp is the NDP event dispatcher that an integrator can provide to
	// receive NDP related events.
	NDPDisp NDPDispatcher

	// OpaqueIIDOpts hold the options for generating opaque interface
	// identifiers (IIDs) as outlined by RFC 7217.
	OpaqueIIDOpts OpaqueInterfaceIdentifierOptions

	// TempIIDSeed is used to seed the initial temporary interface identifier
	// history value used to generate IIDs for temporary SLAAC addresses.
	//
	// Temporary SLAAC adresses are short-lived addresses which are unpredictable
	// and random from the perspective of other nodes on the network. It is
	// recommended that the seed be a random byte buffer of at least
	// header.IIDSize bytes to make sure that temporary SLAAC addresses are
	// sufficiently random. It should follow minimum randomness requirements for
	// security as outlined by RFC 4086.
	//
	// Note: using a nil value, the same seed across netstack program runs, or a
	// seed that is too small would reduce randomness and increase predictability,
	// defeating the purpose of temporary SLAAC addresses.
	TempIIDSeed []byte
}

// NewProtocolWithOptions returns an IPv6 network protocol.
func NewProtocolWithOptions(opts Options) stack.NetworkProtocol {
	opts.NDPConfigs.validate()

	p := &protocol{
		fragmentation: fragmentation.NewFragmentation(header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, fragmentation.DefaultReassembleTimeout),

		ndpDisp:              opts.NDPDisp,
		ndpConfigs:           opts.NDPConfigs,
		opaqueIIDOpts:        opts.OpaqueIIDOpts,
		tempIIDSeed:          opts.TempIIDSeed,
		autoGenIPv6LinkLocal: opts.AutoGenIPv6LinkLocal,
	}
	p.mu.eps = make(map[*endpoint]struct{})
	p.SetDefaultTTL(DefaultTTL)
	return p
}

// NewProtocol is equivalent to NewProtocolWithOptions with an empty Options.
func NewProtocol() stack.NetworkProtocol {
	return NewProtocolWithOptions(Options{})
}
