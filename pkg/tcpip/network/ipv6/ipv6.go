// Copyright 2020 The gVisor Authors.
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

// Package ipv6 contains the implementation of the ipv6 network protocol.
package ipv6

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sort"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/network/fragmentation"
	"gvisor.dev/gvisor/pkg/tcpip/network/hash"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// As per RFC 8200 section 4.5:
	//   If insufficient fragments are received to complete reassembly of a packet
	//   within 60 seconds of the reception of the first-arriving fragment of that
	//   packet, reassembly of that packet must be abandoned.
	//
	// Linux also uses 60 seconds for reassembly timeout:
	// https://github.com/torvalds/linux/blob/47ec5303d73ea344e84f46660fff693c57641386/include/net/ipv6.h#L456
	ReassembleTimeout = 60 * time.Second

	// ProtocolNumber is the ipv6 protocol number.
	ProtocolNumber = header.IPv6ProtocolNumber

	// maxPayloadSize is the maximum size that can be encoded in the 16-bit
	// PayloadLength field of the ipv6 header.
	maxPayloadSize = 0xffff

	// DefaultTTL is the default hop limit for IPv6 Packets egressed by
	// Netstack.
	DefaultTTL = 64

	// buckets for fragment identifiers
	buckets = 2048
)

var _ stack.GroupAddressableEndpoint = (*endpoint)(nil)
var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)
var _ stack.NDPEndpoint = (*endpoint)(nil)
var _ NDPEndpoint = (*endpoint)(nil)

type endpoint struct {
	nic           stack.NetworkInterface
	linkAddrCache stack.LinkAddressCache
	nud           stack.NUDHandler
	dispatcher    stack.TransportDispatcher
	protocol      *protocol
	stack         *stack.Stack

	// enabled is set to 1 when the endpoint is enabled and 0 when it is
	// disabled.
	//
	// Must be accessed using atomic operations.
	enabled uint32

	mu struct {
		sync.RWMutex

		addressableEndpointState stack.AddressableEndpointState
		ndp                      ndpState
	}
}

// NICNameFromID is a function that returns a stable name for the specified NIC,
// even if different NIC IDs are used to refer to the same NIC in different
// program runs. It is used when generating opaque interface identifiers (IIDs).
// If the NIC was created with a name, it is passed to NICNameFromID.
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

// hasTentativeAddr returns true if addr is tentative on e.
func (e *endpoint) hasTentativeAddr(addr tcpip.Address) bool {
	e.mu.RLock()
	addressEndpoint := e.getAddressRLocked(addr)
	e.mu.RUnlock()
	return addressEndpoint != nil && addressEndpoint.GetKind() == stack.PermanentTentative
}

// dupTentativeAddrDetected attempts to inform e that a tentative addr is a
// duplicate on a link.
//
// dupTentativeAddrDetected removes the tentative address if it exists. If the
// address was generated via SLAAC, an attempt is made to generate a new
// address.
func (e *endpoint) dupTentativeAddrDetected(addr tcpip.Address) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil {
		return tcpip.ErrBadAddress
	}

	if addressEndpoint.GetKind() != stack.PermanentTentative {
		return tcpip.ErrInvalidEndpointState
	}

	// If the address is a SLAAC address, do not invalidate its SLAAC prefix as an
	// attempt will be made to generate a new address for it.
	if err := e.removePermanentEndpointLocked(addressEndpoint, false /* allowSLAACInvalidation */); err != nil {
		return err
	}

	prefix := addressEndpoint.Subnet()

	switch t := addressEndpoint.ConfigType(); t {
	case stack.AddressConfigStatic:
	case stack.AddressConfigSlaac:
		e.mu.ndp.regenerateSLAACAddr(prefix)
	case stack.AddressConfigSlaacTemp:
		// Do not reset the generation attempts counter for the prefix as the
		// temporary address is being regenerated in response to a DAD conflict.
		e.mu.ndp.regenerateTempSLAACAddr(prefix, false /* resetGenAttempts */)
	default:
		panic(fmt.Sprintf("unrecognized address config type = %d", t))
	}

	return nil
}

// transitionForwarding transitions the endpoint's forwarding status to
// forwarding.
//
// Must only be called when the forwarding status changes.
func (e *endpoint) transitionForwarding(forwarding bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.Enabled() {
		return
	}

	if forwarding {
		// When transitioning into an IPv6 router, host-only state (NDP discovered
		// routers, discovered on-link prefixes, and auto-generated addresses) is
		// cleaned up/invalidated and NDP router solicitations are stopped.
		e.mu.ndp.stopSolicitingRouters()
		e.mu.ndp.cleanupState(true /* hostOnly */)
	} else {
		// When transitioning into an IPv6 host, NDP router solicitations are
		// started.
		e.mu.ndp.startSolicitingRouters()
	}
}

// Enable implements stack.NetworkEndpoint.
func (e *endpoint) Enable() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If the NIC is not enabled, the endpoint can't do anything meaningful so
	// don't enable the endpoint.
	if !e.nic.Enabled() {
		return tcpip.ErrNotPermitted
	}

	// If the endpoint is already enabled, there is nothing for it to do.
	if !e.setEnabled(true) {
		return nil
	}

	// Join the IPv6 All-Nodes Multicast group if the stack is configured to
	// use IPv6. This is required to ensure that this node properly receives
	// and responds to the various NDP messages that are destined to the
	// all-nodes multicast address. An example is the Neighbor Advertisement
	// when we perform Duplicate Address Detection, or Router Advertisement
	// when we do Router Discovery. See RFC 4862, section 5.4.2 and RFC 4861
	// section 4.2 for more information.
	//
	// Also auto-generate an IPv6 link-local address based on the endpoint's
	// link address if it is configured to do so. Note, each interface is
	// required to have IPv6 link-local unicast address, as per RFC 4291
	// section 2.1.

	// Join the All-Nodes multicast group before starting DAD as responses to DAD
	// (NDP NS) messages may be sent to the All-Nodes multicast group if the
	// source address of the NDP NS is the unspecified address, as per RFC 4861
	// section 7.2.4.
	if _, err := e.mu.addressableEndpointState.JoinGroup(header.IPv6AllNodesMulticastAddress); err != nil {
		return err
	}

	// Perform DAD on the all the unicast IPv6 endpoints that are in the permanent
	// state.
	//
	// Addresses may have aleady completed DAD but in the time since the endpoint
	// was last enabled, other devices may have acquired the same addresses.
	var err *tcpip.Error
	e.mu.addressableEndpointState.ReadOnly().ForEach(func(addressEndpoint stack.AddressEndpoint) bool {
		addr := addressEndpoint.AddressWithPrefix().Address
		if !header.IsV6UnicastAddress(addr) {
			return true
		}

		switch addressEndpoint.GetKind() {
		case stack.Permanent:
			addressEndpoint.SetKind(stack.PermanentTentative)
			fallthrough
		case stack.PermanentTentative:
			err = e.mu.ndp.startDuplicateAddressDetection(addr, addressEndpoint)
			return err == nil
		default:
			return true
		}
	})
	if err != nil {
		return err
	}

	// Do not auto-generate an IPv6 link-local address for loopback devices.
	if e.protocol.autoGenIPv6LinkLocal && !e.nic.IsLoopback() {
		// The valid and preferred lifetime is infinite for the auto-generated
		// link-local address.
		e.mu.ndp.doSLAAC(header.IPv6LinkLocalPrefix.Subnet(), header.NDPInfiniteLifetime, header.NDPInfiniteLifetime)
	}

	// If we are operating as a router, then do not solicit routers since we
	// won't process the RAs anyway.
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

// Enabled implements stack.NetworkEndpoint.
func (e *endpoint) Enabled() bool {
	return e.nic.Enabled() && e.isEnabled()
}

// isEnabled returns true if the endpoint is enabled, regardless of the
// enabled status of the NIC.
func (e *endpoint) isEnabled() bool {
	return atomic.LoadUint32(&e.enabled) == 1
}

// setEnabled sets the enabled status for the endpoint.
//
// Returns true if the enabled status was updated.
func (e *endpoint) setEnabled(v bool) bool {
	if v {
		return atomic.SwapUint32(&e.enabled, 1) == 0
	}
	return atomic.SwapUint32(&e.enabled, 0) == 1
}

// Disable implements stack.NetworkEndpoint.
func (e *endpoint) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableLocked()
}

func (e *endpoint) disableLocked() {
	if !e.setEnabled(false) {
		return
	}

	e.mu.ndp.stopSolicitingRouters()
	e.mu.ndp.cleanupState(false /* hostOnly */)
	e.stopDADForPermanentAddressesLocked()

	// The endpoint may have already left the multicast group.
	if _, err := e.mu.addressableEndpointState.LeaveGroup(header.IPv6AllNodesMulticastAddress); err != nil && err != tcpip.ErrBadLocalAddress {
		panic(fmt.Sprintf("unexpected error when leaving group = %s: %s", header.IPv6AllNodesMulticastAddress, err))
	}
}

// stopDADForPermanentAddressesLocked stops DAD for all permaneent addresses.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) stopDADForPermanentAddressesLocked() {
	// Stop DAD for all the tentative unicast addresses.
	e.mu.addressableEndpointState.ReadOnly().ForEach(func(addressEndpoint stack.AddressEndpoint) bool {
		if addressEndpoint.GetKind() != stack.PermanentTentative {
			return true
		}

		addr := addressEndpoint.AddressWithPrefix().Address
		if header.IsV6UnicastAddress(addr) {
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
	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), header.IPv6MinimumSize)
	if err != nil {
		return 0
	}
	return networkMTU
}

// MaxHeaderLength returns the maximum length needed by ipv6 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.nic.MaxHeaderLength() + header.IPv6MinimumSize
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
	pkt.NetworkProtocolNumber = ProtocolNumber
}

func packetMustBeFragmented(pkt *stack.PacketBuffer, networkMTU uint32, gso *stack.GSO) bool {
	payload := pkt.TransportHeader().View().Size() + pkt.Data.Size()
	return (gso == nil || gso.Type == stack.GSONone) && uint32(payload) > networkMTU
}

// handleFragments fragments pkt and calls the handler function on each
// fragment. It returns the number of fragments handled and the number of
// fragments left to be processed. The IP header must already be present in the
// original packet. The transport header protocol number is required to avoid
// parsing the IPv6 extension headers.
func (e *endpoint) handleFragments(r *stack.Route, gso *stack.GSO, networkMTU uint32, pkt *stack.PacketBuffer, transProto tcpip.TransportProtocolNumber, handler func(*stack.PacketBuffer) *tcpip.Error) (int, int, *tcpip.Error) {
	networkHeader := header.IPv6(pkt.NetworkHeader().View())

	// TODO(gvisor.dev/issue/3912): Once the Authentication or ESP Headers are
	// supported for outbound packets, their length should not affect the fragment
	// maximum payload length because they should only be transmitted once.
	fragmentPayloadLen := (networkMTU - header.IPv6FragmentHeaderSize) &^ 7
	if fragmentPayloadLen < header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit {
		// We need at least 8 bytes of space left for the fragmentable part because
		// the fragment payload must obviously be non-zero and must be a multiple
		// of 8 as per RFC 8200 section 4.5:
		//   Each complete fragment, except possibly the last ("rightmost") one, is
		//   an integer multiple of 8 octets long.
		return 0, 1, tcpip.ErrMessageTooLong
	}

	if fragmentPayloadLen < uint32(pkt.TransportHeader().View().Size()) {
		// As per RFC 8200 Section 4.5, the Transport Header is expected to be small
		// enough to fit in the first fragment.
		return 0, 1, tcpip.ErrMessageTooLong
	}

	pf := fragmentation.MakePacketFragmenter(pkt, fragmentPayloadLen, calculateFragmentReserve(pkt))
	id := atomic.AddUint32(&e.protocol.ids[hashRoute(r, e.protocol.hashIV)%buckets], 1)

	var n int
	for {
		fragPkt, more := buildNextFragment(&pf, networkHeader, transProto, id)
		if err := handler(fragPkt); err != nil {
			return n, pf.RemainingFragmentCount() + 1, err
		}
		n++
		if !more {
			return n, pf.RemainingFragmentCount(), nil
		}
	}
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) *tcpip.Error {
	e.addIPHeader(r, pkt, params)

	// iptables filtering. All packets that reach here are locally
	// generated.
	nicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	if ok := e.protocol.stack.IPTables().Check(stack.Output, pkt, gso, r, "", nicName); !ok {
		// iptables is telling us to drop the packet.
		e.protocol.stack.Stats().IP.IPTablesOutputDropped.Increment()
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
		if ep, err := e.protocol.stack.FindNetworkEndpoint(ProtocolNumber, netHeader.DestinationAddress()); err == nil {
			pkt := pkt.CloneToInbound()
			if e.protocol.stack.ParsePacketBuffer(ProtocolNumber, pkt) == stack.ParsedOK {
				// Since we rewrote the packet but it is being routed back to us, we can
				// safely assume the checksum is valid.
				pkt.RXTransportChecksumValidated = true
				ep.(*endpoint).handlePacket(pkt)
			}
			return nil
		}
	}

	return e.writePacket(r, gso, pkt, params.Protocol, false /* headerIncluded */)
}

func (e *endpoint) writePacket(r *stack.Route, gso *stack.GSO, pkt *stack.PacketBuffer, protocol tcpip.TransportProtocolNumber, headerIncluded bool) *tcpip.Error {
	if r.Loop&stack.PacketLoop != 0 {
		pkt := pkt.CloneToInbound()
		if e.protocol.stack.ParsePacketBuffer(ProtocolNumber, pkt) == stack.ParsedOK {
			// If the packet was generated by the stack (not a raw/packet endpoint
			// where a packet may be written with the header included), then we can
			// safely assume the checksum is valid.
			pkt.RXTransportChecksumValidated = !headerIncluded
			e.handlePacket(pkt)
		}
	}
	if r.Loop&stack.PacketOut == 0 {
		return nil
	}

	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), uint32(pkt.NetworkHeader().View().Size()))
	if err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
		return err
	}

	if packetMustBeFragmented(pkt, networkMTU, gso) {
		sent, remain, err := e.handleFragments(r, gso, networkMTU, pkt, protocol, func(fragPkt *stack.PacketBuffer) *tcpip.Error {
			// TODO(gvisor.dev/issue/3884): Evaluate whether we want to send each
			// fragment one by one using WritePacket() (current strategy) or if we
			// want to create a PacketBufferList from the fragments and feed it to
			// WritePackets(). It'll be faster but cost more memory.
			return e.nic.WritePacket(r, gso, ProtocolNumber, fragPkt)
		})
		r.Stats().IP.PacketsSent.IncrementBy(uint64(sent))
		r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(remain))
		return err
	}

	if err := e.nic.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
		return err
	}

	r.Stats().IP.PacketsSent.Increment()
	return nil
}

// WritePackets implements stack.NetworkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, pkts stack.PacketBufferList, params stack.NetworkHeaderParams) (int, *tcpip.Error) {
	if r.Loop&stack.PacketLoop != 0 {
		panic("not implemented")
	}
	if r.Loop&stack.PacketOut == 0 {
		return pkts.Len(), nil
	}

	linkMTU := e.nic.MTU()
	for pb := pkts.Front(); pb != nil; pb = pb.Next() {
		e.addIPHeader(r, pb, params)

		networkMTU, err := calculateNetworkMTU(linkMTU, uint32(pb.NetworkHeader().View().Size()))
		if err != nil {
			r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(pkts.Len()))
			return 0, err
		}
		if packetMustBeFragmented(pb, networkMTU, gso) {
			// Keep track of the packet that is about to be fragmented so it can be
			// removed once the fragmentation is done.
			originalPkt := pb
			if _, _, err := e.handleFragments(r, gso, networkMTU, pb, params.Protocol, func(fragPkt *stack.PacketBuffer) *tcpip.Error {
				// Modify the packet list in place with the new fragments.
				pkts.InsertAfter(pb, fragPkt)
				pb = fragPkt
				return nil
			}); err != nil {
				r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(pkts.Len()))
				return 0, err
			}
			// Remove the packet that was just fragmented and process the rest.
			pkts.Remove(originalPkt)
		}
	}

	// iptables filtering. All packets that reach here are locally
	// generated.
	nicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	dropped, natPkts := e.protocol.stack.IPTables().CheckPackets(stack.Output, pkts, gso, r, nicName)
	if len(dropped) == 0 && len(natPkts) == 0 {
		// Fast path: If no packets are to be dropped then we can just invoke the
		// faster WritePackets API directly.
		n, err := e.nic.WritePackets(r, gso, pkts, ProtocolNumber)
		r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
		if err != nil {
			r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(pkts.Len() - n))
		}
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
			if ep, err := e.protocol.stack.FindNetworkEndpoint(ProtocolNumber, netHeader.DestinationAddress()); err == nil {
				pkt := pkt.CloneToInbound()
				if e.protocol.stack.ParsePacketBuffer(ProtocolNumber, pkt) == stack.ParsedOK {
					// Since we rewrote the packet but it is being routed back to us, we
					// can safely assume the checksum is valid.
					pkt.RXTransportChecksumValidated = true
					ep.(*endpoint).handlePacket(pkt)
				}
				n++
				continue
			}
		}
		if err := e.nic.WritePacket(r, gso, ProtocolNumber, pkt); err != nil {
			r.Stats().IP.PacketsSent.IncrementBy(uint64(n))
			r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(pkts.Len() - n + len(dropped)))
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

// WriteHeaderIncludedPacket implements stack.NetworkEndpoint.
func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) *tcpip.Error {
	// The packet already has an IP header, but there are a few required checks.
	h, ok := pkt.Data.PullUp(header.IPv6MinimumSize)
	if !ok {
		return tcpip.ErrMalformedHeader
	}
	ip := header.IPv6(h)

	// Always set the payload length.
	pktSize := pkt.Data.Size()
	ip.SetPayloadLength(uint16(pktSize - header.IPv6MinimumSize))

	// Set the source address when zero.
	if ip.SourceAddress() == header.IPv6Any {
		ip.SetSourceAddress(r.LocalAddress)
	}

	// Set the destination. If the packet already included a destination, it will
	// be part of the route anyways.
	ip.SetDestinationAddress(r.RemoteAddress)

	// Populate the packet buffer's network header and don't allow an invalid
	// packet to be sent.
	//
	// Note that parsing only makes sure that the packet is well formed as per the
	// wire format. We also want to check if the header's fields are valid before
	// sending the packet.
	proto, _, _, _, ok := parse.IPv6(pkt)
	if !ok || !header.IPv6(pkt.NetworkHeader().View()).IsValid(pktSize) {
		return tcpip.ErrMalformedHeader
	}

	return e.writePacket(r, nil /* gso */, pkt, proto, true /* headerIncluded */)
}

func (e *endpoint) forwardPacket(pkt *stack.PacketBuffer) bool {
	if !e.protocol.Forwarding() {
		return false
	}

	h := header.IPv6(pkt.NetworkHeader().View())
	dstAddr := h.DestinationAddress()

	// Check if the destination is owned by the stack.
	networkEndpoint, err := e.protocol.stack.FindNetworkEndpoint(ProtocolNumber, dstAddr)
	if err == nil {
		networkEndpoint.(*endpoint).handlePacket(pkt)
		return true
	}
	if err != tcpip.ErrBadAddress {
		return false
	}

	r, err := e.protocol.stack.FindRoute(0, "", dstAddr, ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		return true
	}
	defer r.Release()

	// TODO(b/143425874) Decrease the TTL field in forwarded packets.
	_ = r.WriteHeaderIncludedPacket(stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		// We need to do a deep copy of the IP packet because
		// WriteHeaderIncludedPacket takes ownership of the packet buffer, but we do
		// not own it.
		Data: stack.PayloadSince(pkt.NetworkHeader()).ToVectorisedView(),
	}))
	return true
}

// HandlePacket is called by the link layer when new ipv6 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	stats := e.protocol.stack.Stats()
	stats.IP.PacketsReceived.Increment()

	if !e.isEnabled() {
		stats.IP.DisabledPacketsReceived.Increment()
		return
	}

	// Loopback traffic skips the prerouting chain.
	if !e.nic.IsLoopback() {
		if ok := e.protocol.stack.IPTables().Check(stack.Prerouting, pkt, nil, nil, e.MainAddress().Address, ""); !ok {
			// iptables is telling us to drop the packet.
			stats.IP.IPTablesPreroutingDropped.Increment()
			return
		}
	}

	e.handlePacket(pkt)
}

func (e *endpoint) handlePacket(pkt *stack.PacketBuffer) {
	pkt.NICID = e.nic.ID()
	stats := e.protocol.stack.Stats()

	h := header.IPv6(pkt.NetworkHeader().View())
	if !h.IsValid(pkt.Data.Size() + pkt.NetworkHeader().View().Size() + pkt.TransportHeader().View().Size()) {
		stats.IP.MalformedPacketsReceived.Increment()
		return
	}
	srcAddr := h.SourceAddress()
	dstAddr := h.DestinationAddress()

	// As per RFC 4291 section 2.7:
	//   Multicast addresses must not be used as source addresses in IPv6
	//   packets or appear in any Routing header.
	if header.IsV6MulticastAddress(srcAddr) {
		stats.IP.InvalidSourceAddressesReceived.Increment()
		return
	}

	addressEndpoint := e.AcquireAssignedAddress(dstAddr, e.nic.Promiscuous(), stack.CanBePrimaryEndpoint)
	if addressEndpoint == nil {
		if !e.forwardPacket(pkt) {
			stats.IP.InvalidDestinationAddressesReceived.Increment()
		}
		return
	}
	addressEndpoint.DecRef()

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
	// this machine and need not be forwarded.
	if ok := e.protocol.stack.IPTables().Check(stack.Input, pkt, nil, nil, "", ""); !ok {
		// iptables is telling us to drop the packet.
		stats.IP.IPTablesInputDropped.Increment()
		return
	}

	for {
		// Keep track of the start of the previous header so we can report the
		// special case of a Hop by Hop at a location other than at the start.
		previousHeaderStart := it.HeaderOffset()
		extHdr, done, err := it.Next()
		if err != nil {
			stats.IP.MalformedPacketsReceived.Increment()
			return
		}
		if done {
			break
		}

		switch extHdr := extHdr.(type) {
		case header.IPv6HopByHopOptionsExtHdr:
			// As per RFC 8200 section 4.1, the Hop By Hop extension header is
			// restricted to appear immediately after an IPv6 fixed header.
			if previousHeaderStart != 0 {
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:    header.ICMPv6UnknownHeader,
					pointer: previousHeaderStart,
				}, pkt)
				return
			}

			optsIt := extHdr.Iter()

			for {
				opt, done, err := optsIt.Next()
				if err != nil {
					stats.IP.MalformedPacketsReceived.Increment()
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
				case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
					if header.IsV6MulticastAddress(dstAddr) {
						return
					}
					fallthrough
				case header.IPv6OptionUnknownActionDiscardSendICMP:
					// This case satisfies a requirement of RFC 8200 section 4.2
					// which states that an unknown option starting with bits [10] should:
					//
					//    discard the packet and, regardless of whether or not the
					//    packet's Destination Address was a multicast address, send an
					//    ICMP Parameter Problem, Code 2, message to the packet's
					//    Source Address, pointing to the unrecognized Option Type.
					//
					_ = e.protocol.returnError(&icmpReasonParameterProblem{
						code:               header.ICMPv6UnknownOption,
						pointer:            it.ParseOffset() + optsIt.OptionOffset(),
						respondToMulticast: true,
					}, pkt)
					return
				default:
					panic(fmt.Sprintf("unrecognized action for an unrecognized Hop By Hop extension header option = %d", opt))
				}
			}

		case header.IPv6RoutingExtHdr:
			// As per RFC 8200 section 4.4, if a node encounters a routing header with
			// an unrecognized routing type value, with a non-zero Segments Left
			// value, the node must discard the packet and send an ICMP Parameter
			// Problem, Code 0 to the packet's Source Address, pointing to the
			// unrecognized Routing Type.
			//
			// If the Segments Left is 0, the node must ignore the Routing extension
			// header and process the next header in the packet.
			//
			// Note, the stack does not yet handle any type of routing extension
			// header, so we just make sure Segments Left is zero before processing
			// the next extension header.
			if extHdr.SegmentsLeft() != 0 {
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:    header.ICMPv6ErroneousHeader,
					pointer: it.ParseOffset(),
				}, pkt)
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

			fragmentFieldOffset := it.ParseOffset()

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
						stats.IP.MalformedPacketsReceived.Increment()
						stats.IP.MalformedFragmentsReceived.Increment()
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
					stats.IP.MalformedPacketsReceived.Increment()
					stats.IP.MalformedFragmentsReceived.Increment()
					return
				}
			}

			fragmentPayloadLen := rawPayload.Buf.Size()
			if fragmentPayloadLen == 0 {
				// Drop the packet as it's marked as a fragment but has no payload.
				stats.IP.MalformedPacketsReceived.Increment()
				stats.IP.MalformedFragmentsReceived.Increment()
				return
			}

			// As per RFC 2460 Section 4.5:
			//
			//    If the length of a fragment, as derived from the fragment packet's
			//    Payload Length field, is not a multiple of 8 octets and the M flag
			//    of that fragment is 1, then that fragment must be discarded and an
			//    ICMP Parameter Problem, Code 0, message should be sent to the source
			//    of the fragment, pointing to the Payload Length field of the
			//    fragment packet.
			if extHdr.More() && fragmentPayloadLen%header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit != 0 {
				stats.IP.MalformedPacketsReceived.Increment()
				stats.IP.MalformedFragmentsReceived.Increment()
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:    header.ICMPv6ErroneousHeader,
					pointer: header.IPv6PayloadLenOffset,
				}, pkt)
				return
			}

			// The packet is a fragment, let's try to reassemble it.
			start := extHdr.FragmentOffset() * header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit

			// As per RFC 2460 Section 4.5:
			//
			//    If the length and offset of a fragment are such that the Payload
			//    Length of the packet reassembled from that fragment would exceed
			//    65,535 octets, then that fragment must be discarded and an ICMP
			//    Parameter Problem, Code 0, message should be sent to the source of
			//    the fragment, pointing to the Fragment Offset field of the fragment
			//    packet.
			if int(start)+fragmentPayloadLen > header.IPv6MaximumPayloadSize {
				stats.IP.MalformedPacketsReceived.Increment()
				stats.IP.MalformedFragmentsReceived.Increment()
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:    header.ICMPv6ErroneousHeader,
					pointer: fragmentFieldOffset,
				}, pkt)
				return
			}

			// Set up a callback in case we need to send a Time Exceeded Message as
			// per RFC 2460 Section 4.5.
			var releaseCB func(bool)
			if start == 0 {
				pkt := pkt.Clone()
				releaseCB = func(timedOut bool) {
					if timedOut {
						_ = e.protocol.returnError(&icmpReasonReassemblyTimeout{}, pkt)
					}
				}
			}

			// Note that pkt doesn't have its transport header set after reassembly,
			// and won't until DeliverNetworkPacket sets it.
			data, proto, ready, err := e.protocol.fragmentation.Process(
				// IPv6 ignores the Protocol field since the ID only needs to be unique
				// across source-destination pairs, as per RFC 8200 section 4.5.
				fragmentation.FragmentID{
					Source:      srcAddr,
					Destination: dstAddr,
					ID:          extHdr.ID(),
				},
				start,
				start+uint16(fragmentPayloadLen)-1,
				extHdr.More(),
				uint8(rawPayload.Identifier),
				rawPayload.Buf,
				releaseCB,
			)
			if err != nil {
				stats.IP.MalformedPacketsReceived.Increment()
				stats.IP.MalformedFragmentsReceived.Increment()
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
					stats.IP.MalformedPacketsReceived.Increment()
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
				case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
					if header.IsV6MulticastAddress(dstAddr) {
						return
					}
					fallthrough
				case header.IPv6OptionUnknownActionDiscardSendICMP:
					// This case satisfies a requirement of RFC 8200 section 4.2
					// which states that an unknown option starting with bits [10] should:
					//
					//    discard the packet and, regardless of whether or not the
					//    packet's Destination Address was a multicast address, send an
					//    ICMP Parameter Problem, Code 2, message to the packet's
					//    Source Address, pointing to the unrecognized Option Type.
					//
					_ = e.protocol.returnError(&icmpReasonParameterProblem{
						code:               header.ICMPv6UnknownOption,
						pointer:            it.ParseOffset() + optsIt.OptionOffset(),
						respondToMulticast: true,
					}, pkt)
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

			stats.IP.PacketsDelivered.Increment()
			if p := tcpip.TransportProtocolNumber(extHdr.Identifier); p == header.ICMPv6ProtocolNumber {
				pkt.TransportProtocolNumber = p
				e.handleICMP(pkt, hasFragmentHeader)
			} else {
				stats.IP.PacketsDelivered.Increment()
				switch res := e.dispatcher.DeliverTransportPacket(p, pkt); res {
				case stack.TransportPacketHandled:
				case stack.TransportPacketDestinationPortUnreachable:
					// As per RFC 4443 section 3.1:
					//   A destination node SHOULD originate a Destination Unreachable
					//   message with Code 4 in response to a packet for which the
					//   transport protocol (e.g., UDP) has no listener, if that transport
					//   protocol has no alternative means to inform the sender.
					_ = e.protocol.returnError(&icmpReasonPortUnreachable{}, pkt)
				case stack.TransportPacketProtocolUnreachable:
					// As per RFC 8200 section 4. (page 7):
					//   Extension headers are numbered from IANA IP Protocol Numbers
					//   [IANA-PN], the same values used for IPv4 and IPv6.  When
					//   processing a sequence of Next Header values in a packet, the
					//   first one that is not an extension header [IANA-EH] indicates
					//   that the next item in the packet is the corresponding upper-layer
					//   header.
					// With more related information on page 8:
					//   If, as a result of processing a header, the destination node is
					//   required to proceed to the next header but the Next Header value
					//   in the current header is unrecognized by the node, it should
					//   discard the packet and send an ICMP Parameter Problem message to
					//   the source of the packet, with an ICMP Code value of 1
					//   ("unrecognized Next Header type encountered") and the ICMP
					//   Pointer field containing the offset of the unrecognized value
					//   within the original packet.
					//
					// Which when taken together indicate that an unknown protocol should
					// be treated as an unrecognized next header value.
					_ = e.protocol.returnError(&icmpReasonParameterProblem{
						code:    header.ICMPv6UnknownHeader,
						pointer: it.ParseOffset(),
					}, pkt)
				default:
					panic(fmt.Sprintf("unrecognized result from DeliverTransportPacket = %d", res))
				}
			}

		default:
			_ = e.protocol.returnError(&icmpReasonParameterProblem{
				code:    header.ICMPv6UnknownHeader,
				pointer: it.ParseOffset(),
			}, pkt)
			stats.UnknownProtocolRcvdPackets.Increment()
			return
		}
	}
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {
	e.mu.Lock()
	e.disableLocked()
	e.mu.ndp.removeSLAACAddresses(false /* keepLinkLocal */)
	e.stopDADForPermanentAddressesLocked()
	e.mu.addressableEndpointState.Cleanup()
	e.mu.Unlock()

	e.protocol.forgetEndpoint(e)
}

// NetworkProtocolNumber implements stack.NetworkEndpoint.NetworkProtocolNumber.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

// AddAndAcquirePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, peb stack.PrimaryEndpointBehavior, configType stack.AddressConfigType, deprecated bool) (stack.AddressEndpoint, *tcpip.Error) {
	// TODO(b/169350103): add checks here after making sure we no longer receive
	// an empty address.
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.addAndAcquirePermanentAddressLocked(addr, peb, configType, deprecated)
}

// addAndAcquirePermanentAddressLocked is like AddAndAcquirePermanentAddress but
// with locking requirements.
//
// addAndAcquirePermanentAddressLocked also joins the passed address's
// solicited-node multicast group and start duplicate address detection.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) addAndAcquirePermanentAddressLocked(addr tcpip.AddressWithPrefix, peb stack.PrimaryEndpointBehavior, configType stack.AddressConfigType, deprecated bool) (stack.AddressEndpoint, *tcpip.Error) {
	addressEndpoint, err := e.mu.addressableEndpointState.AddAndAcquirePermanentAddress(addr, peb, configType, deprecated)
	if err != nil {
		return nil, err
	}

	if !header.IsV6UnicastAddress(addr.Address) {
		return addressEndpoint, nil
	}

	snmc := header.SolicitedNodeAddr(addr.Address)
	if _, err := e.mu.addressableEndpointState.JoinGroup(snmc); err != nil {
		return nil, err
	}

	addressEndpoint.SetKind(stack.PermanentTentative)

	if e.Enabled() {
		if err := e.mu.ndp.startDuplicateAddressDetection(addr.Address, addressEndpoint); err != nil {
			return nil, err
		}
	}

	return addressEndpoint, nil
}

// RemovePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) RemovePermanentAddress(addr tcpip.Address) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil || !addressEndpoint.GetKind().IsPermanent() {
		return tcpip.ErrBadLocalAddress
	}

	return e.removePermanentEndpointLocked(addressEndpoint, true)
}

// removePermanentEndpointLocked is like removePermanentAddressLocked except
// it works with a stack.AddressEndpoint.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) removePermanentEndpointLocked(addressEndpoint stack.AddressEndpoint, allowSLAACInvalidation bool) *tcpip.Error {
	addr := addressEndpoint.AddressWithPrefix()
	unicast := header.IsV6UnicastAddress(addr.Address)
	if unicast {
		e.mu.ndp.stopDuplicateAddressDetection(addr.Address)

		// If we are removing an address generated via SLAAC, cleanup
		// its SLAAC resources and notify the integrator.
		switch addressEndpoint.ConfigType() {
		case stack.AddressConfigSlaac:
			e.mu.ndp.cleanupSLAACAddrResourcesAndNotify(addr, allowSLAACInvalidation)
		case stack.AddressConfigSlaacTemp:
			e.mu.ndp.cleanupTempSLAACAddrResourcesAndNotify(addr, allowSLAACInvalidation)
		}
	}

	if err := e.mu.addressableEndpointState.RemovePermanentEndpoint(addressEndpoint); err != nil {
		return err
	}

	if !unicast {
		return nil
	}

	snmc := header.SolicitedNodeAddr(addr.Address)
	if _, err := e.mu.addressableEndpointState.LeaveGroup(snmc); err != nil && err != tcpip.ErrBadLocalAddress {
		return err
	}

	return nil
}

// hasPermanentAddressLocked returns true if the endpoint has a permanent
// address equal to the passed address.
//
// Precondition: e.mu must be read or write locked.
func (e *endpoint) hasPermanentAddressRLocked(addr tcpip.Address) bool {
	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil {
		return false
	}
	return addressEndpoint.GetKind().IsPermanent()
}

// getAddressRLocked returns the endpoint for the passed address.
//
// Precondition: e.mu must be read or write locked.
func (e *endpoint) getAddressRLocked(localAddr tcpip.Address) stack.AddressEndpoint {
	return e.mu.addressableEndpointState.ReadOnly().Lookup(localAddr)
}

// MainAddress implements stack.AddressableEndpoint.
func (e *endpoint) MainAddress() tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.MainAddress()
}

// AcquireAssignedAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior) stack.AddressEndpoint {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.acquireAddressOrCreateTempLocked(localAddr, allowTemp, tempPEB)
}

// acquireAddressOrCreateTempLocked is like AcquireAssignedAddress but with
// locking requirements.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) acquireAddressOrCreateTempLocked(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior) stack.AddressEndpoint {
	return e.mu.addressableEndpointState.AcquireAssignedAddress(localAddr, allowTemp, tempPEB)
}

// AcquireOutgoingPrimaryAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireOutgoingPrimaryAddressRLocked(remoteAddr, allowExpired)
}

// acquireOutgoingPrimaryAddressRLocked is like AcquireOutgoingPrimaryAddress
// but with locking requirements.
//
// Precondition: e.mu must be read locked.
func (e *endpoint) acquireOutgoingPrimaryAddressRLocked(remoteAddr tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	// addrCandidate is a candidate for Source Address Selection, as per
	// RFC 6724 section 5.
	type addrCandidate struct {
		addressEndpoint stack.AddressEndpoint
		scope           header.IPv6AddressScope
	}

	if len(remoteAddr) == 0 {
		return e.mu.addressableEndpointState.AcquireOutgoingPrimaryAddress(remoteAddr, allowExpired)
	}

	// Create a candidate set of available addresses we can potentially use as a
	// source address.
	var cs []addrCandidate
	e.mu.addressableEndpointState.ReadOnly().ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) {
		// If r is not valid for outgoing connections, it is not a valid endpoint.
		if !addressEndpoint.IsAssigned(allowExpired) {
			return
		}

		addr := addressEndpoint.AddressWithPrefix().Address
		scope, err := header.ScopeForIPv6Address(addr)
		if err != nil {
			// Should never happen as we got r from the primary IPv6 endpoint list and
			// ScopeForIPv6Address only returns an error if addr is not an IPv6
			// address.
			panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", addr, err))
		}

		cs = append(cs, addrCandidate{
			addressEndpoint: addressEndpoint,
			scope:           scope,
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
		if sa.addressEndpoint.AddressWithPrefix().Address == remoteAddr {
			return true
		}
		if sb.addressEndpoint.AddressWithPrefix().Address == remoteAddr {
			return false
		}

		// Prefer appropriate scope as per RFC 6724 section 5 rule 2.
		if sa.scope < sb.scope {
			return sa.scope >= remoteScope
		} else if sb.scope < sa.scope {
			return sb.scope < remoteScope
		}

		// Avoid deprecated addresses as per RFC 6724 section 5 rule 3.
		if saDep, sbDep := sa.addressEndpoint.Deprecated(), sb.addressEndpoint.Deprecated(); saDep != sbDep {
			// If sa is not deprecated, it is preferred over sb.
			return sbDep
		}

		// Prefer temporary addresses as per RFC 6724 section 5 rule 7.
		if saTemp, sbTemp := sa.addressEndpoint.ConfigType() == stack.AddressConfigSlaacTemp, sb.addressEndpoint.ConfigType() == stack.AddressConfigSlaacTemp; saTemp != sbTemp {
			return saTemp
		}

		// sa and sb are equal, return the endpoint that is closest to the front of
		// the primary endpoint list.
		return i < j
	})

	// Return the most preferred address that can have its reference count
	// incremented.
	for _, c := range cs {
		if c.addressEndpoint.IncRef() {
			return c.addressEndpoint
		}
	}

	return nil
}

// PrimaryAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PrimaryAddresses()
}

// PermanentAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PermanentAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PermanentAddresses()
}

// JoinGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) JoinGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	if !header.IsV6MulticastAddress(addr) {
		return false, tcpip.ErrBadAddress
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.JoinGroup(addr)
}

// LeaveGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) LeaveGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.LeaveGroup(addr)
}

// IsInGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) IsInGroup(addr tcpip.Address) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.IsInGroup(addr)
}

var _ stack.ForwardingNetworkProtocol = (*protocol)(nil)
var _ stack.NetworkProtocol = (*protocol)(nil)

type protocol struct {
	stack *stack.Stack

	mu struct {
		sync.RWMutex

		eps map[*endpoint]struct{}
	}

	ids    []uint32
	hashIV uint32

	// defaultTTL is the current default TTL for the protocol. Only the
	// uint8 portion of it is meaningful.
	//
	// Must be accessed using atomic operations.
	defaultTTL uint32

	// forwarding is set to 1 when the protocol has forwarding enabled and 0
	// when it is disabled.
	//
	// Must be accessed using atomic operations.
	forwarding uint32

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

	// autoGenIPv6LinkLocal determines whether or not the stack attempts to
	// auto-generate an IPv6 link-local address for newly enabled non-loopback
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
func (p *protocol) NewEndpoint(nic stack.NetworkInterface, linkAddrCache stack.LinkAddressCache, nud stack.NUDHandler, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{
		nic:           nic,
		linkAddrCache: linkAddrCache,
		nud:           nud,
		dispatcher:    dispatcher,
		protocol:      p,
	}
	e.mu.addressableEndpointState.Init(e)
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
	return uint8(atomic.LoadUint32(&p.forwarding)) == 1
}

// setForwarding sets the forwarding status for the protocol.
//
// Returns true if the forwarding status was updated.
func (p *protocol) setForwarding(v bool) bool {
	if v {
		return atomic.SwapUint32(&p.forwarding, 1) == 0
	}
	return atomic.SwapUint32(&p.forwarding, 0) == 1
}

// SetForwarding implements stack.ForwardingNetworkProtocol.
func (p *protocol) SetForwarding(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.setForwarding(v) {
		return
	}

	for ep := range p.mu.eps {
		ep.transitionForwarding(v)
	}
}

// calculateNetworkMTU calculates the network-layer payload MTU based on the
// link-layer payload MTU and the length of every IPv6 header.
// Note that this is different than the Payload Length field of the IPv6 header,
// which includes the length of the extension headers.
func calculateNetworkMTU(linkMTU, networkHeadersLen uint32) (uint32, *tcpip.Error) {
	if linkMTU < header.IPv6MinimumMTU {
		return 0, tcpip.ErrInvalidEndpointState
	}

	// As per RFC 7112 section 5, we should discard packets if their IPv6 header
	// is bigger than 1280 bytes (ie, the minimum link MTU) since we do not
	// support PMTU discovery:
	//   Hosts that do not discover the Path MTU MUST limit the IPv6 Header Chain
	//   length to 1280 bytes.  Limiting the IPv6 Header Chain length to 1280
	//   bytes ensures that the header chain length does not exceed the IPv6
	//   minimum MTU.
	if networkHeadersLen > header.IPv6MinimumMTU {
		return 0, tcpip.ErrMalformedHeader
	}

	networkMTU := linkMTU - uint32(networkHeadersLen)
	if networkMTU > maxPayloadSize {
		networkMTU = maxPayloadSize
	}
	return networkMTU, nil
}

// Options holds options to configure a new protocol.
type Options struct {
	// NDPConfigs is the default NDP configurations used by interfaces.
	NDPConfigs NDPConfigurations

	// AutoGenIPv6LinkLocal determines whether or not the stack attempts to
	// auto-generate an IPv6 link-local address for newly enabled non-loopback
	// NICs.
	//
	// Note, setting this to true does not mean that a link-local address is
	// assigned right away, or at all. If Duplicate Address Detection is enabled,
	// an address is only assigned if it successfully resolves. If it fails, no
	// further attempts are made to auto-generate an IPv6 link-local adddress.
	//
	// The generated link-local address follows RFC 4291 Appendix A guidelines.
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
func NewProtocolWithOptions(opts Options) stack.NetworkProtocolFactory {
	opts.NDPConfigs.validate()

	ids := hash.RandN32(buckets)
	hashIV := hash.RandN32(1)[0]

	return func(s *stack.Stack) stack.NetworkProtocol {
		p := &protocol{
			stack:         s,
			fragmentation: fragmentation.NewFragmentation(header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, ReassembleTimeout, s.Clock()),
			ids:           ids,
			hashIV:        hashIV,

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
}

// NewProtocol is equivalent to NewProtocolWithOptions with an empty Options.
func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	return NewProtocolWithOptions(Options{})(s)
}

func calculateFragmentReserve(pkt *stack.PacketBuffer) int {
	return pkt.AvailableHeaderBytes() + pkt.NetworkHeader().View().Size() + header.IPv6FragmentHeaderSize
}

// hashRoute calculates a hash value for the given route. It uses the source &
// destination address and 32-bit number to generate the hash.
func hashRoute(r *stack.Route, hashIV uint32) uint32 {
	// The FNV-1a was chosen because it is a fast hashing algorithm, and
	// cryptographic properties are not needed here.
	h := fnv.New32a()
	if _, err := h.Write([]byte(r.LocalAddress)); err != nil {
		panic(fmt.Sprintf("Hash.Write: %s, but Hash' implementation of Write is not expected to ever return an error", err))
	}

	if _, err := h.Write([]byte(r.RemoteAddress)); err != nil {
		panic(fmt.Sprintf("Hash.Write: %s, but Hash' implementation of Write is not expected to ever return an error", err))
	}

	s := make([]byte, 4)
	binary.LittleEndian.PutUint32(s, hashIV)
	if _, err := h.Write(s); err != nil {
		panic(fmt.Sprintf("Hash.Write: %s, but Hash' implementation of Write is not expected ever to return an error", err))
	}

	return h.Sum32()
}

func buildNextFragment(pf *fragmentation.PacketFragmenter, originalIPHeaders header.IPv6, transportProto tcpip.TransportProtocolNumber, id uint32) (*stack.PacketBuffer, bool) {
	fragPkt, offset, copied, more := pf.BuildNextFragment()
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	originalIPHeadersLength := len(originalIPHeaders)
	fragmentIPHeadersLength := originalIPHeadersLength + header.IPv6FragmentHeaderSize
	fragmentIPHeaders := header.IPv6(fragPkt.NetworkHeader().Push(fragmentIPHeadersLength))
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	// Copy the IPv6 header and any extension headers already populated.
	if copied := copy(fragmentIPHeaders, originalIPHeaders); copied != originalIPHeadersLength {
		panic(fmt.Sprintf("wrong number of bytes copied into fragmentIPHeaders: got %d, want %d", copied, originalIPHeadersLength))
	}
	fragmentIPHeaders.SetNextHeader(header.IPv6FragmentHeader)
	fragmentIPHeaders.SetPayloadLength(uint16(copied + fragmentIPHeadersLength - header.IPv6MinimumSize))

	fragmentHeader := header.IPv6Fragment(fragmentIPHeaders[originalIPHeadersLength:])
	fragmentHeader.Encode(&header.IPv6FragmentFields{
		M:              more,
		FragmentOffset: uint16(offset / header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit),
		Identification: id,
		NextHeader:     uint8(transportProto),
	})

	return fragPkt, more
}
