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

package stack

import (
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Route represents a route through the networking stack to a given destination.
type Route struct {
	// RemoteAddress is the final destination of the route.
	RemoteAddress tcpip.Address

	// RemoteLinkAddress is the link-layer (MAC) address of the
	// final destination of the route.
	RemoteLinkAddress tcpip.LinkAddress

	// LocalAddress is the local address where the route starts.
	LocalAddress tcpip.Address

	// LocalLinkAddress is the link-layer (MAC) address of the
	// where the route starts.
	LocalLinkAddress tcpip.LinkAddress

	// NextHop is the next node in the path to the destination.
	NextHop tcpip.Address

	// NetProto is the network-layer protocol.
	NetProto tcpip.NetworkProtocolNumber

	// ref a reference to the network endpoint through which the route
	// starts.
	ref *referencedNetworkEndpoint

	// Loop controls where WritePacket should send packets.
	Loop PacketLooping

	// directedBroadcast indicates whether this route is sending a directed
	// broadcast packet.
	directedBroadcast bool
}

// makeRoute initializes a new route. It takes ownership of the provided
// reference to a network endpoint.
func makeRoute(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, localLinkAddr tcpip.LinkAddress, ref *referencedNetworkEndpoint, handleLocal, multicastLoop bool) Route {
	loop := PacketOut
	if handleLocal && localAddr != "" && remoteAddr == localAddr {
		loop = PacketLoop
	} else if multicastLoop && (header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)) {
		loop |= PacketLoop
	} else if remoteAddr == header.IPv4Broadcast {
		loop |= PacketLoop
	}

	return Route{
		NetProto:         netProto,
		LocalAddress:     localAddr,
		LocalLinkAddress: localLinkAddr,
		RemoteAddress:    remoteAddr,
		ref:              ref,
		Loop:             loop,
	}
}

// NICID returns the id of the NIC from which this route originates.
func (r *Route) NICID() tcpip.NICID {
	return r.ref.ep.NICID()
}

// MaxHeaderLength forwards the call to the network endpoint's implementation.
func (r *Route) MaxHeaderLength() uint16 {
	return r.ref.ep.MaxHeaderLength()
}

// Stats returns a mutable copy of current stats.
func (r *Route) Stats() tcpip.Stats {
	return r.ref.nic.stack.Stats()
}

// PseudoHeaderChecksum forwards the call to the network endpoint's
// implementation.
func (r *Route) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, totalLen uint16) uint16 {
	return header.PseudoHeaderChecksum(protocol, r.LocalAddress, r.RemoteAddress, totalLen)
}

// Capabilities returns the link-layer capabilities of the route.
func (r *Route) Capabilities() LinkEndpointCapabilities {
	return r.ref.ep.Capabilities()
}

// GSOMaxSize returns the maximum GSO packet size.
func (r *Route) GSOMaxSize() uint32 {
	if gso, ok := r.ref.ep.(GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

// ResolveWith immediately resolves a route with the specified remote link
// address.
func (r *Route) ResolveWith(addr tcpip.LinkAddress) {
	r.RemoteLinkAddress = addr
}

// Resolve attempts to resolve the link address if necessary. Returns ErrWouldBlock in
// case address resolution requires blocking, e.g. wait for ARP reply. Waker is
// notified when address resolution is complete (success or not).
//
// If address resolution is required, ErrNoLinkAddress and a notification channel is
// returned for the top level caller to block. Channel is closed once address resolution
// is complete (success or not).
//
// The NIC r uses must not be locked.
func (r *Route) Resolve(waker *sleep.Waker) (<-chan struct{}, *tcpip.Error) {
	if !r.IsResolutionRequired() {
		// Nothing to do if there is no cache (which does the resolution on cache miss) or
		// link address is already known.
		return nil, nil
	}

	nextAddr := r.NextHop
	if nextAddr == "" {
		// Local link address is already known.
		if r.RemoteAddress == r.LocalAddress {
			r.RemoteLinkAddress = r.LocalLinkAddress
			return nil, nil
		}
		nextAddr = r.RemoteAddress
	}

	if r.ref.nic.neigh != nil {
		entry, ch, err := r.ref.nic.neigh.entry(nextAddr, r.LocalAddress, r.ref.linkRes, waker)
		if err != nil {
			return ch, err
		}
		r.RemoteLinkAddress = entry.LinkAddr
		return nil, nil
	}

	linkAddr, ch, err := r.ref.linkCache.GetLinkAddress(r.ref.nic.ID(), nextAddr, r.LocalAddress, r.NetProto, waker)
	if err != nil {
		return ch, err
	}
	r.RemoteLinkAddress = linkAddr
	return nil, nil
}

// RemoveWaker removes a waker that has been added in Resolve().
func (r *Route) RemoveWaker(waker *sleep.Waker) {
	nextAddr := r.NextHop
	if nextAddr == "" {
		nextAddr = r.RemoteAddress
	}

	if r.ref.nic.neigh != nil {
		r.ref.nic.neigh.removeWaker(nextAddr, waker)
		return
	}

	r.ref.linkCache.RemoveWaker(r.ref.nic.ID(), nextAddr, waker)
}

// IsResolutionRequired returns true if Resolve() must be called to resolve
// the link address before the this route can be written to.
//
// The NIC r uses must not be locked.
func (r *Route) IsResolutionRequired() bool {
	if r.ref.nic.neigh != nil {
		return r.ref.isValidForOutgoing() && r.ref.linkRes != nil && r.RemoteLinkAddress == ""
	}
	return r.ref.isValidForOutgoing() && r.ref.linkCache != nil && r.RemoteLinkAddress == ""
}

// WritePacket writes the packet through the given route.
func (r *Route) WritePacket(gso *GSO, params NetworkHeaderParams, pkt *PacketBuffer) *tcpip.Error {
	if !r.ref.isValidForOutgoing() {
		return tcpip.ErrInvalidEndpointState
	}

	// WritePacket takes ownership of pkt, calculate numBytes first.
	numBytes := pkt.Size()

	err := r.ref.ep.WritePacket(r, gso, params, pkt)
	if err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
	} else {
		r.ref.nic.stats.Tx.Packets.Increment()
		r.ref.nic.stats.Tx.Bytes.IncrementBy(uint64(numBytes))
	}
	return err
}

// WritePackets writes a list of n packets through the given route and returns
// the number of packets written.
func (r *Route) WritePackets(gso *GSO, pkts PacketBufferList, params NetworkHeaderParams) (int, *tcpip.Error) {
	if !r.ref.isValidForOutgoing() {
		return 0, tcpip.ErrInvalidEndpointState
	}

	// WritePackets takes ownership of pkt, calculate length first.
	numPkts := pkts.Len()

	n, err := r.ref.ep.WritePackets(r, gso, pkts, params)
	if err != nil {
		r.Stats().IP.OutgoingPacketErrors.IncrementBy(uint64(numPkts - n))
	}
	r.ref.nic.stats.Tx.Packets.IncrementBy(uint64(n))

	writtenBytes := 0
	for i, pb := 0, pkts.Front(); i < n && pb != nil; i, pb = i+1, pb.Next() {
		writtenBytes += pb.Size()
	}

	r.ref.nic.stats.Tx.Bytes.IncrementBy(uint64(writtenBytes))
	return n, err
}

// WriteHeaderIncludedPacket writes a packet already containing a network
// header through the given route.
func (r *Route) WriteHeaderIncludedPacket(pkt *PacketBuffer) *tcpip.Error {
	if !r.ref.isValidForOutgoing() {
		return tcpip.ErrInvalidEndpointState
	}

	// WriteHeaderIncludedPacket takes ownership of pkt, calculate numBytes first.
	numBytes := pkt.Data.Size()

	if err := r.ref.ep.WriteHeaderIncludedPacket(r, pkt); err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
		return err
	}
	r.ref.nic.stats.Tx.Packets.Increment()
	r.ref.nic.stats.Tx.Bytes.IncrementBy(uint64(numBytes))
	return nil
}

// DefaultTTL returns the default TTL of the underlying network endpoint.
func (r *Route) DefaultTTL() uint8 {
	return r.ref.ep.DefaultTTL()
}

// MTU returns the MTU of the underlying network endpoint.
func (r *Route) MTU() uint32 {
	return r.ref.ep.MTU()
}

// NetworkProtocolNumber returns the NetworkProtocolNumber of the underlying
// network endpoint.
func (r *Route) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return r.ref.ep.NetworkProtocolNumber()
}

// Release frees all resources associated with the route.
func (r *Route) Release() {
	if r.ref != nil {
		r.ref.decRef()
		r.ref = nil
	}
}

// Clone Clone a route such that the original one can be released and the new
// one will remain valid.
func (r *Route) Clone() Route {
	if r.ref != nil {
		r.ref.incRef()
	}
	return *r
}

// MakeLoopedRoute duplicates the given route with special handling for routes
// used for sending multicast or broadcast packets. In those cases the
// multicast/broadcast address is the remote address when sending out, but for
// incoming (looped) packets it becomes the local address. Similarly, the local
// interface address that was the local address going out becomes the remote
// address coming in. This is different to unicast routes where local and
// remote addresses remain the same as they identify location (local vs remote)
// not direction (source vs destination).
func (r *Route) MakeLoopedRoute() Route {
	l := r.Clone()
	if r.RemoteAddress == header.IPv4Broadcast || header.IsV4MulticastAddress(r.RemoteAddress) || header.IsV6MulticastAddress(r.RemoteAddress) {
		l.RemoteAddress, l.LocalAddress = l.LocalAddress, l.RemoteAddress
		l.RemoteLinkAddress = l.LocalLinkAddress
	}
	return l
}

// Stack returns the instance of the Stack that owns this route.
func (r *Route) Stack() *Stack {
	return r.ref.stack()
}

// IsOutboundBroadcast returns true if the route is for an outbound broadcast
// packet.
func (r *Route) IsOutboundBroadcast() bool {
	// Only IPv4 has a notion of broadcast.
	return r.directedBroadcast || r.RemoteAddress == header.IPv4Broadcast
}

// IsInboundBroadcast returns true if the route is for an inbound broadcast
// packet.
func (r *Route) IsInboundBroadcast() bool {
	// Only IPv4 has a notion of broadcast.
	if r.LocalAddress == header.IPv4Broadcast {
		return true
	}

	addr := r.ref.addrWithPrefix()
	subnet := addr.Subnet()
	return subnet.IsBroadcast(r.LocalAddress)
}

// ReverseRoute returns new route with given source and destination address.
func (r *Route) ReverseRoute(src tcpip.Address, dst tcpip.Address) Route {
	return Route{
		NetProto:          r.NetProto,
		LocalAddress:      dst,
		LocalLinkAddress:  r.RemoteLinkAddress,
		RemoteAddress:     src,
		RemoteLinkAddress: r.LocalLinkAddress,
		ref:               r.ref,
		Loop:              r.Loop,
	}
}
