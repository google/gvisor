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
	"fmt"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Route represents a route through the networking stack to a given destination.
//
// It is safe to call Route's methods from multiple goroutines.
//
// The exported fields are immutable.
//
// TODO(gvisor.dev/issue/4902): Unexpose immutable fields.
type Route struct {
	routeInfo

	// localAddressNIC is the interface the address is associated with.
	// TODO(gvisor.dev/issue/4548): Remove this field once we can query the
	// address's assigned status without the NIC.
	localAddressNIC *NIC

	mu struct {
		sync.RWMutex

		// localAddressEndpoint is the local address this route is associated with.
		localAddressEndpoint AssignableAddressEndpoint

		// remoteLinkAddress is the link-layer (MAC) address of the next hop in the
		// route.
		remoteLinkAddress tcpip.LinkAddress
	}

	// outgoingNIC is the interface this route uses to write packets.
	outgoingNIC *NIC

	// linkCache is set if link address resolution is enabled for this protocol on
	// the route's NIC.
	linkCache LinkAddressCache

	// linkRes is set if link address resolution is enabled for this protocol on
	// the route's NIC.
	linkRes LinkAddressResolver
}

type routeInfo struct {
	// RemoteAddress is the final destination of the route.
	RemoteAddress tcpip.Address

	// LocalAddress is the local address where the route starts.
	LocalAddress tcpip.Address

	// LocalLinkAddress is the link-layer (MAC) address of the
	// where the route starts.
	LocalLinkAddress tcpip.LinkAddress

	// NextHop is the next node in the path to the destination.
	NextHop tcpip.Address

	// NetProto is the network-layer protocol.
	NetProto tcpip.NetworkProtocolNumber

	// Loop controls where WritePacket should send packets.
	Loop PacketLooping
}

// RouteInfo contains all of Route's exported fields.
type RouteInfo struct {
	routeInfo

	// RemoteLinkAddress is the link-layer (MAC) address of the next hop in the
	// route.
	RemoteLinkAddress tcpip.LinkAddress
}

// Fields returns a RouteInfo with all of r's exported fields. This allows
// callers to store the route's fields without retaining a reference to it.
func (r *Route) Fields() RouteInfo {
	return RouteInfo{
		routeInfo:         r.routeInfo,
		RemoteLinkAddress: r.RemoteLinkAddress(),
	}
}

// constructAndValidateRoute validates and initializes a route. It takes
// ownership of the provided local address.
//
// Returns an empty route if validation fails.
func constructAndValidateRoute(netProto tcpip.NetworkProtocolNumber, addressEndpoint AssignableAddressEndpoint, localAddressNIC, outgoingNIC *NIC, gateway, localAddr, remoteAddr tcpip.Address, handleLocal, multicastLoop bool) *Route {
	if len(localAddr) == 0 {
		localAddr = addressEndpoint.AddressWithPrefix().Address
	}

	if localAddressNIC != outgoingNIC && header.IsV6LinkLocalAddress(localAddr) {
		addressEndpoint.DecRef()
		return nil
	}

	// If no remote address is provided, use the local address.
	if len(remoteAddr) == 0 {
		remoteAddr = localAddr
	}

	r := makeRoute(
		netProto,
		localAddr,
		remoteAddr,
		outgoingNIC,
		localAddressNIC,
		addressEndpoint,
		handleLocal,
		multicastLoop,
	)

	// If the route requires us to send a packet through some gateway, do not
	// broadcast it.
	if len(gateway) > 0 {
		r.NextHop = gateway
	} else if subnet := addressEndpoint.Subnet(); subnet.IsBroadcast(remoteAddr) {
		r.ResolveWith(header.EthernetBroadcastAddress)
	}

	return r
}

// makeRoute initializes a new route. It takes ownership of the provided
// AssignableAddressEndpoint.
func makeRoute(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *NIC, localAddressEndpoint AssignableAddressEndpoint, handleLocal, multicastLoop bool) *Route {
	if localAddressNIC.stack != outgoingNIC.stack {
		panic(fmt.Sprintf("cannot create a route with NICs from different stacks"))
	}

	if len(localAddr) == 0 {
		localAddr = localAddressEndpoint.AddressWithPrefix().Address
	}

	loop := PacketOut

	// TODO(gvisor.dev/issue/4689): Loopback interface loops back packets at the
	// link endpoint level. We can remove this check once loopback interfaces
	// loop back packets at the network layer.
	if !outgoingNIC.IsLoopback() {
		if handleLocal && localAddr != "" && remoteAddr == localAddr {
			loop = PacketLoop
		} else if multicastLoop && (header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)) {
			loop |= PacketLoop
		} else if remoteAddr == header.IPv4Broadcast {
			loop |= PacketLoop
		} else if subnet := localAddressEndpoint.AddressWithPrefix().Subnet(); subnet.IsBroadcast(remoteAddr) {
			loop |= PacketLoop
		}
	}

	return makeRouteInner(netProto, localAddr, remoteAddr, outgoingNIC, localAddressNIC, localAddressEndpoint, loop)
}

func makeRouteInner(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *NIC, localAddressEndpoint AssignableAddressEndpoint, loop PacketLooping) *Route {
	r := &Route{
		routeInfo: routeInfo{
			NetProto:         netProto,
			LocalAddress:     localAddr,
			LocalLinkAddress: outgoingNIC.LinkEndpoint.LinkAddress(),
			RemoteAddress:    remoteAddr,
			Loop:             loop,
		},
		localAddressNIC: localAddressNIC,
		outgoingNIC:     outgoingNIC,
	}

	r.mu.Lock()
	r.mu.localAddressEndpoint = localAddressEndpoint
	r.mu.Unlock()

	if r.outgoingNIC.LinkEndpoint.Capabilities()&CapabilityResolutionRequired != 0 {
		if linkRes, ok := r.outgoingNIC.stack.linkAddrResolvers[r.NetProto]; ok {
			r.linkRes = linkRes
			r.linkCache = r.outgoingNIC.stack
		}
	}

	return r
}

// makeLocalRoute initializes a new local route. It takes ownership of the
// provided AssignableAddressEndpoint.
//
// A local route is a route to a destination that is local to the stack.
func makeLocalRoute(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *NIC, localAddressEndpoint AssignableAddressEndpoint) *Route {
	loop := PacketLoop
	// TODO(gvisor.dev/issue/4689): Loopback interface loops back packets at the
	// link endpoint level. We can remove this check once loopback interfaces
	// loop back packets at the network layer.
	if outgoingNIC.IsLoopback() {
		loop = PacketOut
	}
	return makeRouteInner(netProto, localAddr, remoteAddr, outgoingNIC, localAddressNIC, localAddressEndpoint, loop)
}

// RemoteLinkAddress returns the link-layer (MAC) address of the next hop in
// the route.
func (r *Route) RemoteLinkAddress() tcpip.LinkAddress {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mu.remoteLinkAddress
}

// NICID returns the id of the NIC from which this route originates.
func (r *Route) NICID() tcpip.NICID {
	return r.outgoingNIC.ID()
}

// MaxHeaderLength forwards the call to the network endpoint's implementation.
func (r *Route) MaxHeaderLength() uint16 {
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto).MaxHeaderLength()
}

// Stats returns a mutable copy of current stats.
func (r *Route) Stats() tcpip.Stats {
	return r.outgoingNIC.stack.Stats()
}

// PseudoHeaderChecksum forwards the call to the network endpoint's
// implementation.
func (r *Route) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, totalLen uint16) uint16 {
	return header.PseudoHeaderChecksum(protocol, r.LocalAddress, r.RemoteAddress, totalLen)
}

// RequiresTXTransportChecksum returns false if the route does not require
// transport checksums to be populated.
func (r *Route) RequiresTXTransportChecksum() bool {
	if r.local() {
		return false
	}
	return r.outgoingNIC.LinkEndpoint.Capabilities()&CapabilityTXChecksumOffload == 0
}

// HasSoftwareGSOCapability returns true if the route supports software GSO.
func (r *Route) HasSoftwareGSOCapability() bool {
	return r.outgoingNIC.LinkEndpoint.Capabilities()&CapabilitySoftwareGSO != 0
}

// HasHardwareGSOCapability returns true if the route supports hardware GSO.
func (r *Route) HasHardwareGSOCapability() bool {
	return r.outgoingNIC.LinkEndpoint.Capabilities()&CapabilityHardwareGSO != 0
}

// HasSaveRestoreCapability returns true if the route supports save/restore.
func (r *Route) HasSaveRestoreCapability() bool {
	return r.outgoingNIC.LinkEndpoint.Capabilities()&CapabilitySaveRestore != 0
}

// HasDisconncetOkCapability returns true if the route supports disconnecting.
func (r *Route) HasDisconncetOkCapability() bool {
	return r.outgoingNIC.LinkEndpoint.Capabilities()&CapabilityDisconnectOk != 0
}

// GSOMaxSize returns the maximum GSO packet size.
func (r *Route) GSOMaxSize() uint32 {
	if gso, ok := r.outgoingNIC.LinkEndpoint.(GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

// ResolveWith immediately resolves a route with the specified remote link
// address.
func (r *Route) ResolveWith(addr tcpip.LinkAddress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mu.remoteLinkAddress = addr
}

// Resolve attempts to resolve the link address if necessary.
//
// Returns tcpip.ErrWouldBlock if address resolution requires blocking (e.g.
// waiting for ARP reply). If address resolution is required, a notification
// channel is also returned for the caller to block on. The channel is closed
// once address resolution is complete (successful or not). If a callback is
// provided, it will be called when address resolution is complete, regardless
// of success or failure.
func (r *Route) Resolve(afterResolve func()) (<-chan struct{}, *tcpip.Error) {
	r.mu.Lock()

	if !r.isResolutionRequiredRLocked() {
		// Nothing to do if there is no cache (which does the resolution on cache miss) or
		// link address is already known.
		r.mu.Unlock()
		return nil, nil
	}

	nextAddr := r.NextHop
	if nextAddr == "" {
		// Local link address is already known.
		if r.RemoteAddress == r.LocalAddress {
			r.mu.remoteLinkAddress = r.LocalLinkAddress
			r.mu.Unlock()
			return nil, nil
		}
		nextAddr = r.RemoteAddress
	}

	// If specified, the local address used for link address resolution must be an
	// address on the outgoing interface.
	var linkAddressResolutionRequestLocalAddr tcpip.Address
	if r.localAddressNIC == r.outgoingNIC {
		linkAddressResolutionRequestLocalAddr = r.LocalAddress
	}

	// Increment the route's reference count because finishResolution retains a
	// reference to the route and releases it when called.
	r.acquireLocked()
	r.mu.Unlock()

	finishResolution := func(linkAddress tcpip.LinkAddress, ok bool) {
		if ok {
			r.ResolveWith(linkAddress)
		}
		if afterResolve != nil {
			afterResolve()
		}
		r.Release()
	}

	if neigh := r.outgoingNIC.neigh; neigh != nil {
		_, ch, err := neigh.entry(nextAddr, linkAddressResolutionRequestLocalAddr, r.linkRes, finishResolution)
		if err != nil {
			return ch, err
		}
		return nil, nil
	}

	_, ch, err := r.linkCache.GetLinkAddress(r.outgoingNIC.ID(), nextAddr, linkAddressResolutionRequestLocalAddr, r.NetProto, finishResolution)
	if err != nil {
		return ch, err
	}
	return nil, nil
}

// local returns true if the route is a local route.
func (r *Route) local() bool {
	return r.Loop == PacketLoop || r.outgoingNIC.IsLoopback()
}

// IsResolutionRequired returns true if Resolve() must be called to resolve
// the link address before the route can be written to.
//
// The NICs the route is associated with must not be locked.
func (r *Route) IsResolutionRequired() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isResolutionRequiredRLocked()
}

func (r *Route) isResolutionRequiredRLocked() bool {
	if !r.isValidForOutgoingRLocked() || r.mu.remoteLinkAddress != "" || r.local() {
		return false
	}

	return (r.outgoingNIC.neigh != nil && r.linkRes != nil) || r.linkCache != nil
}

func (r *Route) isValidForOutgoing() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isValidForOutgoingRLocked()
}

func (r *Route) isValidForOutgoingRLocked() bool {
	if !r.outgoingNIC.Enabled() {
		return false
	}

	localAddressEndpoint := r.mu.localAddressEndpoint
	if localAddressEndpoint == nil || !r.localAddressNIC.isValidForOutgoing(localAddressEndpoint) {
		return false
	}

	// If the source NIC and outgoing NIC are different, make sure the stack has
	// forwarding enabled, or the packet will be handled locally.
	if r.outgoingNIC != r.localAddressNIC && !r.outgoingNIC.stack.Forwarding(r.NetProto) && (!r.outgoingNIC.stack.handleLocal || !r.outgoingNIC.hasAddress(r.NetProto, r.RemoteAddress)) {
		return false
	}

	return true
}

// WritePacket writes the packet through the given route.
func (r *Route) WritePacket(gso *GSO, params NetworkHeaderParams, pkt *PacketBuffer) *tcpip.Error {
	if !r.isValidForOutgoing() {
		return tcpip.ErrInvalidEndpointState
	}

	return r.outgoingNIC.getNetworkEndpoint(r.NetProto).WritePacket(r, gso, params, pkt)
}

// WritePackets writes a list of n packets through the given route and returns
// the number of packets written.
func (r *Route) WritePackets(gso *GSO, pkts PacketBufferList, params NetworkHeaderParams) (int, *tcpip.Error) {
	if !r.isValidForOutgoing() {
		return 0, tcpip.ErrInvalidEndpointState
	}

	return r.outgoingNIC.getNetworkEndpoint(r.NetProto).WritePackets(r, gso, pkts, params)
}

// WriteHeaderIncludedPacket writes a packet already containing a network
// header through the given route.
func (r *Route) WriteHeaderIncludedPacket(pkt *PacketBuffer) *tcpip.Error {
	if !r.isValidForOutgoing() {
		return tcpip.ErrInvalidEndpointState
	}

	return r.outgoingNIC.getNetworkEndpoint(r.NetProto).WriteHeaderIncludedPacket(r, pkt)
}

// DefaultTTL returns the default TTL of the underlying network endpoint.
func (r *Route) DefaultTTL() uint8 {
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto).DefaultTTL()
}

// MTU returns the MTU of the underlying network endpoint.
func (r *Route) MTU() uint32 {
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto).MTU()
}

// Release decrements the reference counter of the resources associated with the
// route.
func (r *Route) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ep := r.mu.localAddressEndpoint; ep != nil {
		ep.DecRef()
	}
}

// Acquire increments the reference counter of the resources associated with the
// route.
func (r *Route) Acquire() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.acquireLocked()
}

func (r *Route) acquireLocked() {
	if ep := r.mu.localAddressEndpoint; ep != nil {
		if !ep.IncRef() {
			panic(fmt.Sprintf("failed to increment reference count for local address endpoint = %s", r.LocalAddress))
		}
	}
}

// Stack returns the instance of the Stack that owns this route.
func (r *Route) Stack() *Stack {
	return r.outgoingNIC.stack
}

func (r *Route) isV4Broadcast(addr tcpip.Address) bool {
	if addr == header.IPv4Broadcast {
		return true
	}

	r.mu.RLock()
	localAddressEndpoint := r.mu.localAddressEndpoint
	r.mu.RUnlock()
	if localAddressEndpoint == nil {
		return false
	}

	subnet := localAddressEndpoint.Subnet()
	return subnet.IsBroadcast(addr)
}

// IsOutboundBroadcast returns true if the route is for an outbound broadcast
// packet.
func (r *Route) IsOutboundBroadcast() bool {
	// Only IPv4 has a notion of broadcast.
	return r.isV4Broadcast(r.RemoteAddress)
}
