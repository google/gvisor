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
	"math/rand"
	"reflect"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// NetworkInterface is an interface that can be used by a NetworkEndpoint
type NetworkInterface interface {
	// ID returns the NetworkInterface's ID.
	ID() tcpip.NICID

	// IsLoopback returns true if the NetworkInterface is a loopback interface.
	IsLoopback() bool

	// Name returns the name of the interface.
	//
	// May return an empty string if the NIC is not configured with a name.
	Name() string
}

var _ NetworkInterface = (*NIC)(nil)

// NIC represents a "network interface card" to which the networking stack is
// attached.
type NIC struct {
	stack   *Stack
	id      tcpip.NICID
	name    string
	linkEP  LinkEndpoint
	context NICContext

	stats            NICStats
	neigh            *neighborCache
	networkEndpoints map[tcpip.NetworkProtocolNumber]NetworkEndpoint

	mu struct {
		sync.RWMutex
		enabled     bool
		spoofing    bool
		promiscuous bool
		// packetEPs is protected by mu, but the contained PacketEndpoint
		// values are not.
		packetEPs map[tcpip.NetworkProtocolNumber][]PacketEndpoint
	}
}

// NICStats includes transmitted and received stats.
type NICStats struct {
	Tx DirectionStats
	Rx DirectionStats

	DisabledRx DirectionStats
}

func makeNICStats() NICStats {
	var s NICStats
	tcpip.InitStatCounters(reflect.ValueOf(&s).Elem())
	return s
}

// DirectionStats includes packet and byte counts.
type DirectionStats struct {
	Packets *tcpip.StatCounter
	Bytes   *tcpip.StatCounter
}

// newNIC returns a new NIC using the default NDP configurations from stack.
func newNIC(stack *Stack, id tcpip.NICID, name string, ep LinkEndpoint, ctx NICContext) *NIC {
	// TODO(b/141011931): Validate a LinkEndpoint (ep) is valid. For
	// example, make sure that the link address it provides is a valid
	// unicast ethernet address.

	// TODO(b/143357959): RFC 8200 section 5 requires that IPv6 endpoints
	// observe an MTU of at least 1280 bytes. Ensure that this requirement
	// of IPv6 is supported on this endpoint's LinkEndpoint.

	nic := &NIC{
		stack:            stack,
		id:               id,
		name:             name,
		linkEP:           ep,
		context:          ctx,
		stats:            makeNICStats(),
		networkEndpoints: make(map[tcpip.NetworkProtocolNumber]NetworkEndpoint),
	}
	nic.mu.packetEPs = make(map[tcpip.NetworkProtocolNumber][]PacketEndpoint)

	// Check for Neighbor Unreachability Detection support.
	var nud NUDHandler
	if ep.Capabilities()&CapabilityResolutionRequired != 0 && len(stack.linkAddrResolvers) != 0 && stack.useNeighborCache {
		rng := rand.New(rand.NewSource(stack.clock.NowNanoseconds()))
		nic.neigh = &neighborCache{
			nic:   nic,
			state: NewNUDState(stack.nudConfigs, rng),
			cache: make(map[tcpip.Address]*neighborEntry, neighborCacheSize),
		}

		// An interface value that holds a nil pointer but non-nil type is not the
		// same as the nil interface. Because of this, nud must only be assignd if
		// nic.neigh is non-nil since a nil reference to a neighborCache is not
		// valid.
		//
		// See https://golang.org/doc/faq#nil_error for more information.
		nud = nic.neigh
	}

	// Register supported packet and network endpoint protocols.
	for _, netProto := range header.Ethertypes {
		nic.mu.packetEPs[netProto] = []PacketEndpoint{}
	}
	for _, netProto := range stack.networkProtocols {
		netNum := netProto.Number()
		nic.mu.packetEPs[netNum] = nil
		nic.networkEndpoints[netNum] = netProto.NewEndpoint(nic, stack, nud, nic, ep, stack)
	}

	nic.linkEP.Attach(nic)

	return nic
}

// enabled returns true if n is enabled.
func (n *NIC) enabled() bool {
	n.mu.RLock()
	enabled := n.mu.enabled
	n.mu.RUnlock()
	return enabled
}

// disable disables n.
//
// It undoes the work done by enable.
func (n *NIC) disable() *tcpip.Error {
	n.mu.RLock()
	enabled := n.mu.enabled
	n.mu.RUnlock()
	if !enabled {
		return nil
	}

	n.mu.Lock()
	err := n.disableLocked()
	n.mu.Unlock()
	return err
}

// disableLocked disables n.
//
// It undoes the work done by enable.
//
// n MUST be locked.
func (n *NIC) disableLocked() *tcpip.Error {
	if !n.mu.enabled {
		return nil
	}

	// TODO(gvisor.dev/issue/1491): Should Routes that are currently bound to n be
	// invalidated? Currently, Routes will continue to work when a NIC is enabled
	// again, and applications may not know that the underlying NIC was ever
	// disabled.

	for _, ep := range n.networkEndpoints {
		if err := ep.Disable(); err != nil {
			return err
		}
	}

	n.mu.enabled = false
	return nil
}

// enable enables n.
//
// If the stack has IPv6 enabled, enable will join the IPv6 All-Nodes Multicast
// address (ff02::1), start DAD for permanent addresses, and start soliciting
// routers if the stack is not operating as a router. If the stack is also
// configured to auto-generate a link-local address, one will be generated.
func (n *NIC) enable() *tcpip.Error {
	n.mu.RLock()
	enabled := n.mu.enabled
	n.mu.RUnlock()
	if enabled {
		return nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.mu.enabled {
		return nil
	}

	n.mu.enabled = true

	for _, ep := range n.networkEndpoints {
		if err := ep.Enable(); err != nil {
			return err
		}
	}

	return nil
}

// remove detaches NIC from the link endpoint, and marks existing referenced
// network endpoints expired. This guarantees no packets between this NIC and
// the network stack.
func (n *NIC) remove() *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.disableLocked()

	for p, ep := range n.networkEndpoints {
		// TODO(#3871): Should Close return errors?
		ep.Close()
		delete(n.networkEndpoints, p)
	}

	// Detach from link endpoint, so no packet comes in.
	n.linkEP.Attach(nil)

	return nil
}

// setPromiscuousMode enables or disables promiscuous mode.
func (n *NIC) setPromiscuousMode(enable bool) {
	n.mu.Lock()
	n.mu.promiscuous = enable
	n.mu.Unlock()
}

func (n *NIC) isPromiscuousMode() bool {
	n.mu.RLock()
	rv := n.mu.promiscuous
	n.mu.RUnlock()
	return rv
}

// IsLoopback implements NetworkInterface.
func (n *NIC) IsLoopback() bool {
	return n.linkEP.Capabilities()&CapabilityLoopback != 0
}

// setSpoofing enables or disables address spoofing.
func (n *NIC) setSpoofing(enable bool) {
	n.mu.Lock()
	n.mu.spoofing = enable
	n.mu.Unlock()
}

// primaryEndpoint will return the first non-deprecated endpoint if such an
// endpoint exists for the given protocol and remoteAddr. If no non-deprecated
// endpoint exists, the first deprecated endpoint will be returned.
//
// If an IPv6 primary endpoint is requested, Source Address Selection (as
// defined by RFC 6724 section 5) will be performed.
func (n *NIC) primaryEndpoint(protocol tcpip.NetworkProtocolNumber, remoteAddr tcpip.Address) *referencedNetworkEndpoint {
	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return nil
	}

	nep := ep.AcquirePrimaryAddress(remoteAddr, n.mu.spoofing)
	if nep == nil {
		return nil
	}

	return n.nepToRef(protocol, ep, nep)
}

type getRefBehaviour int

const (
	none getRefBehaviour = iota

	// spoofing indicates that the NIC's spoofing flag should be observed when
	// getting a NIC's referenced network endpoint.
	spoofing

	// promiscuous indicates that the NIC's promiscuous flag should be observed
	// when getting a NIC's referenced network endpoint.
	promiscuous
)

func (n *NIC) nepToRef(p tcpip.NetworkProtocolNumber, ep NetworkEndpoint, nep AddressEndpoint) *referencedNetworkEndpoint {
	ref := &referencedNetworkEndpoint{
		ep:  ep,
		nep: nep,
		nic: n,
	}

	// Set up cache if link address resolution exists for this protocol.
	if n.linkEP.Capabilities()&CapabilityResolutionRequired != 0 {
		if linkRes, ok := n.stack.linkAddrResolvers[p]; ok {
			ref.linkCache = n.stack
			ref.linkRes = linkRes
		}
	}

	return ref
}

func (n *NIC) getRef(protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) *referencedNetworkEndpoint {
	return n.getRefOrCreateTemp(protocol, dst, CanBePrimaryEndpoint, promiscuous)
}

// findEndpoint finds the endpoint, if any, with the given address.
func (n *NIC) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior) *referencedNetworkEndpoint {
	return n.getRefOrCreateTemp(protocol, address, peb, spoofing)
}

// getRefEpOrCreateTemp returns the referenced network endpoint for the given
// protocol and address.
//
// If none exists a temporary one may be created if we are in promiscuous mode
// or spoofing. Promiscuous mode will only be checked if promiscuous is true.
// Similarly, spoofing will only be checked if spoofing is true.
//
// If the address is the IPv4 broadcast address for an endpoint's network, that
// endpoint will be returned.
func (n *NIC) getRefOrCreateTemp(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior, tempRef getRefBehaviour) *referencedNetworkEndpoint {
	n.mu.RLock()
	var spoofingOrPromiscuous bool
	switch tempRef {
	case spoofing:
		spoofingOrPromiscuous = n.mu.spoofing
	case promiscuous:
		spoofingOrPromiscuous = n.mu.promiscuous
	}
	n.mu.RUnlock()
	return n.getRefOrCreateTempInner(protocol, address, spoofingOrPromiscuous, peb)
}

// getRefOrCreateTempInner is like getRefEpOrCreateTemp except a boolean is
// passed to indicate whether or not we should generate temporary endpoints.
func (n *NIC) getRefOrCreateTempInner(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, createTemp bool, peb PrimaryEndpointBehavior) *referencedNetworkEndpoint {
	if protocol == 0 {
		return nil
	}

	ep, ok := n.networkEndpoints[protocol]
	if ok {
		if nep := ep.AcquireAssignedAddress(address, createTemp, peb); nep != nil {
			return n.nepToRef(protocol, ep, nep)
		}
	}

	return nil
}

// addAddress adds a new address to n, so that it starts accepting packets
// targeted at the given address (and network protocol).
func (n *NIC) addAddress(protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior) *tcpip.Error {
	ep, ok := n.networkEndpoints[protocolAddress.Protocol]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}

	_, err := ep.AddPermanentAddress(protocolAddress.AddressWithPrefix, peb, AddressConfigStatic, false /* deprecated */)
	return err
}

// allPermanentAddresses returns all permanent addresses associated with
// this NIC.
func (n *NIC) allPermanentAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress
	for p, ep := range n.networkEndpoints {
		for _, a := range ep.AllPermanentAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

// primaryAddresses returns the primary addresses associated with this NIC.
func (n *NIC) primaryAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress
	for p, ep := range n.networkEndpoints {
		for _, a := range ep.PrimaryAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

// primaryAddress returns the primary address associated with this NIC.
//
// primaryAddress will return the first non-deprecated address if such an
// address exists. If no non-deprecated address exists, the first deprecated
// address will be returned.
func (n *NIC) primaryAddress(proto tcpip.NetworkProtocolNumber) tcpip.AddressWithPrefix {
	ref := n.primaryEndpoint(proto, "")
	if ref == nil {
		return tcpip.AddressWithPrefix{}
	}
	addr := ref.addrWithPrefix()
	ref.decRef()
	return addr
}

// removeAddress removes an address from n.
func (n *NIC) removeAddress(addr tcpip.Address) *tcpip.Error {
	for _, ep := range n.networkEndpoints {
		if err := ep.RemovePermanentAddress(addr); err == tcpip.ErrBadLocalAddress {
			continue
		} else {
			return err
		}
	}

	return tcpip.ErrBadLocalAddress
}

func (n *NIC) neighbors() ([]NeighborEntry, *tcpip.Error) {
	if n.neigh == nil {
		return nil, tcpip.ErrNotSupported
	}

	return n.neigh.entries(), nil
}

func (n *NIC) removeWaker(addr tcpip.Address, w *sleep.Waker) {
	if n.neigh == nil {
		return
	}

	n.neigh.removeWaker(addr, w)
}

func (n *NIC) addStaticNeighbor(addr tcpip.Address, linkAddress tcpip.LinkAddress) *tcpip.Error {
	if n.neigh == nil {
		return tcpip.ErrNotSupported
	}

	n.neigh.addStaticEntry(addr, linkAddress)
	return nil
}

func (n *NIC) removeNeighbor(addr tcpip.Address) *tcpip.Error {
	if n.neigh == nil {
		return tcpip.ErrNotSupported
	}

	if !n.neigh.removeEntry(addr) {
		return tcpip.ErrBadAddress
	}
	return nil
}

func (n *NIC) clearNeighbors() *tcpip.Error {
	if n.neigh == nil {
		return tcpip.ErrNotSupported
	}

	n.neigh.clear()
	return nil
}

// joinGroup adds a new endpoint for the given multicast address, if none
// exists yet. Otherwise it just increments its count.
func (n *NIC) joinGroup(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	// TODO(b/143102137): When implementing MLD, make sure MLD packets are
	// not sent unless a valid link-local address is available for use on n
	// as an MLD packet's source address must be a link-local address as
	// outlined in RFC 3810 section 5.

	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return tcpip.ErrNotSupported
	}

	gep, ok := ep.(GroupAddressableEndpoint)
	if !ok {
		return tcpip.ErrNotSupported
	}

	_, err := gep.JoinGroup(addr)
	return err
}

// leaveGroup decrements the count for the given multicast address, and when it
// reaches zero removes the endpoint for this address.
func (n *NIC) leaveGroup(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return tcpip.ErrNotSupported
	}

	gep, ok := ep.(GroupAddressableEndpoint)
	if !ok {
		return tcpip.ErrNotSupported
	}

	if _, err := gep.LeaveGroup(addr); err != nil {
		return err
	}

	return nil
}

// isInGroup returns true if n has joined the multicast group addr.
func (n *NIC) isInGroup(addr tcpip.Address) bool {
	for _, ep := range n.networkEndpoints {
		gep, ok := ep.(GroupAddressableEndpoint)
		if !ok {
			continue
		}

		if gep.IsInGroup(addr) {
			return true
		}
	}

	return false
}

func handlePacket(protocol tcpip.NetworkProtocolNumber, dst, src tcpip.Address, localLinkAddr, remotelinkAddr tcpip.LinkAddress, ref *referencedNetworkEndpoint, pkt *PacketBuffer) {
	r := makeRoute(protocol, dst, src, localLinkAddr, ref, false /* handleLocal */, false /* multicastLoop */)
	r.RemoteLinkAddress = remotelinkAddr

	ref.ep.HandlePacket(&r, pkt)
	ref.decRef()
}

// DeliverNetworkPacket finds the appropriate network protocol endpoint and
// hands the packet over for further processing. This function is called when
// the NIC receives a packet from the link endpoint.
// Note that the ownership of the slice backing vv is retained by the caller.
// This rule applies only to the slice itself, not to the items of the slice;
// the ownership of the items is not retained by the caller.
func (n *NIC) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	n.mu.RLock()
	enabled := n.mu.enabled
	// If the NIC is not yet enabled, don't receive any packets.
	if !enabled {
		n.mu.RUnlock()

		n.stats.DisabledRx.Packets.Increment()
		n.stats.DisabledRx.Bytes.IncrementBy(uint64(pkt.Data.Size()))
		return
	}

	n.stats.Rx.Packets.Increment()
	n.stats.Rx.Bytes.IncrementBy(uint64(pkt.Data.Size()))

	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		n.mu.RUnlock()
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	// If no local link layer address is provided, assume it was sent
	// directly to this NIC.
	if local == "" {
		local = n.linkEP.LinkAddress()
	}

	// Are any packet sockets listening for this network protocol?
	packetEPs := n.mu.packetEPs[protocol]
	// Add any other packet sockets that maybe listening for all protocols.
	packetEPs = append(packetEPs, n.mu.packetEPs[header.EthernetProtocolAll]...)
	n.mu.RUnlock()
	for _, ep := range packetEPs {
		p := pkt.Clone()
		p.PktType = tcpip.PacketHost
		ep.HandlePacket(n.id, local, protocol, p)
	}

	if netProto.Number() == header.IPv4ProtocolNumber || netProto.Number() == header.IPv6ProtocolNumber {
		n.stack.stats.IP.PacketsReceived.Increment()
	}

	// Parse headers.
	transProtoNum, hasTransportHdr, ok := netProto.Parse(pkt)
	if !ok {
		// The packet is too small to contain a network header.
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}
	if hasTransportHdr {
		// Parse the transport header if present.
		if state, ok := n.stack.transportProtocols[transProtoNum]; ok {
			state.proto.Parse(pkt)
		}
	}

	src, dst := netProto.ParseAddresses(pkt.NetworkHeader().View())

	if n.stack.handleLocal && !n.IsLoopback() && n.getRef(protocol, src) != nil {
		// The source address is one of our own, so we never should have gotten a
		// packet like this unless handleLocal is false. Loopback also calls this
		// function even though the packets didn't come from the physical interface
		// so don't drop those.
		n.stack.stats.IP.InvalidSourceAddressesReceived.Increment()
		return
	}

	// Loopback traffic skips the prerouting chain.
	if !n.IsLoopback() {
		// iptables filtering.
		ipt := n.stack.IPTables()
		address := n.primaryAddress(protocol)
		if ok := ipt.Check(Prerouting, pkt, nil, nil, address.Address, ""); !ok {
			// iptables is telling us to drop the packet.
			n.stack.stats.IP.IPTablesPreroutingDropped.Increment()
			return
		}
	}

	if ref := n.getRef(protocol, dst); ref != nil {
		handlePacket(protocol, dst, src, n.linkEP.LinkAddress(), remote, ref, pkt)
		return
	}

	// This NIC doesn't care about the packet. Find a NIC that cares about the
	// packet and forward it to the NIC.
	//
	// TODO: Should we be forwarding the packet even if promiscuous?
	if n.stack.Forwarding(protocol) {
		r, err := n.stack.FindRoute(0, "", dst, protocol, false /* multicastLoop */)
		if err != nil {
			n.stack.stats.IP.InvalidDestinationAddressesReceived.Increment()
			return
		}

		// Found a NIC.
		n := r.ref.nic
		ref := n.getRefOrCreateTempInner(protocol, dst, false, NeverPrimaryEndpoint)
		ok := ref != nil && ref.isValidForOutgoing()
		if ok {
			r.LocalLinkAddress = n.linkEP.LinkAddress()
			r.RemoteLinkAddress = remote
			r.RemoteAddress = src
			// TODO(b/123449044): Update the source NIC as well.
			ref.ep.HandlePacket(&r, pkt)
			ref.decRef()
			r.Release()
			return
		}

		// n doesn't have a destination endpoint.
		// Send the packet out of n.
		// TODO(b/128629022): move this logic to route.WritePacket.
		// TODO(gvisor.dev/issue/1085): According to the RFC, we must decrease the TTL field for ipv4/ipv6.
		if ch, err := r.Resolve(nil); err != nil {
			if err == tcpip.ErrWouldBlock {
				n.stack.forwarder.enqueue(ch, n, &r, protocol, pkt)
				// forwarder will release route.
				return
			}
			n.stack.stats.IP.InvalidDestinationAddressesReceived.Increment()
			r.Release()
			return
		}

		// The link-address resolution finished immediately.
		n.forwardPacket(&r, protocol, pkt)
		r.Release()
		return
	}

	// If a packet socket handled the packet, don't treat it as invalid.
	if len(packetEPs) == 0 {
		n.stack.stats.IP.InvalidDestinationAddressesReceived.Increment()
	}
}

// DeliverOutboundPacket implements NetworkDispatcher.DeliverOutboundPacket.
func (n *NIC) DeliverOutboundPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	n.mu.RLock()
	// We do not deliver to protocol specific packet endpoints as on Linux
	// only ETH_P_ALL endpoints get outbound packets.
	// Add any other packet sockets that maybe listening for all protocols.
	packetEPs := n.mu.packetEPs[header.EthernetProtocolAll]
	n.mu.RUnlock()
	for _, ep := range packetEPs {
		p := pkt.Clone()
		p.PktType = tcpip.PacketOutgoing
		// Add the link layer header as outgoing packets are intercepted
		// before the link layer header is created.
		n.linkEP.AddHeader(local, remote, protocol, p)
		ep.HandlePacket(n.id, local, protocol, p)
	}
}

func (n *NIC) forwardPacket(r *Route, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	// TODO(b/143425874) Decrease the TTL field in forwarded packets.

	// pkt may have set its header and may not have enough headroom for link-layer
	// header for the other link to prepend. Here we create a new packet to
	// forward.
	fwdPkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: int(n.linkEP.MaxHeaderLength()),
		Data:               buffer.NewVectorisedView(pkt.Size(), pkt.Views()),
	})

	// WritePacket takes ownership of fwdPkt, calculate numBytes first.
	numBytes := fwdPkt.Size()

	if err := n.linkEP.WritePacket(r, nil /* gso */, protocol, fwdPkt); err != nil {
		r.Stats().IP.OutgoingPacketErrors.Increment()
		return
	}

	n.stats.Tx.Packets.Increment()
	n.stats.Tx.Bytes.IncrementBy(uint64(numBytes))
}

// DeliverTransportPacket delivers the packets to the appropriate transport
// protocol endpoint.
func (n *NIC) DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) {
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	transProto := state.proto

	// Raw socket packets are delivered based solely on the transport
	// protocol number. We do not inspect the payload to ensure it's
	// validly formed.
	n.stack.demux.deliverRawPacket(r, protocol, pkt)

	// TransportHeader is empty only when pkt is an ICMP packet or was reassembled
	// from fragments.
	if pkt.TransportHeader().View().IsEmpty() {
		// TODO(gvisor.dev/issue/170): ICMP packets don't have their TransportHeader
		// fields set yet, parse it here. See icmp/protocol.go:protocol.Parse for a
		// full explanation.
		if protocol == header.ICMPv4ProtocolNumber || protocol == header.ICMPv6ProtocolNumber {
			// ICMP packets may be longer, but until icmp.Parse is implemented, here
			// we parse it using the minimum size.
			if _, ok := pkt.TransportHeader().Consume(transProto.MinimumPacketSize()); !ok {
				n.stack.stats.MalformedRcvdPackets.Increment()
				return
			}
		} else {
			// This is either a bad packet or was re-assembled from fragments.
			transProto.Parse(pkt)
		}
	}

	if pkt.TransportHeader().View().Size() < transProto.MinimumPacketSize() {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}

	srcPort, dstPort, err := transProto.ParsePorts(pkt.TransportHeader().View())
	if err != nil {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}

	id := TransportEndpointID{dstPort, r.LocalAddress, srcPort, r.RemoteAddress}
	if n.stack.demux.deliverPacket(r, protocol, pkt, id) {
		return
	}

	// Try to deliver to per-stack default handler.
	if state.defaultHandler != nil {
		if state.defaultHandler(r, id, pkt) {
			return
		}
	}

	// We could not find an appropriate destination for this packet, so
	// deliver it to the global handler.
	if !transProto.HandleUnknownDestinationPacket(r, id, pkt) {
		n.stack.stats.MalformedRcvdPackets.Increment()
	}
}

// DeliverTransportControlPacket delivers control packets to the appropriate
// transport protocol endpoint.
func (n *NIC) DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, pkt *PacketBuffer) {
	state, ok := n.stack.transportProtocols[trans]
	if !ok {
		return
	}

	transProto := state.proto

	// ICMPv4 only guarantees that 8 bytes of the transport protocol will
	// be present in the payload. We know that the ports are within the
	// first 8 bytes for all known transport protocols.
	transHeader, ok := pkt.Data.PullUp(8)
	if !ok {
		return
	}

	srcPort, dstPort, err := transProto.ParsePorts(transHeader)
	if err != nil {
		return
	}

	id := TransportEndpointID{srcPort, local, dstPort, remote}
	if n.stack.demux.deliverControlPacket(n, net, trans, typ, extra, pkt, id) {
		return
	}
}

// ID implements NetworkInterface.
func (n *NIC) ID() tcpip.NICID {
	return n.id
}

// Name implements NetworkInterface.
func (n *NIC) Name() string {
	return n.name
}

// LinkEndpoint returns the link endpoint of n.
func (n *NIC) LinkEndpoint() LinkEndpoint {
	return n.linkEP
}

// nudConfigs gets the NUD configurations for n.
func (n *NIC) nudConfigs() (NUDConfigurations, *tcpip.Error) {
	if n.neigh == nil {
		return NUDConfigurations{}, tcpip.ErrNotSupported
	}
	return n.neigh.config(), nil
}

// setNUDConfigs sets the NUD configurations for n.
//
// Note, if c contains invalid NUD configuration values, it will be fixed to
// use default values for the erroneous values.
func (n *NIC) setNUDConfigs(c NUDConfigurations) *tcpip.Error {
	if n.neigh == nil {
		return tcpip.ErrNotSupported
	}
	c.resetInvalidFields()
	n.neigh.setConfig(c)
	return nil
}

func (n *NIC) registerPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	eps, ok := n.mu.packetEPs[netProto]
	if !ok {
		return tcpip.ErrNotSupported
	}
	n.mu.packetEPs[netProto] = append(eps, ep)

	return nil
}

func (n *NIC) unregisterPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	n.mu.Lock()
	defer n.mu.Unlock()

	eps, ok := n.mu.packetEPs[netProto]
	if !ok {
		return
	}

	for i, epOther := range eps {
		if epOther == ep {
			n.mu.packetEPs[netProto] = append(eps[:i], eps[i+1:]...)
			return
		}
	}
}

type referencedNetworkEndpoint struct {
	ep  NetworkEndpoint
	nep AddressEndpoint
	nic *NIC

	// linkCache is set if link address resolution is enabled for this
	// protocol. Set to nil otherwise.
	linkCache LinkAddressCache

	// linkRes is set if link address resolution is enabled for this protocol.
	// Set to nil otherwise.
	linkRes LinkAddressResolver
}

func (r *referencedNetworkEndpoint) address() tcpip.Address {
	return r.nep.AddressWithPrefix().Address
}

func (r *referencedNetworkEndpoint) addrWithPrefix() tcpip.AddressWithPrefix {
	return r.nep.AddressWithPrefix()
}

// isValidForOutgoing returns true if the endpoint can be used to send out a
// packet. It requires the endpoint to not be marked expired (i.e., its address)
// has been removed) unless the NIC is in spoofing mode, or temporary.
func (r *referencedNetworkEndpoint) isValidForOutgoing() bool {
	r.nic.mu.RLock()
	enabled := r.nic.mu.enabled
	spoofing := r.nic.mu.spoofing
	r.nic.mu.RUnlock()

	return enabled && r.nep.IsAssigned(spoofing)
}

// decRef decrements the ref count and cleans up the endpoint once it reaches
// zero.
func (r *referencedNetworkEndpoint) decRef() {
	r.nep.DecRef()
}

// incRef increments the ref count. It must only be called when the caller is
// known to be holding a reference to the endpoint, otherwise tryIncRef should
// be used.
func (r *referencedNetworkEndpoint) incRef() {
	_ = r.nep.IncRef()
}

// stack returns the Stack instance that owns the underlying endpoint.
func (r *referencedNetworkEndpoint) stack() *Stack {
	return r.nic.stack
}
