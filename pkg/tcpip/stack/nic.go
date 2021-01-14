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
	"math/rand"
	"reflect"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var _ NetworkInterface = (*NIC)(nil)

// NIC represents a "network interface card" to which the networking stack is
// attached.
type NIC struct {
	LinkEndpoint

	stack   *Stack
	id      tcpip.NICID
	name    string
	context NICContext

	stats NICStats
	neigh *neighborCache

	// The network endpoints themselves may be modified by calling the interface's
	// methods, but the map reference and entries must be constant.
	networkEndpoints map[tcpip.NetworkProtocolNumber]NetworkEndpoint

	// enabled is set to 1 when the NIC is enabled and 0 when it is disabled.
	//
	// Must be accessed using atomic operations.
	enabled uint32

	mu struct {
		sync.RWMutex
		spoofing    bool
		promiscuous bool
		// packetEPs is protected by mu, but the contained packetEndpointList are
		// not.
		packetEPs map[tcpip.NetworkProtocolNumber]*packetEndpointList
	}
}

// NICStats hold statistics for a NIC.
type NICStats struct {
	Tx DirectionStats
	Rx DirectionStats

	DisabledRx DirectionStats

	Neighbor NeighborStats
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

type packetEndpointList struct {
	mu sync.RWMutex

	// eps is protected by mu, but the contained PacketEndpoint values are not.
	eps []PacketEndpoint
}

func (p *packetEndpointList) add(ep PacketEndpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.eps = append(p.eps, ep)
}

func (p *packetEndpointList) remove(ep PacketEndpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, epOther := range p.eps {
		if epOther == ep {
			p.eps = append(p.eps[:i], p.eps[i+1:]...)
			break
		}
	}
}

// forEach calls fn with each endpoints in p while holding the read lock on p.
func (p *packetEndpointList) forEach(fn func(PacketEndpoint)) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, ep := range p.eps {
		fn(ep)
	}
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
		LinkEndpoint: ep,

		stack:            stack,
		id:               id,
		name:             name,
		context:          ctx,
		stats:            makeNICStats(),
		networkEndpoints: make(map[tcpip.NetworkProtocolNumber]NetworkEndpoint),
	}
	nic.mu.packetEPs = make(map[tcpip.NetworkProtocolNumber]*packetEndpointList)

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
		nic.mu.packetEPs[netProto] = new(packetEndpointList)
	}
	for _, netProto := range stack.networkProtocols {
		netNum := netProto.Number()
		nic.mu.packetEPs[netNum] = new(packetEndpointList)
		nic.networkEndpoints[netNum] = netProto.NewEndpoint(nic, stack, nud, nic)
	}

	nic.LinkEndpoint.Attach(nic)

	return nic
}

func (n *NIC) getNetworkEndpoint(proto tcpip.NetworkProtocolNumber) NetworkEndpoint {
	return n.networkEndpoints[proto]
}

// Enabled implements NetworkInterface.
func (n *NIC) Enabled() bool {
	return atomic.LoadUint32(&n.enabled) == 1
}

// setEnabled sets the enabled status for the NIC.
//
// Returns true if the enabled status was updated.
func (n *NIC) setEnabled(v bool) bool {
	if v {
		return atomic.SwapUint32(&n.enabled, 1) == 0
	}
	return atomic.SwapUint32(&n.enabled, 0) == 1
}

// disable disables n.
//
// It undoes the work done by enable.
func (n *NIC) disable() {
	n.mu.Lock()
	n.disableLocked()
	n.mu.Unlock()
}

// disableLocked disables n.
//
// It undoes the work done by enable.
//
// n MUST be locked.
func (n *NIC) disableLocked() {
	if !n.Enabled() {
		return
	}

	// TODO(gvisor.dev/issue/1491): Should Routes that are currently bound to n be
	// invalidated? Currently, Routes will continue to work when a NIC is enabled
	// again, and applications may not know that the underlying NIC was ever
	// disabled.

	for _, ep := range n.networkEndpoints {
		ep.Disable()
	}

	// Clear the neighbour table (including static entries) as we cannot guarantee
	// that the current neighbour table will be valid when the NIC is enabled
	// again.
	//
	// This matches linux's behaviour at the time of writing:
	// https://github.com/torvalds/linux/blob/71c061d2443814de15e177489d5cc00a4a253ef3/net/core/neighbour.c#L371
	if err := n.clearNeighbors(); err != nil && err != tcpip.ErrNotSupported {
		panic(fmt.Sprintf("n.clearNeighbors(): %s", err))
	}

	if !n.setEnabled(false) {
		panic("should have only done work to disable the NIC if it was enabled")
	}
}

// enable enables n.
//
// If the stack has IPv6 enabled, enable will join the IPv6 All-Nodes Multicast
// address (ff02::1), start DAD for permanent addresses, and start soliciting
// routers if the stack is not operating as a router. If the stack is also
// configured to auto-generate a link-local address, one will be generated.
func (n *NIC) enable() *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.setEnabled(true) {
		return nil
	}

	for _, ep := range n.networkEndpoints {
		if err := ep.Enable(); err != nil {
			return err
		}
	}

	return nil
}

// remove detaches NIC from the link endpoint and releases network endpoint
// resources. This guarantees no packets between this NIC and the network
// stack.
func (n *NIC) remove() *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.disableLocked()

	for _, ep := range n.networkEndpoints {
		ep.Close()
	}

	// Detach from link endpoint, so no packet comes in.
	n.LinkEndpoint.Attach(nil)
	return nil
}

// setPromiscuousMode enables or disables promiscuous mode.
func (n *NIC) setPromiscuousMode(enable bool) {
	n.mu.Lock()
	n.mu.promiscuous = enable
	n.mu.Unlock()
}

// Promiscuous implements NetworkInterface.
func (n *NIC) Promiscuous() bool {
	n.mu.RLock()
	rv := n.mu.promiscuous
	n.mu.RUnlock()
	return rv
}

// IsLoopback implements NetworkInterface.
func (n *NIC) IsLoopback() bool {
	return n.LinkEndpoint.Capabilities()&CapabilityLoopback != 0
}

// WritePacket implements NetworkLinkEndpoint.
func (n *NIC) WritePacket(r *Route, gso *GSO, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) *tcpip.Error {
	// As per relevant RFCs, we should queue packets while we wait for link
	// resolution to complete.
	//
	// RFC 1122 section 2.3.2.2 (for IPv4):
	//   The link layer SHOULD save (rather than discard) at least
	//   one (the latest) packet of each set of packets destined to
	//   the same unresolved IP address, and transmit the saved
	//   packet when the address has been resolved.
	//
	// RFC 4861 section 7.2.2 (for IPv6):
	//   While waiting for address resolution to complete, the sender MUST, for
	//   each neighbor, retain a small queue of packets waiting for address
	//   resolution to complete. The queue MUST hold at least one packet, and MAY
	//   contain more. However, the number of queued packets per neighbor SHOULD
	//   be limited to some small value. When a queue overflows, the new arrival
	//   SHOULD replace the oldest entry. Once address resolution completes, the
	//   node transmits any queued packets.
	if ch, err := r.Resolve(nil); err != nil {
		if err == tcpip.ErrWouldBlock {
			r.Acquire()
			n.stack.linkResQueue.enqueue(ch, r, protocol, pkt)
			return nil
		}
		return err
	}

	return n.writePacket(r, gso, protocol, pkt)
}

// WritePacketToRemote implements NetworkInterface.
func (n *NIC) WritePacketToRemote(remoteLinkAddr tcpip.LinkAddress, gso *GSO, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) *tcpip.Error {
	r := Route{
		routeInfo: routeInfo{
			NetProto: protocol,
		},
	}
	r.ResolveWith(remoteLinkAddr)
	return n.writePacket(&r, gso, protocol, pkt)
}

func (n *NIC) writePacket(r *Route, gso *GSO, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) *tcpip.Error {
	// WritePacket takes ownership of pkt, calculate numBytes first.
	numBytes := pkt.Size()

	if err := n.LinkEndpoint.WritePacket(r, gso, protocol, pkt); err != nil {
		return err
	}

	n.stats.Tx.Packets.Increment()
	n.stats.Tx.Bytes.IncrementBy(uint64(numBytes))
	return nil
}

// WritePackets implements NetworkLinkEndpoint.
func (n *NIC) WritePackets(r *Route, gso *GSO, pkts PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	// TODO(gvisor.dev/issue/4458): Queue packets whie link address resolution
	// is being peformed like WritePacket.
	writtenPackets, err := n.LinkEndpoint.WritePackets(r, gso, pkts, protocol)
	n.stats.Tx.Packets.IncrementBy(uint64(writtenPackets))
	writtenBytes := 0
	for i, pb := 0, pkts.Front(); i < writtenPackets && pb != nil; i, pb = i+1, pb.Next() {
		writtenBytes += pb.Size()
	}

	n.stats.Tx.Bytes.IncrementBy(uint64(writtenBytes))
	return writtenPackets, err
}

// setSpoofing enables or disables address spoofing.
func (n *NIC) setSpoofing(enable bool) {
	n.mu.Lock()
	n.mu.spoofing = enable
	n.mu.Unlock()
}

// primaryAddress returns an address that can be used to communicate with
// remoteAddr.
func (n *NIC) primaryEndpoint(protocol tcpip.NetworkProtocolNumber, remoteAddr tcpip.Address) AssignableAddressEndpoint {
	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return nil
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return nil
	}

	n.mu.RLock()
	spoofing := n.mu.spoofing
	n.mu.RUnlock()

	return addressableEndpoint.AcquireOutgoingPrimaryAddress(remoteAddr, spoofing)
}

type getAddressBehaviour int

const (
	// spoofing indicates that the NIC's spoofing flag should be observed when
	// getting a NIC's address endpoint.
	spoofing getAddressBehaviour = iota

	// promiscuous indicates that the NIC's promiscuous flag should be observed
	// when getting a NIC's address endpoint.
	promiscuous
)

func (n *NIC) getAddress(protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) AssignableAddressEndpoint {
	return n.getAddressOrCreateTemp(protocol, dst, CanBePrimaryEndpoint, promiscuous)
}

func (n *NIC) hasAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	ep := n.getAddressOrCreateTempInner(protocol, addr, false, NeverPrimaryEndpoint)
	if ep != nil {
		ep.DecRef()
		return true
	}

	return false
}

// findEndpoint finds the endpoint, if any, with the given address.
func (n *NIC) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior) AssignableAddressEndpoint {
	return n.getAddressOrCreateTemp(protocol, address, peb, spoofing)
}

// getAddressEpOrCreateTemp returns the address endpoint for the given protocol
// and address.
//
// If none exists a temporary one may be created if we are in promiscuous mode
// or spoofing. Promiscuous mode will only be checked if promiscuous is true.
// Similarly, spoofing will only be checked if spoofing is true.
//
// If the address is the IPv4 broadcast address for an endpoint's network, that
// endpoint will be returned.
func (n *NIC) getAddressOrCreateTemp(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior, tempRef getAddressBehaviour) AssignableAddressEndpoint {
	n.mu.RLock()
	var spoofingOrPromiscuous bool
	switch tempRef {
	case spoofing:
		spoofingOrPromiscuous = n.mu.spoofing
	case promiscuous:
		spoofingOrPromiscuous = n.mu.promiscuous
	}
	n.mu.RUnlock()
	return n.getAddressOrCreateTempInner(protocol, address, spoofingOrPromiscuous, peb)
}

// getAddressOrCreateTempInner is like getAddressEpOrCreateTemp except a boolean
// is passed to indicate whether or not we should generate temporary endpoints.
func (n *NIC) getAddressOrCreateTempInner(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, createTemp bool, peb PrimaryEndpointBehavior) AssignableAddressEndpoint {
	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return nil
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return nil
	}

	return addressableEndpoint.AcquireAssignedAddress(address, createTemp, peb)
}

// addAddress adds a new address to n, so that it starts accepting packets
// targeted at the given address (and network protocol).
func (n *NIC) addAddress(protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior) *tcpip.Error {
	ep, ok := n.networkEndpoints[protocolAddress.Protocol]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return tcpip.ErrNotSupported
	}

	addressEndpoint, err := addressableEndpoint.AddAndAcquirePermanentAddress(protocolAddress.AddressWithPrefix, peb, AddressConfigStatic, false /* deprecated */)
	if err == nil {
		// We have no need for the address endpoint.
		addressEndpoint.DecRef()
	}
	return err
}

// allPermanentAddresses returns all permanent addresses associated with
// this NIC.
func (n *NIC) allPermanentAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress
	for p, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		for _, a := range addressableEndpoint.PermanentAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

// primaryAddresses returns the primary addresses associated with this NIC.
func (n *NIC) primaryAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress
	for p, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		for _, a := range addressableEndpoint.PrimaryAddresses() {
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
	ep, ok := n.networkEndpoints[proto]
	if !ok {
		return tcpip.AddressWithPrefix{}
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return tcpip.AddressWithPrefix{}
	}

	return addressableEndpoint.MainAddress()
}

// removeAddress removes an address from n.
func (n *NIC) removeAddress(addr tcpip.Address) *tcpip.Error {
	for _, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		if err := addressableEndpoint.RemovePermanentAddress(addr); err == tcpip.ErrBadLocalAddress {
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

	return gep.JoinGroup(addr)
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

	return gep.LeaveGroup(addr)
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

// DeliverNetworkPacket finds the appropriate network protocol endpoint and
// hands the packet over for further processing. This function is called when
// the NIC receives a packet from the link endpoint.
// Note that the ownership of the slice backing vv is retained by the caller.
// This rule applies only to the slice itself, not to the items of the slice;
// the ownership of the items is not retained by the caller.
func (n *NIC) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	n.mu.RLock()
	enabled := n.Enabled()
	// If the NIC is not yet enabled, don't receive any packets.
	if !enabled {
		n.mu.RUnlock()

		n.stats.DisabledRx.Packets.Increment()
		n.stats.DisabledRx.Bytes.IncrementBy(uint64(pkt.Data.Size()))
		return
	}

	n.stats.Rx.Packets.Increment()
	n.stats.Rx.Bytes.IncrementBy(uint64(pkt.Data.Size()))

	networkEndpoint, ok := n.networkEndpoints[protocol]
	if !ok {
		n.mu.RUnlock()
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	// If no local link layer address is provided, assume it was sent
	// directly to this NIC.
	if local == "" {
		local = n.LinkEndpoint.LinkAddress()
	}
	pkt.RXTransportChecksumValidated = n.LinkEndpoint.Capabilities()&CapabilityRXChecksumOffload != 0

	// Are any packet type sockets listening for this network protocol?
	protoEPs := n.mu.packetEPs[protocol]
	// Other packet type sockets that are listening for all protocols.
	anyEPs := n.mu.packetEPs[header.EthernetProtocolAll]
	n.mu.RUnlock()

	// Deliver to interested packet endpoints without holding NIC lock.
	deliverPacketEPs := func(ep PacketEndpoint) {
		p := pkt.Clone()
		p.PktType = tcpip.PacketHost
		ep.HandlePacket(n.id, local, protocol, p)
	}
	if protoEPs != nil {
		protoEPs.forEach(deliverPacketEPs)
	}
	if anyEPs != nil {
		anyEPs.forEach(deliverPacketEPs)
	}

	// Parse headers.
	netProto := n.stack.NetworkProtocolInstance(protocol)
	transProtoNum, hasTransportHdr, ok := netProto.Parse(pkt)
	if !ok {
		// The packet is too small to contain a network header.
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}
	if hasTransportHdr {
		pkt.TransportProtocolNumber = transProtoNum
		// Parse the transport header if present.
		if state, ok := n.stack.transportProtocols[transProtoNum]; ok {
			state.proto.Parse(pkt)
		}
	}

	if n.stack.handleLocal && !n.IsLoopback() {
		src, _ := netProto.ParseAddresses(pkt.NetworkHeader().View())
		if r := n.getAddress(protocol, src); r != nil {
			r.DecRef()

			// The source address is one of our own, so we never should have gotten a
			// packet like this unless handleLocal is false. Loopback also calls this
			// function even though the packets didn't come from the physical interface
			// so don't drop those.
			n.stack.stats.IP.InvalidSourceAddressesReceived.Increment()
			return
		}
	}

	networkEndpoint.HandlePacket(pkt)
}

// DeliverOutboundPacket implements NetworkDispatcher.DeliverOutboundPacket.
func (n *NIC) DeliverOutboundPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	n.mu.RLock()
	// We do not deliver to protocol specific packet endpoints as on Linux
	// only ETH_P_ALL endpoints get outbound packets.
	// Add any other packet sockets that maybe listening for all protocols.
	eps := n.mu.packetEPs[header.EthernetProtocolAll]
	n.mu.RUnlock()

	eps.forEach(func(ep PacketEndpoint) {
		p := pkt.Clone()
		p.PktType = tcpip.PacketOutgoing
		// Add the link layer header as outgoing packets are intercepted
		// before the link layer header is created.
		n.LinkEndpoint.AddHeader(local, remote, protocol, p)
		ep.HandlePacket(n.id, local, protocol, p)
	})
}

// DeliverTransportPacket delivers the packets to the appropriate transport
// protocol endpoint.
func (n *NIC) DeliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) TransportPacketDisposition {
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return TransportPacketProtocolUnreachable
	}

	transProto := state.proto

	// Raw socket packets are delivered based solely on the transport
	// protocol number. We do not inspect the payload to ensure it's
	// validly formed.
	n.stack.demux.deliverRawPacket(protocol, pkt)

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
				// We consider a malformed transport packet handled because there is
				// nothing the caller can do.
				return TransportPacketHandled
			}
		} else if !transProto.Parse(pkt) {
			n.stack.stats.MalformedRcvdPackets.Increment()
			return TransportPacketHandled
		}
	}

	srcPort, dstPort, err := transProto.ParsePorts(pkt.TransportHeader().View())
	if err != nil {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return TransportPacketHandled
	}

	netProto, ok := n.stack.networkProtocols[pkt.NetworkProtocolNumber]
	if !ok {
		panic(fmt.Sprintf("expected network protocol = %d, have = %#v", pkt.NetworkProtocolNumber, n.stack.networkProtocolNumbers()))
	}

	src, dst := netProto.ParseAddresses(pkt.NetworkHeader().View())
	id := TransportEndpointID{
		LocalPort:     dstPort,
		LocalAddress:  dst,
		RemotePort:    srcPort,
		RemoteAddress: src,
	}
	if n.stack.demux.deliverPacket(protocol, pkt, id) {
		return TransportPacketHandled
	}

	// Try to deliver to per-stack default handler.
	if state.defaultHandler != nil {
		if state.defaultHandler(id, pkt) {
			return TransportPacketHandled
		}
	}

	// We could not find an appropriate destination for this packet so
	// give the protocol specific error handler a chance to handle it.
	// If it doesn't handle it then we should do so.
	switch res := transProto.HandleUnknownDestinationPacket(id, pkt); res {
	case UnknownDestinationPacketMalformed:
		n.stack.stats.MalformedRcvdPackets.Increment()
		return TransportPacketHandled
	case UnknownDestinationPacketUnhandled:
		return TransportPacketDestinationPortUnreachable
	case UnknownDestinationPacketHandled:
		return TransportPacketHandled
	default:
		panic(fmt.Sprintf("unrecognized result from HandleUnknownDestinationPacket = %d", res))
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
	eps.add(ep)

	return nil
}

func (n *NIC) unregisterPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	n.mu.Lock()
	defer n.mu.Unlock()

	eps, ok := n.mu.packetEPs[netProto]
	if !ok {
		return
	}
	eps.remove(ep)
}

// isValidForOutgoing returns true if the endpoint can be used to send out a
// packet. It requires the endpoint to not be marked expired (i.e., its address
// has been removed) unless the NIC is in spoofing mode, or temporary.
func (n *NIC) isValidForOutgoing(ep AssignableAddressEndpoint) bool {
	n.mu.RLock()
	spoofing := n.mu.spoofing
	n.mu.RUnlock()
	return n.Enabled() && ep.IsAssigned(spoofing)
}
