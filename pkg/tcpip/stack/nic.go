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
	"strings"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/ilist"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// NIC represents a "network interface card" to which the networking stack is
// attached.
type NIC struct {
	stack    *Stack
	id       tcpip.NICID
	name     string
	linkEP   LinkEndpoint
	loopback bool

	mu            sync.RWMutex
	spoofing      bool
	promiscuous   bool
	primary       map[tcpip.NetworkProtocolNumber]*ilist.List
	endpoints     map[NetworkEndpointID]*referencedNetworkEndpoint
	addressRanges []tcpip.Subnet
	mcastJoins    map[NetworkEndpointID]int32

	stats NICStats
}

// NICStats includes transmitted and received stats.
type NICStats struct {
	Tx DirectionStats
	Rx DirectionStats
}

// DirectionStats includes packet and byte counts.
type DirectionStats struct {
	Packets *tcpip.StatCounter
	Bytes   *tcpip.StatCounter
}

// PrimaryEndpointBehavior is an enumeration of an endpoint's primacy behavior.
type PrimaryEndpointBehavior int

const (
	// CanBePrimaryEndpoint indicates the endpoint can be used as a primary
	// endpoint for new connections with no local address. This is the
	// default when calling NIC.AddAddress.
	CanBePrimaryEndpoint PrimaryEndpointBehavior = iota

	// FirstPrimaryEndpoint indicates the endpoint should be the first
	// primary endpoint considered. If there are multiple endpoints with
	// this behavior, the most recently-added one will be first.
	FirstPrimaryEndpoint

	// NeverPrimaryEndpoint indicates the endpoint should never be a
	// primary endpoint.
	NeverPrimaryEndpoint
)

func newNIC(stack *Stack, id tcpip.NICID, name string, ep LinkEndpoint, loopback bool) *NIC {
	return &NIC{
		stack:      stack,
		id:         id,
		name:       name,
		linkEP:     ep,
		loopback:   loopback,
		primary:    make(map[tcpip.NetworkProtocolNumber]*ilist.List),
		endpoints:  make(map[NetworkEndpointID]*referencedNetworkEndpoint),
		mcastJoins: make(map[NetworkEndpointID]int32),
		stats: NICStats{
			Tx: DirectionStats{
				Packets: &tcpip.StatCounter{},
				Bytes:   &tcpip.StatCounter{},
			},
			Rx: DirectionStats{
				Packets: &tcpip.StatCounter{},
				Bytes:   &tcpip.StatCounter{},
			},
		},
	}
}

// attachLinkEndpoint attaches the NIC to the endpoint, which will enable it
// to start delivering packets.
func (n *NIC) attachLinkEndpoint() {
	n.linkEP.Attach(n)
}

// setPromiscuousMode enables or disables promiscuous mode.
func (n *NIC) setPromiscuousMode(enable bool) {
	n.mu.Lock()
	n.promiscuous = enable
	n.mu.Unlock()
}

func (n *NIC) isPromiscuousMode() bool {
	n.mu.RLock()
	rv := n.promiscuous
	n.mu.RUnlock()
	return rv
}

// setSpoofing enables or disables address spoofing.
func (n *NIC) setSpoofing(enable bool) {
	n.mu.Lock()
	n.spoofing = enable
	n.mu.Unlock()
}

// primaryEndpoint returns the primary endpoint of n for the given network
// protocol.
func (n *NIC) primaryEndpoint(protocol tcpip.NetworkProtocolNumber) *referencedNetworkEndpoint {
	n.mu.RLock()
	defer n.mu.RUnlock()

	list := n.primary[protocol]
	if list == nil {
		return nil
	}

	for e := list.Front(); e != nil; e = e.Next() {
		r := e.(*referencedNetworkEndpoint)
		// TODO(crawshaw): allow broadcast address when SO_BROADCAST is set.
		switch r.ep.ID().LocalAddress {
		case header.IPv4Broadcast, header.IPv4Any:
			continue
		}
		if r.isValidForOutgoing() && r.tryIncRef() {
			return r
		}
	}

	return nil
}

func (n *NIC) getRef(protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) *referencedNetworkEndpoint {
	return n.getRefOrCreateTemp(protocol, dst, CanBePrimaryEndpoint, n.promiscuous)
}

// findEndpoint finds the endpoint, if any, with the given address.
func (n *NIC) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior) *referencedNetworkEndpoint {
	return n.getRefOrCreateTemp(protocol, address, peb, n.spoofing)
}

// getRefEpOrCreateTemp returns the referenced network endpoint for the given
// protocol and address. If none exists a temporary one may be created if
// we are in promiscuous mode or spoofing.
func (n *NIC) getRefOrCreateTemp(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior, spoofingOrPromiscuous bool) *referencedNetworkEndpoint {
	id := NetworkEndpointID{address}

	n.mu.RLock()

	if ref, ok := n.endpoints[id]; ok {
		// An endpoint with this id exists, check if it can be used and return it.
		switch ref.getKind() {
		case permanentExpired:
			if !spoofingOrPromiscuous {
				n.mu.RUnlock()
				return nil
			}
			fallthrough
		case temporary, permanent:
			if ref.tryIncRef() {
				n.mu.RUnlock()
				return ref
			}
		}
	}

	// A usable reference was not found, create a temporary one if requested by
	// the caller or if the address is found in the NIC's subnets.
	createTempEP := spoofingOrPromiscuous
	if !createTempEP {
		for _, sn := range n.addressRanges {
			// Skip the subnet address.
			if address == sn.ID() {
				continue
			}
			// For now just skip the broadcast address, until we support it.
			// FIXME(b/137608825): Add support for sending/receiving directed
			// (subnet) broadcast.
			if address == sn.Broadcast() {
				continue
			}
			if sn.Contains(address) {
				createTempEP = true
				break
			}
		}
	}

	n.mu.RUnlock()

	if !createTempEP {
		return nil
	}

	// Try again with the lock in exclusive mode. If we still can't get the
	// endpoint, create a new "temporary" endpoint. It will only exist while
	// there's a route through it.
	n.mu.Lock()
	if ref, ok := n.endpoints[id]; ok {
		// No need to check the type as we are ok with expired endpoints at this
		// point.
		if ref.tryIncRef() {
			n.mu.Unlock()
			return ref
		}
		// tryIncRef failing means the endpoint is scheduled to be removed once the
		// lock is released. Remove it here so we can create a new (temporary) one.
		// The removal logic waiting for the lock handles this case.
		n.removeEndpointLocked(ref)
	}

	// Add a new temporary endpoint.
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		n.mu.Unlock()
		return nil
	}
	ref, _ := n.addAddressLocked(tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   address,
			PrefixLen: netProto.DefaultPrefixLen(),
		},
	}, peb, temporary)

	n.mu.Unlock()
	return ref
}

func (n *NIC) addPermanentAddressLocked(protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior) (*referencedNetworkEndpoint, *tcpip.Error) {
	id := NetworkEndpointID{protocolAddress.AddressWithPrefix.Address}
	if ref, ok := n.endpoints[id]; ok {
		switch ref.getKind() {
		case permanent:
			// The NIC already have a permanent endpoint with that address.
			return nil, tcpip.ErrDuplicateAddress
		case permanentExpired, temporary:
			// Promote the endpoint to become permanent.
			if ref.tryIncRef() {
				ref.setKind(permanent)
				return ref, nil
			}
			// tryIncRef failing means the endpoint is scheduled to be removed once
			// the lock is released. Remove it here so we can create a new
			// (permanent) one. The removal logic waiting for the lock handles this
			// case.
			n.removeEndpointLocked(ref)
		}
	}
	return n.addAddressLocked(protocolAddress, peb, permanent)
}

func (n *NIC) addAddressLocked(protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior, kind networkEndpointKind) (*referencedNetworkEndpoint, *tcpip.Error) {
	// Sanity check.
	id := NetworkEndpointID{protocolAddress.AddressWithPrefix.Address}
	if _, ok := n.endpoints[id]; ok {
		// Endpoint already exists.
		return nil, tcpip.ErrDuplicateAddress
	}

	netProto, ok := n.stack.networkProtocols[protocolAddress.Protocol]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	// Create the new network endpoint.
	ep, err := netProto.NewEndpoint(n.id, protocolAddress.AddressWithPrefix, n.stack, n, n.linkEP)
	if err != nil {
		return nil, err
	}
	ref := &referencedNetworkEndpoint{
		refs:     1,
		ep:       ep,
		nic:      n,
		protocol: protocolAddress.Protocol,
		kind:     kind,
	}

	// Set up cache if link address resolution exists for this protocol.
	if n.linkEP.Capabilities()&CapabilityResolutionRequired != 0 {
		if _, ok := n.stack.linkAddrResolvers[protocolAddress.Protocol]; ok {
			ref.linkCache = n.stack
		}
	}

	n.endpoints[id] = ref

	l, ok := n.primary[protocolAddress.Protocol]
	if !ok {
		l = &ilist.List{}
		n.primary[protocolAddress.Protocol] = l
	}

	switch peb {
	case CanBePrimaryEndpoint:
		l.PushBack(ref)
	case FirstPrimaryEndpoint:
		l.PushFront(ref)
	}

	return ref, nil
}

// AddAddress adds a new address to n, so that it starts accepting packets
// targeted at the given address (and network protocol).
func (n *NIC) AddAddress(protocolAddress tcpip.ProtocolAddress, peb PrimaryEndpointBehavior) *tcpip.Error {
	// Add the endpoint.
	n.mu.Lock()
	_, err := n.addPermanentAddressLocked(protocolAddress, peb)
	n.mu.Unlock()

	return err
}

// AllAddresses returns all addresses (primary and non-primary) associated with
// this NIC.
func (n *NIC) AllAddresses() []tcpip.ProtocolAddress {
	n.mu.RLock()
	defer n.mu.RUnlock()

	addrs := make([]tcpip.ProtocolAddress, 0, len(n.endpoints))
	for nid, ref := range n.endpoints {
		// Don't include expired or tempory endpoints to avoid confusion and
		// prevent the caller from using those.
		switch ref.getKind() {
		case permanentExpired, temporary:
			continue
		}
		addrs = append(addrs, tcpip.ProtocolAddress{
			Protocol: ref.protocol,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   nid.LocalAddress,
				PrefixLen: ref.ep.PrefixLen(),
			},
		})
	}
	return addrs
}

// PrimaryAddresses returns the primary addresses associated with this NIC.
func (n *NIC) PrimaryAddresses() []tcpip.ProtocolAddress {
	n.mu.RLock()
	defer n.mu.RUnlock()

	var addrs []tcpip.ProtocolAddress
	for proto, list := range n.primary {
		for e := list.Front(); e != nil; e = e.Next() {
			ref := e.(*referencedNetworkEndpoint)
			// Don't include expired or tempory endpoints to avoid confusion and
			// prevent the caller from using those.
			switch ref.getKind() {
			case permanentExpired, temporary:
				continue
			}

			addrs = append(addrs, tcpip.ProtocolAddress{
				Protocol: proto,
				AddressWithPrefix: tcpip.AddressWithPrefix{
					Address:   ref.ep.ID().LocalAddress,
					PrefixLen: ref.ep.PrefixLen(),
				},
			})
		}
	}
	return addrs
}

// AddAddressRange adds a range of addresses to n, so that it starts accepting
// packets targeted at the given addresses and network protocol. The range is
// given by a subnet address, and all addresses contained in the subnet are
// used except for the subnet address itself and the subnet's broadcast
// address.
func (n *NIC) AddAddressRange(protocol tcpip.NetworkProtocolNumber, subnet tcpip.Subnet) {
	n.mu.Lock()
	n.addressRanges = append(n.addressRanges, subnet)
	n.mu.Unlock()
}

// RemoveAddressRange removes the given address range from n.
func (n *NIC) RemoveAddressRange(subnet tcpip.Subnet) {
	n.mu.Lock()

	// Use the same underlying array.
	tmp := n.addressRanges[:0]
	for _, sub := range n.addressRanges {
		if sub != subnet {
			tmp = append(tmp, sub)
		}
	}
	n.addressRanges = tmp

	n.mu.Unlock()
}

// Subnets returns the Subnets associated with this NIC.
func (n *NIC) AddressRanges() []tcpip.Subnet {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sns := make([]tcpip.Subnet, 0, len(n.addressRanges)+len(n.endpoints))
	for nid := range n.endpoints {
		sn, err := tcpip.NewSubnet(nid.LocalAddress, tcpip.AddressMask(strings.Repeat("\xff", len(nid.LocalAddress))))
		if err != nil {
			// This should never happen as the mask has been carefully crafted to
			// match the address.
			panic("Invalid endpoint subnet: " + err.Error())
		}
		sns = append(sns, sn)
	}
	return append(sns, n.addressRanges...)
}

func (n *NIC) removeEndpointLocked(r *referencedNetworkEndpoint) {
	id := *r.ep.ID()

	// Nothing to do if the reference has already been replaced with a different
	// one. This happens in the case where 1) this endpoint's ref count hit zero
	// and was waiting (on the lock) to be removed and 2) the same address was
	// re-added in the meantime by removing this endpoint from the list and
	// adding a new one.
	if n.endpoints[id] != r {
		return
	}

	if r.getKind() == permanent {
		panic("Reference count dropped to zero before being removed")
	}

	delete(n.endpoints, id)
	wasInList := r.Next() != nil || r.Prev() != nil || r == n.primary[r.protocol].Front()
	if wasInList {
		n.primary[r.protocol].Remove(r)
	}

	r.ep.Close()
}

func (n *NIC) removeEndpoint(r *referencedNetworkEndpoint) {
	n.mu.Lock()
	n.removeEndpointLocked(r)
	n.mu.Unlock()
}

func (n *NIC) removePermanentAddressLocked(addr tcpip.Address) *tcpip.Error {
	r := n.endpoints[NetworkEndpointID{addr}]
	if r == nil || r.getKind() != permanent {
		return tcpip.ErrBadLocalAddress
	}

	r.setKind(permanentExpired)
	r.decRefLocked()

	return nil
}

// RemoveAddress removes an address from n.
func (n *NIC) RemoveAddress(addr tcpip.Address) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.removePermanentAddressLocked(addr)
}

// joinGroup adds a new endpoint for the given multicast address, if none
// exists yet. Otherwise it just increments its count.
func (n *NIC) joinGroup(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := NetworkEndpointID{addr}
	joins := n.mcastJoins[id]
	if joins == 0 {
		netProto, ok := n.stack.networkProtocols[protocol]
		if !ok {
			return tcpip.ErrUnknownProtocol
		}
		if _, err := n.addPermanentAddressLocked(tcpip.ProtocolAddress{
			Protocol: protocol,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: netProto.DefaultPrefixLen(),
			},
		}, NeverPrimaryEndpoint); err != nil {
			return err
		}
	}
	n.mcastJoins[id] = joins + 1
	return nil
}

// leaveGroup decrements the count for the given multicast address, and when it
// reaches zero removes the endpoint for this address.
func (n *NIC) leaveGroup(addr tcpip.Address) *tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := NetworkEndpointID{addr}
	joins := n.mcastJoins[id]
	switch joins {
	case 0:
		// There are no joins with this address on this NIC.
		return tcpip.ErrBadLocalAddress
	case 1:
		// This is the last one, clean up.
		if err := n.removePermanentAddressLocked(addr); err != nil {
			return err
		}
	}
	n.mcastJoins[id] = joins - 1
	return nil
}

func handlePacket(protocol tcpip.NetworkProtocolNumber, dst, src tcpip.Address, localLinkAddr, remotelinkAddr tcpip.LinkAddress, ref *referencedNetworkEndpoint, vv buffer.VectorisedView) {
	r := makeRoute(protocol, dst, src, localLinkAddr, ref, false /* handleLocal */, false /* multicastLoop */)
	r.RemoteLinkAddress = remotelinkAddr
	ref.ep.HandlePacket(&r, vv)
	ref.decRef()
}

// DeliverNetworkPacket finds the appropriate network protocol endpoint and
// hands the packet over for further processing. This function is called when
// the NIC receives a packet from the physical interface.
// Note that the ownership of the slice backing vv is retained by the caller.
// This rule applies only to the slice itself, not to the items of the slice;
// the ownership of the items is not retained by the caller.
func (n *NIC) DeliverNetworkPacket(linkEP LinkEndpoint, remote, _ tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	n.stats.Rx.Packets.Increment()
	n.stats.Rx.Bytes.IncrementBy(uint64(vv.Size()))

	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	if netProto.Number() == header.IPv4ProtocolNumber || netProto.Number() == header.IPv6ProtocolNumber {
		n.stack.stats.IP.PacketsReceived.Increment()
	}

	if len(vv.First()) < netProto.MinimumPacketSize() {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}

	src, dst := netProto.ParseAddresses(vv.First())

	n.stack.AddLinkAddress(n.id, src, remote)

	// If the packet is destined to the IPv4 Broadcast address, then make a
	// route to each IPv4 network endpoint and let each endpoint handle the
	// packet.
	if dst == header.IPv4Broadcast {
		// n.endpoints is mutex protected so acquire lock.
		n.mu.RLock()
		for _, ref := range n.endpoints {
			if ref.isValidForIncoming() && ref.protocol == header.IPv4ProtocolNumber && ref.tryIncRef() {
				handlePacket(protocol, dst, src, linkEP.LinkAddress(), remote, ref, vv)
			}
		}
		n.mu.RUnlock()
		return
	}

	if ref := n.getRef(protocol, dst); ref != nil {
		handlePacket(protocol, dst, src, linkEP.LinkAddress(), remote, ref, vv)
		return
	}

	// This NIC doesn't care about the packet. Find a NIC that cares about the
	// packet and forward it to the NIC.
	//
	// TODO: Should we be forwarding the packet even if promiscuous?
	if n.stack.Forwarding() {
		r, err := n.stack.FindRoute(0, "", dst, protocol, false /* multicastLoop */)
		if err != nil {
			n.stack.stats.IP.InvalidAddressesReceived.Increment()
			return
		}
		defer r.Release()

		r.LocalLinkAddress = n.linkEP.LinkAddress()
		r.RemoteLinkAddress = remote

		// Found a NIC.
		n := r.ref.nic
		n.mu.RLock()
		ref, ok := n.endpoints[NetworkEndpointID{dst}]
		ok = ok && ref.isValidForOutgoing() && ref.tryIncRef()
		n.mu.RUnlock()
		if ok {
			r.RemoteAddress = src
			// TODO(b/123449044): Update the source NIC as well.
			ref.ep.HandlePacket(&r, vv)
			ref.decRef()
		} else {
			// n doesn't have a destination endpoint.
			// Send the packet out of n.
			hdr := buffer.NewPrependableFromView(vv.First())
			vv.RemoveFirst()

			// TODO(b/128629022): use route.WritePacket.
			if err := n.linkEP.WritePacket(&r, nil /* gso */, hdr, vv, protocol); err != nil {
				r.Stats().IP.OutgoingPacketErrors.Increment()
			} else {
				n.stats.Tx.Packets.Increment()
				n.stats.Tx.Bytes.IncrementBy(uint64(hdr.UsedLength() + vv.Size()))
			}
		}
		return
	}

	n.stack.stats.IP.InvalidAddressesReceived.Increment()
}

// DeliverTransportPacket delivers the packets to the appropriate transport
// protocol endpoint.
func (n *NIC) DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, netHeader buffer.View, vv buffer.VectorisedView) {
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	transProto := state.proto

	// Raw socket packets are delivered based solely on the transport
	// protocol number. We do not inspect the payload to ensure it's
	// validly formed.
	n.stack.demux.deliverRawPacket(r, protocol, netHeader, vv)

	if len(vv.First()) < transProto.MinimumPacketSize() {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}

	srcPort, dstPort, err := transProto.ParsePorts(vv.First())
	if err != nil {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}

	id := TransportEndpointID{dstPort, r.LocalAddress, srcPort, r.RemoteAddress}
	if n.stack.demux.deliverPacket(r, protocol, netHeader, vv, id) {
		return
	}

	// Try to deliver to per-stack default handler.
	if state.defaultHandler != nil {
		if state.defaultHandler(r, id, netHeader, vv) {
			return
		}
	}

	// We could not find an appropriate destination for this packet, so
	// deliver it to the global handler.
	if !transProto.HandleUnknownDestinationPacket(r, id, netHeader, vv) {
		n.stack.stats.MalformedRcvdPackets.Increment()
	}
}

// DeliverTransportControlPacket delivers control packets to the appropriate
// transport protocol endpoint.
func (n *NIC) DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, vv buffer.VectorisedView) {
	state, ok := n.stack.transportProtocols[trans]
	if !ok {
		return
	}

	transProto := state.proto

	// ICMPv4 only guarantees that 8 bytes of the transport protocol will
	// be present in the payload. We know that the ports are within the
	// first 8 bytes for all known transport protocols.
	if len(vv.First()) < 8 {
		return
	}

	srcPort, dstPort, err := transProto.ParsePorts(vv.First())
	if err != nil {
		return
	}

	id := TransportEndpointID{srcPort, local, dstPort, remote}
	if n.stack.demux.deliverControlPacket(n, net, trans, typ, extra, vv, id) {
		return
	}
}

// ID returns the identifier of n.
func (n *NIC) ID() tcpip.NICID {
	return n.id
}

// Stack returns the instance of the Stack that owns this NIC.
func (n *NIC) Stack() *Stack {
	return n.stack
}

type networkEndpointKind int32

const (
	// A permanent endpoint is created by adding a permanent address (vs. a
	// temporary one) to the NIC. Its reference count is biased by 1 to avoid
	// removal when no route holds a reference to it. It is removed by explicitly
	// removing the permanent address from the NIC.
	permanent networkEndpointKind = iota

	// An expired permanent endoint is a permanent endoint that had its address
	// removed from the NIC, and it is waiting to be removed once no more routes
	// hold a reference to it. This is achieved by decreasing its reference count
	// by 1. If its address is re-added before the endpoint is removed, its type
	// changes back to permanent and its reference count increases by 1 again.
	permanentExpired

	// A temporary endpoint is created for spoofing outgoing packets, or when in
	// promiscuous mode and accepting incoming packets that don't match any
	// permanent endpoint. Its reference count is not biased by 1 and the
	// endpoint is removed immediately when no more route holds a reference to
	// it. A temporary endpoint can be promoted to permanent if its address
	// is added permanently.
	temporary
)

type referencedNetworkEndpoint struct {
	ilist.Entry
	ep       NetworkEndpoint
	nic      *NIC
	protocol tcpip.NetworkProtocolNumber

	// linkCache is set if link address resolution is enabled for this
	// protocol. Set to nil otherwise.
	linkCache LinkAddressCache

	// refs is counting references held for this endpoint. When refs hits zero it
	// triggers the automatic removal of the endpoint from the NIC.
	refs int32

	// networkEndpointKind must only be accessed using {get,set}Kind().
	kind networkEndpointKind
}

func (r *referencedNetworkEndpoint) getKind() networkEndpointKind {
	return networkEndpointKind(atomic.LoadInt32((*int32)(&r.kind)))
}

func (r *referencedNetworkEndpoint) setKind(kind networkEndpointKind) {
	atomic.StoreInt32((*int32)(&r.kind), int32(kind))
}

// isValidForOutgoing returns true if the endpoint can be used to send out a
// packet. It requires the endpoint to not be marked expired (i.e., its address
// has been removed), or the NIC to be in spoofing mode.
func (r *referencedNetworkEndpoint) isValidForOutgoing() bool {
	return r.getKind() != permanentExpired || r.nic.spoofing
}

// isValidForIncoming returns true if the endpoint can accept an incoming
// packet. It requires the endpoint to not be marked expired (i.e., its address
// has been removed), or the NIC to be in promiscuous mode.
func (r *referencedNetworkEndpoint) isValidForIncoming() bool {
	return r.getKind() != permanentExpired || r.nic.promiscuous
}

// decRef decrements the ref count and cleans up the endpoint once it reaches
// zero.
func (r *referencedNetworkEndpoint) decRef() {
	if atomic.AddInt32(&r.refs, -1) == 0 {
		r.nic.removeEndpoint(r)
	}
}

// decRefLocked is the same as decRef but assumes that the NIC.mu mutex is
// locked.
func (r *referencedNetworkEndpoint) decRefLocked() {
	if atomic.AddInt32(&r.refs, -1) == 0 {
		r.nic.removeEndpointLocked(r)
	}
}

// incRef increments the ref count. It must only be called when the caller is
// known to be holding a reference to the endpoint, otherwise tryIncRef should
// be used.
func (r *referencedNetworkEndpoint) incRef() {
	atomic.AddInt32(&r.refs, 1)
}

// tryIncRef attempts to increment the ref count from n to n+1, but only if n is
// not zero. That is, it will increment the count if the endpoint is still
// alive, and do nothing if it has already been clean up.
func (r *referencedNetworkEndpoint) tryIncRef() bool {
	for {
		v := atomic.LoadInt32(&r.refs)
		if v == 0 {
			return false
		}

		if atomic.CompareAndSwapInt32(&r.refs, v, v+1) {
			return true
		}
	}
}

// stack returns the Stack instance that owns the underlying endpoint.
func (r *referencedNetworkEndpoint) stack() *Stack {
	return r.nic.stack
}
