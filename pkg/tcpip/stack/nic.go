// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"strings"
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/ilist"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
)

// NIC represents a "network interface card" to which the networking stack is
// attached.
type NIC struct {
	stack  *Stack
	id     tcpip.NICID
	name   string
	linkEP LinkEndpoint

	demux *transportDemuxer

	mu          sync.RWMutex
	spoofing    bool
	promiscuous bool
	primary     map[tcpip.NetworkProtocolNumber]*ilist.List
	endpoints   map[NetworkEndpointID]*referencedNetworkEndpoint
	subnets     []tcpip.Subnet
}

func newNIC(stack *Stack, id tcpip.NICID, name string, ep LinkEndpoint) *NIC {
	return &NIC{
		stack:     stack,
		id:        id,
		name:      name,
		linkEP:    ep,
		demux:     newTransportDemuxer(stack),
		primary:   make(map[tcpip.NetworkProtocolNumber]*ilist.List),
		endpoints: make(map[NetworkEndpointID]*referencedNetworkEndpoint),
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
		if r.tryIncRef() {
			return r
		}
	}

	return nil
}

// findEndpoint finds the endpoint, if any, with the given address.
func (n *NIC) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address) *referencedNetworkEndpoint {
	id := NetworkEndpointID{address}

	n.mu.RLock()
	ref := n.endpoints[id]
	if ref != nil && !ref.tryIncRef() {
		ref = nil
	}
	spoofing := n.spoofing
	n.mu.RUnlock()

	if ref != nil || !spoofing {
		return ref
	}

	// Try again with the lock in exclusive mode. If we still can't get the
	// endpoint, create a new "temporary" endpoint. It will only exist while
	// there's a route through it.
	n.mu.Lock()
	ref = n.endpoints[id]
	if ref == nil || !ref.tryIncRef() {
		ref, _ = n.addAddressLocked(protocol, address, true)
		if ref != nil {
			ref.holdsInsertRef = false
		}
	}
	n.mu.Unlock()
	return ref
}

func (n *NIC) addAddressLocked(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, replace bool) (*referencedNetworkEndpoint, *tcpip.Error) {
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	// Create the new network endpoint.
	ep, err := netProto.NewEndpoint(n.id, addr, n.stack, n, n.linkEP)
	if err != nil {
		return nil, err
	}

	id := *ep.ID()
	if ref, ok := n.endpoints[id]; ok {
		if !replace {
			return nil, tcpip.ErrDuplicateAddress
		}

		n.removeEndpointLocked(ref)
	}

	ref := &referencedNetworkEndpoint{
		refs:           1,
		ep:             ep,
		nic:            n,
		protocol:       protocol,
		holdsInsertRef: true,
	}

	// Set up cache if link address resolution exists for this protocol.
	if n.linkEP.Capabilities()&CapabilityResolutionRequired != 0 {
		if linkRes := n.stack.linkAddrResolvers[protocol]; linkRes != nil {
			ref.linkCache = n.stack
		}
	}

	n.endpoints[id] = ref

	l, ok := n.primary[protocol]
	if !ok {
		l = &ilist.List{}
		n.primary[protocol] = l
	}

	l.PushBack(ref)

	return ref, nil
}

// AddAddress adds a new address to n, so that it starts accepting packets
// targeted at the given address (and network protocol).
func (n *NIC) AddAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	// Add the endpoint.
	n.mu.Lock()
	_, err := n.addAddressLocked(protocol, addr, false)
	n.mu.Unlock()

	return err
}

// Addresses returns the addresses associated with this NIC.
func (n *NIC) Addresses() []tcpip.ProtocolAddress {
	n.mu.RLock()
	defer n.mu.RUnlock()
	addrs := make([]tcpip.ProtocolAddress, 0, len(n.endpoints))
	for nid, ep := range n.endpoints {
		addrs = append(addrs, tcpip.ProtocolAddress{
			Protocol: ep.protocol,
			Address:  nid.LocalAddress,
		})
	}
	return addrs
}

// AddSubnet adds a new subnet to n, so that it starts accepting packets
// targeted at the given address and network protocol.
func (n *NIC) AddSubnet(protocol tcpip.NetworkProtocolNumber, subnet tcpip.Subnet) {
	n.mu.Lock()
	n.subnets = append(n.subnets, subnet)
	n.mu.Unlock()
}

// Subnets returns the Subnets associated with this NIC.
func (n *NIC) Subnets() []tcpip.Subnet {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sns := make([]tcpip.Subnet, 0, len(n.subnets)+len(n.endpoints))
	for nid := range n.endpoints {
		sn, err := tcpip.NewSubnet(nid.LocalAddress, tcpip.AddressMask(strings.Repeat("\xff", len(nid.LocalAddress))))
		if err != nil {
			// This should never happen as the mask has been carefully crafted to
			// match the address.
			panic("Invalid endpoint subnet: " + err.Error())
		}
		sns = append(sns, sn)
	}
	return append(sns, n.subnets...)
}

func (n *NIC) removeEndpointLocked(r *referencedNetworkEndpoint) {
	id := *r.ep.ID()

	// Nothing to do if the reference has already been replaced with a
	// different one.
	if n.endpoints[id] != r {
		return
	}

	if r.holdsInsertRef {
		panic("Reference count dropped to zero before being removed")
	}

	delete(n.endpoints, id)
	n.primary[r.protocol].Remove(r)
	r.ep.Close()
}

func (n *NIC) removeEndpoint(r *referencedNetworkEndpoint) {
	n.mu.Lock()
	n.removeEndpointLocked(r)
	n.mu.Unlock()
}

// RemoveAddress removes an address from n.
func (n *NIC) RemoveAddress(addr tcpip.Address) *tcpip.Error {
	n.mu.Lock()
	r := n.endpoints[NetworkEndpointID{addr}]
	if r == nil || !r.holdsInsertRef {
		n.mu.Unlock()
		return tcpip.ErrBadLocalAddress
	}

	r.holdsInsertRef = false
	n.mu.Unlock()

	r.decRef()

	return nil
}

// DeliverNetworkPacket finds the appropriate network protocol endpoint and
// hands the packet over for further processing. This function is called when
// the NIC receives a packet from the physical interface.
// Note that the ownership of the slice backing vv is retained by the caller.
// This rule applies only to the slice itself, not to the items of the slice;
// the ownership of the items is not retained by the caller.
func (n *NIC) DeliverNetworkPacket(linkEP LinkEndpoint, remoteLinkAddr tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv *buffer.VectorisedView) {
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		atomic.AddUint64(&n.stack.stats.UnknownProtocolRcvdPackets, 1)
		return
	}

	if len(vv.First()) < netProto.MinimumPacketSize() {
		atomic.AddUint64(&n.stack.stats.MalformedRcvdPackets, 1)
		return
	}

	src, dst := netProto.ParseAddresses(vv.First())
	id := NetworkEndpointID{dst}

	n.mu.RLock()
	ref := n.endpoints[id]
	if ref != nil && !ref.tryIncRef() {
		ref = nil
	}
	promiscuous := n.promiscuous
	subnets := n.subnets
	n.mu.RUnlock()

	if ref == nil {
		// Check if the packet is for a subnet this NIC cares about.
		if !promiscuous {
			for _, sn := range subnets {
				if sn.Contains(dst) {
					promiscuous = true
					break
				}
			}
		}
		if promiscuous {
			// Try again with the lock in exclusive mode. If we still can't
			// get the endpoint, create a new "temporary" one. It will only
			// exist while there's a route through it.
			n.mu.Lock()
			ref = n.endpoints[id]
			if ref == nil || !ref.tryIncRef() {
				ref, _ = n.addAddressLocked(protocol, dst, true)
				if ref != nil {
					ref.holdsInsertRef = false
				}
			}
			n.mu.Unlock()
		}
	}

	if ref == nil {
		atomic.AddUint64(&n.stack.stats.UnknownNetworkEndpointRcvdPackets, 1)
		return
	}

	r := makeRoute(protocol, dst, src, linkEP.LinkAddress(), ref)
	r.RemoteLinkAddress = remoteLinkAddr
	ref.ep.HandlePacket(&r, vv)
	ref.decRef()
}

// DeliverTransportPacket delivers the packets to the appropriate transport
// protocol endpoint.
func (n *NIC) DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, vv *buffer.VectorisedView) {
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		atomic.AddUint64(&n.stack.stats.UnknownProtocolRcvdPackets, 1)
		return
	}

	transProto := state.proto
	if len(vv.First()) < transProto.MinimumPacketSize() {
		atomic.AddUint64(&n.stack.stats.MalformedRcvdPackets, 1)
		return
	}

	srcPort, dstPort, err := transProto.ParsePorts(vv.First())
	if err != nil {
		atomic.AddUint64(&n.stack.stats.MalformedRcvdPackets, 1)
		return
	}

	id := TransportEndpointID{dstPort, r.LocalAddress, srcPort, r.RemoteAddress}
	if n.demux.deliverPacket(r, protocol, vv, id) {
		return
	}
	if n.stack.demux.deliverPacket(r, protocol, vv, id) {
		return
	}

	// Try to deliver to per-stack default handler.
	if state.defaultHandler != nil {
		if state.defaultHandler(r, id, vv) {
			return
		}
	}

	// We could not find an appropriate destination for this packet, so
	// deliver it to the global handler.
	if !transProto.HandleUnknownDestinationPacket(r, id, vv) {
		atomic.AddUint64(&n.stack.stats.MalformedRcvdPackets, 1)
	}
}

// DeliverTransportControlPacket delivers control packets to the appropriate
// transport protocol endpoint.
func (n *NIC) DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, vv *buffer.VectorisedView) {
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
	if n.demux.deliverControlPacket(net, trans, typ, extra, vv, id) {
		return
	}
	if n.stack.demux.deliverControlPacket(net, trans, typ, extra, vv, id) {
		return
	}
}

// ID returns the identifier of n.
func (n *NIC) ID() tcpip.NICID {
	return n.id
}

type referencedNetworkEndpoint struct {
	ilist.Entry
	refs     int32
	ep       NetworkEndpoint
	nic      *NIC
	protocol tcpip.NetworkProtocolNumber

	// linkCache is set if link address resolution is enabled for this
	// protocol. Set to nil otherwise.
	linkCache LinkAddressCache

	// holdsInsertRef is protected by the NIC's mutex. It indicates whether
	// the reference count is biased by 1 due to the insertion of the
	// endpoint. It is reset to false when RemoveAddress is called on the
	// NIC.
	holdsInsertRef bool
}

// decRef decrements the ref count and cleans up the endpoint once it reaches
// zero.
func (r *referencedNetworkEndpoint) decRef() {
	if atomic.AddInt32(&r.refs, -1) == 0 {
		r.nic.removeEndpoint(r)
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
