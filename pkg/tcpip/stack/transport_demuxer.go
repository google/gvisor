// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
)

type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
}

// transportEndpoints manages all endpoints of a given protocol. It has its own
// mutex so as to reduce interference between protocols.
type transportEndpoints struct {
	mu        sync.RWMutex
	endpoints map[TransportEndpointID]TransportEndpoint
}

// transportDemuxer demultiplexes packets targeted at a transport endpoint
// (i.e., after they've been parsed by the network layer). It does two levels
// of demultiplexing: first based on the network and transport protocols, then
// based on endpoints IDs.
type transportDemuxer struct {
	protocol map[protocolIDs]*transportEndpoints
}

func newTransportDemuxer(stack *Stack) *transportDemuxer {
	d := &transportDemuxer{protocol: make(map[protocolIDs]*transportEndpoints)}

	// Add each network and transport pair to the demuxer.
	for netProto := range stack.networkProtocols {
		for proto := range stack.transportProtocols {
			d.protocol[protocolIDs{netProto, proto}] = &transportEndpoints{endpoints: make(map[TransportEndpointID]TransportEndpoint)}
		}
	}

	return d
}

// registerEndpoint registers the given endpoint with the dispatcher such that
// packets that match the endpoint ID are delivered to it.
func (d *transportDemuxer) registerEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) *tcpip.Error {
	for i, n := range netProtos {
		if err := d.singleRegisterEndpoint(n, protocol, id, ep); err != nil {
			d.unregisterEndpoint(netProtos[:i], protocol, id)
			return err
		}
	}

	return nil
}

func (d *transportDemuxer) singleRegisterEndpoint(netProto tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) *tcpip.Error {
	eps, ok := d.protocol[protocolIDs{netProto, protocol}]
	if !ok {
		return nil
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()

	if _, ok := eps.endpoints[id]; ok {
		return tcpip.ErrPortInUse
	}

	eps.endpoints[id] = ep

	return nil
}

// unregisterEndpoint unregisters the endpoint with the given id such that it
// won't receive any more packets.
func (d *transportDemuxer) unregisterEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID) {
	for _, n := range netProtos {
		if eps, ok := d.protocol[protocolIDs{n, protocol}]; ok {
			eps.mu.Lock()
			delete(eps.endpoints, id)
			eps.mu.Unlock()
		}
	}
}

// deliverPacket attempts to deliver the given packet. Returns true if it found
// an endpoint, false otherwise.
func (d *transportDemuxer) deliverPacket(r *Route, protocol tcpip.TransportProtocolNumber, vv *buffer.VectorisedView, id TransportEndpointID) bool {
	eps, ok := d.protocol[protocolIDs{r.NetProto, protocol}]
	if !ok {
		return false
	}

	eps.mu.RLock()
	ep := d.findEndpointLocked(eps, vv, id)
	eps.mu.RUnlock()

	// Fail if we didn't find one.
	if ep == nil {
		return false
	}

	// Deliver the packet.
	ep.HandlePacket(r, id, vv)

	return true
}

// deliverControlPacket attempts to deliver the given control packet. Returns
// true if it found an endpoint, false otherwise.
func (d *transportDemuxer) deliverControlPacket(net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, vv *buffer.VectorisedView, id TransportEndpointID) bool {
	eps, ok := d.protocol[protocolIDs{net, trans}]
	if !ok {
		return false
	}

	// Try to find the endpoint.
	eps.mu.RLock()
	ep := d.findEndpointLocked(eps, vv, id)
	eps.mu.RUnlock()

	// Fail if we didn't find one.
	if ep == nil {
		return false
	}

	// Deliver the packet.
	ep.HandleControlPacket(id, typ, extra, vv)

	return true
}

func (d *transportDemuxer) findEndpointLocked(eps *transportEndpoints, vv *buffer.VectorisedView, id TransportEndpointID) TransportEndpoint {
	// Try to find a match with the id as provided.
	if ep := eps.endpoints[id]; ep != nil {
		return ep
	}

	// Try to find a match with the id minus the local address.
	nid := id

	nid.LocalAddress = ""
	if ep := eps.endpoints[nid]; ep != nil {
		return ep
	}

	// Try to find a match with the id minus the remote part.
	nid.LocalAddress = id.LocalAddress
	nid.RemoteAddress = ""
	nid.RemotePort = 0
	if ep := eps.endpoints[nid]; ep != nil {
		return ep
	}

	// Try to find a match with only the local port.
	nid.LocalAddress = ""
	return eps.endpoints[nid]
}
