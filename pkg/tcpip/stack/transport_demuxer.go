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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
)

type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
}

// transportEndpoints manages all endpoints of a given protocol. It has its own
// mutex so as to reduce interference between protocols.
type transportEndpoints struct {
	// mu protects all fields of the transportEndpoints.
	mu        sync.RWMutex
	endpoints map[TransportEndpointID]TransportEndpoint
	// rawEndpoints contains endpoints for raw sockets, which receive all
	// traffic of a given protocol regardless of port.
	rawEndpoints []RawTransportEndpoint
}

// unregisterEndpoint unregisters the endpoint with the given id such that it
// won't receive any more packets.
func (eps *transportEndpoints) unregisterEndpoint(id TransportEndpointID, ep TransportEndpoint) {
	eps.mu.Lock()
	defer eps.mu.Unlock()
	e, ok := eps.endpoints[id]
	if !ok {
		return
	}
	if multiPortEp, ok := e.(*multiPortEndpoint); ok {
		if !multiPortEp.unregisterEndpoint(ep) {
			return
		}
	}
	delete(eps.endpoints, id)
}

// transportDemuxer demultiplexes packets targeted at a transport endpoint
// (i.e., after they've been parsed by the network layer). It does two levels
// of demultiplexing: first based on the network and transport protocols, then
// based on endpoints IDs. It should only be instantiated via
// newTransportDemuxer.
type transportDemuxer struct {
	// protocol is immutable.
	protocol map[protocolIDs]*transportEndpoints
}

func newTransportDemuxer(stack *Stack) *transportDemuxer {
	d := &transportDemuxer{protocol: make(map[protocolIDs]*transportEndpoints)}

	// Add each network and transport pair to the demuxer.
	for netProto := range stack.networkProtocols {
		for proto := range stack.transportProtocols {
			d.protocol[protocolIDs{netProto, proto}] = &transportEndpoints{
				endpoints: make(map[TransportEndpointID]TransportEndpoint),
			}
		}
	}

	return d
}

// registerEndpoint registers the given endpoint with the dispatcher such that
// packets that match the endpoint ID are delivered to it.
func (d *transportDemuxer) registerEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, reusePort bool) *tcpip.Error {
	for i, n := range netProtos {
		if err := d.singleRegisterEndpoint(n, protocol, id, ep, reusePort); err != nil {
			d.unregisterEndpoint(netProtos[:i], protocol, id, ep)
			return err
		}
	}

	return nil
}

// multiPortEndpoint is a container for TransportEndpoints which are bound to
// the same pair of address and port.
type multiPortEndpoint struct {
	mu           sync.RWMutex
	endpointsArr []TransportEndpoint
	endpointsMap map[TransportEndpoint]int
	// seed is a random secret for a jenkins hash.
	seed uint32
}

// reciprocalScale scales a value into range [0, n).
//
// This is similar to val % n, but faster.
// See http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
func reciprocalScale(val, n uint32) uint32 {
	return uint32((uint64(val) * uint64(n)) >> 32)
}

// selectEndpoint calculates a hash of destination and source addresses and
// ports then uses it to select a socket. In this case, all packets from one
// address will be sent to same endpoint.
func (ep *multiPortEndpoint) selectEndpoint(id TransportEndpointID) TransportEndpoint {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	payload := []byte{
		byte(id.LocalPort),
		byte(id.LocalPort >> 8),
		byte(id.RemotePort),
		byte(id.RemotePort >> 8),
	}

	h := jenkins.Sum32(ep.seed)
	h.Write(payload)
	h.Write([]byte(id.LocalAddress))
	h.Write([]byte(id.RemoteAddress))
	hash := h.Sum32()

	idx := reciprocalScale(hash, uint32(len(ep.endpointsArr)))
	return ep.endpointsArr[idx]
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (ep *multiPortEndpoint) HandlePacket(r *Route, id TransportEndpointID, vv buffer.VectorisedView) {
	// If this is a broadcast or multicast datagram, deliver the datagram to all
	// endpoints managed by ep.
	if id.LocalAddress == header.IPv4Broadcast || header.IsV4MulticastAddress(id.LocalAddress) || header.IsV6MulticastAddress(id.LocalAddress) {
		for i, endpoint := range ep.endpointsArr {
			// HandlePacket modifies vv, so each endpoint needs its own copy.
			if i == len(ep.endpointsArr)-1 {
				endpoint.HandlePacket(r, id, vv)
				break
			}
			vvCopy := buffer.NewView(vv.Size())
			copy(vvCopy, vv.ToView())
			endpoint.HandlePacket(r, id, vvCopy.ToVectorisedView())
		}
	} else {
		ep.selectEndpoint(id).HandlePacket(r, id, vv)
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (ep *multiPortEndpoint) HandleControlPacket(id TransportEndpointID, typ ControlType, extra uint32, vv buffer.VectorisedView) {
	ep.selectEndpoint(id).HandleControlPacket(id, typ, extra, vv)
}

func (ep *multiPortEndpoint) singleRegisterEndpoint(t TransportEndpoint) {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	// A new endpoint is added into endpointsArr and its index there is
	// saved in endpointsMap. This will allows to remove endpoint from
	// the array fast.
	ep.endpointsMap[ep] = len(ep.endpointsArr)
	ep.endpointsArr = append(ep.endpointsArr, t)
}

// unregisterEndpoint returns true if multiPortEndpoint has to be unregistered.
func (ep *multiPortEndpoint) unregisterEndpoint(t TransportEndpoint) bool {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	idx, ok := ep.endpointsMap[t]
	if !ok {
		return false
	}
	delete(ep.endpointsMap, t)
	l := len(ep.endpointsArr)
	if l > 1 {
		// The last endpoint in endpointsArr is moved instead of the deleted one.
		lastEp := ep.endpointsArr[l-1]
		ep.endpointsArr[idx] = lastEp
		ep.endpointsMap[lastEp] = idx
		ep.endpointsArr = ep.endpointsArr[0 : l-1]
		return false
	}
	return true
}

func (d *transportDemuxer) singleRegisterEndpoint(netProto tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, reusePort bool) *tcpip.Error {
	if id.RemotePort != 0 {
		reusePort = false
	}

	eps, ok := d.protocol[protocolIDs{netProto, protocol}]
	if !ok {
		return nil
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()

	var multiPortEp *multiPortEndpoint
	if _, ok := eps.endpoints[id]; ok {
		if !reusePort {
			return tcpip.ErrPortInUse
		}
		multiPortEp, ok = eps.endpoints[id].(*multiPortEndpoint)
		if !ok {
			return tcpip.ErrPortInUse
		}
	}

	if reusePort {
		if multiPortEp == nil {
			multiPortEp = &multiPortEndpoint{}
			multiPortEp.endpointsMap = make(map[TransportEndpoint]int)
			multiPortEp.seed = rand.Uint32()
			eps.endpoints[id] = multiPortEp
		}

		multiPortEp.singleRegisterEndpoint(ep)

		return nil
	}
	eps.endpoints[id] = ep

	return nil
}

// unregisterEndpoint unregisters the endpoint with the given id such that it
// won't receive any more packets.
func (d *transportDemuxer) unregisterEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) {
	for _, n := range netProtos {
		if eps, ok := d.protocol[protocolIDs{n, protocol}]; ok {
			eps.unregisterEndpoint(id, ep)
		}
	}
}

var loopbackSubnet = func() tcpip.Subnet {
	sn, err := tcpip.NewSubnet("\x7f\x00\x00\x00", "\xff\x00\x00\x00")
	if err != nil {
		panic(err)
	}
	return sn
}()

// deliverPacket attempts to find one or more matching transport endpoints, and
// then, if matches are found, delivers the packet to them. Returns true if it
// found one or more endpoints, false otherwise.
func (d *transportDemuxer) deliverPacket(r *Route, protocol tcpip.TransportProtocolNumber, netHeader buffer.View, vv buffer.VectorisedView, id TransportEndpointID) bool {
	eps, ok := d.protocol[protocolIDs{r.NetProto, protocol}]
	if !ok {
		return false
	}

	// If a sender bound to the Loopback interface sends a broadcast,
	// that broadcast must not be delivered to the sender.
	if loopbackSubnet.Contains(r.RemoteAddress) && r.LocalAddress == header.IPv4Broadcast && id.LocalPort == id.RemotePort {
		return false
	}

	// If the packet is a broadcast, then find all matching transport endpoints.
	// Otherwise, try to find a single matching transport endpoint.
	destEps := make([]TransportEndpoint, 0, 1)
	eps.mu.RLock()

	if protocol == header.UDPProtocolNumber && id.LocalAddress == header.IPv4Broadcast {
		for epID, endpoint := range eps.endpoints {
			if epID.LocalPort == id.LocalPort {
				destEps = append(destEps, endpoint)
			}
		}
	} else if ep := d.findEndpointLocked(eps, vv, id); ep != nil {
		destEps = append(destEps, ep)
	}

	// As in net/ipv4/ip_input.c:ip_local_deliver, attempt to deliver via
	// raw endpoint first. If there are multipe raw endpoints, they all
	// receive the packet.
	foundRaw := false
	for _, rawEP := range eps.rawEndpoints {
		// Each endpoint gets its own copy of the packet for the sake
		// of save/restore.
		rawEP.HandlePacket(r, buffer.NewViewFromBytes(netHeader), vv.ToView().ToVectorisedView())
		foundRaw = true
	}
	eps.mu.RUnlock()

	// Fail if we didn't find at least one matching transport endpoint.
	if len(destEps) == 0 && !foundRaw {
		// UDP packet could not be delivered to an unknown destination port.
		if protocol == header.UDPProtocolNumber {
			r.Stats().UDP.UnknownPortErrors.Increment()
		}
		return false
	}

	// Deliver the packet.
	for _, ep := range destEps {
		ep.HandlePacket(r, id, vv)
	}

	return true
}

// deliverControlPacket attempts to deliver the given control packet. Returns
// true if it found an endpoint, false otherwise.
func (d *transportDemuxer) deliverControlPacket(net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, vv buffer.VectorisedView, id TransportEndpointID) bool {
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

func (d *transportDemuxer) findEndpointLocked(eps *transportEndpoints, vv buffer.VectorisedView, id TransportEndpointID) TransportEndpoint {
	// Try to find a match with the id as provided.
	if ep, ok := eps.endpoints[id]; ok {
		return ep
	}

	// Try to find a match with the id minus the local address.
	nid := id

	nid.LocalAddress = ""
	if ep, ok := eps.endpoints[nid]; ok {
		return ep
	}

	// Try to find a match with the id minus the remote part.
	nid.LocalAddress = id.LocalAddress
	nid.RemoteAddress = ""
	nid.RemotePort = 0
	if ep, ok := eps.endpoints[nid]; ok {
		return ep
	}

	// Try to find a match with only the local port.
	nid.LocalAddress = ""
	if ep, ok := eps.endpoints[nid]; ok {
		return ep
	}

	return nil
}

// registerRawEndpoint registers the given endpoint with the dispatcher such
// that packets of the appropriate protocol are delivered to it. A single
// packet can be sent to one or more raw endpoints along with a non-raw
// endpoint.
func (d *transportDemuxer) registerRawEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) *tcpip.Error {
	eps, ok := d.protocol[protocolIDs{netProto, transProto}]
	if !ok {
		return nil
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()
	eps.rawEndpoints = append(eps.rawEndpoints, ep)

	return nil
}

// unregisterRawEndpoint unregisters the raw endpoint for the given transport
// protocol such that it won't receive any more packets.
func (d *transportDemuxer) unregisterRawEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) {
	eps, ok := d.protocol[protocolIDs{netProto, transProto}]
	if !ok {
		panic(fmt.Errorf("tried to unregister endpoint with unsupported network and transport protocol pair: %d, %d", netProto, transProto))
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()
	for i, rawEP := range eps.rawEndpoints {
		if rawEP == ep {
			eps.rawEndpoints = append(eps.rawEndpoints[:i], eps.rawEndpoints[i+1:]...)
			return
		}
	}
}
