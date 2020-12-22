// Copyright 2019 The gVisor Authors.
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

package udp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Forwarder is a session request forwarder, which allows clients to decide
// what to do with a session request, for example: ignore it, or process it.
//
// The canonical way of using it is to pass the Forwarder.HandlePacket function
// to stack.SetTransportProtocolHandler.
type Forwarder struct {
	handler func(*ForwarderRequest)

	stack *stack.Stack
}

// NewForwarder allocates and initializes a new forwarder.
func NewForwarder(s *stack.Stack, handler func(*ForwarderRequest)) *Forwarder {
	return &Forwarder{
		stack:   s,
		handler: handler,
	}
}

// HandlePacket handles all packets.
//
// This function is expected to be passed as an argument to the
// stack.SetTransportProtocolHandler function.
func (f *Forwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	f.handler(&ForwarderRequest{
		stack: f.stack,
		id:    id,
		pkt:   pkt,
	})

	return true
}

// ForwarderRequest represents a session request received by the forwarder and
// passed to the client. Clients may optionally create an endpoint to represent
// it via CreateEndpoint.
type ForwarderRequest struct {
	stack *stack.Stack
	id    stack.TransportEndpointID
	pkt   *stack.PacketBuffer
}

// ID returns the 4-tuple (src address, src port, dst address, dst port) that
// represents the session request.
func (r *ForwarderRequest) ID() stack.TransportEndpointID {
	return r.id
}

// CreateEndpoint creates a connected UDP endpoint for the session request.
func (r *ForwarderRequest) CreateEndpoint(queue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	netHdr := r.pkt.Network()
	route, err := r.stack.FindRoute(r.pkt.NICID, netHdr.DestinationAddress(), netHdr.SourceAddress(), r.pkt.NetworkProtocolNumber, false /* multicastLoop */)
	if err != nil {
		return nil, err
	}
	route.ResolveWith(r.pkt.SourceLinkAddress())

	ep := newEndpoint(r.stack, r.pkt.NetworkProtocolNumber, queue)
	if err := r.stack.RegisterTransportEndpoint(r.pkt.NICID, []tcpip.NetworkProtocolNumber{r.pkt.NetworkProtocolNumber}, ProtocolNumber, r.id, ep, ep.portFlags, tcpip.NICID(ep.ops.GetBindToDevice())); err != nil {
		ep.Close()
		route.Release()
		return nil, err
	}

	ep.ID = r.id
	ep.route = route
	ep.dstPort = r.id.RemotePort
	ep.effectiveNetProtos = []tcpip.NetworkProtocolNumber{r.pkt.NetworkProtocolNumber}
	ep.RegisterNICID = r.pkt.NICID
	ep.boundPortFlags = ep.portFlags

	ep.state = StateConnected

	ep.rcvMu.Lock()
	ep.rcvReady = true
	ep.rcvMu.Unlock()

	ep.HandlePacket(r.id, r.pkt)

	return ep, nil
}
