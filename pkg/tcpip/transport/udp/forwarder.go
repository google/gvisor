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
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
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
func (f *Forwarder) HandlePacket(r *stack.Route, id stack.TransportEndpointID, netHeader buffer.View, vv buffer.VectorisedView) bool {
	f.handler(&ForwarderRequest{
		stack: f.stack,
		route: r,
		id:    id,
		vv:    vv,
	})

	return true
}

// ForwarderRequest represents a session request received by the forwarder and
// passed to the client. Clients may optionally create an endpoint to represent
// it via CreateEndpoint.
type ForwarderRequest struct {
	stack *stack.Stack
	route *stack.Route
	id    stack.TransportEndpointID
	vv    buffer.VectorisedView
}

// ID returns the 4-tuple (src address, src port, dst address, dst port) that
// represents the session request.
func (r *ForwarderRequest) ID() stack.TransportEndpointID {
	return r.id
}

// CreateEndpoint creates a connected UDP endpoint for the session request.
func (r *ForwarderRequest) CreateEndpoint(queue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	ep := newEndpoint(r.stack, r.route.NetProto, queue)
	if err := r.stack.RegisterTransportEndpoint(r.route.NICID(), []tcpip.NetworkProtocolNumber{r.route.NetProto}, ProtocolNumber, r.id, ep, ep.reusePort); err != nil {
		ep.Close()
		return nil, err
	}

	ep.id = r.id
	ep.route = r.route.Clone()
	ep.dstPort = r.id.RemotePort
	ep.regNICID = r.route.NICID()

	ep.state = stateConnected

	ep.rcvMu.Lock()
	ep.rcvReady = true
	ep.rcvMu.Unlock()

	ep.HandlePacket(r.route, r.id, r.vv)

	return ep, nil
}
