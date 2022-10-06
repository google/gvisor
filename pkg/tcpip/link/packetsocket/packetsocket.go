// Copyright 2022 The gVisor Authors.
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

// Package packetsocket provides a link endpoint that enables delivery of
// incoming and outgoing packets to any interested packet sockets.
package packetsocket

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.NetworkDispatcher = (*endpoint)(nil)
var _ stack.LinkEndpoint = (*endpoint)(nil)

type endpoint struct {
	nested.Endpoint
}

// New creates a new packetsocket link endpoint wrapping a lower link endpoint.
//
// On ingress, the lower link endpoint must only deliver packets that have
// a link-layer header set if one is required for the link.
func New(lower stack.LinkEndpoint) stack.LinkEndpoint {
	e := &endpoint{}
	e.Endpoint.Init(lower, e)
	return e
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (e *endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
	e.Endpoint.DeliverLinkPacket(protocol, pkt, true /* incoming */)

	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}

// WritePackets implements stack.LinkEndpoint.
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		e.Endpoint.DeliverLinkPacket(pkt.NetworkProtocolNumber, pkt, false /* incoming */)
	}

	return e.Endpoint.WritePackets(pkts)
}
