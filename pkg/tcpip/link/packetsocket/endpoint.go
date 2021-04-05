// Copyright 2020 The gVisor Authors.
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

// Package packetsocket provides a link layer endpoint that provides the ability
// to loop outbound packets to any AF_PACKET sockets that may be interested in
// the outgoing packet.
package packetsocket

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type endpoint struct {
	nested.Endpoint
}

// New creates a new packetsocket LinkEndpoint.
func New(lower stack.LinkEndpoint) stack.LinkEndpoint {
	e := &endpoint{}
	e.Endpoint.Init(lower, e)
	return e
}

// WritePacket implements stack.LinkEndpoint.WritePacket.
func (e *endpoint) WritePacket(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	e.Endpoint.DeliverOutboundPacket(r.RemoteLinkAddress, r.LocalLinkAddress, protocol, pkt)
	return e.Endpoint.WritePacket(r, protocol, pkt)
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r stack.RouteInfo, pkts stack.PacketBufferList, proto tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		e.Endpoint.DeliverOutboundPacket(r.RemoteLinkAddress, r.LocalLinkAddress, pkt.NetworkProtocolNumber, pkt)
	}

	return e.Endpoint.WritePackets(r, pkts, proto)
}
