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

// Package pipe provides the implementation of pipe-like data-link layer
// endpoints. Such endpoints allow packets to be sent between two interfaces.
package pipe

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*Endpoint)(nil)

// New returns both ends of a new pipe.
func New(linkAddr1, linkAddr2 tcpip.LinkAddress, capabilities stack.LinkEndpointCapabilities) (*Endpoint, *Endpoint) {
	ep1 := &Endpoint{
		linkAddr:     linkAddr1,
		capabilities: capabilities,
	}
	ep2 := &Endpoint{
		linkAddr:     linkAddr2,
		linked:       ep1,
		capabilities: capabilities,
	}
	ep1.linked = ep2
	return ep1, ep2
}

// Endpoint is one end of a pipe.
type Endpoint struct {
	capabilities  stack.LinkEndpointCapabilities
	linkAddr      tcpip.LinkAddress
	dispatcher    stack.NetworkDispatcher
	linked        *Endpoint
	onWritePacket func(*stack.PacketBuffer)
}

// WritePacket implements stack.LinkEndpoint.
func (e *Endpoint) WritePacket(r *stack.Route, _ *stack.GSO, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	if !e.linked.IsAttached() {
		return nil
	}

	// The pipe endpoint will accept all multicast/broadcast link traffic and only
	// unicast traffic destined to itself.
	if len(e.linked.linkAddr) != 0 &&
		r.RemoteLinkAddress != e.linked.linkAddr &&
		r.RemoteLinkAddress != header.EthernetBroadcastAddress &&
		!header.IsMulticastEthernetAddress(r.RemoteLinkAddress) {
		return nil
	}

	e.linked.dispatcher.DeliverNetworkPacket(e.linkAddr, r.RemoteLinkAddress, proto, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buffer.NewVectorisedView(pkt.Size(), pkt.Views()),
	}))

	return nil
}

// WritePackets implements stack.LinkEndpoint.
func (*Endpoint) WritePackets(*stack.Route, *stack.GSO, stack.PacketBufferList, tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	panic("not implemented")
}

// WriteRawPacket implements stack.LinkEndpoint.
func (*Endpoint) WriteRawPacket(buffer.VectorisedView) *tcpip.Error {
	panic("not implemented")
}

// Attach implements stack.LinkEndpoint.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.
func (e *Endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// Wait implements stack.LinkEndpoint.
func (*Endpoint) Wait() {}

// MTU implements stack.LinkEndpoint.
func (*Endpoint) MTU() uint32 {
	return header.IPv6MinimumMTU
}

// Capabilities implements stack.LinkEndpoint.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.capabilities
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress implements stack.LinkEndpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// ARPHardwareType implements stack.LinkEndpoint.
func (*Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

// AddHeader implements stack.LinkEndpoint.
func (*Endpoint) AddHeader(_, _ tcpip.LinkAddress, _ tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
}
