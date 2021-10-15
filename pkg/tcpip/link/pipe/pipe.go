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
func New(linkAddr1, linkAddr2 tcpip.LinkAddress) (*Endpoint, *Endpoint) {
	ep1 := &Endpoint{
		linkAddr: linkAddr1,
	}
	ep2 := &Endpoint{
		linkAddr: linkAddr2,
	}
	ep1.linked = ep2
	ep2.linked = ep1
	return ep1, ep2
}

// Endpoint is one end of a pipe.
type Endpoint struct {
	dispatcher stack.NetworkDispatcher
	linked     *Endpoint
	linkAddr   tcpip.LinkAddress
}

func (e *Endpoint) deliverPackets(r stack.RouteInfo, proto tcpip.NetworkProtocolNumber, pkts stack.PacketBufferList) {
	if !e.linked.IsAttached() {
		return
	}

	// Note that the local address from the perspective of this endpoint is the
	// remote address from the perspective of the other end of the pipe
	// (e.linked). Similarly, the remote address from the perspective of this
	// endpoint is the local address on the other end.
	//
	// Deliver the packet in a new goroutine to escape this goroutine's stack and
	// avoid a deadlock when a packet triggers a response which leads the stack to
	// try and take a lock it already holds.
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		e.linked.dispatcher.DeliverNetworkPacket(r.LocalLinkAddress /* remote */, r.RemoteLinkAddress /* local */, proto, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.NewVectorisedView(pkt.Size(), pkt.Views()),
		}))
	}
}

// WritePacket implements stack.LinkEndpoint.
func (e *Endpoint) WritePacket(r stack.RouteInfo, proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	e.deliverPackets(r, proto, pkts)
	return nil
}

// WritePackets implements stack.LinkEndpoint.
func (e *Endpoint) WritePackets(r stack.RouteInfo, pkts stack.PacketBufferList, proto tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	n := pkts.Len()
	e.deliverPackets(r, proto, pkts)
	return n, nil
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
func (*Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
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
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.
func (*Endpoint) AddHeader(_, _ tcpip.LinkAddress, _ tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
}

// WriteRawPacket implements stack.LinkEndpoint.
func (e *Endpoint) WriteRawPacket(pkt *stack.PacketBuffer) tcpip.Error {
	return e.WritePacket(stack.RouteInfo{}, 0, pkt)
}
