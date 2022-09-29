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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*Endpoint)(nil)

// New returns both ends of a new pipe.
func New(linkAddr1, linkAddr2 tcpip.LinkAddress, mtu uint32) (*Endpoint, *Endpoint) {
	ep1 := &Endpoint{
		linkAddr: linkAddr1,
		mtu:      mtu,
	}
	ep2 := &Endpoint{
		linkAddr: linkAddr2,
		mtu:      mtu,
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
	mtu        uint32
}

func (e *Endpoint) deliverPackets(pkts stack.PacketBufferList) {
	if !e.linked.IsAttached() {
		return
	}

	for _, pkt := range pkts.AsSlice() {
		// Create a fresh packet with pkt's payload but without struct fields
		// or headers set so the next link protocol can properly set the link
		// header.
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: pkt.ToBuffer(),
		})
		e.linked.dispatcher.DeliverNetworkPacket(pkt.NetworkProtocolNumber, newPkt)
		newPkt.DecRef()
	}
}

// WritePackets implements stack.LinkEndpoint.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := pkts.Len()
	e.deliverPackets(pkts)
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
func (e *Endpoint) MTU() uint32 {
	return e.mtu
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
func (*Endpoint) AddHeader(stack.PacketBufferPtr) {}
