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

// Package loopback provides the implemention of loopback data-link layer
// endpoints. Such endpoints just turn outbound packets into inbound ones.
//
// Loopback endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package loopback

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type endpoint struct {
	dispatcher stack.NetworkDispatcher
}

// New creates a new loopback endpoint. This link-layer endpoint just turns
// outbound packets into inbound packets.
func New() stack.LinkEndpoint {
	return &endpoint{}
}

// Attach implements stack.LinkEndpoint.Attach. It just saves the stack network-
// layer dispatcher for later use when packets need to be dispatched.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns a constant that matches the
// linux loopback interface.
func (*endpoint) MTU() uint32 {
	return 65536
}

// Capabilities implements stack.LinkEndpoint.Capabilities. Loopback advertises
// itself as supporting checksum offload, but in reality it's just omitted.
func (*endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload | stack.CapabilityTXChecksumOffload | stack.CapabilitySaveRestore | stack.CapabilityLoopback
}

// MaxHeaderLength implements stack.LinkEndpoint.MaxHeaderLength. Given that the
// loopback interface doesn't have a header, it just returns 0.
func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (*endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// Wait implements stack.LinkEndpoint.Wait.
func (*endpoint) Wait() {}

// WritePacket implements stack.LinkEndpoint.WritePacket. It delivers outbound
// packets to the network-layer dispatcher.
func (e *endpoint) WritePacket(_ *stack.Route, _ *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) *tcpip.Error {
	views := make([]buffer.View, 1, 1+len(pkt.Data.Views()))
	views[0] = pkt.Header.View()
	views = append(views, pkt.Data.Views()...)

	// Because we're immediately turning around and writing the packet back
	// to the rx path, we intentionally don't preserve the remote and local
	// link addresses from the stack.Route we're passed.
	e.dispatcher.DeliverNetworkPacket(e, "" /* remote */, "" /* local */, protocol, tcpip.PacketBuffer{
		Data: buffer.NewVectorisedView(len(views[0])+pkt.Data.Size(), views),
	})

	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *endpoint) WritePackets(_ *stack.Route, _ *stack.GSO, hdrs []stack.PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	panic("not implemented")
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	// Reject the packet if it's shorter than an ethernet header.
	if vv.Size() < header.EthernetMinimumSize {
		return tcpip.ErrBadAddress
	}

	// There should be an ethernet header at the beginning of vv.
	linkHeader := header.Ethernet(vv.First()[:header.EthernetMinimumSize])
	vv.TrimFront(len(linkHeader))
	e.dispatcher.DeliverNetworkPacket(e, "" /* remote */, "" /* local */, linkHeader.Type(), tcpip.PacketBuffer{
		Data:       vv,
		LinkHeader: buffer.View(linkHeader),
	})

	return nil
}
