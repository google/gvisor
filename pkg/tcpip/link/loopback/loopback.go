// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

type endpoint struct {
	dispatcher stack.NetworkDispatcher
}

// New creates a new loopback endpoint. This link-layer endpoint just turns
// outbound packets into inbound packets.
func New() tcpip.LinkEndpointID {
	return stack.RegisterLinkEndpoint(&endpoint{})
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
	return stack.CapabilityChecksumOffload | stack.CapabilitySaveRestore | stack.CapabilityLoopback
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

// WritePacket implements stack.LinkEndpoint.WritePacket. It delivers outbound
// packets to the network-layer dispatcher.
func (e *endpoint) WritePacket(_ *stack.Route, _ *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	views := make([]buffer.View, 1, 1+len(payload.Views()))
	views[0] = hdr.View()
	views = append(views, payload.Views()...)
	vv := buffer.NewVectorisedView(len(views[0])+payload.Size(), views)

	// Because we're immediately turning around and writing the packet back to the
	// rx path, we intentionally don't preserve the remote and local link
	// addresses from the stack.Route we're passed.
	e.dispatcher.DeliverNetworkPacket(e, "" /* remote */, "" /* local */, protocol, vv)

	return nil
}
