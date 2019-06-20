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

// Package muxed provides a muxed link endpoints.
package muxed

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// InjectableEndpoint is an injectable multi endpoint. The endpoint has
// trivial routing rules that determine which InjectableEndpoint a given packet
// will be written to. Note that HandleLocal works differently for this
// endpoint (see WritePacket).
type InjectableEndpoint struct {
	routes     map[tcpip.Address]stack.InjectableLinkEndpoint
	dispatcher stack.NetworkDispatcher
}

// MTU implements stack.LinkEndpoint.
func (m *InjectableEndpoint) MTU() uint32 {
	minMTU := ^uint32(0)
	for _, endpoint := range m.routes {
		if endpointMTU := endpoint.MTU(); endpointMTU < minMTU {
			minMTU = endpointMTU
		}
	}
	return minMTU
}

// Capabilities implements stack.LinkEndpoint.
func (m *InjectableEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	minCapabilities := stack.LinkEndpointCapabilities(^uint(0))
	for _, endpoint := range m.routes {
		minCapabilities &= endpoint.Capabilities()
	}
	return minCapabilities
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (m *InjectableEndpoint) MaxHeaderLength() uint16 {
	minHeaderLen := ^uint16(0)
	for _, endpoint := range m.routes {
		if headerLen := endpoint.MaxHeaderLength(); headerLen < minHeaderLen {
			minHeaderLen = headerLen
		}
	}
	return minHeaderLen
}

// LinkAddress implements stack.LinkEndpoint.
func (m *InjectableEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// Attach implements stack.LinkEndpoint.
func (m *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	for _, endpoint := range m.routes {
		endpoint.Attach(dispatcher)
	}
	m.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.
func (m *InjectableEndpoint) IsAttached() bool {
	return m.dispatcher != nil
}

// Inject implements stack.InjectableLinkEndpoint.
func (m *InjectableEndpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	m.dispatcher.DeliverNetworkPacket(m, "" /* remote */, "" /* local */, protocol, vv)
}

// WritePacket writes outbound packets to the appropriate LinkInjectableEndpoint
// based on the RemoteAddress. HandleLocal only works if r.RemoteAddress has a
// route registered in this endpoint.
func (m *InjectableEndpoint) WritePacket(r *stack.Route, _ *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	if endpoint, ok := m.routes[r.RemoteAddress]; ok {
		return endpoint.WritePacket(r, nil /* gso */, hdr, payload, protocol)
	}
	return tcpip.ErrNoRoute
}

// WriteRawPacket writes outbound packets to the appropriate
// LinkInjectableEndpoint based on the dest address.
func (m *InjectableEndpoint) WriteRawPacket(dest tcpip.Address, packet []byte) *tcpip.Error {
	endpoint, ok := m.routes[dest]
	if !ok {
		return tcpip.ErrNoRoute
	}
	return endpoint.WriteRawPacket(dest, packet)
}

// NewInjectableEndpoint creates a new multi-endpoint injectable endpoint.
func NewInjectableEndpoint(routes map[tcpip.Address]stack.InjectableLinkEndpoint) (tcpip.LinkEndpointID, *InjectableEndpoint) {
	e := &InjectableEndpoint{
		routes: routes,
	}
	return stack.RegisterLinkEndpoint(e), e
}
