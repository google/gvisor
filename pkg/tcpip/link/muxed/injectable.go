// Copyright 2019 Google LLC
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

// Package injectable provides a muxed injectable endpoint.
package injectable

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

// MuxedInjectableEndpoint is an injectable multi endpoint. The endpoint has
// trivial routing rules that determine which InjectableEndpoint a given packet
// will be written to. Note that HandleLocal works differently for this
// endpoint (see WritePacket).
type MuxedInjectableEndpoint struct {
	routes     map[tcpip.Address]stack.InjectableLinkEndpoint
	dispatcher stack.NetworkDispatcher
}

// MTU implements stack.LinkEndpoint.
func (m *MuxedInjectableEndpoint) MTU() uint32 {
	minMTU := ^uint32(0)
	for _, endpoint := range m.routes {
		if endpointMTU := endpoint.MTU(); endpointMTU < minMTU {
			minMTU = endpointMTU
		}
	}
	return minMTU
}

// Capabilities implements stack.LinkEndpoint.
func (m *MuxedInjectableEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	minCapabilities := stack.LinkEndpointCapabilities(^uint(0))
	for _, endpoint := range m.routes {
		minCapabilities &= endpoint.Capabilities()
	}
	return minCapabilities
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (m *MuxedInjectableEndpoint) MaxHeaderLength() uint16 {
	minHeaderLen := ^uint16(0)
	for _, endpoint := range m.routes {
		if headerLen := endpoint.MaxHeaderLength(); headerLen < minHeaderLen {
			minHeaderLen = headerLen
		}
	}
	return minHeaderLen
}

// LinkAddress implements stack.LinkEndpoint.
func (m *MuxedInjectableEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// Attach implements stack.LinkEndpoint.
func (m *MuxedInjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	for _, endpoint := range m.routes {
		endpoint.Attach(dispatcher)
	}
	m.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.
func (m *MuxedInjectableEndpoint) IsAttached() bool {
	return m.dispatcher != nil
}

// Inject implements stack.InjectableLinkEndpoint.
func (m *MuxedInjectableEndpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	m.dispatcher.DeliverNetworkPacket(m, "" /* remote */, "" /* local */, protocol, vv)
}

// WritePacket writes outbound packets to the appropriate LinkInjectableEndpoint
// based on the RemoteAddress. HandleLocal only works if r.RemoteAddress has a
// route registered in this endpoint.
func (m *MuxedInjectableEndpoint) WritePacket(r *stack.Route, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	if endpoint, ok := m.routes[r.RemoteAddress]; ok {
		return endpoint.WritePacket(r, hdr, payload, protocol)
	}
	return tcpip.ErrNoRoute
}

// NewMuxedInjectableEndpoint creates a new multi-fd-based injectable endpoint.
func NewMuxedInjectableEndpoint(routes map[tcpip.Address]stack.InjectableLinkEndpoint, mtu uint32) (tcpip.LinkEndpointID, *MuxedInjectableEndpoint) {
	e := &MuxedInjectableEndpoint{
		routes: routes,
	}
	return stack.RegisterLinkEndpoint(e), e
}
