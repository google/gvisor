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
	"gvisor.dev/gvisor/pkg/tcpip/header"
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

// InjectInbound implements stack.InjectableLinkEndpoint.
func (m *InjectableEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	m.dispatcher.DeliverNetworkPacket("" /* remote */, "" /* local */, protocol, pkt)
}

// WritePackets writes outbound packets to the appropriate
// LinkInjectableEndpoint based on the RemoteAddress. HandleLocal only works if
// r.RemoteAddress has a route registered in this endpoint.
func (m *InjectableEndpoint) WritePackets(r stack.RouteInfo, gso *stack.GSO, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	endpoint, ok := m.routes[r.RemoteAddress]
	if !ok {
		return 0, tcpip.ErrNoRoute
	}
	return endpoint.WritePackets(r, gso, pkts, protocol)
}

// WritePacket writes outbound packets to the appropriate LinkInjectableEndpoint
// based on the RemoteAddress. HandleLocal only works if r.RemoteAddress has a
// route registered in this endpoint.
func (m *InjectableEndpoint) WritePacket(r stack.RouteInfo, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	if endpoint, ok := m.routes[r.RemoteAddress]; ok {
		return endpoint.WritePacket(r, gso, protocol, pkt)
	}
	return tcpip.ErrNoRoute
}

// InjectOutbound writes outbound packets to the appropriate
// LinkInjectableEndpoint based on the dest address.
func (m *InjectableEndpoint) InjectOutbound(dest tcpip.Address, packet []byte) *tcpip.Error {
	endpoint, ok := m.routes[dest]
	if !ok {
		return tcpip.ErrNoRoute
	}
	return endpoint.InjectOutbound(dest, packet)
}

// Wait implements stack.LinkEndpoint.Wait.
func (m *InjectableEndpoint) Wait() {
	for _, ep := range m.routes {
		ep.Wait()
	}
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*InjectableEndpoint) ARPHardwareType() header.ARPHardwareType {
	panic("unsupported operation")
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*InjectableEndpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
}

// NewInjectableEndpoint creates a new multi-endpoint injectable endpoint.
func NewInjectableEndpoint(routes map[tcpip.Address]stack.InjectableLinkEndpoint) *InjectableEndpoint {
	return &InjectableEndpoint{
		routes: routes,
	}
}
