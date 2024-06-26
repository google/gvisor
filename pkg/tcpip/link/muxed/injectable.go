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
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// InjectableEndpoint is an injectable multi endpoint. The endpoint has
// trivial routing rules that determine which InjectableEndpoint a given packet
// will be written to. Note that HandleLocal works differently for this
// endpoint (see WritePacket).
//
// +stateify savable
type InjectableEndpoint struct {
	routes map[tcpip.Address]stack.InjectableLinkEndpoint

	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
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

// SetMTU implements stack.LinkEndpoint.
func (m *InjectableEndpoint) SetMTU(mtu uint32) {
	for _, endpoint := range m.routes {
		endpoint.SetMTU(mtu)
	}
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

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
func (m *InjectableEndpoint) SetLinkAddress(tcpip.LinkAddress) {}

// Attach implements stack.LinkEndpoint.
func (m *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	for _, endpoint := range m.routes {
		endpoint.Attach(dispatcher)
	}
	m.mu.Lock()
	m.dispatcher = dispatcher
	m.mu.Unlock()
}

// IsAttached implements stack.LinkEndpoint.
func (m *InjectableEndpoint) IsAttached() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dispatcher != nil
}

// InjectInbound implements stack.InjectableLinkEndpoint.
func (m *InjectableEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	m.mu.RLock()
	d := m.dispatcher
	m.mu.RUnlock()
	d.DeliverNetworkPacket(protocol, pkt)
}

// WritePackets writes outbound packets to the appropriate
// LinkInjectableEndpoint based on the RemoteAddress. HandleLocal only works if
// pkt.EgressRoute.RemoteAddress has a route registered in this endpoint.
func (m *InjectableEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	i := 0
	for _, pkt := range pkts.AsSlice() {
		endpoint, ok := m.routes[pkt.EgressRoute.RemoteAddress]
		if !ok {
			return i, &tcpip.ErrHostUnreachable{}
		}

		var tmpPkts stack.PacketBufferList
		tmpPkts.PushBack(pkt)

		n, err := endpoint.WritePackets(tmpPkts)
		if err != nil {
			return i, err
		}

		i += n
	}

	return i, nil
}

// InjectOutbound writes outbound packets to the appropriate
// LinkInjectableEndpoint based on the dest address.
func (m *InjectableEndpoint) InjectOutbound(dest tcpip.Address, packet *buffer.View) tcpip.Error {
	endpoint, ok := m.routes[dest]
	if !ok {
		return &tcpip.ErrHostUnreachable{}
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
func (*InjectableEndpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (*InjectableEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// Close implements stack.LinkEndpoint.
func (*InjectableEndpoint) Close() {}

// SetOnCloseAction implements stack.LinkEndpoint.SetOnCloseAction.
func (*InjectableEndpoint) SetOnCloseAction(func()) {}

// NewInjectableEndpoint creates a new multi-endpoint injectable endpoint.
func NewInjectableEndpoint(routes map[tcpip.Address]stack.InjectableLinkEndpoint) *InjectableEndpoint {
	return &InjectableEndpoint{
		routes: routes,
	}
}
