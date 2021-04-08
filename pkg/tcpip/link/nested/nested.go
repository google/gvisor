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

// Package nested provides helpers to implement the pattern of nested
// stack.LinkEndpoints.
package nested

import (
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Endpoint is a wrapper around stack.LinkEndpoint and stack.NetworkDispatcher
// that can be used to implement nesting safely by providing lifecycle
// concurrency guards.
//
// See the tests in this package for example usage.
type Endpoint struct {
	child    stack.LinkEndpoint
	embedder stack.NetworkDispatcher

	// mu protects dispatcher.
	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
}

var _ stack.GSOEndpoint = (*Endpoint)(nil)
var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.NetworkDispatcher = (*Endpoint)(nil)

// Init initializes a nested.Endpoint that uses embedder as the dispatcher for
// child on Attach.
//
// See the tests in this package for example usage.
func (e *Endpoint) Init(child stack.LinkEndpoint, embedder stack.NetworkDispatcher) {
	e.child = child
	e.embedder = embedder
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (e *Endpoint) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(remote, local, protocol, pkt)
	}
}

// DeliverOutboundPacket implements stack.NetworkDispatcher.DeliverOutboundPacket.
func (e *Endpoint) DeliverOutboundPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverOutboundPacket(remote, local, protocol, pkt)
	}
}

// Attach implements stack.LinkEndpoint.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = dispatcher
	e.mu.Unlock()
	// If we're attaching to a valid dispatcher, pass embedder as the dispatcher
	// to our child, otherwise detach the child by giving it a nil dispatcher.
	var pass stack.NetworkDispatcher
	if dispatcher != nil {
		pass = e.embedder
	}
	e.child.Attach(pass)
}

// IsAttached implements stack.LinkEndpoint.
func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	isAttached := e.dispatcher != nil
	e.mu.RUnlock()
	return isAttached
}

// MTU implements stack.LinkEndpoint.
func (e *Endpoint) MTU() uint32 {
	return e.child.MTU()
}

// Capabilities implements stack.LinkEndpoint.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.child.Capabilities()
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (e *Endpoint) MaxHeaderLength() uint16 {
	return e.child.MaxHeaderLength()
}

// LinkAddress implements stack.LinkEndpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.child.LinkAddress()
}

// WritePacket implements stack.LinkEndpoint.
func (e *Endpoint) WritePacket(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	return e.child.WritePacket(r, protocol, pkt)
}

// WritePackets implements stack.LinkEndpoint.
func (e *Endpoint) WritePackets(r stack.RouteInfo, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	return e.child.WritePackets(r, pkts, protocol)
}

// Wait implements stack.LinkEndpoint.
func (e *Endpoint) Wait() {
	e.child.Wait()
}

// GSOMaxSize implements stack.GSOEndpoint.
func (e *Endpoint) GSOMaxSize() uint32 {
	if e, ok := e.child.(stack.GSOEndpoint); ok {
		return e.GSOMaxSize()
	}
	return 0
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType
func (e *Endpoint) ARPHardwareType() header.ARPHardwareType {
	return e.child.ARPHardwareType()
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *Endpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.child.AddHeader(local, remote, protocol, pkt)
}
