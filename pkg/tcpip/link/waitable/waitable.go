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

// Package waitable provides the implementation of data-link layer endpoints
// that wrap other endpoints, and can wait for inflight calls to WritePacket or
// DeliverNetworkPacket to finish (and new ones to be prevented).
//
// Waitable endpoints can be used in the networking stack by calling New(eID) to
// create a new endpoint, where eID is the ID of the endpoint being wrapped,
// and then passing it as an argument to Stack.CreateNIC().
package waitable

import (
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Endpoint is a waitable link-layer endpoint.
type Endpoint struct {
	dispatchGate sync.Gate
	dispatcher   stack.NetworkDispatcher

	writeGate sync.Gate
	lower     stack.LinkEndpoint
}

// New creates a new waitable link-layer endpoint. It wraps around another
// endpoint and allows the caller to block new write/dispatch calls and wait for
// the inflight ones to finish before returning.
func New(lower stack.LinkEndpoint) *Endpoint {
	return &Endpoint{
		lower: lower,
	}
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.DeliverNetworkPacket.
// It is called by the link-layer endpoint being wrapped when a packet arrives,
// and only forwards to the actual dispatcher if Wait or WaitDispatch haven't
// been called.
func (e *Endpoint) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if !e.dispatchGate.Enter() {
		return
	}

	e.dispatcher.DeliverNetworkPacket(remote, local, protocol, pkt)
	e.dispatchGate.Leave()
}

// Attach implements stack.LinkEndpoint.Attach. It saves the dispatcher and
// registers with the lower endpoint as its dispatcher so that "e" is called
// for inbound packets.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	e.lower.Attach(e)
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It just forwards the request to the
// lower endpoint.
func (e *Endpoint) MTU() uint32 {
	return e.lower.MTU()
}

// Capabilities implements stack.LinkEndpoint.Capabilities. It just forwards the
// request to the lower endpoint.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.lower.Capabilities()
}

// MaxHeaderLength implements stack.LinkEndpoint.MaxHeaderLength. It just
// forwards the request to the lower endpoint.
func (e *Endpoint) MaxHeaderLength() uint16 {
	return e.lower.MaxHeaderLength()
}

// LinkAddress implements stack.LinkEndpoint.LinkAddress. It just forwards the
// request to the lower endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.lower.LinkAddress()
}

// WritePacket implements stack.LinkEndpoint.WritePacket. It is called by
// higher-level protocols to write packets. It only forwards packets to the
// lower endpoint if Wait or WaitWrite haven't been called.
func (e *Endpoint) WritePacket(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	if !e.writeGate.Enter() {
		return nil
	}

	err := e.lower.WritePacket(r, protocol, pkt)
	e.writeGate.Leave()
	return err
}

// WritePackets implements stack.LinkEndpoint.WritePackets. It is called by
// higher-level protocols to write packets. It only forwards packets to the
// lower endpoint if Wait or WaitWrite haven't been called.
func (e *Endpoint) WritePackets(r stack.RouteInfo, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	if !e.writeGate.Enter() {
		return pkts.Len(), nil
	}

	n, err := e.lower.WritePackets(r, pkts, protocol)
	e.writeGate.Leave()
	return n, err
}

// WaitWrite prevents new calls to WritePacket from reaching the lower endpoint,
// and waits for inflight ones to finish before returning.
func (e *Endpoint) WaitWrite() {
	e.writeGate.Close()
}

// WaitDispatch prevents new calls to DeliverNetworkPacket from reaching the
// actual dispatcher, and waits for inflight ones to finish before returning.
func (e *Endpoint) WaitDispatch() {
	e.dispatchGate.Close()
}

// Wait implements stack.LinkEndpoint.Wait.
func (e *Endpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (e *Endpoint) ARPHardwareType() header.ARPHardwareType {
	return e.lower.ARPHardwareType()
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *Endpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.lower.AddHeader(local, remote, protocol, pkt)
}

// WriteRawPacket implements stack.LinkEndpoint.
func (*Endpoint) WriteRawPacket(*stack.PacketBuffer) tcpip.Error { return &tcpip.ErrNotSupported{} }
