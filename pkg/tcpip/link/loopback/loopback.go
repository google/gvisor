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

// Package loopback provides the implementation of loopback data-link layer
// endpoints. Such endpoints just turn outbound packets into inbound ones.
//
// Loopback endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package loopback

import (
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	loopbackMTU = 65536
)

// +stateify savable
type endpoint struct {
	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
	dispatcher stack.NetworkDispatcher
	// +checklocks:mu
	addr tcpip.LinkAddress
	// +checklocks:mu
	mtu uint32
}

// New creates a new loopback endpoint. This link-layer endpoint just turns
// outbound packets into inbound packets.
func New() stack.LinkEndpoint {
	return &endpoint{
		mtu: loopbackMTU,
	}
}

// Attach implements stack.LinkEndpoint.Attach. It just saves the stack network-
// layer dispatcher for later use when packets need to be dispatched.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU.
func (e *endpoint) MTU() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mtu
}

// SetMTU implements stack.LinkEndpoint.SetMTU. It has no impact.
func (e *endpoint) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
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
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.addr
}

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
func (e *endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.addr = addr
}

// Wait implements stack.LinkEndpoint.Wait.
func (*endpoint) Wait() {}

// WritePackets implements stack.LinkEndpoint.WritePackets. If the endpoint is
// not attached, the packets are not delivered.
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	for _, pkt := range pkts.AsSlice() {
		// In order to properly loop back to the inbound side we must create a
		// fresh packet that only contains the underlying payload with no headers
		// or struct fields set.
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: pkt.ToBuffer(),
		})
		if d != nil {
			d.DeliverNetworkPacket(pkt.NetworkProtocolNumber, newPkt)
		}
		newPkt.DecRef()
	}
	return pkts.Len(), nil
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareLoopback
}

// AddHeader implements stack.LinkEndpoint.
func (*endpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.
func (*endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// Close implements stack.LinkEndpoint.
func (*endpoint) Close() {}

// SetOnCloseAction implements stack.LinkEndpoint.
func (*endpoint) SetOnCloseAction(func()) {}
