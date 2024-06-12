// Copyright 2024 The gVisor Authors.
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

// Package veth provides the implementation of virtual ethernet device pair.
package veth

import (
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.GSOEndpoint = (*Endpoint)(nil)

// +stateify savable
type vethPacket struct {
	e        *Endpoint
	protocol tcpip.NetworkProtocolNumber
	pkt      *stack.PacketBuffer
}

const backlogQueueSize = 64

// Endpoint is link layer endpoint that redirects packets to a pair veth endpoint.
//
// +stateify savable
type Endpoint struct {
	pair *Endpoint
	mtu  uint32

	backlogQueue *chan vethPacket

	// linkAddr is the local address of this endpoint.
	// linkaddr is immutable.
	linkAddr tcpip.LinkAddress

	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
	dispatcher stack.NetworkDispatcher

	// +checklocks:mu
	stack *stack.Stack
	// +checklocks:mu
	idx tcpip.NICID
}

// NewPair creates a new veth pair.
func NewPair(mtu uint32) (*Endpoint, *Endpoint) {
	backlogQueue := make(chan vethPacket, backlogQueueSize)
	a := &Endpoint{
		mtu:          mtu,
		linkAddr:     tcpip.GetRandMacAddr(),
		backlogQueue: &backlogQueue,
	}
	b := &Endpoint{
		mtu:          mtu,
		pair:         a,
		linkAddr:     tcpip.GetRandMacAddr(),
		backlogQueue: &backlogQueue,
	}
	a.pair = b
	go func() {
		for t := range backlogQueue {
			t.e.InjectInbound(t.protocol, t.pkt)
			t.pkt.DecRef()
		}
	}()
	return a, b
}

// SetStack stores the stack and the device index.
func (e *Endpoint) SetStack(s *stack.Stack, idx tcpip.NICID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stack = s
	e.idx = idx
}

// Close closes e. Further packet injections will return an error, and all pending
// packets are discarded. Close may be called concurrently with WritePackets.
func (e *Endpoint) Close() {
	e.mu.Lock()
	stack := e.stack
	e.stack = nil
	e.mu.Unlock()
	if stack == nil {
		return
	}

	e = e.pair
	e.mu.Lock()
	stack = e.stack
	idx := e.idx
	e.stack = nil
	e.mu.Unlock()
	if stack != nil {
		stack.RemoveNIC(idx)
	}
	close(*e.backlogQueue)
}

// InjectInbound injects an inbound packet. If the endpoint is not attached, the
// packet is not delivered.
func (e *Endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload | stack.CapabilityTXChecksumOffload | stack.CapabilitySaveRestore
}

// GSOMaxSize implements stack.GSOEndpoint.
func (*Endpoint) GSOMaxSize() uint32 {
	return stack.GVisorGSOMaxSize
}

// SupportedGSO implements stack.GSOEndpoint.
func (e *Endpoint) SupportedGSO() stack.SupportedGSO {
	return stack.GVisorGSOSupported
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.linkAddr = addr
}

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		// In order to properly loop back to the inbound side we must create a
		// fresh packet that only contains the underlying payload with no headers
		// or struct fields set.
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: pkt.ToBuffer(),
		})
		(*e.backlogQueue) <- vethPacket{
			e:        e.pair,
			protocol: pkt.NetworkProtocolNumber,
			pkt:      newPkt,
		}
		n++
	}

	return n, nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (*Endpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *Endpoint) AddHeader(pkt *stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (e *Endpoint) ParseHeader(pkt *stack.PacketBuffer) bool { return true }
