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

type veth struct {
	mu           sync.RWMutex
	closed       bool
	backlogQueue chan vethPacket
	mtu          uint32
	endpoints    [2]Endpoint
}

func (v *veth) close() {
	v.mu.Lock()
	closed := v.closed
	v.closed = true
	v.mu.Unlock()
	if closed {
		return
	}

	for i := range v.endpoints {
		e := &v.endpoints[i]
		e.mu.Lock()
		action := e.onCloseAction
		e.onCloseAction = nil
		e.mu.Unlock()
		if action != nil {
			action()
		}
	}
	close(v.backlogQueue)
}

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
	peer *Endpoint

	veth *veth

	mu sync.RWMutex `state:"nosave"`
	// +checklocks:mu
	dispatcher stack.NetworkDispatcher
	// linkAddr is the local address of this endpoint.
	//
	// +checklocks:mu
	linkAddr tcpip.LinkAddress
	// +checklocks:mu
	onCloseAction func()
}

// NewPair creates a new veth pair.
func NewPair(mtu uint32) (*Endpoint, *Endpoint) {
	veth := veth{
		backlogQueue: make(chan vethPacket, backlogQueueSize),
		mtu:          mtu,
		endpoints: [2]Endpoint{
			Endpoint{
				linkAddr: tcpip.GetRandMacAddr(),
			},
			Endpoint{
				linkAddr: tcpip.GetRandMacAddr(),
			},
		},
	}
	a := &veth.endpoints[0]
	b := &veth.endpoints[1]
	a.peer = b
	b.peer = a
	a.veth = &veth
	b.veth = &veth
	go func() {
		for t := range veth.backlogQueue {
			t.e.InjectInbound(t.protocol, t.pkt)
			t.pkt.DecRef()
		}

	}()
	return a, b
}

// Close closes e. Further packet injections will return an error, and all pending
// packets are discarded. Close may be called concurrently with WritePackets.
func (e *Endpoint) Close() {
	e.veth.close()
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

// MTU implements stack.LinkEndpoint.MTU.
func (e *Endpoint) MTU() uint32 {
	e.veth.mu.RLock()
	defer e.veth.mu.RUnlock()
	return e.veth.mtu
}

// SetMTU implements stack.LinkEndpoint.SetMTU.
func (e *Endpoint) SetMTU(mtu uint32) {
	e.veth.mu.Lock()
	defer e.veth.mu.Unlock()
	e.veth.mtu = mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	// TODO(b/352384218): Enable CapabilityTXChecksumOffload.
	return stack.CapabilityRXChecksumOffload | stack.CapabilitySaveRestore
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
	e.mu.RLock()
	defer e.mu.RUnlock()
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
	e.veth.mu.RLock()
	defer e.veth.mu.RUnlock()

	if e.veth.closed {
		return 0, nil
	}

	n := 0
	for _, pkt := range pkts.AsSlice() {
		// In order to properly loop back to the inbound side we must create a
		// fresh packet that only contains the underlying payload with no headers
		// or struct fields set. We must deep clone the payload to avoid
		// two goroutines writing to the same buffer.
		//
		// TODO(b/240580913): Remove this once IP headers use reference counted
		// views instead of raw byte slices.
		payload := pkt.ToBuffer()
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload.DeepClone(),
		})
		payload.Release()
		(e.veth.backlogQueue) <- vethPacket{
			e:        e.peer,
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

// SetOnCloseAction implements stack.LinkEndpoint.
func (e *Endpoint) SetOnCloseAction(action func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onCloseAction = action
}
