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

package stack

import (
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var _ NetworkLinkEndpoint = (*BridgeEndpoint)(nil)

type bridgePort struct {
	bridge *BridgeEndpoint
	nic    *nic
}

// ParseHeader implements stack.LinkEndpoint.
func (p *bridgePort) ParseHeader(pkt *PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (p *bridgePort) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	bridge := p.bridge
	bridge.mu.RLock()

	// Send the packet to all other ports.
	for _, port := range bridge.ports {
		if p == port {
			continue
		}
		newPkt := NewPacketBuffer(PacketBufferOptions{
			ReserveHeaderBytes: int(port.nic.MaxHeaderLength()),
			Payload:            pkt.ToBuffer(),
		})
		port.nic.writeRawPacket(newPkt)
		newPkt.DecRef()
	}

	d := bridge.dispatcher
	bridge.mu.RUnlock()
	if d != nil {
		// The dispatcher may acquire Stack.mu in DeliverNetworkPacket(), which is
		// ordered above bridge.mu. So call DeliverNetworkPacket() without holding
		// bridge.mu to avoid circular locking.
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

func (p *bridgePort) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
}

// NewBridgeEndpoint creates a new bridge endpoint.
func NewBridgeEndpoint(mtu uint32) *BridgeEndpoint {
	b := &BridgeEndpoint{
		mtu:  mtu,
		addr: tcpip.GetRandMacAddr(),
	}
	b.ports = make(map[tcpip.NICID]*bridgePort)
	return b
}

// BridgeEndpoint is a bridge endpoint.
type BridgeEndpoint struct {
	mu bridgeRWMutex
	// +checklocks:mu
	ports map[tcpip.NICID]*bridgePort
	// +checklocks:mu
	dispatcher NetworkDispatcher
	// +checklocks:mu
	addr tcpip.LinkAddress
	// +checklocks:mu
	attached bool
	// +checklocks:mu
	mtu             uint32
	maxHeaderLength atomicbitops.Uint32
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (b *BridgeEndpoint) WritePackets(pkts PacketBufferList) (int, tcpip.Error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	pktsSlice := pkts.AsSlice()
	n := len(pktsSlice)
	for _, p := range b.ports {
		for _, pkt := range pktsSlice {
			// In order to properly loop back to the inbound side we must create a
			// fresh packet that only contains the underlying payload with no headers
			// or struct fields set.
			newPkt := NewPacketBuffer(PacketBufferOptions{
				Payload:            pkt.ToBuffer(),
				ReserveHeaderBytes: int(p.nic.MaxHeaderLength()),
			})
			newPkt.EgressRoute = pkt.EgressRoute
			newPkt.NetworkProtocolNumber = pkt.NetworkProtocolNumber
			p.nic.writePacket(newPkt)
			newPkt.DecRef()
		}
	}

	return n, nil
}

// AddNIC adds the specified NIC to the bridge.
func (b *BridgeEndpoint) AddNIC(n *nic) tcpip.Error {
	b.mu.Lock()
	defer b.mu.Unlock()

	port := &bridgePort{
		nic:    n,
		bridge: b,
	}
	n.NetworkLinkEndpoint.Attach(port)
	b.ports[n.id] = port

	if b.maxHeaderLength.Load() < uint32(n.MaxHeaderLength()) {
		b.maxHeaderLength.Store(uint32(n.MaxHeaderLength()))
	}

	return nil
}

// DelNIC remove the specified NIC from the bridge.
func (b *BridgeEndpoint) DelNIC(nic *nic) tcpip.Error {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.ports, nic.id)
	nic.NetworkLinkEndpoint.Attach(nic)
	return nil
}

// MTU implements stack.LinkEndpoint.MTU.
func (b *BridgeEndpoint) MTU() uint32 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.mtu > header.EthernetMinimumSize {
		return b.mtu - header.EthernetMinimumSize
	}
	return 0
}

// SetMTU implements stack.LinkEndpoint.SetMTU.
func (b *BridgeEndpoint) SetMTU(mtu uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mtu = mtu
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (b *BridgeEndpoint) MaxHeaderLength() uint16 {
	return uint16(b.maxHeaderLength.Load())
}

// LinkAddress implements stack.LinkEndpoint.LinkAddress.
func (b *BridgeEndpoint) LinkAddress() tcpip.LinkAddress {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.addr
}

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
func (b *BridgeEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.addr = addr
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (b *BridgeEndpoint) Capabilities() LinkEndpointCapabilities {
	return CapabilityRXChecksumOffload | CapabilitySaveRestore | CapabilityResolutionRequired
}

// Attach implements stack.LinkEndpoint.Attach.
func (b *BridgeEndpoint) Attach(dispatcher NetworkDispatcher) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.ports {
		p.nic.Primary = nil
	}
	b.dispatcher = dispatcher
	b.ports = make(map[tcpip.NICID]*bridgePort)
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (b *BridgeEndpoint) IsAttached() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.dispatcher != nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (b *BridgeEndpoint) Wait() {
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (b *BridgeEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (b *BridgeEndpoint) AddHeader(pkt *PacketBuffer) {
}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (b *BridgeEndpoint) ParseHeader(*PacketBuffer) bool {
	return true
}

// Close implements stack.LinkEndpoint.Close.
func (b *BridgeEndpoint) Close() {}

// SetOnCloseAction implements stack.LinkEndpoint.Close.
func (b *BridgeEndpoint) SetOnCloseAction(func()) {}
