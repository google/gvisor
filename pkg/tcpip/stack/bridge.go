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

// +stateify savable
type bridgePort struct {
	bridge *BridgeEndpoint
	nic    *nic
}

// BridgeFDBKey is the MAC address of a device which a bridge port is associated with.
type BridgeFDBKey tcpip.LinkAddress

// BridgeFDBEntry consists of all metadata for a FDB record.
type BridgeFDBEntry struct {
	port *bridgePort
}

// PortLinkAddress returns the mac address of the device that is bound to the bridge port.
func (e BridgeFDBEntry) PortLinkAddress() tcpip.LinkAddress {
	if e.port == nil {
		return ""
	}
	return e.port.nic.LinkAddress()
}

// ParseHeader implements stack.LinkEndpoint.
func (p *bridgePort) ParseHeader(pkt *PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (p *bridgePort) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	bridge := p.bridge
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	updateFDB := false
	bridge.mu.RLock()
	// Add an entry at the bridge FDB, it maps a MAC address
	// to a bridge port where the traffic is received when
	// the MAC address is not multicast.
	// Network packets that are sent to the learned MAC address
	// will be forwarded to the bridge port that is stored in
	// the FDB table.
	sourceAddress := eth.SourceAddress()
	if _, hasSourceFDB := bridge.fdbTable[BridgeFDBKey(sourceAddress)]; !header.IsMulticastEthernetAddress(sourceAddress) && !hasSourceFDB {
		updateFDB = true
	}
	if entry, exist := bridge.fdbTable[BridgeFDBKey(eth.DestinationAddress())]; !exist {
		// When no FDB entry is found, send the packet to all ports.
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
	} else if entry.port != p {
		destPort := entry.port
		newPkt := NewPacketBuffer(PacketBufferOptions{
			ReserveHeaderBytes: int(destPort.nic.MaxHeaderLength()),
			Payload:            pkt.ToBuffer(),
		})
		destPort.nic.writeRawPacket(newPkt)
		newPkt.DecRef()
	}

	d := bridge.dispatcher
	bridge.mu.RUnlock()
	if updateFDB {
		bridge.mu.Lock()
		bridge.addFDBEntryLocked(eth.SourceAddress(), p, 0)
		bridge.mu.Unlock()
	}
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
	b.fdbTable = make(map[BridgeFDBKey]BridgeFDBEntry)
	return b
}

// BridgeEndpoint is a bridge endpoint.
//
// +stateify savable
type BridgeEndpoint struct {
	mu bridgeRWMutex `state:"nosave"`
	// +checklocks:mu
	ports map[tcpip.NICID]*bridgePort
	// +checklocks:mu
	dispatcher NetworkDispatcher
	// +checklocks:mu
	addr tcpip.LinkAddress
	// +checklocks:mu
	attached bool
	// +checklocks:mu
	mtu uint32
	// +checklocks:mu
	fdbTable        map[BridgeFDBKey]BridgeFDBEntry
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

	port := b.ports[nic.id]
	for k, e := range b.fdbTable {
		if e.port == port {
			delete(b.fdbTable, k)
		}
	}
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
	b.fdbTable = make(map[BridgeFDBKey]BridgeFDBEntry)
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

// Add a new FDBEntry by learning. The learning happens when a packaet
// is recevied by a bridge port, the bridge will use the port for the future
// deliveries to the NIC device.
// The addr is the key when it looks for the entry.
//
// +checklocks:b.mu
func (b *BridgeEndpoint) addFDBEntryLocked(addr tcpip.LinkAddress, source *bridgePort, flags uint64) bool {
	// TODO(b/376924093): limit bridge FDB size.
	b.fdbTable[BridgeFDBKey(addr)] = BridgeFDBEntry{
		port: source,
	}
	return true
}

// FindFDBEntry find the FDB entry for the given address. If it doesn't exist,
// it will return an empty entry.
func (b *BridgeEndpoint) FindFDBEntry(addr tcpip.LinkAddress) BridgeFDBEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.fdbTable[BridgeFDBKey(addr)]
}
