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
	// As in br_fdb_update, the bridge's and its ports' own addresses are
	// never learned.
	sourceAddress := eth.SourceAddress()
	if _, hasSourceFDB := bridge.fdbTable[BridgeFDBKey(sourceAddress)]; !header.IsMulticastEthernetAddress(sourceAddress) && !hasSourceFDB && !bridge.isLocalAddressLocked(sourceAddress) {
		updateFDB = true
	}
	destAddress := eth.DestinationAddress()
	isMulticast := header.IsMulticastEthernetAddress(destAddress)
	// As with BR_FDB_LOCAL entries in br_handle_frame_finish, a unicast frame
	// for the bridge or for any of its ports is passed up and not forwarded.
	isLocal := !isMulticast && bridge.isLocalAddressLocked(destAddress)
	// Classify the frame as eth_type_trans does against the receiving port's
	// address, except that, as in br_handle_frame, a frame for the bridge's
	// address is for this host. A frame for another port's address is passed
	// up as PacketOtherHost, which the network layer drops.
	switch {
	case destAddress == header.EthernetBroadcastAddress:
		pkt.PktType = tcpip.PacketBroadcast
	case isMulticast:
		pkt.PktType = tcpip.PacketMulticast
	case destAddress == bridge.addr || destAddress == p.nic.LinkAddress():
		pkt.PktType = tcpip.PacketHost
	default:
		pkt.PktType = tcpip.PacketOtherHost
	}
	entry, inFDB := bridge.fdbTable[BridgeFDBKey(destAddress)]
	switch {
	case isLocal:
		// Passed up below.
	case !inFDB:
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
	case entry.port != p:
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
	// As in Linux, only group frames and frames addressed to the bridge or to
	// one of its ports are passed up. Passing up transit unicast lets IP
	// forwarding inject a duplicate back onto the bridge.
	if d != nil && (isMulticast || isLocal) {
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
	b.portAddrs = make(map[tcpip.NICID]tcpip.LinkAddress)
	b.localAddrs = make(map[tcpip.LinkAddress]int)
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
	// portAddrs maps each port to its link address, and localAddrs counts the
	// ports with each link address, like the BR_FDB_LOCAL entries Linux keeps
	// for its ports.
	//
	// +checklocks:mu
	portAddrs map[tcpip.NICID]tcpip.LinkAddress
	// +checklocks:mu
	localAddrs map[tcpip.LinkAddress]int
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
	b.addPortAddrLocked(n)

	if b.maxHeaderLength.Load() < uint32(n.MaxHeaderLength()) {
		b.maxHeaderLength.Store(uint32(n.MaxHeaderLength()))
	}

	return nil
}

// NICAddressChanged updates the bridge after the link address of the
// specified NIC changed, as br_fdb_changeaddr does on NETDEV_CHANGEADDR.
func (b *BridgeEndpoint) NICAddressChanged(n *nic) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.ports[n.id]; !ok {
		return
	}
	b.removePortAddrLocked(n)
	b.addPortAddrLocked(n)
}

// +checklocks:b.mu
func (b *BridgeEndpoint) addPortAddrLocked(n *nic) {
	addr := n.LinkAddress()
	b.portAddrs[n.id] = addr
	b.localAddrs[addr]++
}

// +checklocks:b.mu
func (b *BridgeEndpoint) removePortAddrLocked(n *nic) {
	addr, ok := b.portAddrs[n.id]
	if !ok {
		return
	}
	delete(b.portAddrs, n.id)
	if b.localAddrs[addr]--; b.localAddrs[addr] == 0 {
		delete(b.localAddrs, addr)
	}
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
	b.removePortAddrLocked(nic)
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
	b.mu.RLock()
	defer b.mu.RUnlock()
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
	b.portAddrs = make(map[tcpip.NICID]tcpip.LinkAddress)
	b.localAddrs = make(map[tcpip.LinkAddress]int)
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

// Add a new FDBEntry by learning. The learning happens when a packet
// is received by a bridge port, the bridge will use the port for the future
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

// isLocalAddressLocked returns whether addr is the address of the bridge or of
// one of its ports. Linux keeps BR_FDB_LOCAL entries for these addresses
// (br_fdb_change_mac_address, br_add_if, br_fdb_changeaddr).
//
// +checklocksread:b.mu
func (b *BridgeEndpoint) isLocalAddressLocked(addr tcpip.LinkAddress) bool {
	return addr == b.addr || b.localAddrs[addr] > 0
}

// FindFDBEntry find the FDB entry for the given address. If it doesn't exist,
// it will return an empty entry.
func (b *BridgeEndpoint) FindFDBEntry(addr tcpip.LinkAddress) BridgeFDBEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.fdbTable[BridgeFDBKey(addr)]
}
