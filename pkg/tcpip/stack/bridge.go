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

// BridgePortFlags is a set of per-port bridge options.
type BridgePortFlags uint32

const (
	// BridgePortHairpin allows the bridge to send a frame back out of the port
	// it was received on. It is Linux's BR_HAIRPIN_MODE.
	BridgePortHairpin BridgePortFlags = 1 << iota

	// BridgePortLearning makes the bridge learn source addresses seen on the
	// port. It is Linux's BR_LEARNING.
	BridgePortLearning
)

// defaultBridgePortFlags are the modeled flags of a newly added port. Linux
// starts a port with BR_LEARNING, BR_FLOOD, BR_MCAST_FLOOD and BR_BCAST_FLOOD
// (net/bridge/br_if.c:new_nbp()); only BR_LEARNING is modeled.
const defaultBridgePortFlags = BridgePortLearning

// +stateify savable
type bridgePort struct {
	bridge *BridgeEndpoint
	nic    *nic
	// addr is the link address of nic as counted in bridge.localAddrs.
	//
	// +checklocks:bridge.mu
	addr tcpip.LinkAddress

	// +checklocks:bridge.mu
	flags BridgePortFlags

	// removed is set when the port is removed from the bridge. A frame looked
	// up before then may still be on its way to the port.
	removed atomicbitops.Bool
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
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	p.bridge.mu.RLock()
	f := p.lookupLocked(eth.SourceAddress(), eth.DestinationAddress())
	p.bridge.mu.RUnlock()
	pkt.PktType = f.pktType
	p.handleFrameFinish(protocol, pkt, &f)
}

// bridgeForwarding is where a bridge sends a frame received on one of its
// ports.
type bridgeForwarding struct {
	// d is the bridge's dispatcher.
	d NetworkDispatcher

	// ports are the ports a frame for an unknown address is flooded to. It is
	// the bridge's port list, which is never modified.
	ports []*bridgePort

	// to is the port a frame for a learned address is sent to.
	to *bridgePort

	// hairpin is whether the frame may be sent back out of the ingress port.
	hairpin bool

	// learn is whether the source address of the frame is learned.
	learn bool

	// passUp is whether the frame is passed up to the bridge's dispatcher.
	passUp bool

	// pktType is the packet type of the frame.
	pktType tcpip.PacketType
}

// lookupLocked returns where the bridge sends a frame from src to dst
// received on p, as br_handle_frame_finish looks it up.
//
// +checklocksread:p.bridge.mu
func (p *bridgePort) lookupLocked(src, dst tcpip.LinkAddress) bridgeForwarding {
	bridge := p.bridge
	f := bridgeForwarding{
		d:       bridge.dispatcher,
		hairpin: p.flags&BridgePortHairpin != 0,
	}
	// Add an entry at the bridge FDB, it maps a MAC address
	// to a bridge port where the traffic is received when
	// the MAC address is not multicast and the port has learning enabled.
	// Network packets that are sent to the learned MAC address
	// will be forwarded to the bridge port that is stored in
	// the FDB table.
	f.learn = bridge.shouldLearnLocked(p, src)
	isMulticast := header.IsMulticastEthernetAddress(dst)
	// As with BR_FDB_LOCAL entries in br_handle_frame_finish, a unicast frame
	// for the bridge or for any of its ports is passed up and not forwarded.
	isLocal := !isMulticast && bridge.isLocalAddressLocked(dst)
	// Classify the frame as eth_type_trans does against the receiving port's
	// address, except that, as in br_handle_frame, a frame for the bridge's
	// address is for this host. A frame for another port's address is passed
	// up as PacketOtherHost, which the network layer drops.
	switch {
	case dst == header.EthernetBroadcastAddress:
		f.pktType = tcpip.PacketBroadcast
	case isMulticast:
		f.pktType = tcpip.PacketMulticast
	case dst == bridge.addr || dst == p.nic.LinkAddress():
		f.pktType = tcpip.PacketHost
	default:
		f.pktType = tcpip.PacketOtherHost
	}
	entry, inFDB := bridge.fdbTable[BridgeFDBKey(dst)]
	// As in net/bridge/br_forward.c:should_deliver(), the ingress port gets
	// the frame only in hairpin mode.
	switch {
	case isLocal:
		// Passed up.
	case !inFDB:
		f.ports = bridge.portList
	case entry.port != p || f.hairpin:
		f.to = entry.port
	}
	// As in Linux, only group frames and frames addressed to the bridge or to
	// one of its ports are passed up. Passing up transit unicast lets IP
	// forwarding inject a duplicate back onto the bridge.
	f.passUp = f.d != nil && (isMulticast || isLocal)
	return f
}

// handleFrameFinish learns the source address of a frame received on p and
// forwards, floods or passes up the frame as f says, as br_handle_frame_finish
// does.
//
// The dispatcher may acquire Stack.mu, which is ordered above bridge.mu, so
// frames are sent and passed up without holding bridge.mu. Linux forwards
// under RCU only, too.
func (p *bridgePort) handleFrameFinish(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer, f *bridgeForwarding) {
	if f.learn {
		src := header.Ethernet(pkt.LinkHeader().Slice()).SourceAddress()
		p.bridge.mu.Lock()
		// The port or the bridge's addresses may have changed while bridge.mu
		// was unlocked, so check again. Linux's fdb_create() likewise inserts
		// under hash_lock only if no entry exists.
		if p.bridge.shouldLearnLocked(p, src) {
			p.bridge.addFDBEntryLocked(src, p, 0)
		}
		p.bridge.mu.Unlock()
	}
	// When no FDB entry is found, send the packet to all ports. The ingress
	// port is skipped unless it is in hairpin mode.
	for _, port := range f.ports {
		if port == p && !f.hairpin {
			continue
		}
		p.forward(port, pkt)
	}
	if f.to != nil {
		p.forward(f.to, pkt)
	}
	if f.passUp {
		f.d.DeliverNetworkPacket(protocol, pkt)
	}
}

// forward sends a frame received on p out of the port to.
func (p *bridgePort) forward(to *bridgePort, pkt *PacketBuffer) {
	if to.removed.Load() {
		return
	}
	newPkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: int(to.nic.MaxHeaderLength()),
		Payload:            pkt.ToBuffer(),
	})
	to.nic.writeRawPacket(newPkt)
	newPkt.DecRef()
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
	// portList holds the ports in ports, newest first. It is replaced and never
	// modified, so it can be used after mu is released.
	//
	// +checklocks:mu
	portList []*bridgePort
	// localAddrs counts the ports with each link address, like the
	// BR_FDB_LOCAL entries Linux keeps for its ports.
	//
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
//
// As for forwarded frames, the ports send the packets without bridge.mu held.
func (b *BridgeEndpoint) WritePackets(pkts PacketBufferList) (int, tcpip.Error) {
	b.mu.RLock()
	ports := b.portList
	b.mu.RUnlock()

	pktsSlice := pkts.AsSlice()
	n := len(pktsSlice)
	for _, p := range ports {
		if p.removed.Load() {
			continue
		}
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
		flags:  defaultBridgePortFlags,
	}
	n.NetworkLinkEndpoint.Attach(port)
	b.ports[n.id] = port
	// As br_add_if does with list_add_rcu, the newest port is flooded first.
	b.portList = append([]*bridgePort{port}, b.portList...)
	b.addPortAddrLocked(port)

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
	port, ok := b.ports[n.id]
	if !ok {
		return
	}
	b.removePortAddrLocked(port)
	b.addPortAddrLocked(port)
}

// +checklocks:b.mu
func (b *BridgeEndpoint) addPortAddrLocked(p *bridgePort) {
	addr := p.nic.LinkAddress()
	p.addr = addr // +checklocksforce: p.bridge is b.
	b.localAddrs[addr]++
}

// +checklocks:b.mu
func (b *BridgeEndpoint) removePortAddrLocked(p *bridgePort) {
	addr := p.addr // +checklocksforce: p.bridge is b.
	if b.localAddrs[addr]--; b.localAddrs[addr] == 0 {
		delete(b.localAddrs, addr)
	}
}

// DelNIC remove the specified NIC from the bridge.
func (b *BridgeEndpoint) DelNIC(nic *nic) tcpip.Error {
	b.mu.Lock()
	defer b.mu.Unlock()

	port, ok := b.ports[nic.id]
	if ok {
		port.removed.Store(true)
	}
	for k, e := range b.fdbTable {
		if e.port == port {
			delete(b.fdbTable, k)
		}
	}
	if ok {
		b.removePortAddrLocked(port)
	}
	delete(b.ports, nic.id)
	portList := make([]*bridgePort, 0, len(b.ports))
	for _, p := range b.portList {
		if p != port {
			portList = append(portList, p)
		}
	}
	b.portList = portList
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
		p.removed.Store(true)
		p.nic.Primary = nil
	}
	b.dispatcher = dispatcher
	b.ports = make(map[tcpip.NICID]*bridgePort)
	b.portList = nil
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

// shouldLearnLocked returns whether a frame from addr received on p adds an FDB
// entry. Multicast addresses are never learned and, as in br_fdb_update(),
// neither are the addresses of the bridge and its ports. Nothing is learned
// from a port without learning (BR_LEARNING, as in br_handle_frame_finish()) or
// from a port that has left the bridge.
//
// +checklocksread:b.mu
func (b *BridgeEndpoint) shouldLearnLocked(p *bridgePort, addr tcpip.LinkAddress) bool {
	if p.flags&BridgePortLearning == 0 || header.IsMulticastEthernetAddress(addr) || b.isLocalAddressLocked(addr) || b.ports[p.nic.id] != p { // +checklocksforce: p.bridge is b.
		return false
	}
	_, ok := b.fdbTable[BridgeFDBKey(addr)]
	return !ok
}

// FindFDBEntry find the FDB entry for the given address. If it doesn't exist,
// it will return an empty entry.
func (b *BridgeEndpoint) FindFDBEntry(addr tcpip.LinkAddress) BridgeFDBEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.fdbTable[BridgeFDBKey(addr)]
}

// bridgeOfPortLocked returns the bridge that the NIC with the given ID is a
// port of.
//
// +checklocksread:s.mu
func (s *Stack) bridgeOfPortLocked(id tcpip.NICID) (*BridgeEndpoint, tcpip.Error) {
	n, ok := s.nics[id]
	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}
	if n.Primary == nil {
		return nil, &tcpip.ErrNotSupported{}
	}
	b, ok := n.Primary.NetworkLinkEndpoint.(*BridgeEndpoint)
	if !ok {
		return nil, &tcpip.ErrNotSupported{}
	}
	return b, nil
}

// BridgePortFlags returns the bridge port flags of the NIC with the given ID.
// It returns ErrUnknownNICID if there is no such NIC and ErrNotSupported if
// the NIC is not a bridge port.
func (s *Stack) BridgePortFlags(id tcpip.NICID) (BridgePortFlags, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := s.bridgeOfPortLocked(id)
	if err != nil {
		return 0, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	port, ok := b.ports[id]
	if !ok {
		return 0, &tcpip.ErrNotSupported{}
	}
	return port.flags, nil // +checklocksforce: port.bridge is b.
}

// SetBridgePortFlags sets the flags in set and then clears the flags in clear
// on the bridge port of the NIC with the given ID. It returns
// ErrUnknownNICID if there is no such NIC and ErrNotSupported if the NIC is
// not a bridge port.
//
// Addresses that were already learned stay in the forwarding table when
// learning is turned off.
func (s *Stack) SetBridgePortFlags(id tcpip.NICID, set, clear BridgePortFlags) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := s.bridgeOfPortLocked(id)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	port, ok := b.ports[id]
	if !ok {
		return &tcpip.ErrNotSupported{}
	}
	port.flags = (port.flags | set) &^ clear // +checklocksforce: port.bridge is b.
	return nil
}
