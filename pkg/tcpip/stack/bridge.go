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
	"math/rand"
	"net"

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

func (p *bridgePort) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	bridge := p.bridge
	bridge.mu.Lock()
	defer bridge.mu.Unlock()

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

	bridge.injectInbound(protocol, pkt)
}

func (p *bridgePort) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
}

func getRandMacAddr() tcpip.LinkAddress {
	mac := make(net.HardwareAddr, 6)
	rand.Read(mac) // Fill with random data.
	mac[0] &^= 0x1 // Clear multicast bit.
	mac[0] |= 0x2  // Set local assignment bit (IEEE802).
	return tcpip.LinkAddress(mac)
}

func NewBridgeEndpoint(mtu uint32) *BridgeEndpoint {
	b := &BridgeEndpoint{
		mtu:  mtu,
		addr: getRandMacAddr(),
	}
	b.ports = make(map[tcpip.NICID]*bridgePort)
	return b
}

type BridgeEndpoint struct {
	mu              bridgeRWMutex
	ports           map[tcpip.NICID]*bridgePort
	dispatcher      NetworkDispatcher
	maxHeaderLength uint16
	addr            tcpip.LinkAddress
	attached        bool
	mtu             uint32
}

func (b *BridgeEndpoint) WritePackets(pkts PacketBufferList) (int, tcpip.Error) {
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
			newPkt.NetworkProtocolNumber = pkt.NetworkProtocolNumber
			p.nic.writePacket(newPkt)
			newPkt.DecRef()
		}
	}

	return n, nil
}

func (b *BridgeEndpoint) AddNIC(n *nic) tcpip.Error {
	b.mu.Lock()
	defer b.mu.Unlock()

	port := &bridgePort{
		nic:    n,
		bridge: b,
	}
	n.NetworkLinkEndpoint.Attach(port)
	b.ports[n.id] = port

	return nil
}

func (b *BridgeEndpoint) injectInbound(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	d := b.dispatcher
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

func (b *BridgeEndpoint) MTU() uint32 {
	if b.mtu > header.EthernetMinimumSize {
		return b.mtu - header.EthernetMinimumSize
	}
	return 0
}
func (b *BridgeEndpoint) MaxHeaderLength() uint16 {
	return 200
}
func (b *BridgeEndpoint) LinkAddress() tcpip.LinkAddress {
	return b.addr
}

func (b *BridgeEndpoint) Capabilities() LinkEndpointCapabilities {
	return CapabilityRXChecksumOffload | CapabilityTXChecksumOffload | CapabilitySaveRestore | CapabilityResolutionRequired
}

func (b *BridgeEndpoint) Attach(dispatcher NetworkDispatcher) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dispatcher = dispatcher
}

func (b *BridgeEndpoint) IsAttached() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.dispatcher != nil
}

func (b *BridgeEndpoint) Wait() {
}

func (b *BridgeEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

func (b *BridgeEndpoint) AddHeader(pkt *PacketBuffer) {
}

func (b *BridgeEndpoint) ParseHeader(*PacketBuffer) bool {
	return true
}
