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

// Package arp implements the ARP network protocol. It is used to resolve
// IPv4 addresses into link-local MAC addresses, and advertises IPv4
// addresses of its stack with the local network.
//
// To use it in the networking stack, pass arp.NewProtocol() as one of the
// network protocols when calling stack.New. Then add an "arp" address to every
// NIC on the stack that should respond to ARP requests. That is:
//
//	if err := s.AddAddress(1, arp.ProtocolNumber, "arp"); err != nil {
//		// handle err
//	}
package arp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// ProtocolNumber is the ARP protocol number.
	ProtocolNumber = header.ARPProtocolNumber

	// ProtocolAddress is the address expected by the ARP endpoint.
	ProtocolAddress = tcpip.Address("arp")
)

// endpoint implements stack.NetworkEndpoint.
type endpoint struct {
	protocol      *protocol
	nicID         tcpip.NICID
	linkEP        stack.LinkEndpoint
	linkAddrCache stack.LinkAddressCache
	nud           stack.NUDHandler
}

// DefaultTTL is unused for ARP. It implements stack.NetworkEndpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return 0
}

func (e *endpoint) MTU() uint32 {
	lmtu := e.linkEP.MTU()
	return lmtu - uint32(e.MaxHeaderLength())
}

func (e *endpoint) NICID() tcpip.NICID {
	return e.nicID
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.linkEP.Capabilities()
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.ARPSize
}

func (e *endpoint) Close() {}

func (e *endpoint) WritePacket(*stack.Route, *stack.GSO, stack.NetworkHeaderParams, *stack.PacketBuffer) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// NetworkProtocolNumber implements stack.NetworkEndpoint.NetworkProtocolNumber.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// WritePackets implements stack.NetworkEndpoint.WritePackets.
func (e *endpoint) WritePackets(*stack.Route, *stack.GSO, stack.PacketBufferList, stack.NetworkHeaderParams) (int, *tcpip.Error) {
	return 0, tcpip.ErrNotSupported
}

func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) *tcpip.Error {
	return tcpip.ErrNotSupported
}

func (e *endpoint) HandlePacket(r *stack.Route, pkt *stack.PacketBuffer) {
	h := header.ARP(pkt.NetworkHeader().View())
	if !h.IsValid() {
		return
	}

	switch h.Op() {
	case header.ARPRequest:
		localAddr := tcpip.Address(h.ProtocolAddressTarget())

		if e.nud == nil {
			if e.linkAddrCache.CheckLocalAddress(e.nicID, header.IPv4ProtocolNumber, localAddr) == 0 {
				return // we have no useful answer, ignore the request
			}

			addr := tcpip.Address(h.ProtocolAddressSender())
			linkAddr := tcpip.LinkAddress(h.HardwareAddressSender())
			e.linkAddrCache.AddLinkAddress(e.nicID, addr, linkAddr)
		} else {
			if r.Stack().CheckLocalAddress(e.nicID, header.IPv4ProtocolNumber, localAddr) == 0 {
				return // we have no useful answer, ignore the request
			}

			remoteAddr := tcpip.Address(h.ProtocolAddressSender())
			remoteLinkAddr := tcpip.LinkAddress(h.HardwareAddressSender())
			e.nud.HandleProbe(remoteAddr, localAddr, ProtocolNumber, remoteLinkAddr, e.protocol)
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(e.linkEP.MaxHeaderLength()) + header.ARPSize,
		})
		packet := header.ARP(pkt.NetworkHeader().Push(header.ARPSize))
		packet.SetIPv4OverEthernet()
		packet.SetOp(header.ARPReply)
		copy(packet.HardwareAddressSender(), r.LocalLinkAddress[:])
		copy(packet.ProtocolAddressSender(), h.ProtocolAddressTarget())
		copy(packet.HardwareAddressTarget(), h.HardwareAddressSender())
		copy(packet.ProtocolAddressTarget(), h.ProtocolAddressSender())
		_ = e.linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, pkt)

	case header.ARPReply:
		addr := tcpip.Address(h.ProtocolAddressSender())
		linkAddr := tcpip.LinkAddress(h.HardwareAddressSender())

		if e.nud == nil {
			e.linkAddrCache.AddLinkAddress(e.nicID, addr, linkAddr)
			return
		}

		// The solicited, override, and isRouter flags are not available for ARP;
		// they are only available for IPv6 Neighbor Advertisements.
		e.nud.HandleConfirmation(addr, linkAddr, stack.ReachabilityConfirmationFlags{
			// Solicited and unsolicited (also referred to as gratuitous) ARP Replies
			// are handled equivalently to a solicited Neighbor Advertisement.
			Solicited: true,
			// If a different link address is received than the one cached, the entry
			// should always go to Stale.
			Override: false,
			// ARP does not distinguish between router and non-router hosts.
			IsRouter: false,
		})
	}
}

// protocol implements stack.NetworkProtocol and stack.LinkAddressResolver.
type protocol struct {
}

func (p *protocol) Number() tcpip.NetworkProtocolNumber { return ProtocolNumber }
func (p *protocol) MinimumPacketSize() int              { return header.ARPSize }
func (p *protocol) DefaultPrefixLen() int               { return 0 }

func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.ARP(v)
	return tcpip.Address(h.ProtocolAddressSender()), ProtocolAddress
}

func (p *protocol) NewEndpoint(nicID tcpip.NICID, linkAddrCache stack.LinkAddressCache, nud stack.NUDHandler, dispatcher stack.TransportDispatcher, sender stack.LinkEndpoint, st *stack.Stack) stack.NetworkEndpoint {
	return &endpoint{
		protocol:      p,
		nicID:         nicID,
		linkEP:        sender,
		linkAddrCache: linkAddrCache,
		nud:           nud,
	}
}

// LinkAddressProtocol implements stack.LinkAddressResolver.LinkAddressProtocol.
func (*protocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv4ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.LinkAddressRequest.
func (*protocol) LinkAddressRequest(addr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress, linkEP stack.LinkEndpoint) *tcpip.Error {
	r := &stack.Route{
		RemoteLinkAddress: remoteLinkAddr,
	}
	if len(r.RemoteLinkAddress) == 0 {
		r.RemoteLinkAddress = header.EthernetBroadcastAddress
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(linkEP.MaxHeaderLength()) + header.ARPSize,
	})
	h := header.ARP(pkt.NetworkHeader().Push(header.ARPSize))
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	copy(h.HardwareAddressSender(), linkEP.LinkAddress())
	copy(h.ProtocolAddressSender(), localAddr)
	copy(h.ProtocolAddressTarget(), addr)

	return linkEP.WritePacket(r, nil /* gso */, ProtocolNumber, pkt)
}

// ResolveStaticAddress implements stack.LinkAddressResolver.ResolveStaticAddress.
func (*protocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if addr == header.IPv4Broadcast {
		return header.EthernetBroadcastAddress, true
	}
	if header.IsV4MulticastAddress(addr) {
		return header.EthernetAddressFromMulticastIPv4Address(addr), true
	}
	return tcpip.LinkAddress([]byte(nil)), false
}

// SetOption implements stack.NetworkProtocol.SetOption.
func (*protocol) SetOption(tcpip.SettableNetworkProtocolOption) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Option implements stack.NetworkProtocol.Option.
func (*protocol) Option(tcpip.GettableNetworkProtocolOption) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Close implements stack.TransportProtocol.Close.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.Wait.
func (*protocol) Wait() {}

// Parse implements stack.NetworkProtocol.Parse.
func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	_, ok = pkt.NetworkHeader().Consume(header.ARPSize)
	if !ok {
		return 0, false, false
	}
	return 0, false, true
}

// NewProtocol returns an ARP network protocol.
func NewProtocol() stack.NetworkProtocol {
	return &protocol{}
}
