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
package arp

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// ProtocolNumber is the ARP protocol number.
	ProtocolNumber = header.ARPProtocolNumber

	// ProtocolAddress is the address expected by the ARP endpoint.
	ProtocolAddress = tcpip.Address("arp")
)

var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)

type endpoint struct {
	stack.AddressableEndpointState

	protocol *protocol

	// enabled is set to 1 when the NIC is enabled and 0 when it is disabled.
	//
	// Must be accessed using atomic operations.
	enabled uint32

	nic           stack.NetworkInterface
	linkAddrCache stack.LinkAddressCache
	nud           stack.NUDHandler
}

func (e *endpoint) Enable() *tcpip.Error {
	if !e.nic.Enabled() {
		return tcpip.ErrNotPermitted
	}

	e.setEnabled(true)
	return nil
}

func (e *endpoint) Enabled() bool {
	return e.nic.Enabled() && e.isEnabled()
}

// isEnabled returns true if the endpoint is enabled, regardless of the
// enabled status of the NIC.
func (e *endpoint) isEnabled() bool {
	return atomic.LoadUint32(&e.enabled) == 1
}

// setEnabled sets the enabled status for the endpoint.
func (e *endpoint) setEnabled(v bool) {
	if v {
		atomic.StoreUint32(&e.enabled, 1)
	} else {
		atomic.StoreUint32(&e.enabled, 0)
	}
}

func (e *endpoint) Disable() {
	e.setEnabled(false)
}

// DefaultTTL is unused for ARP. It implements stack.NetworkEndpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return 0
}

func (e *endpoint) MTU() uint32 {
	lmtu := e.nic.MTU()
	return lmtu - uint32(e.MaxHeaderLength())
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return e.nic.MaxHeaderLength() + header.ARPSize
}

func (e *endpoint) Close() {
	e.AddressableEndpointState.Cleanup()
}

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

func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	if !e.isEnabled() {
		return
	}

	h := header.ARP(pkt.NetworkHeader().View())
	if !h.IsValid() {
		return
	}

	switch h.Op() {
	case header.ARPRequest:
		localAddr := tcpip.Address(h.ProtocolAddressTarget())

		if e.nud == nil {
			if e.linkAddrCache.CheckLocalAddress(e.nic.ID(), header.IPv4ProtocolNumber, localAddr) == 0 {
				return // we have no useful answer, ignore the request
			}

			addr := tcpip.Address(h.ProtocolAddressSender())
			linkAddr := tcpip.LinkAddress(h.HardwareAddressSender())
			e.linkAddrCache.AddLinkAddress(e.nic.ID(), addr, linkAddr)
		} else {
			if e.protocol.stack.CheckLocalAddress(e.nic.ID(), header.IPv4ProtocolNumber, localAddr) == 0 {
				return // we have no useful answer, ignore the request
			}

			remoteAddr := tcpip.Address(h.ProtocolAddressSender())
			remoteLinkAddr := tcpip.LinkAddress(h.HardwareAddressSender())
			e.nud.HandleProbe(remoteAddr, ProtocolNumber, remoteLinkAddr, e.protocol)
		}

		respPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(e.nic.MaxHeaderLength()) + header.ARPSize,
		})
		packet := header.ARP(respPkt.NetworkHeader().Push(header.ARPSize))
		respPkt.NetworkProtocolNumber = ProtocolNumber
		packet.SetIPv4OverEthernet()
		packet.SetOp(header.ARPReply)
		// TODO(gvisor.dev/issue/4582): check copied length once TAP devices have a
		// link address.
		_ = copy(packet.HardwareAddressSender(), e.nic.LinkAddress())
		if n := copy(packet.ProtocolAddressSender(), h.ProtocolAddressTarget()); n != header.IPv4AddressSize {
			panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.IPv4AddressSize))
		}
		origSender := h.HardwareAddressSender()
		if n := copy(packet.HardwareAddressTarget(), origSender); n != header.EthernetAddressSize {
			panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.EthernetAddressSize))
		}
		if n := copy(packet.ProtocolAddressTarget(), h.ProtocolAddressSender()); n != header.IPv4AddressSize {
			panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.IPv4AddressSize))
		}

		// As per RFC 826, under Packet Reception:
		//   Swap hardware and protocol fields, putting the local hardware and
		//   protocol addresses in the sender fields.
		//
		//   Send the packet to the (new) target hardware address on the same
		//   hardware on which the request was received.
		_ = e.nic.WritePacketToRemote(tcpip.LinkAddress(origSender), nil /* gso */, ProtocolNumber, respPkt)

	case header.ARPReply:
		addr := tcpip.Address(h.ProtocolAddressSender())
		linkAddr := tcpip.LinkAddress(h.HardwareAddressSender())

		if e.nud == nil {
			e.linkAddrCache.AddLinkAddress(e.nic.ID(), addr, linkAddr)
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
	stack *stack.Stack
}

func (p *protocol) Number() tcpip.NetworkProtocolNumber { return ProtocolNumber }
func (p *protocol) MinimumPacketSize() int              { return header.ARPSize }
func (p *protocol) DefaultPrefixLen() int               { return 0 }

func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.ARP(v)
	return tcpip.Address(h.ProtocolAddressSender()), ProtocolAddress
}

func (p *protocol) NewEndpoint(nic stack.NetworkInterface, linkAddrCache stack.LinkAddressCache, nud stack.NUDHandler, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{
		protocol:      p,
		nic:           nic,
		linkAddrCache: linkAddrCache,
		nud:           nud,
	}
	e.AddressableEndpointState.Init(e)
	return e
}

// LinkAddressProtocol implements stack.LinkAddressResolver.LinkAddressProtocol.
func (*protocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv4ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.LinkAddressRequest.
func (p *protocol) LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress, nic stack.NetworkInterface) *tcpip.Error {
	if len(remoteLinkAddr) == 0 {
		remoteLinkAddr = header.EthernetBroadcastAddress
	}

	nicID := nic.ID()
	if len(localAddr) == 0 {
		addr, err := p.stack.GetMainNICAddress(nicID, header.IPv4ProtocolNumber)
		if err != nil {
			return err
		}

		if len(addr.Address) == 0 {
			return tcpip.ErrNetworkUnreachable
		}

		localAddr = addr.Address
	} else if p.stack.CheckLocalAddress(nicID, header.IPv4ProtocolNumber, localAddr) == 0 {
		return tcpip.ErrBadLocalAddress
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(nic.MaxHeaderLength()) + header.ARPSize,
	})
	h := header.ARP(pkt.NetworkHeader().Push(header.ARPSize))
	pkt.NetworkProtocolNumber = ProtocolNumber
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	// TODO(gvisor.dev/issue/4582): check copied length once TAP devices have a
	// link address.
	_ = copy(h.HardwareAddressSender(), nic.LinkAddress())
	if n := copy(h.ProtocolAddressSender(), localAddr); n != header.IPv4AddressSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.IPv4AddressSize))
	}
	if n := copy(h.ProtocolAddressTarget(), targetAddr); n != header.IPv4AddressSize {
		panic(fmt.Sprintf("copied %d bytes, expected %d bytes", n, header.IPv4AddressSize))
	}
	return nic.WritePacketToRemote(remoteLinkAddr, nil /* gso */, ProtocolNumber, pkt)
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
	return 0, false, parse.ARP(pkt)
}

// NewProtocol returns an ARP network protocol.
//
// Note, to make sure that the ARP endpoint receives ARP packets, the "arp"
// address must be added to every NIC that should respond to ARP requests. See
// ProtocolAddress for more details.
func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	return &protocol{stack: s}
}
