// Copyright 2019 The gVisor Authors.
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
	"fmt"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// AcceptTarget accepts packets.
type AcceptTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*AcceptTarget) Action(*PacketBuffer, *ConnTrack, Hook, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleAccept, 0
}

// DropTarget drops packets.
type DropTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*DropTarget) Action(*PacketBuffer, *ConnTrack, Hook, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleDrop, 0
}

// ErrorTarget logs an error and drops the packet. It represents a target that
// should be unreachable.
type ErrorTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*ErrorTarget) Action(*PacketBuffer, *ConnTrack, Hook, *Route, tcpip.Address) (RuleVerdict, int) {
	log.Debugf("ErrorTarget triggered.")
	return RuleDrop, 0
}

// UserChainTarget marks a rule as the beginning of a user chain.
type UserChainTarget struct {
	// Name is the chain name.
	Name string

	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*UserChainTarget) Action(*PacketBuffer, *ConnTrack, Hook, *Route, tcpip.Address) (RuleVerdict, int) {
	panic("UserChainTarget should never be called.")
}

// ReturnTarget returns from the current chain. If the chain is a built-in, the
// hook's underflow should be called.
type ReturnTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*ReturnTarget) Action(*PacketBuffer, *ConnTrack, Hook, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleReturn, 0
}

// RedirectTarget redirects the packet to this machine by modifying the
// destination port/IP. Outgoing packets are redirected to the loopback device,
// and incoming packets are redirected to the incoming interface (rather than
// forwarded).
type RedirectTarget struct {
	// Port indicates port used to redirect. It is immutable.
	Port uint16

	// NetworkProtocol is the network protocol the target is used with. It
	// is immutable.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (rt *RedirectTarget) Action(pkt *PacketBuffer, ct *ConnTrack, hook Hook, r *Route, address tcpip.Address) (RuleVerdict, int) {
	// Sanity check.
	if rt.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"RedirectTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			rt.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	// Packet is already manipulated.
	if pkt.NatDone {
		return RuleAccept, 0
	}

	// Drop the packet if network and transport header are not set.
	if pkt.NetworkHeader().View().IsEmpty() || pkt.TransportHeader().View().IsEmpty() {
		return RuleDrop, 0
	}

	// Change the address to loopback (127.0.0.1 or ::1) in Output and to
	// the primary address of the incoming interface in Prerouting.
	switch hook {
	case Output:
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			address = tcpip.Address([]byte{127, 0, 0, 1})
		} else {
			address = header.IPv6Loopback
		}
	case Prerouting:
		// No-op, as address is already set correctly.
	default:
		panic("redirect target is supported only on output and prerouting hooks")
	}

	switch protocol := pkt.TransportProtocolNumber; protocol {
	case header.UDPProtocolNumber:
		udpHeader := header.UDP(pkt.TransportHeader().View())
		udpHeader.SetDestinationPort(rt.Port)

		// Calculate UDP checksum and set it.
		if hook == Output {
			udpHeader.SetChecksum(0)
			netHeader := pkt.Network()
			netHeader.SetDestinationAddress(address)

			// Only calculate the checksum if offloading isn't supported.
			if r.RequiresTXTransportChecksum() {
				length := uint16(pkt.Size()) - uint16(len(pkt.NetworkHeader().View()))
				xsum := header.PseudoHeaderChecksum(protocol, netHeader.SourceAddress(), netHeader.DestinationAddress(), length)
				xsum = header.ChecksumCombine(xsum, pkt.Data().AsRange().Checksum())
				udpHeader.SetChecksum(^udpHeader.CalculateChecksum(xsum))
			}
		}

		// After modification, IPv4 packets need a valid checksum.
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			netHeader := header.IPv4(pkt.NetworkHeader().View())
			netHeader.SetChecksum(0)
			netHeader.SetChecksum(^netHeader.CalculateChecksum())
		}
		pkt.NatDone = true
	case header.TCPProtocolNumber:
		if ct == nil {
			return RuleAccept, 0
		}

		// Set up conection for matching NAT rule. Only the first
		// packet of the connection comes here. Other packets will be
		// manipulated in connection tracking.
		if conn := ct.insertRedirectConn(pkt, hook, rt.Port, address); conn != nil {
			ct.handlePacket(pkt, hook, r)
		}
	default:
		return RuleDrop, 0
	}

	return RuleAccept, 0
}

// SNATTarget modifies the source port/IP in the outgoing packets.
type SNATTarget struct {
	Addr tcpip.Address
	Port uint16

	// NetworkProtocol is the network protocol the target is used with. It
	// is immutable.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (st *SNATTarget) Action(pkt *PacketBuffer, ct *ConnTrack, hook Hook, r *Route, address tcpip.Address) (RuleVerdict, int) {
	// Sanity check.
	if st.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"SNATTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			st.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	// Packet is already manipulated.
	if pkt.NatDone {
		return RuleAccept, 0
	}

	// Drop the packet if network and transport header are not set.
	if pkt.NetworkHeader().View().IsEmpty() || pkt.TransportHeader().View().IsEmpty() {
		return RuleDrop, 0
	}

	switch hook {
	case Postrouting, Input:
	case Prerouting, Output, Forward:
		panic(fmt.Sprintf("%s not supported", hook))
	default:
		panic(fmt.Sprintf("%s unrecognized", hook))
	}

	switch protocol := pkt.TransportProtocolNumber; protocol {
	case header.UDPProtocolNumber:
		udpHeader := header.UDP(pkt.TransportHeader().View())
		udpHeader.SetChecksum(0)
		udpHeader.SetSourcePort(st.Port)
		netHeader := pkt.Network()
		netHeader.SetSourceAddress(st.Addr)

		// Only calculate the checksum if offloading isn't supported.
		if r.RequiresTXTransportChecksum() {
			length := uint16(pkt.Size()) - uint16(len(pkt.NetworkHeader().View()))
			xsum := header.PseudoHeaderChecksum(protocol, netHeader.SourceAddress(), netHeader.DestinationAddress(), length)
			xsum = header.ChecksumCombine(xsum, pkt.Data().AsRange().Checksum())
			udpHeader.SetChecksum(^udpHeader.CalculateChecksum(xsum))
		}

		// After modification, IPv4 packets need a valid checksum.
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			netHeader := header.IPv4(pkt.NetworkHeader().View())
			netHeader.SetChecksum(0)
			netHeader.SetChecksum(^netHeader.CalculateChecksum())
		}
		pkt.NatDone = true
	case header.TCPProtocolNumber:
		if ct == nil {
			return RuleAccept, 0
		}

		// Set up conection for matching NAT rule. Only the first
		// packet of the connection comes here. Other packets will be
		// manipulated in connection tracking.
		if conn := ct.insertSNATConn(pkt, hook, st.Port, st.Addr); conn != nil {
			ct.handlePacket(pkt, hook, r)
		}
	default:
		return RuleDrop, 0
	}

	return RuleAccept, 0
}
