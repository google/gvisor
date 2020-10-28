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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// AcceptTarget accepts packets.
type AcceptTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// ID implements Target.ID.
func (at *AcceptTarget) ID() TargetID {
	return TargetID{
		NetworkProtocol: at.NetworkProtocol,
	}
}

// Action implements Target.Action.
func (*AcceptTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleAccept, 0
}

// DropTarget drops packets.
type DropTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// ID implements Target.ID.
func (dt *DropTarget) ID() TargetID {
	return TargetID{
		NetworkProtocol: dt.NetworkProtocol,
	}
}

// Action implements Target.Action.
func (*DropTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleDrop, 0
}

// ErrorTargetName is used to mark targets as error targets. Error targets
// shouldn't be reached - an error has occurred if we fall through to one.
const ErrorTargetName = "ERROR"

// ErrorTarget logs an error and drops the packet. It represents a target that
// should be unreachable.
type ErrorTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// ID implements Target.ID.
func (et *ErrorTarget) ID() TargetID {
	return TargetID{
		Name:            ErrorTargetName,
		NetworkProtocol: et.NetworkProtocol,
	}
}

// Action implements Target.Action.
func (*ErrorTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
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

// ID implements Target.ID.
func (uc *UserChainTarget) ID() TargetID {
	return TargetID{
		Name:            ErrorTargetName,
		NetworkProtocol: uc.NetworkProtocol,
	}
}

// Action implements Target.Action.
func (*UserChainTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	panic("UserChainTarget should never be called.")
}

// ReturnTarget returns from the current chain. If the chain is a built-in, the
// hook's underflow should be called.
type ReturnTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// ID implements Target.ID.
func (rt *ReturnTarget) ID() TargetID {
	return TargetID{
		NetworkProtocol: rt.NetworkProtocol,
	}
}

// Action implements Target.Action.
func (*ReturnTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleReturn, 0
}

// RedirectTargetName is used to mark targets as redirect targets. Redirect
// targets should be reached for only NAT and Mangle tables. These targets will
// change the destination port/destination IP for packets.
const RedirectTargetName = "REDIRECT"

// RedirectTarget redirects the packet by modifying the destination port/IP.
// TODO(gvisor.dev/issue/170): Other flags need to be added after we support
// them.
type RedirectTarget struct {
	// Addr indicates address used to redirect.
	Addr tcpip.Address

	// Port indicates port used to redirect.
	Port uint16

	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// ID implements Target.ID.
func (rt *RedirectTarget) ID() TargetID {
	return TargetID{
		Name:            RedirectTargetName,
		NetworkProtocol: rt.NetworkProtocol,
	}
}

// Action implements Target.Action.
// TODO(gvisor.dev/issue/170): Parse headers without copying. The current
// implementation only works for PREROUTING and calls pkt.Clone(), neither
// of which should be the case.
func (rt *RedirectTarget) Action(pkt *PacketBuffer, ct *ConnTrack, hook Hook, gso *GSO, r *Route, address tcpip.Address) (RuleVerdict, int) {
	// Packet is already manipulated.
	if pkt.NatDone {
		return RuleAccept, 0
	}

	// Drop the packet if network and transport header are not set.
	if pkt.NetworkHeader().View().IsEmpty() || pkt.TransportHeader().View().IsEmpty() {
		return RuleDrop, 0
	}

	// Change the address to localhost (127.0.0.1 or ::1) in Output and to
	// the primary address of the incoming interface in Prerouting.
	switch hook {
	case Output:
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			rt.Addr = tcpip.Address([]byte{127, 0, 0, 1})
		} else {
			rt.Addr = header.IPv6Loopback
		}
	case Prerouting:
		rt.Addr = address
	default:
		panic("redirect target is supported only on output and prerouting hooks")
	}

	// TODO(gvisor.dev/issue/170): Check Flags in RedirectTarget if
	// we need to change dest address (for OUTPUT chain) or ports.
	switch protocol := pkt.TransportProtocolNumber; protocol {
	case header.UDPProtocolNumber:
		udpHeader := header.UDP(pkt.TransportHeader().View())
		udpHeader.SetDestinationPort(rt.Port)

		// Calculate UDP checksum and set it.
		if hook == Output {
			udpHeader.SetChecksum(0)
			netHeader := pkt.Network()
			netHeader.SetDestinationAddress(rt.Addr)

			// Only calculate the checksum if offloading isn't supported.
			if !r.HasTXTransportChecksumOffloadCapability() {
				length := uint16(pkt.Size()) - uint16(len(pkt.NetworkHeader().View()))
				xsum := header.PseudoHeaderChecksum(protocol, netHeader.SourceAddress(), netHeader.DestinationAddress(), length)
				xsum = header.ChecksumVV(pkt.Data, xsum)
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
		if conn := ct.insertRedirectConn(pkt, hook, rt); conn != nil {
			ct.handlePacket(pkt, hook, gso, r)
		}
	default:
		return RuleDrop, 0
	}

	return RuleAccept, 0
}
