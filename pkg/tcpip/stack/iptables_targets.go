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
type AcceptTarget struct{}

// Action implements Target.Action.
func (AcceptTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleAccept, 0
}

// DropTarget drops packets.
type DropTarget struct{}

// Action implements Target.Action.
func (DropTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleDrop, 0
}

// ErrorTarget logs an error and drops the packet. It represents a target that
// should be unreachable.
type ErrorTarget struct{}

// Action implements Target.Action.
func (ErrorTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	log.Debugf("ErrorTarget triggered.")
	return RuleDrop, 0
}

// UserChainTarget marks a rule as the beginning of a user chain.
type UserChainTarget struct {
	Name string
}

// Action implements Target.Action.
func (UserChainTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	panic("UserChainTarget should never be called.")
}

// ReturnTarget returns from the current chain. If the chain is a built-in, the
// hook's underflow should be called.
type ReturnTarget struct{}

// Action implements Target.Action.
func (ReturnTarget) Action(*PacketBuffer, *ConnTrack, Hook, *GSO, *Route, tcpip.Address) (RuleVerdict, int) {
	return RuleReturn, 0
}

// RedirectTarget redirects the packet by modifying the destination port/IP.
// Min and Max values for IP and Ports in the struct indicate the range of
// values which can be used to redirect.
type RedirectTarget struct {
	// TODO(gvisor.dev/issue/170): Other flags need to be added after
	// we support them.
	// RangeProtoSpecified flag indicates single port is specified to
	// redirect.
	RangeProtoSpecified bool

	// MinIP indicates address used to redirect.
	MinIP tcpip.Address

	// MaxIP indicates address used to redirect.
	MaxIP tcpip.Address

	// MinPort indicates port used to redirect.
	MinPort uint16

	// MaxPort indicates port used to redirect.
	MaxPort uint16
}

// Action implements Target.Action.
// TODO(gvisor.dev/issue/170): Parse headers without copying. The current
// implementation only works for PREROUTING and calls pkt.Clone(), neither
// of which should be the case.
func (rt RedirectTarget) Action(pkt *PacketBuffer, ct *ConnTrack, hook Hook, gso *GSO, r *Route, address tcpip.Address) (RuleVerdict, int) {
	// Packet is already manipulated.
	if pkt.NatDone {
		return RuleAccept, 0
	}

	// Drop the packet if network and transport header are not set.
	if pkt.NetworkHeader == nil || pkt.TransportHeader == nil {
		return RuleDrop, 0
	}

	// Change the address to localhost (127.0.0.1) in Output and
	// to primary address of the incoming interface in Prerouting.
	switch hook {
	case Output:
		rt.MinIP = tcpip.Address([]byte{127, 0, 0, 1})
		rt.MaxIP = tcpip.Address([]byte{127, 0, 0, 1})
	case Prerouting:
		rt.MinIP = address
		rt.MaxIP = address
	default:
		panic("redirect target is supported only on output and prerouting hooks")
	}

	// TODO(gvisor.dev/issue/170): Check Flags in RedirectTarget if
	// we need to change dest address (for OUTPUT chain) or ports.
	netHeader := header.IPv4(pkt.NetworkHeader)
	switch protocol := netHeader.TransportProtocol(); protocol {
	case header.UDPProtocolNumber:
		udpHeader := header.UDP(pkt.TransportHeader)
		udpHeader.SetDestinationPort(rt.MinPort)

		// Calculate UDP checksum and set it.
		if hook == Output {
			udpHeader.SetChecksum(0)
			hdr := &pkt.Header
			length := uint16(pkt.Data.Size()+hdr.UsedLength()) - uint16(netHeader.HeaderLength())

			// Only calculate the checksum if offloading isn't supported.
			if r.Capabilities()&CapabilityTXChecksumOffload == 0 {
				xsum := r.PseudoHeaderChecksum(protocol, length)
				for _, v := range pkt.Data.Views() {
					xsum = header.Checksum(v, xsum)
				}
				udpHeader.SetChecksum(0)
				udpHeader.SetChecksum(^udpHeader.CalculateChecksum(xsum))
			}
		}
		// Change destination address.
		netHeader.SetDestinationAddress(rt.MinIP)
		netHeader.SetChecksum(0)
		netHeader.SetChecksum(^netHeader.CalculateChecksum())
		pkt.NatDone = true
	case header.TCPProtocolNumber:
		if ct == nil {
			return RuleAccept, 0
		}

		// Set up conection for matching NAT rule. Only the first
		// packet of the connection comes here. Other packets will be
		// manipulated in connection tracking.
		if conn := ct.createConnFor(pkt, hook, rt); conn != nil {
			ct.handlePacket(pkt, hook, gso, r)
		}
	default:
		return RuleDrop, 0
	}

	return RuleAccept, 0
}
