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

package iptables

import (
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// AcceptTarget accepts packets.
type AcceptTarget struct{}

// Action implements Target.Action.
func (AcceptTarget) Action(packet tcpip.PacketBuffer, filter IPHeaderFilter) (RuleVerdict, int) {
	return RuleAccept, 0
}

// DropTarget drops packets.
type DropTarget struct{}

// Action implements Target.Action.
func (DropTarget) Action(packet tcpip.PacketBuffer, filter IPHeaderFilter) (RuleVerdict, int) {
	return RuleDrop, 0
}

// ErrorTarget logs an error and drops the packet. It represents a target that
// should be unreachable.
type ErrorTarget struct{}

// Action implements Target.Action.
func (ErrorTarget) Action(packet tcpip.PacketBuffer, filter IPHeaderFilter) (RuleVerdict, int) {
	log.Debugf("ErrorTarget triggered.")
	return RuleDrop, 0
}

// UserChainTarget marks a rule as the beginning of a user chain.
type UserChainTarget struct {
	Name string
}

// Action implements Target.Action.
func (UserChainTarget) Action(tcpip.PacketBuffer, IPHeaderFilter) (RuleVerdict, int) {
	panic("UserChainTarget should never be called.")
}

// ReturnTarget returns from the current chain. If the chain is a built-in, the
// hook's underflow should be called.
type ReturnTarget struct{}

// Action implements Target.Action.
func (ReturnTarget) Action(tcpip.PacketBuffer, IPHeaderFilter) (RuleVerdict, int) {
	return RuleReturn, 0
}

// RedirectTarget redirects the packet by modifying the destination port/IP.
// Min and Max values for IP and Ports in the struct indicate the range of
// values which can be used to redirect.
type RedirectTarget struct {
	// Flags to check if the redirect is for address or ports.
	Flags uint32

	// Min address used to redirect.
	MinIP tcpip.Address

	// Max address used to redirect.
	MaxIP tcpip.Address

	// Min port used to redirect.
	MinPort uint16

	// Max port used to redirect.
	MaxPort uint16
}

// Action implements Target.Action.
func (rt RedirectTarget) Action(pkt tcpip.PacketBuffer, filter IPHeaderFilter) (RuleVerdict, int) {
	headerView := pkt.Data.First()

	// Network header should be set.
	netHeader := header.IPv4(headerView)
	if netHeader == nil {
		return RuleDrop, 0
	}

	// TODO(gvisor.dev/issue/170): Check Flags in RedirectTarget if
	// we need to change dest address (for OUTPUT chain) or ports.
	hlen := int(netHeader.HeaderLength())

	switch protocol := filter.Protocol; protocol {
	case header.UDPProtocolNumber:
		udp := header.UDP(headerView[hlen:])
		udp.SetDestinationPort(rt.MinPort)
	case header.TCPProtocolNumber:
		// TODO(gvisor.dev/issue/170): Need to recompute checksum
		// and implement nat connection tracking to support TCP.
		tcp := header.TCP(headerView[hlen:])
		tcp.SetDestinationPort(rt.MinPort)
	default:
		return RuleDrop, 0
	}
	return RuleAccept, 0
}
