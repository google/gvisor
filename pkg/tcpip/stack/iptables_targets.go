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
func (AcceptTarget) Action(packet PacketBuffer) (RuleVerdict, int) {
	return RuleAccept, 0
}

// DropTarget drops packets.
type DropTarget struct{}

// Action implements Target.Action.
func (DropTarget) Action(packet PacketBuffer) (RuleVerdict, int) {
	return RuleDrop, 0
}

// ErrorTarget logs an error and drops the packet. It represents a target that
// should be unreachable.
type ErrorTarget struct{}

// Action implements Target.Action.
func (ErrorTarget) Action(packet PacketBuffer) (RuleVerdict, int) {
	log.Debugf("ErrorTarget triggered.")
	return RuleDrop, 0
}

// UserChainTarget marks a rule as the beginning of a user chain.
type UserChainTarget struct {
	Name string
}

// Action implements Target.Action.
func (UserChainTarget) Action(PacketBuffer) (RuleVerdict, int) {
	panic("UserChainTarget should never be called.")
}

// ReturnTarget returns from the current chain. If the chain is a built-in, the
// hook's underflow should be called.
type ReturnTarget struct{}

// Action implements Target.Action.
func (ReturnTarget) Action(PacketBuffer) (RuleVerdict, int) {
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
// TODO(gvisor.dev/issue/170): Parse headers without copying. The current
// implementation only works for PREROUTING and calls pkt.Clone(), neither
// of which should be the case.
func (rt RedirectTarget) Action(pkt PacketBuffer) (RuleVerdict, int) {
	newPkt := pkt.Clone()

	// Set network header.
	headerView, ok := newPkt.Data.PullUp(header.IPv4MinimumSize)
	if !ok {
		return RuleDrop, 0
	}
	netHeader := header.IPv4(headerView)
	newPkt.NetworkHeader = headerView

	hlen := int(netHeader.HeaderLength())
	tlen := int(netHeader.TotalLength())
	newPkt.Data.TrimFront(hlen)
	newPkt.Data.CapLength(tlen - hlen)

	// TODO(gvisor.dev/issue/170): Change destination address to
	// loopback or interface address on which the packet was
	// received.

	// TODO(gvisor.dev/issue/170): Check Flags in RedirectTarget if
	// we need to change dest address (for OUTPUT chain) or ports.
	switch protocol := netHeader.TransportProtocol(); protocol {
	case header.UDPProtocolNumber:
		var udpHeader header.UDP
		if newPkt.TransportHeader != nil {
			udpHeader = header.UDP(newPkt.TransportHeader)
		} else {
			if pkt.Data.Size() < header.UDPMinimumSize {
				return RuleDrop, 0
			}
			hdr, ok := newPkt.Data.PullUp(header.UDPMinimumSize)
			if !ok {
				return RuleDrop, 0
			}
			udpHeader = header.UDP(hdr)
		}
		udpHeader.SetDestinationPort(rt.MinPort)
	case header.TCPProtocolNumber:
		var tcpHeader header.TCP
		if newPkt.TransportHeader != nil {
			tcpHeader = header.TCP(newPkt.TransportHeader)
		} else {
			if pkt.Data.Size() < header.TCPMinimumSize {
				return RuleDrop, 0
			}
			hdr, ok := newPkt.Data.PullUp(header.TCPMinimumSize)
			if !ok {
				return RuleDrop, 0
			}
			tcpHeader = header.TCP(hdr)
		}
		// TODO(gvisor.dev/issue/170): Need to recompute checksum
		// and implement nat connection tracking to support TCP.
		tcpHeader.SetDestinationPort(rt.MinPort)
	default:
		return RuleDrop, 0
	}

	return RuleAccept, 0
}
