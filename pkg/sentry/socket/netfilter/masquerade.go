// Copyright 2026 The gVisor Authors.
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

package netfilter

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// MasqueradeTargetName is used to mark targets as masquerade targets. Masquerade
// targets should be reached for only the NAT table. These targets change the
// source IP to the outgoing interface's primary address (computed at action
// time); only valid in the POSTROUTING chain. The underlying rewrite is already
// implemented by stack.MasqueradeTarget -- this maker just translates the
// iptables MASQUERADE target to/from it.
const MasqueradeTargetName = "MASQUERADE"

type masqueradeTarget struct {
	stack.MasqueradeTarget
	// raw is the original marshalled xt_entry_target (header + NAT range payload)
	// as received from iptables. MASQUERADE has several on-wire layouts across
	// revisions -- rev0 nf_nat_ipv4_multi_range_compat (56B) and rev1/2 nf_nat_range
	// (72B, as emitted by kube-proxy's `--random-fully` rules). We never interpret
	// the range (the source address comes from the egress interface), so we retain
	// the raw bytes to marshal them back verbatim for a faithful iptables-save.
	raw []byte
}

func (mt *masqueradeTarget) id() targetID {
	return targetID{
		name:            MasqueradeTargetName,
		networkProtocol: mt.NetworkProtocol,
	}
}

type masqueradeTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (mm *masqueradeTargetMaker) id() targetID {
	return targetID{
		name:            MasqueradeTargetName,
		networkProtocol: mm.NetworkProtocol,
	}
}

func (*masqueradeTargetMaker) marshal(target target) []byte {
	// Round-trip the exact bytes we received (preserves the revision/layout that
	// iptables negotiated) so iptables-save/kube-proxy see their own rule back.
	if mt, ok := target.(*masqueradeTarget); ok && len(mt.raw) > 0 {
		return append([]byte(nil), mt.raw...)
	}
	// Fallback for internally-constructed targets: the legacy
	// nf_nat_ipv4_multi_range_compat layout (same as SNAT revision 0).
	xt := linux.XTNATTargetV0{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV0,
		},
	}
	copy(xt.Target.Name[:], MasqueradeTargetName)
	xt.NfRange.RangeSize = 1
	return marshal.Marshal(&xt)
}

func (*masqueradeTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	// MASQUERADE is valid only for IPv4 and IPv6 in the nat table's POSTROUTING hook.
	netProto := filter.NetworkProtocol()
	if netProto != header.IPv4ProtocolNumber && netProto != header.IPv6ProtocolNumber {
		nflog("masqueradeTargetMaker: unsupported network protocol: %d", netProto)
		return nil, syserr.ErrNotSupported
	}

	// MASQUERADE ignores the NAT address range entirely -- the source address is
	// the egress interface's, derived at action time by stack.MasqueradeTarget.
	// iptables sends several range layouts across revisions (rev0
	// nf_nat_ipv4_multi_range_compat, rev1/2 nf_nat_range, the latter carrying
	// kube-proxy's --random-fully flag), so we do NOT parse or validate the range;
	// we only require the fixed xt_entry_target header and retain the raw bytes.
	if len(buf) < linux.SizeOfXTEntryTarget {
		nflog("masqueradeTargetMaker: buf too small for masquerade target: %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}
	return &masqueradeTarget{
		MasqueradeTarget: stack.MasqueradeTarget{
			NetworkProtocol: netProto,
		},
		raw: append([]byte(nil), buf...),
	}, nil
}
