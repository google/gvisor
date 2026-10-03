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

// MasqueradeTargetName is used to mark targets as masquerade targets.
// Masquerade targets are only valid in the nat table's POSTROUTING chain. They
// change the source address to the outgoing interface's primary address.
const MasqueradeTargetName = "MASQUERADE"

// +stateify savable
type masqueradeTarget struct {
	stack.MasqueradeTarget

	// raw is the xt_entry_target (header and NAT range) as set by userspace.
	// Linux returns the target data verbatim on IPT_SO_GET_ENTRIES.
	raw []byte
}

func (mt *masqueradeTarget) id() targetID {
	return targetID{
		name:            MasqueradeTargetName,
		networkProtocol: mt.NetworkProtocol,
	}
}

// masqueradeTargetMaker handles MASQUERADE revision 0. As in Linux
// net/netfilter/xt_MASQUERADE.c, IPv4 uses struct
// nf_nat_ipv4_multi_range_compat and IPv6 uses struct nf_nat_range.
//
// +stateify savable
type masqueradeTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (mm *masqueradeTargetMaker) id() targetID {
	return targetID{
		name:            MasqueradeTargetName,
		networkProtocol: mm.NetworkProtocol,
	}
}

func (mm *masqueradeTargetMaker) marshal(target target) []byte {
	mt := target.(*masqueradeTarget)
	if len(mt.raw) > 0 {
		return append([]byte(nil), mt.raw...)
	}

	var flags uint32
	var minPort, maxPort uint16
	if mt.Ports.Size != 0 {
		flags = linux.NF_NAT_RANGE_PROTO_SPECIFIED
		minPort = htons(mt.Ports.Start)
		maxPort = htons(uint16(uint32(mt.Ports.Start) + mt.Ports.Size - 1))
	}
	if mm.NetworkProtocol == header.IPv6ProtocolNumber {
		xt := linux.XTNATTargetV1{
			Target: linux.XTEntryTarget{
				TargetSize: linux.SizeOfXTNATTargetV1,
			},
			Range: linux.NFNATRange{
				Flags:    flags,
				MinProto: minPort,
				MaxProto: maxPort,
			},
		}
		copy(xt.Target.Name[:], MasqueradeTargetName)
		return marshal.Marshal(&xt)
	}
	xt := linux.XTNATTargetV0{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV0,
		},
	}
	copy(xt.Target.Name[:], MasqueradeTargetName)
	xt.NfRange.RangeSize = 1
	xt.NfRange.RangeIPV4.Flags = flags
	xt.NfRange.RangeIPV4.MinPort = minPort
	xt.NfRange.RangeIPV4.MaxPort = maxPort
	return marshal.Marshal(&xt)
}

// unmarshal implements masquerade_tg_check and masquerade_tg6_checkentry from
// net/netfilter/xt_MASQUERADE.c, after xt_check_target's exact size check.
func (mm *masqueradeTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	netProto := filter.NetworkProtocol()
	var flags uint32
	var minPort, maxPort uint16
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(buf) != linux.SizeOfXTNATTargetV0 {
			nflog("masqueradeTargetMaker: buf size %d, want %d", len(buf), linux.SizeOfXTNATTargetV0)
			return nil, syserr.ErrInvalidArgument
		}
		var xt linux.XTNATTargetV0
		xt.UnmarshalUnsafe(buf)
		if xt.NfRange.RangeSize != 1 {
			nflog("masqueradeTargetMaker: bad rangesize %d", xt.NfRange.RangeSize)
			return nil, syserr.ErrInvalidArgument
		}
		flags = xt.NfRange.RangeIPV4.Flags
		minPort = ntohs(xt.NfRange.RangeIPV4.MinPort)
		maxPort = ntohs(xt.NfRange.RangeIPV4.MaxPort)
	case header.IPv6ProtocolNumber:
		if len(buf) != linux.SizeOfXTNATTargetV1 {
			nflog("masqueradeTargetMaker: buf size %d, want %d", len(buf), linux.SizeOfXTNATTargetV1)
			return nil, syserr.ErrInvalidArgument
		}
		var xt linux.XTNATTargetV1
		xt.UnmarshalUnsafe(buf)
		flags = xt.Range.Flags
		minPort = ntohs(xt.Range.MinProto)
		maxPort = ntohs(xt.Range.MaxProto)
	default:
		nflog("masqueradeTargetMaker: unsupported network protocol %d", netProto)
		return nil, syserr.ErrNotSupported
	}

	// The source address always comes from the egress interface.
	if flags&linux.NF_NAT_RANGE_MAP_IPS != 0 {
		nflog("masqueradeTargetMaker: MAP_IPS is not supported")
		return nil, syserr.ErrInvalidArgument
	}

	target := &masqueradeTarget{
		MasqueradeTarget: stack.MasqueradeTarget{
			NetworkProtocol: netProto,
		},
		raw: append([]byte(nil), buf...),
	}
	if flags&linux.NF_NAT_RANGE_PROTO_SPECIFIED != 0 {
		// Linux does not check the order, but iptables never builds an
		// inverted range. Reject it, as the nftables compat target does.
		if minPort > maxPort {
			nflog("masqueradeTargetMaker: invalid port range %d-%d", minPort, maxPort)
			return nil, syserr.ErrInvalidArgument
		}
		target.Ports = stack.PortOrIdentRange{
			Start: minPort,
			Size:  uint32(maxPort) - uint32(minPort) + 1,
		}
	}
	return target, nil
}
