// Copyright 2023 The gVisor Authors.
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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// SNATTargetName is used to mark targets as SNAT targets. SNAT targets should
// be reached for only NAT table. These targets will change the source port
// and/or IP for packets.
const SNATTargetName = "SNAT"

type snatTarget struct {
	stack.SNATTarget
}

func (st *snatTarget) id() targetID {
	return targetID{
		name:            SNATTargetName,
		networkProtocol: st.NetworkProtocol,
	}
}

type snatTargetMakerV4 struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (st *snatTargetMakerV4) id() targetID {
	return targetID{
		name:            SNATTargetName,
		networkProtocol: st.NetworkProtocol,
	}
}

func (*snatTargetMakerV4) marshal(target target) []byte {
	st := target.(*snatTarget)
	// This is a snat target named snat.
	xt := linux.XTNATTargetV0{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV0,
		},
	}
	copy(xt.Target.Name[:], SNATTargetName)

	xt.NfRange.RangeSize = 1
	xt.NfRange.RangeIPV4.Flags |= linux.NF_NAT_RANGE_MAP_IPS | linux.NF_NAT_RANGE_PROTO_SPECIFIED
	xt.NfRange.RangeIPV4.MinPort = htons(st.Port)
	xt.NfRange.RangeIPV4.MaxPort = xt.NfRange.RangeIPV4.MinPort
	copy(xt.NfRange.RangeIPV4.MinIP[:], st.Addr.AsSlice())
	copy(xt.NfRange.RangeIPV4.MaxIP[:], st.Addr.AsSlice())
	return marshal.Marshal(&xt)
}

func (*snatTargetMakerV4) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if len(buf) < linux.SizeOfXTNATTargetV0 {
		nflog("snatTargetMakerV4: buf has insufficient size for snat target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("snatTargetMakerV4: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var st linux.XTNATTargetV0
	st.UnmarshalUnsafe(buf)

	// Copy linux.XTNATTargetV0 to stack.SNATTarget.
	target := snatTarget{SNATTarget: stack.SNATTarget{
		NetworkProtocol: filter.NetworkProtocol(),
	}}

	// RangeSize should be 1.
	nfRange := st.NfRange
	if nfRange.RangeSize != 1 {
		nflog("snatTargetMakerV4: bad rangesize %d", nfRange.RangeSize)
		return nil, syserr.ErrInvalidArgument
	}

	// TODO(gvisor.dev/issue/5772): If the rule doesn't specify the source port,
	// choose one automatically.
	if nfRange.RangeIPV4.MinPort == 0 {
		nflog("snatTargetMakerV4: snat target needs to specify a non-zero port")
		return nil, syserr.ErrInvalidArgument
	}

	if nfRange.RangeIPV4.MinPort != nfRange.RangeIPV4.MaxPort {
		nflog("snatTargetMakerV4: MinPort != MaxPort (%d, %d)", nfRange.RangeIPV4.MinPort, nfRange.RangeIPV4.MaxPort)
		return nil, syserr.ErrInvalidArgument
	}
	if nfRange.RangeIPV4.MinIP != nfRange.RangeIPV4.MaxIP {
		nflog("snatTargetMakerV4: MinIP != MaxIP (%d, %d)", nfRange.RangeIPV4.MinPort, nfRange.RangeIPV4.MaxPort)
		return nil, syserr.ErrInvalidArgument
	}

	target.Addr = tcpip.AddrFrom4(nfRange.RangeIPV4.MinIP)
	target.Port = ntohs(nfRange.RangeIPV4.MinPort)

	return &target, nil
}

type snatTargetMakerR1 struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (st *snatTargetMakerR1) id() targetID {
	return targetID{
		name:            SNATTargetName,
		networkProtocol: st.NetworkProtocol,
		revision:        1,
	}
}

func (*snatTargetMakerR1) marshal(target target) []byte {
	st := target.(*snatTarget)
	nt := linux.XTNATTargetV1{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV1,
		},
		Range: linux.NFNATRange{
			Flags: linux.NF_NAT_RANGE_MAP_IPS | linux.NF_NAT_RANGE_PROTO_SPECIFIED,
		},
	}
	copy(nt.Target.Name[:], SNATTargetName)
	copy(nt.Range.MinAddr[:], st.Addr.AsSlice())
	copy(nt.Range.MaxAddr[:], st.Addr.AsSlice())
	nt.Range.MinProto = htons(st.Port)
	nt.Range.MaxProto = nt.Range.MinProto

	return marshal.Marshal(&nt)
}

func (st *snatTargetMakerR1) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if size := linux.SizeOfXTNATTargetV1; len(buf) < size {
		nflog("snatTargetMakerR1: buf has insufficient size (%d) for SNAT target (%d)", len(buf), size)
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("snatTargetMakerR1: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var natRange linux.NFNATRange
	natRange.UnmarshalUnsafe(buf[linux.SizeOfXTEntryTarget:])

	// TODO(gvisor.dev/issue/5697): Support port or address ranges.
	if natRange.MinAddr != natRange.MaxAddr {
		nflog("snatTargetMakerR1: MinAddr and MaxAddr are different")
		return nil, syserr.ErrInvalidArgument
	}
	if natRange.MinProto != natRange.MaxProto {
		nflog("snatTargetMakerR1: MinProto and MaxProto are different")
		return nil, syserr.ErrInvalidArgument
	}

	// TODO(gvisor.dev/issue/5698): Support other NF_NAT_RANGE flags.
	if natRange.Flags != linux.NF_NAT_RANGE_MAP_IPS|linux.NF_NAT_RANGE_PROTO_SPECIFIED {
		nflog("snatTargetMakerR1: invalid range flags %d", natRange.Flags)
		return nil, syserr.ErrInvalidArgument
	}

	target := snatTarget{
		SNATTarget: stack.SNATTarget{
			NetworkProtocol: filter.NetworkProtocol(),
			Port:            ntohs(natRange.MinProto),
		},
	}
	switch st.NetworkProtocol {
	case header.IPv4ProtocolNumber:
		target.SNATTarget.Addr = tcpip.AddrFrom4Slice(natRange.MinAddr[:4])
	case header.IPv6ProtocolNumber:
		target.SNATTarget.Addr = tcpip.AddrFrom16(natRange.MinAddr)
	default:
		panic(fmt.Sprintf("invalid protocol number: %d", st.NetworkProtocol))
	}

	return &target, nil
}

type snatTargetMakerR2 struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (st *snatTargetMakerR2) id() targetID {
	return targetID{
		name:            SNATTargetName,
		networkProtocol: st.NetworkProtocol,
		revision:        2,
	}
}

func (*snatTargetMakerR2) marshal(target target) []byte {
	st := target.(*snatTarget)
	nt := linux.XTNATTargetV2{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV1,
		},
		Range: linux.NFNATRange2{
			Flags: linux.NF_NAT_RANGE_MAP_IPS | linux.NF_NAT_RANGE_PROTO_SPECIFIED,
		},
	}
	copy(nt.Target.Name[:], SNATTargetName)
	copy(nt.Range.MinAddr[:], st.Addr.AsSlice())
	copy(nt.Range.MaxAddr[:], st.Addr.AsSlice())
	nt.Range.MinProto = htons(st.Port)
	nt.Range.MaxProto = nt.Range.MinProto

	return marshal.Marshal(&nt)
}

func (st *snatTargetMakerR2) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if size := linux.SizeOfXTNATTargetV2; len(buf) < size {
		nflog("snatTargetMakerR2: buf has insufficient size (%d) for SNAT target (%d)", len(buf), size)
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("snatTargetMakerR2: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var natRange linux.NFNATRange2
	natRange.UnmarshalUnsafe(buf[linux.SizeOfXTEntryTarget:])

	// TODO(gvisor.dev/issue/5697): Support port or address ranges.
	if natRange.MinAddr != natRange.MaxAddr {
		nflog("snatTargetMakerR2: MinAddr and MaxAddr are different")
		return nil, syserr.ErrInvalidArgument
	}
	if natRange.MinProto != natRange.MaxProto {
		nflog("snatTargetMakerR2: MinProto and MaxProto are different")
		return nil, syserr.ErrInvalidArgument
	}
	if natRange.BaseProto != 0 {
		nflog("snatTargetMakerR2: BaseProto is nonzero")
		return nil, syserr.ErrInvalidArgument
	}

	// TODO(gvisor.dev/issue/5698): Support other NF_NAT_RANGE flags.
	if natRange.Flags != linux.NF_NAT_RANGE_MAP_IPS|linux.NF_NAT_RANGE_PROTO_SPECIFIED {
		nflog("snatTargetMakerR2: invalid range flags %d", natRange.Flags)
		return nil, syserr.ErrInvalidArgument
	}

	target := snatTarget{
		SNATTarget: stack.SNATTarget{
			NetworkProtocol: filter.NetworkProtocol(),
			Port:            ntohs(natRange.MinProto),
		},
	}
	switch st.NetworkProtocol {
	case header.IPv4ProtocolNumber:
		target.SNATTarget.Addr = tcpip.AddrFrom4Slice(natRange.MinAddr[:4])
	case header.IPv6ProtocolNumber:
		target.SNATTarget.Addr = tcpip.AddrFrom16(natRange.MinAddr)
	default:
		panic(fmt.Sprintf("invalid protocol number: %d", st.NetworkProtocol))
	}

	return &target, nil
}
