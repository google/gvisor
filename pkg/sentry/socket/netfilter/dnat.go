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

// DNATTargetName is used to mark targets as DNAT targets. DNAT targets should
// be reached for only NAT table. These targets will change the source port
// and/or IP for packets.
const DNATTargetName = "DNAT"

type dnatTarget struct {
	stack.DNATTarget
	revision uint8
}

func (dt *dnatTarget) id() targetID {
	return targetID{
		name:            DNATTargetName,
		networkProtocol: dt.NetworkProtocol,
		revision:        dt.revision,
	}
}

type dnatTargetMakerV4 struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (dt *dnatTargetMakerV4) id() targetID {
	return targetID{
		name:            DNATTargetName,
		networkProtocol: dt.NetworkProtocol,
	}
}

func (*dnatTargetMakerV4) marshal(target target) []byte {
	dt := target.(*dnatTarget)
	// This is a dnat target named dnat.
	xt := linux.XTNATTargetV0{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV0,
		},
	}
	copy(xt.Target.Name[:], DNATTargetName)

	if dt.ChangeAddress {
		xt.NfRange.RangeIPV4.Flags |= linux.NF_NAT_RANGE_MAP_IPS
	}
	if dt.ChangePort {
		xt.NfRange.RangeIPV4.Flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}
	xt.NfRange.RangeSize = 1
	xt.NfRange.RangeIPV4.MinPort = htons(dt.Port)
	xt.NfRange.RangeIPV4.MaxPort = xt.NfRange.RangeIPV4.MinPort
	copy(xt.NfRange.RangeIPV4.MinIP[:], dt.Addr.AsSlice())
	copy(xt.NfRange.RangeIPV4.MaxIP[:], dt.Addr.AsSlice())
	return marshal.Marshal(&xt)
}

func (*dnatTargetMakerV4) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if len(buf) < linux.SizeOfXTNATTargetV0 {
		nflog("dnatTargetMakerV4: buf has insufficient size for dnat target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("dnatTargetMakerV4: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var dt linux.XTNATTargetV0
	dt.UnmarshalUnsafe(buf)

	// Copy linux.XTNATTargetV0 to stack.DNATTarget.
	target := dnatTarget{DNATTarget: stack.DNATTarget{
		NetworkProtocol: filter.NetworkProtocol(),
	}}

	// RangeSize should be 1.
	nfRange := dt.NfRange
	if nfRange.RangeSize != 1 {
		nflog("dnatTargetMakerV4: bad rangesize %d", nfRange.RangeSize)
		return nil, syserr.ErrInvalidArgument
	}

	if nfRange.RangeIPV4.MinPort == 0 {
		nflog("dnatTargetMakerV4: dnat target needs to specify a non-zero port")
		return nil, syserr.ErrInvalidArgument
	}

	if nfRange.RangeIPV4.MinPort != nfRange.RangeIPV4.MaxPort {
		nflog("dnatTargetMakerV4: MinPort != MaxPort (%d, %d)", nfRange.RangeIPV4.MinPort, nfRange.RangeIPV4.MaxPort)
		return nil, syserr.ErrInvalidArgument
	}
	if nfRange.RangeIPV4.MinIP != nfRange.RangeIPV4.MaxIP {
		nflog("dnatTargetMakerV4: MinIP != MaxIP (%d, %d)", nfRange.RangeIPV4.MinPort, nfRange.RangeIPV4.MaxPort)
		return nil, syserr.ErrInvalidArgument
	}
	if nfRange.RangeIPV4.Flags&^(linux.NF_NAT_RANGE_MAP_IPS|linux.NF_NAT_RANGE_PROTO_SPECIFIED) != 0 {
		nflog("dnatTargetMakerV4: unknown flags used (%x)", nfRange.RangeIPV4.Flags)
		return nil, syserr.ErrInvalidArgument
	}

	target.ChangeAddress = nfRange.RangeIPV4.Flags&linux.NF_NAT_RANGE_MAP_IPS != 0
	target.ChangePort = nfRange.RangeIPV4.Flags&linux.NF_NAT_RANGE_PROTO_SPECIFIED != 0
	target.Addr = tcpip.AddrFrom4(nfRange.RangeIPV4.MinIP)
	target.Port = ntohs(nfRange.RangeIPV4.MinPort)

	return &target, nil
}

type dnatTargetMakerR1 struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (dt *dnatTargetMakerR1) id() targetID {
	return targetID{
		name:            DNATTargetName,
		networkProtocol: dt.NetworkProtocol,
		revision:        1,
	}
}

func (*dnatTargetMakerR1) marshal(target target) []byte {
	dt := target.(*dnatTarget)
	nt := linux.XTNATTargetV1{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV1,
			Revision:   1,
		},
	}
	copy(nt.Target.Name[:], DNATTargetName)

	if dt.ChangeAddress {
		nt.Range.Flags |= linux.NF_NAT_RANGE_MAP_IPS
	}
	if dt.ChangePort {
		nt.Range.Flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}

	copy(nt.Range.MinAddr[:], dt.Addr.AsSlice())
	copy(nt.Range.MaxAddr[:], dt.Addr.AsSlice())
	nt.Range.MinProto = htons(dt.Port)
	nt.Range.MaxProto = nt.Range.MinProto

	return marshal.Marshal(&nt)
}

func (dt *dnatTargetMakerR1) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if size := linux.SizeOfXTNATTargetV1; len(buf) < size {
		nflog("dnatTargetMakerR1: buf has insufficient size (%d) for DNAT target (%d)", len(buf), size)
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("dnatTargetMakerR1: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var natRange linux.NFNATRange
	natRange.UnmarshalUnsafe(buf[linux.SizeOfXTEntryTarget:])

	if natRange.MinAddr != natRange.MaxAddr {
		nflog("dnatTargetMakerR1: MinAddr and MaxAddr are different")
		return nil, syserr.ErrInvalidArgument
	}
	if natRange.MinProto != natRange.MaxProto {
		nflog("dnatTargetMakerR1: MinProto and MaxProto are different")
		return nil, syserr.ErrInvalidArgument
	}

	if natRange.Flags&^(linux.NF_NAT_RANGE_MAP_IPS|linux.NF_NAT_RANGE_PROTO_SPECIFIED) != 0 {
		nflog("dnatTargetMakerR1: invalid flags used (%x)", natRange.Flags)
		return nil, syserr.ErrInvalidArgument
	}

	target := dnatTarget{
		DNATTarget: stack.DNATTarget{
			NetworkProtocol: filter.NetworkProtocol(),
			Port:            ntohs(natRange.MinProto),
			ChangeAddress:   natRange.Flags&linux.NF_NAT_RANGE_MAP_IPS != 0,
			ChangePort:      natRange.Flags&linux.NF_NAT_RANGE_PROTO_SPECIFIED != 0,
		},
		revision: 1,
	}
	switch dt.NetworkProtocol {
	case header.IPv4ProtocolNumber:
		target.DNATTarget.Addr = tcpip.AddrFrom4Slice(natRange.MinAddr[:4])
	case header.IPv6ProtocolNumber:
		target.DNATTarget.Addr = tcpip.AddrFrom16(natRange.MinAddr)
	default:
		panic(fmt.Sprintf("invalid protocol number: %d", dt.NetworkProtocol))
	}

	return &target, nil
}

type dnatTargetMakerR2 struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (dt *dnatTargetMakerR2) id() targetID {
	return targetID{
		name:            DNATTargetName,
		networkProtocol: dt.NetworkProtocol,
		revision:        2,
	}
}

func (*dnatTargetMakerR2) marshal(target target) []byte {
	dt := target.(*dnatTarget)
	nt := linux.XTNATTargetV2{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV1,
			Revision:   2,
		},
	}
	copy(nt.Target.Name[:], DNATTargetName)

	if dt.ChangeAddress {
		nt.Range.Flags |= linux.NF_NAT_RANGE_MAP_IPS
	}
	if dt.ChangePort {
		nt.Range.Flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}
	copy(nt.Range.MinAddr[:], dt.Addr.AsSlice())
	copy(nt.Range.MaxAddr[:], dt.Addr.AsSlice())
	nt.Range.MinProto = htons(dt.Port)
	nt.Range.MaxProto = nt.Range.MinProto

	return marshal.Marshal(&nt)
}

func (dt *dnatTargetMakerR2) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	nflog("dnatTargetMakerR2 unmarshal")
	if size := linux.SizeOfXTNATTargetV2; len(buf) < size {
		nflog("dnatTargetMakerR2: buf has insufficient size (%d) for DNAT target (%d)", len(buf), size)
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("dnatTargetMakerR2: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var natRange linux.NFNATRange2
	natRange.UnmarshalUnsafe(buf[linux.SizeOfXTEntryTarget:])

	if natRange.MinAddr != natRange.MaxAddr {
		nflog("dnatTargetMakerR2: MinAddr and MaxAddr are different")
		return nil, syserr.ErrInvalidArgument
	}
	if natRange.MinProto != natRange.MaxProto {
		nflog("dnatTargetMakerR2: MinProto and MaxProto are different")
		return nil, syserr.ErrInvalidArgument
	}
	if natRange.BaseProto != 0 {
		nflog("dnatTargetMakerR2: BaseProto is nonzero")
		return nil, syserr.ErrInvalidArgument
	}

	if natRange.Flags&^(linux.NF_NAT_RANGE_MAP_IPS|linux.NF_NAT_RANGE_PROTO_SPECIFIED) != 0 {
		nflog("dnatTargetMakerR2: invalid flags used (%x)", natRange.Flags)
		return nil, syserr.ErrInvalidArgument
	}

	target := dnatTarget{
		DNATTarget: stack.DNATTarget{
			NetworkProtocol: filter.NetworkProtocol(),
			Port:            ntohs(natRange.MinProto),
			ChangeAddress:   natRange.Flags&linux.NF_NAT_RANGE_MAP_IPS != 0,
			ChangePort:      natRange.Flags&linux.NF_NAT_RANGE_PROTO_SPECIFIED != 0,
		},
		revision: 2,
	}
	switch dt.NetworkProtocol {
	case header.IPv4ProtocolNumber:
		target.DNATTarget.Addr = tcpip.AddrFrom4Slice(natRange.MinAddr[:4])
	case header.IPv6ProtocolNumber:
		target.DNATTarget.Addr = tcpip.AddrFrom16(natRange.MinAddr)
	default:
		panic(fmt.Sprintf("invalid protocol number: %d", dt.NetworkProtocol))
	}

	return &target, nil
}
