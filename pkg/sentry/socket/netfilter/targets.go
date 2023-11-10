// Copyright 2020 The gVisor Authors.
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
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ErrorTargetName is used to mark targets as error targets. Error targets
// shouldn't be reached - an error has occurred if we fall through to one.
const ErrorTargetName = "ERROR"

// RedirectTargetName is used to mark targets as redirect targets. Redirect
// targets should be reached for only NAT and Mangle tables. These targets will
// change the destination port and/or IP for packets.
const RedirectTargetName = "REDIRECT"

func init() {
	// Standard targets include ACCEPT, DROP, RETURN, and JUMP.
	registerTargetMaker(&standardTargetMaker{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&standardTargetMaker{
		NetworkProtocol: header.IPv6ProtocolNumber,
	})

	// Both user chains and actual errors are represented in iptables by
	// error targets.
	registerTargetMaker(&errorTargetMaker{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&errorTargetMaker{
		NetworkProtocol: header.IPv6ProtocolNumber,
	})

	// REDIRECT targets.
	registerTargetMaker(&redirectTargetMaker{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&nfNATTargetMaker{
		NetworkProtocol: header.IPv6ProtocolNumber,
	})

	// SNAT targets.
	registerTargetMaker(&snatTargetMakerV4{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&snatTargetMakerR1{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&snatTargetMakerR1{
		NetworkProtocol: header.IPv6ProtocolNumber,
	})
	registerTargetMaker(&snatTargetMakerR2{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&snatTargetMakerR2{
		NetworkProtocol: header.IPv6ProtocolNumber,
	})

	// DNAT targets.
	registerTargetMaker(&dnatTargetMakerV4{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&dnatTargetMakerR1{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&dnatTargetMakerR1{
		NetworkProtocol: header.IPv6ProtocolNumber,
	})
	registerTargetMaker(&dnatTargetMakerR2{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
	registerTargetMaker(&dnatTargetMakerR2{
		NetworkProtocol: header.IPv6ProtocolNumber,
	})
}

// The stack package provides some basic, useful targets for us. The following
// types wrap them for compatibility with the extension system.

type acceptTarget struct {
	stack.AcceptTarget
}

func (at *acceptTarget) id() targetID {
	return targetID{
		networkProtocol: at.NetworkProtocol,
	}
}

type dropTarget struct {
	stack.DropTarget
}

func (dt *dropTarget) id() targetID {
	return targetID{
		networkProtocol: dt.NetworkProtocol,
	}
}

type errorTarget struct {
	stack.ErrorTarget
}

func (et *errorTarget) id() targetID {
	return targetID{
		name:            ErrorTargetName,
		networkProtocol: et.NetworkProtocol,
	}
}

type userChainTarget struct {
	stack.UserChainTarget
}

func (uc *userChainTarget) id() targetID {
	return targetID{
		name:            ErrorTargetName,
		networkProtocol: uc.NetworkProtocol,
	}
}

type returnTarget struct {
	stack.ReturnTarget
}

func (rt *returnTarget) id() targetID {
	return targetID{
		networkProtocol: rt.NetworkProtocol,
	}
}

type redirectTarget struct {
	stack.RedirectTarget

	// addr must be (un)marshalled when reading and writing the target to
	// userspace, but does not affect behavior.
	addr tcpip.Address
}

func (rt *redirectTarget) id() targetID {
	return targetID{
		name:            RedirectTargetName,
		networkProtocol: rt.NetworkProtocol,
	}
}

type standardTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (sm *standardTargetMaker) id() targetID {
	// Standard targets have the empty string as a name and no revisions.
	return targetID{
		networkProtocol: sm.NetworkProtocol,
	}
}

func (*standardTargetMaker) marshal(target target) []byte {
	// Translate verdicts the same way as the iptables tool.
	var verdict int32
	switch tg := target.(type) {
	case *acceptTarget:
		verdict = -linux.NF_ACCEPT - 1
	case *dropTarget:
		verdict = -linux.NF_DROP - 1
	case *returnTarget:
		verdict = linux.NF_RETURN
	case *JumpTarget:
		verdict = int32(tg.Offset)
	default:
		panic(fmt.Errorf("unknown target of type %T", target))
	}

	// The target's name will be the empty string.
	xt := linux.XTStandardTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTStandardTarget,
		},
		Verdict: verdict,
	}

	return marshal.Marshal(&xt)
}

func (*standardTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if len(buf) != linux.SizeOfXTStandardTarget {
		nflog("buf has wrong size for standard target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}
	var standardTarget linux.XTStandardTarget
	standardTarget.UnmarshalUnsafe(buf)

	if standardTarget.Verdict < 0 {
		// A Verdict < 0 indicates a non-jump verdict.
		return translateToStandardTarget(standardTarget.Verdict, filter.NetworkProtocol())
	}
	// A verdict >= 0 indicates a jump.
	return &JumpTarget{
		Offset:          uint32(standardTarget.Verdict),
		NetworkProtocol: filter.NetworkProtocol(),
	}, nil
}

type errorTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (em *errorTargetMaker) id() targetID {
	// Error targets have no revision.
	return targetID{
		name:            ErrorTargetName,
		networkProtocol: em.NetworkProtocol,
	}
}

func (*errorTargetMaker) marshal(target target) []byte {
	var errorName string
	switch tg := target.(type) {
	case *errorTarget:
		errorName = ErrorTargetName
	case *userChainTarget:
		errorName = tg.Name
	default:
		panic(fmt.Sprintf("errorMakerTarget cannot marshal unknown type %T", target))
	}

	// This is an error target named error
	xt := linux.XTErrorTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTErrorTarget,
		},
	}
	copy(xt.Name[:], errorName)
	copy(xt.Target.Name[:], ErrorTargetName)

	return marshal.Marshal(&xt)
}

func (*errorTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if len(buf) != linux.SizeOfXTErrorTarget {
		nflog("buf has insufficient size for error target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}
	var errTgt linux.XTErrorTarget
	errTgt.UnmarshalUnsafe(buf)

	// Error targets are used in 2 cases:
	//	* An actual error case. These rules have an error named
	//		ErrorTargetName. The last entry of the table is usually an error
	//		case to catch any packets that somehow fall through every rule.
	//	* To mark the start of a user defined chain. These
	//		rules have an error with the name of the chain.
	switch name := errTgt.Name.String(); name {
	case ErrorTargetName:
		return &errorTarget{stack.ErrorTarget{
			NetworkProtocol: filter.NetworkProtocol(),
		}}, nil
	default:
		// User defined chain.
		return &userChainTarget{stack.UserChainTarget{
			Name:            name,
			NetworkProtocol: filter.NetworkProtocol(),
		}}, nil
	}
}

type redirectTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (rm *redirectTargetMaker) id() targetID {
	return targetID{
		name:            RedirectTargetName,
		networkProtocol: rm.NetworkProtocol,
	}
}

func (*redirectTargetMaker) marshal(target target) []byte {
	rt := target.(*redirectTarget)
	// This is a redirect target named redirect
	xt := linux.XTRedirectTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTRedirectTarget,
		},
	}
	copy(xt.Target.Name[:], RedirectTargetName)

	xt.NfRange.RangeSize = 1
	xt.NfRange.RangeIPV4.Flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	xt.NfRange.RangeIPV4.MinPort = htons(rt.Port)
	xt.NfRange.RangeIPV4.MaxPort = xt.NfRange.RangeIPV4.MinPort
	return marshal.Marshal(&xt)
}

func (*redirectTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if len(buf) < linux.SizeOfXTRedirectTarget {
		nflog("redirectTargetMaker: buf has insufficient size for redirect target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("redirectTargetMaker: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var rt linux.XTRedirectTarget
	rt.UnmarshalUnsafe(buf)

	// Copy linux.XTRedirectTarget to stack.RedirectTarget.
	target := redirectTarget{RedirectTarget: stack.RedirectTarget{
		NetworkProtocol: filter.NetworkProtocol(),
	}}

	// RangeSize should be 1.
	nfRange := rt.NfRange
	if nfRange.RangeSize != 1 {
		nflog("redirectTargetMaker: bad rangesize %d", nfRange.RangeSize)
		return nil, syserr.ErrInvalidArgument
	}

	// Also check if we need to map ports or IP.
	// For now, redirect target only supports destination port change.
	// Port range and IP range are not supported yet.
	if nfRange.RangeIPV4.Flags != linux.NF_NAT_RANGE_PROTO_SPECIFIED {
		nflog("redirectTargetMaker: invalid range flags %d", nfRange.RangeIPV4.Flags)
		return nil, syserr.ErrInvalidArgument
	}

	if nfRange.RangeIPV4.MinPort != nfRange.RangeIPV4.MaxPort {
		nflog("redirectTargetMaker: MinPort != MaxPort (%d, %d)", nfRange.RangeIPV4.MinPort, nfRange.RangeIPV4.MaxPort)
		return nil, syserr.ErrInvalidArgument
	}
	if nfRange.RangeIPV4.MinIP != nfRange.RangeIPV4.MaxIP {
		nflog("redirectTargetMaker: MinIP != MaxIP (%d, %d)", nfRange.RangeIPV4.MinPort, nfRange.RangeIPV4.MaxPort)
		return nil, syserr.ErrInvalidArgument
	}

	target.addr = tcpip.AddrFrom4(nfRange.RangeIPV4.MinIP)
	target.Port = ntohs(nfRange.RangeIPV4.MinPort)

	return &target, nil
}

type nfNATTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (rm *nfNATTargetMaker) id() targetID {
	return targetID{
		name:            RedirectTargetName,
		networkProtocol: rm.NetworkProtocol,
	}
}

func (*nfNATTargetMaker) marshal(target target) []byte {
	rt := target.(*redirectTarget)
	nt := linux.XTNATTargetV1{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV1,
		},
		Range: linux.NFNATRange{
			Flags: linux.NF_NAT_RANGE_PROTO_SPECIFIED,
		},
	}
	copy(nt.Target.Name[:], RedirectTargetName)
	copy(nt.Range.MinAddr[:], rt.addr.AsSlice())
	copy(nt.Range.MaxAddr[:], rt.addr.AsSlice())

	nt.Range.MinProto = htons(rt.Port)
	nt.Range.MaxProto = nt.Range.MinProto

	return marshal.Marshal(&nt)
}

func (*nfNATTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if size := linux.SizeOfXTNATTargetV1; len(buf) < size {
		nflog("nfNATTargetMaker: buf has insufficient size (%d) for nfNAT target (%d)", len(buf), size)
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("nfNATTargetMaker: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var natRange linux.NFNATRange
	natRange.UnmarshalUnsafe(buf[linux.SizeOfXTEntryTarget:])

	// We don't support port or address ranges.
	if natRange.MinAddr != natRange.MaxAddr {
		nflog("nfNATTargetMaker: MinAddr and MaxAddr are different")
		return nil, syserr.ErrInvalidArgument
	}
	if natRange.MinProto != natRange.MaxProto {
		nflog("nfNATTargetMaker: MinProto and MaxProto are different")
		return nil, syserr.ErrInvalidArgument
	}

	// For now, redirect target only supports destination change.
	if natRange.Flags != linux.NF_NAT_RANGE_PROTO_SPECIFIED {
		nflog("nfNATTargetMaker: invalid range flags %d", natRange.Flags)
		return nil, syserr.ErrInvalidArgument
	}

	target := redirectTarget{
		RedirectTarget: stack.RedirectTarget{
			NetworkProtocol: filter.NetworkProtocol(),
			Port:            ntohs(natRange.MinProto),
		},
		addr: tcpip.AddrFrom16(natRange.MinAddr),
	}

	return &target, nil
}

// translateToStandardTarget translates from the value in a
// linux.XTStandardTarget to an stack.Verdict.
func translateToStandardTarget(val int32, netProto tcpip.NetworkProtocolNumber) (target, *syserr.Error) {
	switch val {
	case -linux.NF_ACCEPT - 1:
		return &acceptTarget{stack.AcceptTarget{
			NetworkProtocol: netProto,
		}}, nil
	case -linux.NF_DROP - 1:
		return &dropTarget{stack.DropTarget{
			NetworkProtocol: netProto,
		}}, nil
	case -linux.NF_QUEUE - 1:
		nflog("unsupported iptables verdict QUEUE")
		return nil, syserr.ErrInvalidArgument
	case linux.NF_RETURN:
		return &returnTarget{stack.ReturnTarget{
			NetworkProtocol: netProto,
		}}, nil
	default:
		nflog("unknown iptables verdict %d", val)
		return nil, syserr.ErrInvalidArgument
	}
}

// parseTarget parses a target from optVal. optVal should contain only the
// target.
func parseTarget(filter stack.IPHeaderFilter, optVal []byte, ipv6 bool) (stack.Target, *syserr.Error) {
	nflog("set entries: parsing target of size %d", len(optVal))
	if len(optVal) < linux.SizeOfXTEntryTarget {
		nflog("optVal has insufficient size for entry target %d", len(optVal))
		return nil, syserr.ErrInvalidArgument
	}
	var target linux.XTEntryTarget
	// Do not advance optVal as targetMake.unmarshal() may unmarshal
	// XTEntryTarget again but with some added fields.
	target.UnmarshalUnsafe(optVal)

	return unmarshalTarget(target, filter, optVal)
}

// JumpTarget implements stack.Target.
type JumpTarget struct {
	// Offset is the byte offset of the rule to jump to. It is used for
	// marshaling and unmarshaling.
	Offset uint32

	// RuleNum is the rule to jump to.
	RuleNum int

	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// ID implements Target.ID.
func (jt *JumpTarget) id() targetID {
	return targetID{
		networkProtocol: jt.NetworkProtocol,
	}
}

// Action implements stack.Target.Action.
func (jt *JumpTarget) Action(stack.PacketBufferPtr, stack.Hook, *stack.Route, stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	return stack.RuleJump, jt.RuleNum
}

func ntohs(port uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return hostarch.ByteOrder.Uint16(buf)
}

func htons(port uint16) uint16 {
	buf := make([]byte, 2)
	hostarch.ByteOrder.PutUint16(buf, port)
	return binary.BigEndian.Uint16(buf)
}
