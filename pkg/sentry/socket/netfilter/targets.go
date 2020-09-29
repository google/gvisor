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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/usermem"
)

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

	registerTargetMaker(&redirectTargetMaker{
		NetworkProtocol: header.IPv4ProtocolNumber,
	})
}

type standardTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (sm *standardTargetMaker) id() stack.TargetID {
	// Standard targets have the empty string as a name and no revisions.
	return stack.TargetID{
		NetworkProtocol: sm.NetworkProtocol,
	}
}
func (*standardTargetMaker) marshal(target stack.Target) []byte {
	// Translate verdicts the same way as the iptables tool.
	var verdict int32
	switch tg := target.(type) {
	case *stack.AcceptTarget:
		verdict = -linux.NF_ACCEPT - 1
	case *stack.DropTarget:
		verdict = -linux.NF_DROP - 1
	case *stack.ReturnTarget:
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

	ret := make([]byte, 0, linux.SizeOfXTStandardTarget)
	return binary.Marshal(ret, usermem.ByteOrder, xt)
}

func (*standardTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (stack.Target, *syserr.Error) {
	if len(buf) != linux.SizeOfXTStandardTarget {
		nflog("buf has wrong size for standard target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}
	var standardTarget linux.XTStandardTarget
	buf = buf[:linux.SizeOfXTStandardTarget]
	binary.Unmarshal(buf, usermem.ByteOrder, &standardTarget)

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

func (em *errorTargetMaker) id() stack.TargetID {
	// Error targets have no revision.
	return stack.TargetID{
		Name:            stack.ErrorTargetName,
		NetworkProtocol: em.NetworkProtocol,
	}
}

func (*errorTargetMaker) marshal(target stack.Target) []byte {
	var errorName string
	switch tg := target.(type) {
	case *stack.ErrorTarget:
		errorName = stack.ErrorTargetName
	case *stack.UserChainTarget:
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
	copy(xt.Target.Name[:], stack.ErrorTargetName)

	ret := make([]byte, 0, linux.SizeOfXTErrorTarget)
	return binary.Marshal(ret, usermem.ByteOrder, xt)
}

func (*errorTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (stack.Target, *syserr.Error) {
	if len(buf) != linux.SizeOfXTErrorTarget {
		nflog("buf has insufficient size for error target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}
	var errorTarget linux.XTErrorTarget
	buf = buf[:linux.SizeOfXTErrorTarget]
	binary.Unmarshal(buf, usermem.ByteOrder, &errorTarget)

	// Error targets are used in 2 cases:
	// * An actual error case. These rules have an error
	//   named stack.ErrorTargetName. The last entry of the table
	//   is usually an error case to catch any packets that
	//   somehow fall through every rule.
	// * To mark the start of a user defined chain. These
	//   rules have an error with the name of the chain.
	switch name := errorTarget.Name.String(); name {
	case stack.ErrorTargetName:
		return &stack.ErrorTarget{NetworkProtocol: filter.NetworkProtocol()}, nil
	default:
		// User defined chain.
		return &stack.UserChainTarget{
			Name:            name,
			NetworkProtocol: filter.NetworkProtocol(),
		}, nil
	}
}

type redirectTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (rm *redirectTargetMaker) id() stack.TargetID {
	return stack.TargetID{
		Name:            stack.RedirectTargetName,
		NetworkProtocol: rm.NetworkProtocol,
	}
}

func (*redirectTargetMaker) marshal(target stack.Target) []byte {
	rt := target.(*stack.RedirectTarget)
	// This is a redirect target named redirect
	xt := linux.XTRedirectTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTRedirectTarget,
		},
	}
	copy(xt.Target.Name[:], stack.RedirectTargetName)

	ret := make([]byte, 0, linux.SizeOfXTRedirectTarget)
	xt.NfRange.RangeSize = 1
	if rt.RangeProtoSpecified {
		xt.NfRange.RangeIPV4.Flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}
	xt.NfRange.RangeIPV4.MinPort = htons(rt.MinPort)
	xt.NfRange.RangeIPV4.MaxPort = htons(rt.MaxPort)
	return binary.Marshal(ret, usermem.ByteOrder, xt)
}

func (*redirectTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (stack.Target, *syserr.Error) {
	if len(buf) < linux.SizeOfXTRedirectTarget {
		nflog("redirectTargetMaker: buf has insufficient size for redirect target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}

	if p := filter.Protocol; p != header.TCPProtocolNumber && p != header.UDPProtocolNumber {
		nflog("redirectTargetMaker: bad proto %d", p)
		return nil, syserr.ErrInvalidArgument
	}

	var redirectTarget linux.XTRedirectTarget
	buf = buf[:linux.SizeOfXTRedirectTarget]
	binary.Unmarshal(buf, usermem.ByteOrder, &redirectTarget)

	// Copy linux.XTRedirectTarget to stack.RedirectTarget.
	target := stack.RedirectTarget{NetworkProtocol: filter.NetworkProtocol()}

	// RangeSize should be 1.
	nfRange := redirectTarget.NfRange
	if nfRange.RangeSize != 1 {
		nflog("redirectTargetMaker: bad rangesize %d", nfRange.RangeSize)
		return nil, syserr.ErrInvalidArgument
	}

	// TODO(gvisor.dev/issue/170): Check if the flags are valid.
	// Also check if we need to map ports or IP.
	// For now, redirect target only supports destination port change.
	// Port range and IP range are not supported yet.
	if nfRange.RangeIPV4.Flags&linux.NF_NAT_RANGE_PROTO_SPECIFIED == 0 {
		nflog("redirectTargetMaker: invalid range flags %d", nfRange.RangeIPV4.Flags)
		return nil, syserr.ErrInvalidArgument
	}
	target.RangeProtoSpecified = true

	target.MinIP = tcpip.Address(nfRange.RangeIPV4.MinIP[:])
	target.MaxIP = tcpip.Address(nfRange.RangeIPV4.MaxIP[:])

	// TODO(gvisor.dev/issue/170): Port range is not supported yet.
	if nfRange.RangeIPV4.MinPort != nfRange.RangeIPV4.MaxPort {
		nflog("redirectTargetMaker: MinPort != MaxPort (%d, %d)", nfRange.RangeIPV4.MinPort, nfRange.RangeIPV4.MaxPort)
		return nil, syserr.ErrInvalidArgument
	}

	target.MinPort = ntohs(nfRange.RangeIPV4.MinPort)
	target.MaxPort = ntohs(nfRange.RangeIPV4.MaxPort)

	return &target, nil
}

// translateToStandardTarget translates from the value in a
// linux.XTStandardTarget to an stack.Verdict.
func translateToStandardTarget(val int32, netProto tcpip.NetworkProtocolNumber) (stack.Target, *syserr.Error) {
	// TODO(gvisor.dev/issue/170): Support other verdicts.
	switch val {
	case -linux.NF_ACCEPT - 1:
		return &stack.AcceptTarget{NetworkProtocol: netProto}, nil
	case -linux.NF_DROP - 1:
		return &stack.DropTarget{NetworkProtocol: netProto}, nil
	case -linux.NF_QUEUE - 1:
		nflog("unsupported iptables verdict QUEUE")
		return nil, syserr.ErrInvalidArgument
	case linux.NF_RETURN:
		return &stack.ReturnTarget{NetworkProtocol: netProto}, nil
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
	buf := optVal[:linux.SizeOfXTEntryTarget]
	binary.Unmarshal(buf, usermem.ByteOrder, &target)

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
func (jt *JumpTarget) ID() stack.TargetID {
	return stack.TargetID{
		NetworkProtocol: jt.NetworkProtocol,
	}
}

// Action implements stack.Target.Action.
func (jt JumpTarget) Action(*stack.PacketBuffer, *stack.ConnTrack, stack.Hook, *stack.GSO, *stack.Route, tcpip.Address) (stack.RuleVerdict, int) {
	return stack.RuleJump, jt.RuleNum
}

func ntohs(port uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return usermem.ByteOrder.Uint16(buf)
}

func htons(port uint16) uint16 {
	buf := make([]byte, 2)
	usermem.ByteOrder.PutUint16(buf, port)
	return binary.BigEndian.Uint16(buf)
}
