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
	"errors"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/usermem"
)

// errorTargetName is used to mark targets as error targets. Error targets
// shouldn't be reached - an error has occurred if we fall through to one.
const errorTargetName = "ERROR"

// redirectTargetName is used to mark targets as redirect targets. Redirect
// targets should be reached for only NAT and Mangle tables. These targets will
// change the destination port/destination IP for packets.
const redirectTargetName = "REDIRECT"

func marshalTarget(target stack.Target) []byte {
	switch tg := target.(type) {
	case stack.AcceptTarget:
		return marshalStandardTarget(stack.RuleAccept)
	case stack.DropTarget:
		return marshalStandardTarget(stack.RuleDrop)
	case stack.ErrorTarget:
		return marshalErrorTarget(errorTargetName)
	case stack.UserChainTarget:
		return marshalErrorTarget(tg.Name)
	case stack.ReturnTarget:
		return marshalStandardTarget(stack.RuleReturn)
	case stack.RedirectTarget:
		return marshalRedirectTarget(tg)
	case JumpTarget:
		return marshalJumpTarget(tg)
	default:
		panic(fmt.Errorf("unknown target of type %T", target))
	}
}

func marshalStandardTarget(verdict stack.RuleVerdict) []byte {
	nflog("convert to binary: marshalling standard target")

	// The target's name will be the empty string.
	target := linux.XTStandardTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTStandardTarget,
		},
		Verdict: translateFromStandardVerdict(verdict),
	}

	ret := make([]byte, 0, linux.SizeOfXTStandardTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

func marshalErrorTarget(errorName string) []byte {
	// This is an error target named error
	target := linux.XTErrorTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTErrorTarget,
		},
	}
	copy(target.Name[:], errorName)
	copy(target.Target.Name[:], errorTargetName)

	ret := make([]byte, 0, linux.SizeOfXTErrorTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

func marshalRedirectTarget(rt stack.RedirectTarget) []byte {
	// This is a redirect target named redirect
	target := linux.XTRedirectTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTRedirectTarget,
		},
	}
	copy(target.Target.Name[:], redirectTargetName)

	ret := make([]byte, 0, linux.SizeOfXTRedirectTarget)
	target.NfRange.RangeSize = 1
	if rt.RangeProtoSpecified {
		target.NfRange.RangeIPV4.Flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}
	// Convert port from little endian to big endian.
	port := make([]byte, 2)
	binary.LittleEndian.PutUint16(port, rt.MinPort)
	target.NfRange.RangeIPV4.MinPort = binary.BigEndian.Uint16(port)
	binary.LittleEndian.PutUint16(port, rt.MaxPort)
	target.NfRange.RangeIPV4.MaxPort = binary.BigEndian.Uint16(port)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

func marshalJumpTarget(jt JumpTarget) []byte {
	nflog("convert to binary: marshalling jump target")

	// The target's name will be the empty string.
	target := linux.XTStandardTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTStandardTarget,
		},
		// Verdict is overloaded by the ABI. When positive, it holds
		// the jump offset from the start of the table.
		Verdict: int32(jt.Offset),
	}

	ret := make([]byte, 0, linux.SizeOfXTStandardTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

// translateFromStandardVerdict translates verdicts the same way as the iptables
// tool.
func translateFromStandardVerdict(verdict stack.RuleVerdict) int32 {
	switch verdict {
	case stack.RuleAccept:
		return -linux.NF_ACCEPT - 1
	case stack.RuleDrop:
		return -linux.NF_DROP - 1
	case stack.RuleReturn:
		return linux.NF_RETURN
	default:
		// TODO(gvisor.dev/issue/170): Support Jump.
		panic(fmt.Sprintf("unknown standard verdict: %d", verdict))
	}
}

// translateToStandardTarget translates from the value in a
// linux.XTStandardTarget to an stack.Verdict.
func translateToStandardTarget(val int32) (stack.Target, error) {
	// TODO(gvisor.dev/issue/170): Support other verdicts.
	switch val {
	case -linux.NF_ACCEPT - 1:
		return stack.AcceptTarget{}, nil
	case -linux.NF_DROP - 1:
		return stack.DropTarget{}, nil
	case -linux.NF_QUEUE - 1:
		return nil, errors.New("unsupported iptables verdict QUEUE")
	case linux.NF_RETURN:
		return stack.ReturnTarget{}, nil
	default:
		return nil, fmt.Errorf("unknown iptables verdict %d", val)
	}
}

// parseTarget parses a target from optVal. optVal should contain only the
// target.
func parseTarget(filter stack.IPHeaderFilter, optVal []byte) (stack.Target, error) {
	nflog("set entries: parsing target of size %d", len(optVal))
	if len(optVal) < linux.SizeOfXTEntryTarget {
		return nil, fmt.Errorf("optVal has insufficient size for entry target %d", len(optVal))
	}
	var target linux.XTEntryTarget
	buf := optVal[:linux.SizeOfXTEntryTarget]
	binary.Unmarshal(buf, usermem.ByteOrder, &target)
	switch target.Name.String() {
	case "":
		// Standard target.
		if len(optVal) != linux.SizeOfXTStandardTarget {
			return nil, fmt.Errorf("optVal has wrong size for standard target %d", len(optVal))
		}
		var standardTarget linux.XTStandardTarget
		buf = optVal[:linux.SizeOfXTStandardTarget]
		binary.Unmarshal(buf, usermem.ByteOrder, &standardTarget)

		if standardTarget.Verdict < 0 {
			// A Verdict < 0 indicates a non-jump verdict.
			return translateToStandardTarget(standardTarget.Verdict)
		}
		// A verdict >= 0 indicates a jump.
		return JumpTarget{Offset: uint32(standardTarget.Verdict)}, nil

	case errorTargetName:
		// Error target.
		if len(optVal) != linux.SizeOfXTErrorTarget {
			return nil, fmt.Errorf("optVal has insufficient size for error target %d", len(optVal))
		}
		var errorTarget linux.XTErrorTarget
		buf = optVal[:linux.SizeOfXTErrorTarget]
		binary.Unmarshal(buf, usermem.ByteOrder, &errorTarget)

		// Error targets are used in 2 cases:
		// * An actual error case. These rules have an error
		//   named errorTargetName. The last entry of the table
		//   is usually an error case to catch any packets that
		//   somehow fall through every rule.
		// * To mark the start of a user defined chain. These
		//   rules have an error with the name of the chain.
		switch name := errorTarget.Name.String(); name {
		case errorTargetName:
			nflog("set entries: error target")
			return stack.ErrorTarget{}, nil
		default:
			// User defined chain.
			nflog("set entries: user-defined target %q", name)
			return stack.UserChainTarget{Name: name}, nil
		}

	case redirectTargetName:
		// Redirect target.
		if len(optVal) < linux.SizeOfXTRedirectTarget {
			return nil, fmt.Errorf("netfilter.SetEntries: optVal has insufficient size for redirect target %d", len(optVal))
		}

		if filter.Protocol != header.TCPProtocolNumber && filter.Protocol != header.UDPProtocolNumber {
			return nil, fmt.Errorf("netfilter.SetEntries: invalid argument")
		}

		var redirectTarget linux.XTRedirectTarget
		buf = optVal[:linux.SizeOfXTRedirectTarget]
		binary.Unmarshal(buf, usermem.ByteOrder, &redirectTarget)

		// Copy linux.XTRedirectTarget to stack.RedirectTarget.
		var target stack.RedirectTarget
		nfRange := redirectTarget.NfRange

		// RangeSize should be 1.
		if nfRange.RangeSize != 1 {
			return nil, fmt.Errorf("netfilter.SetEntries: invalid argument")
		}

		// TODO(gvisor.dev/issue/170): Check if the flags are valid.
		// Also check if we need to map ports or IP.
		// For now, redirect target only supports destination port change.
		// Port range and IP range are not supported yet.
		if nfRange.RangeIPV4.Flags&linux.NF_NAT_RANGE_PROTO_SPECIFIED == 0 {
			return nil, fmt.Errorf("netfilter.SetEntries: invalid argument")
		}
		target.RangeProtoSpecified = true

		target.MinIP = tcpip.Address(nfRange.RangeIPV4.MinIP[:])
		target.MaxIP = tcpip.Address(nfRange.RangeIPV4.MaxIP[:])

		// TODO(gvisor.dev/issue/170): Port range is not supported yet.
		if nfRange.RangeIPV4.MinPort != nfRange.RangeIPV4.MaxPort {
			return nil, fmt.Errorf("netfilter.SetEntries: invalid argument")
		}

		// Convert port from big endian to little endian.
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, nfRange.RangeIPV4.MinPort)
		target.MinPort = binary.LittleEndian.Uint16(port)

		binary.BigEndian.PutUint16(port, nfRange.RangeIPV4.MaxPort)
		target.MaxPort = binary.LittleEndian.Uint16(port)
		return target, nil
	}

	// Unknown target.
	return nil, fmt.Errorf("unknown target %q doesn't exist or isn't supported yet", target.Name.String())
}

// JumpTarget implements stack.Target.
type JumpTarget struct {
	// Offset is the byte offset of the rule to jump to. It is used for
	// marshaling and unmarshaling.
	Offset uint32

	// RuleNum is the rule to jump to.
	RuleNum int
}

// Action implements stack.Target.Action.
func (jt JumpTarget) Action(*stack.PacketBuffer, *stack.ConnTrack, stack.Hook, *stack.GSO, *stack.Route, tcpip.Address) (stack.RuleVerdict, int) {
	return stack.RuleJump, jt.RuleNum
}
