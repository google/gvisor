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

// MarkTargetName is the name of the MARK target, which sets the packet's
// netfilter mark.
const MarkTargetName = "MARK"

// markTargetRevision is the only MARK revision Linux registers
// (net/netfilter/xt_mark.c).
const markTargetRevision = 2

func init() {
	registerTargetMaker(&markTargetMaker{NetworkProtocol: header.IPv4ProtocolNumber})
	registerTargetMaker(&markTargetMaker{NetworkProtocol: header.IPv6ProtocolNumber})
}

// markTarget sets pkt.Mark. Like Linux mark_tg, it returns XT_CONTINUE
// (RuleContinue), so traversal continues with the next rule.
//
// +stateify savable
type markTarget struct {
	mark            uint32
	mask            uint32
	networkProtocol tcpip.NetworkProtocolNumber
}

func (mt *markTarget) id() targetID {
	return targetID{
		name:            MarkTargetName,
		networkProtocol: mt.networkProtocol,
		revision:        markTargetRevision,
	}
}

// Action implements stack.Target.Action.
func (mt *markTarget) Action(pkt *stack.PacketBuffer, _ stack.Hook, _ *stack.Route, _ stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	pkt.Mark = (pkt.Mark &^ mt.mask) ^ mt.mark
	return stack.RuleContinue, 0
}

// markTargetMaker implements targetMaker for the MARK target (revision 2).
//
// +stateify savable
type markTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (mm *markTargetMaker) id() targetID {
	return targetID{
		name:            MarkTargetName,
		networkProtocol: mm.NetworkProtocol,
		revision:        markTargetRevision,
	}
}

func (*markTargetMaker) marshal(target target) []byte {
	mt := target.(*markTarget)
	xt := linux.XTMarkTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTMarkTarget,
			Revision:   markTargetRevision,
		},
		Mark: mt.mark,
		Mask: mt.mask,
	}
	copy(xt.Target.Name[:], MarkTargetName)
	return marshal.Marshal(&xt)
}

func (mm *markTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	// Linux xt_check_target requires the exact target size.
	if len(buf) != linux.SizeOfXTMarkTarget {
		nflog("markTargetMaker: buf size %d, want %d", len(buf), linux.SizeOfXTMarkTarget)
		return nil, syserr.ErrInvalidArgument
	}
	var xt linux.XTMarkTarget
	xt.UnmarshalUnsafe(buf)
	return &markTarget{
		mark:            xt.Mark,
		mask:            xt.Mask,
		networkProtocol: filter.NetworkProtocol(),
	}, nil
}
