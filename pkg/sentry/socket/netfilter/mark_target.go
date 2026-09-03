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
// netfilter mark. kube-proxy uses it (revision 2, set-xmark semantics) for its
// masquerade/drop marks, e.g. `-j MARK --or-mark 0x4000`.
const MarkTargetName = "MARK"

// markTargetRevision is the xt_mark_tginfo2 revision. iptables negotiates the
// highest supported revision; 2 is what modern iptables/kube-proxy use.
const markTargetRevision = 2

// markTargetV2Size is sizeof(xt_entry_target) + sizeof(xt_mark_tginfo2{u32,u32}).
const markTargetV2Size = linux.SizeOfXTEntryTarget + 8

// xtMarkTargetV2 corresponds to xt_entry_target + struct xt_mark_tginfo2
// {__u32 mark, mask}. set-xmark semantics: mark = (mark &^ mask) ^ value.
//
// +marshal
type xtMarkTargetV2 struct {
	Target linux.XTEntryTarget
	Mark   uint32
	Mask   uint32
}

func init() {
	registerTargetMaker(&markTargetMaker{NetworkProtocol: header.IPv4ProtocolNumber})
	registerTargetMaker(&markTargetMaker{NetworkProtocol: header.IPv6ProtocolNumber})
}

// markTarget sets pkt.Mark. It is non-terminating: after setting the mark,
// traversal continues to the next rule (RuleContinue), matching Linux's -j MARK.
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
	xt := xtMarkTargetV2{
		Target: linux.XTEntryTarget{
			TargetSize: uint16(markTargetV2Size),
			Revision:   markTargetRevision,
		},
		Mark: mt.mark,
		Mask: mt.mask,
	}
	copy(xt.Target.Name[:], MarkTargetName)
	return marshal.Marshal(&xt)
}

func (mm *markTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if len(buf) < markTargetV2Size {
		nflog("markTargetMaker: buf has insufficient size for MARK target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}
	var xt xtMarkTargetV2
	xt.UnmarshalUnsafe(buf)
	return &markTarget{
		mark:            xt.Mark,
		mask:            xt.Mask,
		networkProtocol: filter.NetworkProtocol(),
	}, nil
}
