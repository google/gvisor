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
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestMarkTargetSetXmarkAndContinue(t *testing.T) {
	mt := &markTarget{mark: 0x10, mask: 0xffffffff, networkProtocol: header.IPv4ProtocolNumber}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pkt.DecRef()

	v, jump := mt.Action(pkt, stack.Prerouting, nil, nil)
	if v != stack.RuleContinue {
		t.Errorf("Action() verdict = %v, want RuleContinue (Linux -j MARK is XT_CONTINUE)", v)
	}
	if jump != 0 {
		t.Errorf("Action() jump = %d, want 0", jump)
	}
	if pkt.Mark != 0x10 {
		t.Errorf("pkt.Mark = %#x, want 0x10", pkt.Mark)
	}

	mt.mark = 0x4000
	mt.mask = 0x4000
	v, _ = mt.Action(pkt, stack.Prerouting, nil, nil)
	if v != stack.RuleContinue {
		t.Errorf("or-mark Action() verdict = %v, want RuleContinue", v)
	}
	if pkt.Mark != 0x4010 {
		t.Errorf("pkt.Mark after --or-mark 0x4000 = %#x, want 0x4010", pkt.Mark)
	}
}

func TestMarkTargetUnmarshalRev2(t *testing.T) {
	orig := &markTarget{mark: 0x42, mask: 0xffffffff, networkProtocol: header.IPv4ProtocolNumber}
	maker := &markTargetMaker{NetworkProtocol: header.IPv4ProtocolNumber}
	buf := maker.marshal(orig)
	got, err := maker.unmarshal(buf, emptyIPv4Filter)
	if err != nil {
		t.Fatalf("unmarshal() = %v", err)
	}
	mt := got.(*markTarget)
	if mt.mark != orig.mark || mt.mask != orig.mask {
		t.Errorf("unmarshaled mark/mask = %#x/%#x, want %#x/%#x", mt.mark, mt.mask, orig.mark, orig.mask)
	}
}
