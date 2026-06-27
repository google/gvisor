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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestMarkMatcher(t *testing.T) {
	matcher := MarkMatcher{
		mark:   0x1234,
		mask:   0xffffffff,
		invert: false,
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pkt.DecRef()

	pkt.Mark = 0x1234
	if matches, _ := matcher.Match(0, pkt, "", ""); !matches {
		t.Errorf("Match() = false, want true for matching mark")
	}

	pkt.Mark = 0x5678
	if matches, _ := matcher.Match(0, pkt, "", ""); matches {
		t.Errorf("Match() = true, want false for non-matching mark")
	}

	matcher.invert = true
	pkt.Mark = 0x1234
	if matches, _ := matcher.Match(0, pkt, "", ""); matches {
		t.Errorf("Match() = true, want false for inverted matching mark")
	}

	pkt.Mark = 0x5678
	if matches, _ := matcher.Match(0, pkt, "", ""); !matches {
		t.Errorf("Match() = false, want true for inverted non-matching mark")
	}
}

func TestMarkMarshalerUnmarshal(t *testing.T) {
	info := linux.XTMarkMtinfo1{
		Mark:   0x11223344,
		Mask:   0xf0f0f0f0,
		Invert: 1,
	}
	buf := marshal.Marshal(&info)

	marshaler := markMarshaler{}
	m, err := marshaler.unmarshal(nil, buf, stack.IPHeaderFilter{})
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	mm, ok := m.(*MarkMatcher)
	if !ok {
		t.Fatalf("unmarshaled matcher is %T, want *MarkMatcher", m)
	}
	if mm.mark != info.Mark || mm.mask != info.Mask || !mm.invert {
		t.Errorf("unmarshaled %+v, want mark=%x mask=%x invert=true", mm, info.Mark, info.Mask)
	}
}
