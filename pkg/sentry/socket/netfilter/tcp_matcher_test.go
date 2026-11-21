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

func TestTCPMatcherFragmentOffset(t *testing.T) {
	m := &TCPMatcher{sourcePortEnd: 0xffff, destinationPortEnd: 0xffff}
	s := stack.New(stack.Options{})
	defer s.Destroy()
	unset := stack.HookUnset
	s.IPTables().ForceReplaceTable(stack.FilterID, stack.Table{
		Rules: []stack.Rule{
			{Filter: emptyIPv4Filter, Matchers: []stack.Matcher{m}, Target: &stack.AcceptTarget{}},
			{Filter: emptyIPv4Filter, Target: &stack.AcceptTarget{}},
		},
		BuiltinChains: [stack.NumHooks]int{unset, 0, 1, 1, unset},
		Underflows:    [stack.NumHooks]int{unset, 1, 1, 1, unset},
	}, false /* ipv6 */)

	for _, tc := range []struct {
		offset           uint16
		matches, hotdrop bool
	}{{0, true, false}, {8, false, true}, {16, false, false}} {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv4MinimumSize + header.TCPMinimumSize})
		pkt.TransportHeader().Push(header.TCPMinimumSize)
		header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize)).Encode(&header.IPv4Fields{
			Protocol:       uint8(header.TCPProtocolNumber),
			FragmentOffset: tc.offset,
		})
		pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
		if matches, hotdrop := m.Match(stack.Input, pkt, "", ""); matches != tc.matches || hotdrop != tc.hotdrop {
			t.Errorf("offset %d: Match() = (%t, %t), want (%t, %t)", tc.offset, matches, hotdrop, tc.matches, tc.hotdrop)
		}
		if got := s.IPTables().CheckInput(pkt, ""); got == tc.hotdrop {
			t.Errorf("offset %d: CheckInput() = %t, want %t", tc.offset, got, !tc.hotdrop)
		}
		pkt.DecRef()
	}
}
