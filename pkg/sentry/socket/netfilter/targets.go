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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

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
