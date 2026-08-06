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

	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func makeRule(target stack.Target, matchers ...stack.Matcher) stack.Rule {
	return stack.Rule{
		Filter:   emptyIPv4Filter,
		Target:   target,
		Matchers: matchers,
	}
}

func makeBuiltinChains(prerouting int) [stack.NumHooks]int {
	return [stack.NumHooks]int{
		stack.Prerouting:  prerouting,
		stack.Input:       stack.HookUnset,
		stack.Forward:     stack.HookUnset,
		stack.Output:      stack.HookUnset,
		stack.Postrouting: stack.HookUnset,
	}
}

func makeUnderflows(prerouting int) [stack.NumHooks]int {
	return [stack.NumHooks]int{
		stack.Prerouting:  prerouting,
		stack.Input:       stack.HookUnset,
		stack.Forward:     stack.HookUnset,
		stack.Output:      stack.HookUnset,
		stack.Postrouting: stack.HookUnset,
	}
}

func TestCheckLoopsAndChainsDirectLoop(t *testing.T) {
	// Rule 0 (builtin hook Prerouting) jumps to itself (Rule 0). This mirrors
	// the syzkaller reproducer where a rule's target offset jumps to itself.
	table := stack.Table{
		Rules: []stack.Rule{
			makeRule(&JumpTarget{RuleNum: 0}),
		},
		BuiltinChains: makeBuiltinChains(0),
		Underflows:    makeUnderflows(0),
	}
	if err := checkLoopsAndChains(table, false); err != syserr.ErrInvalidArgument {
		t.Fatalf("checkLoopsAndChains expected %v for direct jump loop, got %v", syserr.ErrInvalidArgument, err)
	}
}

func TestCheckLoopsAndChainsIndirectLoop(t *testing.T) {
	// Builtin chain Prerouting (Rule 0) jumps to user chain A (Rule 3).
	// User chain A (Rule 3) jumps to user chain B (Rule 6).
	// User chain B (Rule 6) jumps back to user chain A (Rule 3), forming a cycle.
	table := stack.Table{
		Rules: []stack.Rule{
			makeRule(&JumpTarget{RuleNum: 3}), // Rule 0: Prerouting -> jump to Rule 3
			makeRule(&acceptTarget{}),         // Rule 1: Prerouting underflow
			makeRule(&userChainTarget{}),      // Rule 2: user chain A header
			makeRule(&JumpTarget{RuleNum: 6}), // Rule 3: user chain A rule -> jump to Rule 6
			makeRule(&returnTarget{}),         // Rule 4: user chain A return
			makeRule(&userChainTarget{}),      // Rule 5: user chain B header
			makeRule(&JumpTarget{RuleNum: 3}), // Rule 6: user chain B rule -> jump back to Rule 3 (cycle!)
			makeRule(&returnTarget{}),         // Rule 7: user chain B return
		},
		BuiltinChains: makeBuiltinChains(0),
		Underflows:    makeUnderflows(1),
	}
	if err := checkLoopsAndChains(table, false); err != syserr.ErrInvalidArgument {
		t.Fatalf("checkLoopsAndChains expected %v for indirect jump loop, got %v", syserr.ErrInvalidArgument, err)
	}
}

func TestCheckLoopsAndChainsJumpToNonUserChain(t *testing.T) {
	// Builtin chain Prerouting (Rule 0) jumps to Rule 2, which is not
	// preceded by a userChainTarget.
	table := stack.Table{
		Rules: []stack.Rule{
			makeRule(&JumpTarget{RuleNum: 2}), // Rule 0: Prerouting -> jump to Rule 2
			makeRule(&acceptTarget{}),         // Rule 1: Prerouting underflow
			makeRule(&acceptTarget{}),         // Rule 2: not a user chain
		},
		BuiltinChains: makeBuiltinChains(0),
		Underflows:    makeUnderflows(1),
	}
	if err := checkLoopsAndChains(table, false); err != syserr.ErrInvalidArgument {
		t.Fatalf("checkLoopsAndChains expected %v for jump to non-user chain, got %v", syserr.ErrInvalidArgument, err)
	}
}

func TestCheckLoopsAndChainsNoUnconditionalFinalRule(t *testing.T) {
	// User chain A (Rule 3) ends without an unconditional final rule before
	// falling off the end of table.Rules.
	table := stack.Table{
		Rules: []stack.Rule{
			makeRule(&JumpTarget{RuleNum: 3}),         // Rule 0: Prerouting -> jump to Rule 3
			makeRule(&acceptTarget{}),                 // Rule 1: Prerouting underflow
			makeRule(&userChainTarget{}),              // Rule 2: user chain A header
			makeRule(&returnTarget{}, &MarkMatcher{}), // Rule 3: conditional return
		},
		BuiltinChains: makeBuiltinChains(0),
		Underflows:    makeUnderflows(1),
	}
	if err := checkLoopsAndChains(table, false); err != syserr.ErrInvalidArgument {
		t.Fatalf("checkLoopsAndChains expected %v for unterminated user chain, got %v", syserr.ErrInvalidArgument, err)
	}
}

func TestCheckLoopsAndChainsValid(t *testing.T) {
	// Valid ruleset: Prerouting (Rule 0) jumps to user chain A (Rule 3).
	// User chain A (Rule 3) returns unconditionally.
	table := stack.Table{
		Rules: []stack.Rule{
			makeRule(&JumpTarget{RuleNum: 3}), // Rule 0: Prerouting -> jump to Rule 3
			makeRule(&acceptTarget{}),         // Rule 1: Prerouting underflow
			makeRule(&userChainTarget{}),      // Rule 2: user chain A header
			makeRule(&returnTarget{}),         // Rule 3: unconditional RETURN
		},
		BuiltinChains: makeBuiltinChains(0),
		Underflows:    makeUnderflows(1),
	}
	if err := checkLoopsAndChains(table, false); err != nil {
		t.Fatalf("checkLoopsAndChains expected nil for valid table, got %v", err)
	}
}
