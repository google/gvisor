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
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
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
	return makeHookEntries(map[stack.Hook]int{stack.Prerouting: prerouting})
}

func makeUnderflows(prerouting int) [stack.NumHooks]int {
	return makeHookEntries(map[stack.Hook]int{stack.Prerouting: prerouting})
}

func makeHookEntries(entries map[stack.Hook]int) [stack.NumHooks]int {
	hookEntries := [stack.NumHooks]int{
		stack.Prerouting:  stack.HookUnset,
		stack.Input:       stack.HookUnset,
		stack.Forward:     stack.HookUnset,
		stack.Output:      stack.HookUnset,
		stack.Postrouting: stack.HookUnset,
	}
	for hook, ruleIdx := range entries {
		hookEntries[hook] = ruleIdx
	}
	return hookEntries
}

func marshalReplace(table stack.Table, tableName string, ipv6 bool) []byte {
	marshalRules := marshalEntries4
	if ipv6 {
		marshalRules = marshalEntries6
	}
	offsets := make([]uint32, len(table.Rules))
	var offset uint32
	for ruleIdx, rule := range table.Rules {
		offsets[ruleIdx] = offset
		offset += uint32(len(marshalRules([]stack.Rule{rule})))
	}
	for _, rule := range table.Rules {
		if jump, ok := rule.Target.(*JumpTarget); ok {
			jump.Offset = offsets[jump.RuleNum]
		}
	}
	var info linux.IPTGetinfo
	if ipv6 {
		_, info = getEntries6(table, linux.TableName{})
	} else {
		_, info = getEntries4(table, linux.TableName{})
	}
	replace := linux.IPTReplace{
		NumEntries: info.NumEntries,
		Size:       info.Size,
		HookEntry:  info.HookEntry,
		Underflow:  info.Underflow,
	}
	copy(replace.Name[:], tableName)
	return append(marshal.Marshal(&replace), marshalRules(table.Rules)...)
}

func marshalEntries4(rules []stack.Rule) []byte {
	entries, _ := getEntries4(stack.Table{Rules: rules}, linux.TableName{})
	var buf []byte
	for i := range entries.Entrytable {
		entry := make([]byte, entries.Entrytable[i].SizeBytes())
		entries.Entrytable[i].MarshalBytes(entry)
		buf = append(buf, entry...)
	}
	return buf
}

func marshalEntries6(rules []stack.Rule) []byte {
	entries, _ := getEntries6(stack.Table{Rules: rules}, linux.TableName{})
	var buf []byte
	for i := range entries.Entrytable {
		entry := make([]byte, entries.Entrytable[i].SizeBytes())
		entries.Entrytable[i].MarshalBytes(entry)
		buf = append(buf, entry...)
	}
	return buf
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
	if err := checkLoopsAndChains(table, false); err != syserr.ErrLinkLoop {
		t.Fatalf("checkLoopsAndChains expected %v for indirect jump loop, got %v", syserr.ErrLinkLoop, err)
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

func TestCheckLoopsAndChainsUnreachableLoop(t *testing.T) {
	table := stack.Table{
		Rules: []stack.Rule{
			makeRule(&acceptTarget{}),
			makeRule(&userChainTarget{}),
			makeRule(&JumpTarget{RuleNum: 5}),
			makeRule(&returnTarget{}),
			makeRule(&userChainTarget{}),
			makeRule(&JumpTarget{RuleNum: 2}),
			makeRule(&returnTarget{}),
		},
		BuiltinChains: makeBuiltinChains(0),
		Underflows:    makeUnderflows(0),
	}
	if err := checkLoopsAndChains(table, false); err != syserr.ErrInvalidArgument {
		t.Fatalf("checkLoopsAndChains expected %v for unreachable jump loop, got %v", syserr.ErrInvalidArgument, err)
	}
}

func TestCheckTargetHooks(t *testing.T) {
	for _, test := range []struct {
		name  string
		table stack.Table
		want  *syserr.Error
	}{
		{
			name: "redirect on postrouting",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&redirectTarget{}), // Rule 0: Postrouting
					makeRule(&acceptTarget{}),   // Rule 1: Postrouting underflow
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Postrouting: 0}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Postrouting: 1}),
			},
			want: syserr.ErrInvalidArgument,
		},
		{
			name: "redirect on output",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&redirectTarget{}), // Rule 0: Output
					makeRule(&acceptTarget{}),   // Rule 1: Output underflow
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Output: 0}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Output: 1}),
			},
		},
		{
			name: "snat on output",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&snatTarget{}),   // Rule 0: Output
					makeRule(&acceptTarget{}), // Rule 1: Output underflow
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Output: 0}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Output: 1}),
			},
			want: syserr.ErrInvalidArgument,
		},
		{
			name: "snat on postrouting",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&snatTarget{}),   // Rule 0: Postrouting
					makeRule(&acceptTarget{}), // Rule 1: Postrouting underflow
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Postrouting: 0}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Postrouting: 1}),
			},
		},
		{
			name: "snat on input",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&snatTarget{}),   // Rule 0: Input
					makeRule(&acceptTarget{}), // Rule 1: Input underflow
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Input: 0}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Input: 1}),
			},
		},
		{
			name: "redirect in user chain from postrouting",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&JumpTarget{RuleNum: 3}), // Rule 0: Postrouting -> jump to Rule 3
					makeRule(&acceptTarget{}),         // Rule 1: Postrouting underflow
					makeRule(&userChainTarget{}),      // Rule 2: user chain header
					makeRule(&redirectTarget{}),       // Rule 3: user chain rule
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Postrouting: 0}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Postrouting: 1}),
			},
			want: syserr.ErrInvalidArgument,
		},
		{
			name: "redirect in user chain from output",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&JumpTarget{RuleNum: 3}), // Rule 0: Output -> jump to Rule 3
					makeRule(&acceptTarget{}),         // Rule 1: Output underflow
					makeRule(&userChainTarget{}),      // Rule 2: user chain header
					makeRule(&redirectTarget{}),       // Rule 3: user chain rule
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Output: 0}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Output: 1}),
			},
		},
		{
			name: "dnat in user chain from prerouting and postrouting",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&JumpTarget{RuleNum: 5}), // Rule 0: Prerouting -> jump to Rule 5
					makeRule(&acceptTarget{}),         // Rule 1: Prerouting underflow
					makeRule(&JumpTarget{RuleNum: 5}), // Rule 2: Postrouting -> jump to Rule 5
					makeRule(&acceptTarget{}),         // Rule 3: Postrouting underflow
					makeRule(&userChainTarget{}),      // Rule 4: user chain header
					makeRule(&dnatTarget{}),           // Rule 5: user chain rule
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Prerouting: 0, stack.Postrouting: 2}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Prerouting: 1, stack.Postrouting: 3}),
			},
			want: syserr.ErrInvalidArgument,
		},
		{
			name: "dnat in user chain from prerouting and output",
			table: stack.Table{
				Rules: []stack.Rule{
					makeRule(&JumpTarget{RuleNum: 5}), // Rule 0: Prerouting -> jump to Rule 5
					makeRule(&acceptTarget{}),         // Rule 1: Prerouting underflow
					makeRule(&JumpTarget{RuleNum: 5}), // Rule 2: Output -> jump to Rule 5
					makeRule(&acceptTarget{}),         // Rule 3: Output underflow
					makeRule(&userChainTarget{}),      // Rule 4: user chain header
					makeRule(&dnatTarget{}),           // Rule 5: user chain rule
				},
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Prerouting: 0, stack.Output: 2}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Prerouting: 1, stack.Output: 3}),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := checkTargetHooks(test.table, false); err != test.want {
				t.Fatalf("checkTargetHooks expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestParseTargetTable(t *testing.T) {
	filter := emptyIPv4Filter
	filter.Protocol = header.TCPProtocolNumber
	for _, test := range []struct {
		name      string
		target    target
		tableName string
		want      *syserr.Error
	}{
		{
			name: "redirect in the filter table",
			target: &redirectTarget{RedirectTarget: stack.RedirectTarget{
				NetworkProtocol: header.IPv4ProtocolNumber,
				Port:            9999,
			}},
			tableName: filterTable,
			want:      syserr.ErrInvalidArgument,
		},
		{
			name: "redirect in the nat table",
			target: &redirectTarget{RedirectTarget: stack.RedirectTarget{
				NetworkProtocol: header.IPv4ProtocolNumber,
				Port:            9999,
			}},
			tableName: natTable,
		},
		{
			name: "dnat in the filter table",
			target: &dnatTarget{DNATTarget: stack.DNATTarget{
				NetworkProtocol: header.IPv4ProtocolNumber,
				Port:            9999,
				ChangePort:      true,
			}},
			tableName: filterTable,
			want:      syserr.ErrInvalidArgument,
		},
		{
			name:      "snat in the raw table",
			target:    &snatTarget{SNATTarget: stack.SNATTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			tableName: rawTable,
			want:      syserr.ErrInvalidArgument,
		},
		{
			name: "reject in the filter table",
			target: &rejectIPv4Target{RejectIPv4Target: stack.RejectIPv4Target{
				RejectWith: stack.RejectIPv4WithICMPPortUnreachable,
			}},
			tableName: filterTable,
		},
		{
			name:      "ct in the raw table",
			target:    &ctTarget{CTTarget: stack.CTTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			tableName: rawTable,
		},
		{
			name:      "accept in the filter table",
			target:    &acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
			tableName: filterTable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseTarget(filter, marshalTarget(test.target), false /* ipv6 */, test.tableName); err != test.want {
				t.Fatalf("parseTarget expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestModifyEntriesTableOrder(t *testing.T) {
	for _, test := range []struct {
		name      string
		rules     []stack.Rule
		tableName string
		ipv6      bool
	}{
		{
			name: "ct before an unsupported reject type in the filter table",
			rules: []stack.Rule{
				makeRule(&ctTarget{CTTarget: stack.CTTarget{NetworkProtocol: header.IPv4ProtocolNumber}}),
				makeRule(&rejectIPv4Target{RejectIPv4Target: stack.RejectIPv4Target{
					RejectWith: stack.RejectIPv4WithICMPHostUnreachable,
				}}),
			},
			tableName: filterTable,
		},
		{
			name: "unsupported ipv6 reject type in the nat table",
			rules: []stack.Rule{
				{
					Filter: emptyIPv6Filter,
					Target: &rejectIPv6Target{RejectIPv6Target: stack.RejectIPv6Target{
						RejectWith: stack.RejectIPv6WithICMPAdminProhibited,
					}},
				},
			},
			tableName: natTable,
			ipv6:      true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var replace linux.IPTReplace
			copy(replace.Name[:], test.tableName)
			replace.NumEntries = uint32(len(test.rules))
			stk := stack.New(stack.Options{})
			var table stack.Table
			var targets map[int][]byte
			var err *syserr.Error
			if test.ipv6 {
				_, targets, err = modifyEntries6(nil /* mapper */, marshalEntries6(test.rules), &replace, &table)
			} else {
				_, targets, err = modifyEntries4(nil /* mapper */, marshalEntries4(test.rules), &replace, &table)
			}
			if err == nil {
				err = parseTargets(stk, table.Rules, targets, test.ipv6, test.tableName)
			}
			if err != syserr.ErrInvalidArgument {
				t.Fatalf("parseTargets expected %v, got %v", syserr.ErrInvalidArgument, err)
			}
		})
	}
}

func TestModifyEntriesShortTarget(t *testing.T) {
	entry := linux.IPTEntry{
		TargetOffset: linux.SizeOfIPTEntry,
		NextOffset:   linux.SizeOfIPTEntry + 8,
	}
	replace := linux.IPTReplace{NumEntries: 1}
	var table stack.Table
	if _, _, err := modifyEntries4(nil /* mapper */, append(marshal.Marshal(&entry), make([]byte, 8)...), &replace, &table); err != syserr.ErrInvalidArgument {
		t.Fatalf("modifyEntries4 expected %v, got %v", syserr.ErrInvalidArgument, err)
	}
}

func TestParseTargetsRejectHandler(t *testing.T) {
	stk := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
	})
	for _, test := range []struct {
		name   string
		target target
		ipv6   bool
	}{
		{
			name: "ipv4 reject",
			target: &rejectIPv4Target{RejectIPv4Target: stack.RejectIPv4Target{
				RejectWith: stack.RejectIPv4WithICMPPortUnreachable,
			}},
		},
		{
			name: "ipv6 reject",
			target: &rejectIPv6Target{RejectIPv6Target: stack.RejectIPv6Target{
				RejectWith: stack.RejectIPv6WithICMPPortUnreachable,
			}},
			ipv6: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			filter := emptyIPv4Filter
			if test.ipv6 {
				filter = emptyIPv6Filter
			}
			rules := []stack.Rule{
				{Filter: filter, Target: &acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: filter.NetworkProtocol()}}},
				{Filter: filter},
			}
			if err := parseTargets(stk, rules, map[int][]byte{1: marshalTarget(test.target)}, test.ipv6, filterTable); err != nil {
				t.Fatalf("parseTargets failed: %v", err)
			}
			switch target := rules[1].Target.(type) {
			case *rejectIPv4Target:
				if target.Handler == nil {
					t.Fatalf("parseTargets left %T without a handler", target)
				}
			case *rejectIPv6Target:
				if target.Handler == nil {
					t.Fatalf("parseTargets left %T without a handler", target)
				}
			default:
				t.Fatalf("parseTargets returned %T", target)
			}
		})
	}
}

func TestSetEntriesParsesTargets(t *testing.T) {
	filter := emptyIPv4Filter
	filter.Protocol = header.TCPProtocolNumber
	accept := &acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	table := stack.Table{
		Rules: []stack.Rule{
			makeRule(accept),
			makeRule(accept),
			{
				Filter: filter,
				Target: &redirectTarget{RedirectTarget: stack.RedirectTarget{
					NetworkProtocol: header.IPv4ProtocolNumber,
					Port:            9999,
				}},
			},
			makeRule(accept),
			makeRule(accept),
		},
		BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Prerouting: 0, stack.Input: 1, stack.Output: 2, stack.Postrouting: 4}),
		Underflows:    makeHookEntries(map[stack.Hook]int{stack.Prerouting: 0, stack.Input: 1, stack.Output: 3, stack.Postrouting: 4}),
	}
	stk := stack.New(stack.Options{})
	if err := SetEntries(nil /* mapper */, stk, marshalReplace(table, natTable, false /* ipv6 */), false /* ipv6 */); err != nil {
		t.Fatalf("SetEntries failed: %v", err)
	}
	target := stk.IPTables().GetTable(stack.NATID, false /* ipv6 */).Rules[2].Target
	if _, ok := target.(*redirectTarget); !ok {
		t.Fatalf("SetEntries installed %T, want *redirectTarget", target)
	}
}

func TestSetEntriesTargetHooks(t *testing.T) {
	filter := emptyIPv4Filter
	filter.Protocol = header.TCPProtocolNumber
	accept := &acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	table := stack.Table{
		Rules: []stack.Rule{
			makeRule(accept),
			makeRule(accept),
			makeRule(accept),
			{
				Filter: filter,
				Target: &redirectTarget{RedirectTarget: stack.RedirectTarget{
					NetworkProtocol: header.IPv4ProtocolNumber,
					Port:            9999,
				}},
			},
			makeRule(accept),
		},
		BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Prerouting: 0, stack.Input: 1, stack.Output: 2, stack.Postrouting: 3}),
		Underflows:    makeHookEntries(map[stack.Hook]int{stack.Prerouting: 0, stack.Input: 1, stack.Output: 2, stack.Postrouting: 4}),
	}
	if err := SetEntries(nil /* mapper */, stack.New(stack.Options{}), marshalReplace(table, natTable, false /* ipv6 */), false /* ipv6 */); err != syserr.ErrInvalidArgument {
		t.Fatalf("SetEntries expected %v, got %v", syserr.ErrInvalidArgument, err)
	}
}

func TestSetEntriesLoopOrder(t *testing.T) {
	for _, test := range []struct {
		name   string
		target stack.Target
		ipv6   bool
	}{
		{
			name: "unsupported reject type",
			target: &rejectIPv4Target{RejectIPv4Target: stack.RejectIPv4Target{
				RejectWith: stack.RejectIPv4WithICMPHostUnreachable,
			}},
		},
		{
			name: "unsupported ipv6 reject type",
			target: &rejectIPv6Target{RejectIPv6Target: stack.RejectIPv6Target{
				RejectWith: stack.RejectIPv6WithICMPAdminProhibited,
			}},
			ipv6: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			filter := emptyIPv4Filter
			if test.ipv6 {
				filter = emptyIPv6Filter
			}
			netProto := filter.NetworkProtocol()
			var rules []stack.Rule
			for _, target := range []stack.Target{
				&acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: netProto}},
				&acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: netProto}},
				test.target,
				&JumpTarget{RuleNum: 6, NetworkProtocol: netProto},
				&acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: netProto}},
				&userChainTarget{UserChainTarget: stack.UserChainTarget{Name: "a", NetworkProtocol: netProto}},
				&JumpTarget{RuleNum: 9, NetworkProtocol: netProto},
				&returnTarget{ReturnTarget: stack.ReturnTarget{NetworkProtocol: netProto}},
				&userChainTarget{UserChainTarget: stack.UserChainTarget{Name: "b", NetworkProtocol: netProto}},
				&JumpTarget{RuleNum: 6, NetworkProtocol: netProto},
				&returnTarget{ReturnTarget: stack.ReturnTarget{NetworkProtocol: netProto}},
			} {
				rules = append(rules, stack.Rule{Filter: filter, Target: target})
			}
			rules[2].Filter.Protocol = header.TCPProtocolNumber
			rules[2].Filter.CheckProtocol = true
			table := stack.Table{
				Rules:         rules,
				BuiltinChains: makeHookEntries(map[stack.Hook]int{stack.Input: 0, stack.Forward: 1, stack.Output: 2}),
				Underflows:    makeHookEntries(map[stack.Hook]int{stack.Input: 0, stack.Forward: 1, stack.Output: 4}),
			}
			if err := SetEntries(nil /* mapper */, stack.New(stack.Options{}), marshalReplace(table, filterTable, test.ipv6), test.ipv6); err != syserr.ErrLinkLoop {
				t.Fatalf("SetEntries expected %v, got %v", syserr.ErrLinkLoop, err)
			}
		})
	}
}
