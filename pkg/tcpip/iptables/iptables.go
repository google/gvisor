// Copyright 2019 The gVisor Authors.
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

// Package iptables supports packet filtering and manipulation via the iptables
// tool.
package iptables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Table names.
const (
	TablenameNat    = "nat"
	TablenameMangle = "mangle"
	TablenameFilter = "filter"
)

// Chain names as defined by net/ipv4/netfilter/ip_tables.c.
const (
	ChainNamePrerouting  = "PREROUTING"
	ChainNameInput       = "INPUT"
	ChainNameForward     = "FORWARD"
	ChainNameOutput      = "OUTPUT"
	ChainNamePostrouting = "POSTROUTING"
)

// HookUnset indicates that there is no hook set for an entrypoint or
// underflow.
const HookUnset = -1

// DefaultTables returns a default set of tables. Each chain is set to accept
// all packets.
func DefaultTables() IPTables {
	// TODO(gvisor.dev/issue/170): We may be able to swap out some strings for
	// iotas.
	return IPTables{
		Tables: map[string]Table{
			TablenameNat: Table{
				Rules: []Rule{
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: ErrorTarget{}},
				},
				BuiltinChains: map[Hook]int{
					Prerouting:  0,
					Input:       1,
					Output:      2,
					Postrouting: 3,
				},
				Underflows: map[Hook]int{
					Prerouting:  0,
					Input:       1,
					Output:      2,
					Postrouting: 3,
				},
				UserChains: map[string]int{},
			},
			TablenameMangle: Table{
				Rules: []Rule{
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: ErrorTarget{}},
				},
				BuiltinChains: map[Hook]int{
					Prerouting: 0,
					Output:     1,
				},
				Underflows: map[Hook]int{
					Prerouting: 0,
					Output:     1,
				},
				UserChains: map[string]int{},
			},
			TablenameFilter: Table{
				Rules: []Rule{
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: ErrorTarget{}},
				},
				BuiltinChains: map[Hook]int{
					Input:   0,
					Forward: 1,
					Output:  2,
				},
				Underflows: map[Hook]int{
					Input:   0,
					Forward: 1,
					Output:  2,
				},
				UserChains: map[string]int{},
			},
		},
		Priorities: map[Hook][]string{
			Input:      []string{TablenameNat, TablenameFilter},
			Prerouting: []string{TablenameMangle, TablenameNat},
			Output:     []string{TablenameMangle, TablenameNat, TablenameFilter},
		},
	}
}

// EmptyFilterTable returns a Table with no rules and the filter table chains
// mapped to HookUnset.
func EmptyFilterTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: map[Hook]int{
			Input:   HookUnset,
			Forward: HookUnset,
			Output:  HookUnset,
		},
		Underflows: map[Hook]int{
			Input:   HookUnset,
			Forward: HookUnset,
			Output:  HookUnset,
		},
		UserChains: map[string]int{},
	}
}

// Check runs pkt through the rules for hook. It returns true when the packet
// should continue traversing the network stack and false when it should be
// dropped.
//
// Precondition: pkt.NetworkHeader is set.
func (it *IPTables) Check(hook Hook, pkt tcpip.PacketBuffer) bool {
	// TODO(gvisor.dev/issue/170): A lot of this is uncomplicated because
	// we're missing features. Jumps, the call stack, etc. aren't checked
	// for yet because we're yet to support them.

	// Go through each table containing the hook.
	for _, tablename := range it.Priorities[hook] {
		switch verdict := it.checkTable(hook, pkt, tablename); verdict {
		// If the table returns Accept, move on to the next table.
		case Accept:
			continue
		// The Drop verdict is final.
		case Drop:
			return false
		case Stolen, Queue, Repeat, None, Jump, Return, Continue:
			panic(fmt.Sprintf("Unimplemented verdict %v.", verdict))
		default:
			panic(fmt.Sprintf("Unknown verdict %v.", verdict))
		}
	}

	// Every table returned Accept.
	return true
}

// Precondition: pkt.NetworkHeader is set.
func (it *IPTables) checkTable(hook Hook, pkt tcpip.PacketBuffer, tablename string) Verdict {
	// Start from ruleIdx and walk the list of rules until a rule gives us
	// a verdict.
	table := it.Tables[tablename]
	for ruleIdx := table.BuiltinChains[hook]; ruleIdx < len(table.Rules); ruleIdx++ {
		switch verdict := it.checkRule(hook, pkt, table, ruleIdx); verdict {
		// In either of these cases, this table is done with the packet.
		case Accept, Drop:
			return verdict
		// Continue traversing the rules of the table.
		case Continue:
			continue
		case Stolen, Queue, Repeat, None, Jump, Return:
			panic(fmt.Sprintf("Unimplemented verdict %v.", verdict))
		default:
			panic(fmt.Sprintf("Unknown verdict %v.", verdict))
		}
	}

	panic(fmt.Sprintf("Traversed past the entire list of iptables rules in table %q.", tablename))
}

// Precondition: pk.NetworkHeader is set.
func (it *IPTables) checkRule(hook Hook, pkt tcpip.PacketBuffer, table Table, ruleIdx int) Verdict {
	rule := table.Rules[ruleIdx]

	// First check whether the packet matches the IP header filter.
	// TODO(gvisor.dev/issue/170): Support other fields of the filter.
	if rule.Filter.Protocol != 0 && rule.Filter.Protocol != header.IPv4(pkt.NetworkHeader).TransportProtocol() {
		return Continue
	}

	// Go through each rule matcher. If they all match, run
	// the rule target.
	for _, matcher := range rule.Matchers {
		matches, hotdrop := matcher.Match(hook, pkt, "")
		if hotdrop {
			return Drop
		}
		if !matches {
			return Continue
		}
	}

	// All the matchers matched, so run the target.
	verdict, _ := rule.Target.Action(pkt)
	return verdict
}
