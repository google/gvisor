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
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
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
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
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
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
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

// EmptyNatTable returns a Table with no rules and the filter table chains
// mapped to HookUnset.
func EmptyNatTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: map[Hook]int{
			Prerouting:  HookUnset,
			Input:       HookUnset,
			Output:      HookUnset,
			Postrouting: HookUnset,
		},
		Underflows: map[Hook]int{
			Prerouting:  HookUnset,
			Input:       HookUnset,
			Output:      HookUnset,
			Postrouting: HookUnset,
		},
		UserChains: map[string]int{},
	}
}

// A chainVerdict is what a table decides should be done with a packet.
type chainVerdict int

const (
	// chainAccept indicates the packet should continue through netstack.
	chainAccept chainVerdict = iota

	// chainAccept indicates the packet should be dropped.
	chainDrop

	// chainReturn indicates the packet should return to the calling chain
	// or the underflow rule of a builtin chain.
	chainReturn
)

// Check runs pkt through the rules for hook. It returns true when the packet
// should continue traversing the network stack and false when it should be
// dropped.
//
// Precondition: pkt.NetworkHeader is set.
func (it *IPTables) Check(hook Hook, pkt tcpip.PacketBuffer) bool {
	// Go through each table containing the hook.
	for _, tablename := range it.Priorities[hook] {
		table := it.Tables[tablename]
		ruleIdx := table.BuiltinChains[hook]
		switch verdict := it.checkChain(hook, pkt, table, ruleIdx); verdict {
		// If the table returns Accept, move on to the next table.
		case chainAccept:
			continue
		// The Drop verdict is final.
		case chainDrop:
			return false
		case chainReturn:
			// Any Return from a built-in chain means we have to
			// call the underflow.
			underflow := table.Rules[table.Underflows[hook]]
			switch v, _ := underflow.Target.Action(pkt); v {
			case RuleAccept:
				continue
			case RuleDrop:
				return false
			case RuleJump, RuleReturn:
				panic("Underflows should only return RuleAccept or RuleDrop.")
			default:
				panic(fmt.Sprintf("Unknown verdict: %d", v))
			}

		default:
			panic(fmt.Sprintf("Unknown verdict %v.", verdict))
		}
	}

	// Every table returned Accept.
	return true
}

// Precondition: pkt.NetworkHeader is set.
func (it *IPTables) checkChain(hook Hook, pkt tcpip.PacketBuffer, table Table, ruleIdx int) chainVerdict {
	// Start from ruleIdx and walk the list of rules until a rule gives us
	// a verdict.
	for ruleIdx < len(table.Rules) {
		switch verdict, jumpTo := it.checkRule(hook, pkt, table, ruleIdx); verdict {
		case RuleAccept:
			return chainAccept

		case RuleDrop:
			return chainDrop

		case RuleReturn:
			return chainReturn

		case RuleJump:
			// "Jumping" to the next rule just means we're
			// continuing on down the list.
			if jumpTo == ruleIdx+1 {
				ruleIdx++
				continue
			}
			switch verdict := it.checkChain(hook, pkt, table, jumpTo); verdict {
			case chainAccept:
				return chainAccept
			case chainDrop:
				return chainDrop
			case chainReturn:
				ruleIdx++
				continue
			default:
				panic(fmt.Sprintf("Unknown verdict: %d", verdict))
			}

		default:
			panic(fmt.Sprintf("Unknown verdict: %d", verdict))
		}

	}

	// We got through the entire table without a decision. Default to DROP
	// for safety.
	return chainDrop
}

// Precondition: pk.NetworkHeader is set.
func (it *IPTables) checkRule(hook Hook, pkt tcpip.PacketBuffer, table Table, ruleIdx int) (RuleVerdict, int) {
	rule := table.Rules[ruleIdx]

	// If pkt.NetworkHeader hasn't been set yet, it will be contained in
	// pkt.Data.First().
	if pkt.NetworkHeader == nil {
		pkt.NetworkHeader = pkt.Data.First()
	}

	// Check whether the packet matches the IP header filter.
	if !filterMatch(rule.Filter, header.IPv4(pkt.NetworkHeader)) {
		// Continue on to the next rule.
		return RuleJump, ruleIdx + 1
	}

	// Go through each rule matcher. If they all match, run
	// the rule target.
	for _, matcher := range rule.Matchers {
		matches, hotdrop := matcher.Match(hook, pkt, "")
		if hotdrop {
			return RuleDrop, 0
		}
		if !matches {
			// Continue on to the next rule.
			return RuleJump, ruleIdx + 1
		}
	}

	// All the matchers matched, so run the target.
	return rule.Target.Action(pkt)
}

func filterMatch(filter IPHeaderFilter, hdr header.IPv4) bool {
	// TODO(gvisor.dev/issue/170): Support other fields of the filter.
	// Check the transport protocol.
	if filter.Protocol != 0 && filter.Protocol != hdr.TransportProtocol() {
		return false
	}

	// Check the destination IP.
	dest := hdr.DestinationAddress()
	matches := true
	for i := range filter.Dst {
		if dest[i]&filter.DstMask[i] != filter.Dst[i] {
			matches = false
			break
		}
	}
	if matches == filter.DstInvert {
		return false
	}

	return true
}
