// Copyright 2019 The gVisor authors.
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

const (
	TablenameNat    = "nat"
	TablenameMangle = "mangle"
	TablenameFilter = "filter"
)

// TODO: Make this an iota? Faster! Do it.
// Chain names as defined by net/ipv4/netfilter/ip_tables.c.
const (
	ChainNamePrerouting  = "PREROUTING"
	ChainNameInput       = "INPUT"
	ChainNameForward     = "FORWARD"
	ChainNameOutput      = "OUTPUT"
	ChainNamePostrouting = "POSTROUTING"
)

const HookUnset = -1

// DefaultTables returns a default set of tables. Each chain is set to accept
// all packets.
func DefaultTables() IPTables {
	return IPTables{
		Tables: map[string]Table{
			TablenameNat: Table{
				Rules: []Rule{
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: UnconditionalAcceptTarget{}},
					Rule{Target: PanicTarget{}},
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
					Rule{Target: PanicTarget{}},
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
					Rule{Target: PanicTarget{}},
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
