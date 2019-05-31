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
	tablenameNat    = "nat"
	tablenameMangle = "mangle"
)

// Chain names as defined by net/ipv4/netfilter/ip_tables.c.
const (
	chainNamePrerouting  = "PREROUTING"
	chainNameInput       = "INPUT"
	chainNameForward     = "FORWARD"
	chainNameOutput      = "OUTPUT"
	chainNamePostrouting = "POSTROUTING"
)

// DefaultTables returns a default set of tables. Each chain is set to accept
// all packets.
func DefaultTables() *IPTables {
	tables := IPTables{
		Tables: map[string]*Table{
			tablenameNat: &Table{
				BuiltinChains: map[Hook]*Chain{
					Prerouting:  unconditionalAcceptChain(chainNamePrerouting),
					Input:       unconditionalAcceptChain(chainNameInput),
					Output:      unconditionalAcceptChain(chainNameOutput),
					Postrouting: unconditionalAcceptChain(chainNamePostrouting),
				},
				DefaultTargets: map[Hook]Target{
					Prerouting:  UnconditionalAcceptTarget{},
					Input:       UnconditionalAcceptTarget{},
					Output:      UnconditionalAcceptTarget{},
					Postrouting: UnconditionalAcceptTarget{},
				},
				UserChains: map[string]*Chain{},
			},
			tablenameMangle: &Table{
				BuiltinChains: map[Hook]*Chain{
					Prerouting: unconditionalAcceptChain(chainNamePrerouting),
					Output:     unconditionalAcceptChain(chainNameOutput),
				},
				DefaultTargets: map[Hook]Target{
					Prerouting: UnconditionalAcceptTarget{},
					Output:     UnconditionalAcceptTarget{},
				},
				UserChains: map[string]*Chain{},
			},
		},
		Priorities: map[Hook][]string{
			Prerouting: []string{tablenameMangle, tablenameNat},
			Output:     []string{tablenameMangle, tablenameNat},
		},
	}

	// Initialize each table's Chains field.
	tables.Tables[tablenameNat].Chains = map[string]*Chain{
		chainNamePrerouting:  tables.Tables[tablenameNat].BuiltinChains[Prerouting],
		chainNameInput:       tables.Tables[tablenameNat].BuiltinChains[Input],
		chainNameOutput:      tables.Tables[tablenameNat].BuiltinChains[Output],
		chainNamePostrouting: tables.Tables[tablenameNat].BuiltinChains[Postrouting],
	}
	tables.Tables[tablenameMangle].Chains = map[string]*Chain{
		chainNamePrerouting:  tables.Tables[tablenameMangle].BuiltinChains[Prerouting],
		chainNameInput:       tables.Tables[tablenameMangle].BuiltinChains[Input],
		chainNameOutput:      tables.Tables[tablenameMangle].BuiltinChains[Output],
		chainNamePostrouting: tables.Tables[tablenameMangle].BuiltinChains[Postrouting],
	}

	return &tables
}

func unconditionalAcceptChain(name string) *Chain {
	return &Chain{
		Name: name,
		Rules: []*Rule{
			&Rule{
				Target: UnconditionalAcceptTarget{},
			},
		},
	}
}
