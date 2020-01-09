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

package iptables

import "gvisor.dev/gvisor/pkg/tcpip"

// A Hook specifies one of the hooks built into the network stack.
//
//                      Userspace app          Userspace app
//                            ^                      |
//                            |                      v
//                         [Input]               [Output]
//                            ^                      |
//                            |                      v
//                            |                   routing
//                            |                      |
//                            |                      v
// ----->[Prerouting]----->routing----->[Forward]---------[Postrouting]----->
type Hook uint

// These values correspond to values in include/uapi/linux/netfilter.h.
const (
	// Prerouting happens before a packet is routed to applications or to
	// be forwarded.
	Prerouting Hook = iota

	// Input happens before a packet reaches an application.
	Input

	// Forward happens once it's decided that a packet should be forwarded
	// to another host.
	Forward

	// Output happens after a packet is written by an application to be
	// sent out.
	Output

	// Postrouting happens just before a packet goes out on the wire.
	Postrouting

	// The total number of hooks.
	NumHooks
)

// A Verdict is returned by a rule's target to indicate how traversal of rules
// should (or should not) continue.
type Verdict int

const (
	// Invalid indicates an unkonwn or erroneous verdict.
	Invalid Verdict = iota

	// Accept indicates the packet should continue traversing netstack as
	// normal.
	Accept

	// Drop inicates the packet should be dropped, stopping traversing
	// netstack.
	Drop

	// Stolen indicates the packet was co-opted by the target and should
	// stop traversing netstack.
	Stolen

	// Queue indicates the packet should be queued for userspace processing.
	Queue

	// Repeat indicates the packet should re-traverse the chains for the
	// current hook.
	Repeat

	// None indicates no verdict was reached.
	None

	// Jump indicates a jump to another chain.
	Jump

	// Continue indicates that traversal should continue at the next rule.
	Continue

	// Return indicates that traversal should return to the calling chain.
	Return
)

// IPTables holds all the tables for a netstack.
type IPTables struct {
	// Tables maps table names to tables. User tables have arbitrary names.
	Tables map[string]Table

	// Priorities maps each hook to a list of table names. The order of the
	// list is the order in which each table should be visited for that
	// hook.
	Priorities map[Hook][]string
}

// A Table defines a set of chains and hooks into the network stack. It is
// really just a list of rules with some metadata for entrypoints and such.
type Table struct {
	// Rules holds the rules that make up the table.
	Rules []Rule

	// BuiltinChains maps builtin chains to their entrypoint rule in Rules.
	BuiltinChains map[Hook]int

	// Underflows maps builtin chains to their underflow rule in Rules
	// (i.e. the rule to execute if the chain returns without a verdict).
	Underflows map[Hook]int

	// UserChains holds user-defined chains for the keyed by name. Users
	// can give their chains arbitrary names.
	UserChains map[string]int

	// Metadata holds information about the Table that is useful to users
	// of IPTables, but not to the netstack IPTables code itself.
	metadata interface{}
}

// ValidHooks returns a bitmap of the builtin hooks for the given table.
func (table *Table) ValidHooks() uint32 {
	hooks := uint32(0)
	for hook, _ := range table.BuiltinChains {
		hooks |= 1 << hook
	}
	return hooks
}

// Metadata returns the metadata object stored in table.
func (table *Table) Metadata() interface{} {
	return table.metadata
}

// SetMetadata sets the metadata object stored in table.
func (table *Table) SetMetadata(metadata interface{}) {
	table.metadata = metadata
}

// A Rule is a packet processing rule. It consists of two pieces. First it
// contains zero or more matchers, each of which is a specification of which
// packets this rule applies to. If there are no matchers in the rule, it
// applies to any packet.
type Rule struct {
	// IPHeaderFilters holds basic IP filtering fields common to every rule.
	IPHeaderFilter IPHeaderFilter

	// Matchers is the list of matchers for this rule.
	Matchers []Matcher

	// Target is the action to invoke if all the matchers match the packet.
	Target Target
}

// TODO: This is gross.
// TODO: Save this in SetEntries.
// TODO: Utilize this when traversing tables.
type IPHeaderFilter struct {
	Source              [4]byte
	Destination         [4]byte
	SourceMask          [4]byte
	DestinationMask     [4]byte
	OutputInterface     string
	InputInterface      string
	OutputInterfaceMask string
	InputInterfaceMask  string
	Protocol            uint16
	Flags               uint8
	InverseFlags        uint8
}

// A Matcher is the interface for matching packets.
type Matcher interface {
	// Match returns whether the packet matches and whether the packet
	// should be "hotdropped", i.e. dropped immediately. This is usually
	// used for suspicious packets.
	Match(hook Hook, packet tcpip.PacketBuffer, interfaceName string) (matches bool, hotdrop bool)
}

// A Target is the interface for taking an action for a packet.
type Target interface {
	// Action takes an action on the packet and returns a verdict on how
	// traversal should (or should not) continue. If the return value is
	// Jump, it also returns the name of the chain to jump to.
	Action(packet tcpip.PacketBuffer) (Verdict, string)
}
