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

package iptables

import (
	"gvisor.dev/gvisor/pkg/tcpip"
)

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

// A RuleVerdict is what a rule decides should be done with a packet.
type RuleVerdict int

const (
	// RuleAccept indicates the packet should continue through netstack.
	RuleAccept RuleVerdict = iota

	// RuleDrop indicates the packet should be dropped.
	RuleDrop

	// RuleJump indicates the packet should jump to another chain.
	RuleJump

	// RuleReturn indicates the packet should return to the previous chain.
	RuleReturn
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
	for hook := range table.BuiltinChains {
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
	// Filter holds basic IP filtering fields common to every rule.
	Filter IPHeaderFilter

	// Matchers is the list of matchers for this rule.
	Matchers []Matcher

	// Target is the action to invoke if all the matchers match the packet.
	Target Target
}

// IPHeaderFilter holds basic IP filtering data common to every rule.
type IPHeaderFilter struct {
	// Protocol matches the transport protocol.
	Protocol tcpip.TransportProtocolNumber

	// Dst matches the destination IP address.
	Dst tcpip.Address

	// DstMask masks bits of the destination IP address when comparing with
	// Dst.
	DstMask tcpip.Address

	// DstInvert inverts the meaning of the destination IP check, i.e. when
	// true the filter will match packets that fail the destination
	// comparison.
	DstInvert bool
}

// A Matcher is the interface for matching packets.
type Matcher interface {
	// Name returns the name of the Matcher.
	Name() string

	// Match returns whether the packet matches and whether the packet
	// should be "hotdropped", i.e. dropped immediately. This is usually
	// used for suspicious packets.
	//
	// Precondition: packet.NetworkHeader is set.
	Match(hook Hook, packet tcpip.PacketBuffer, interfaceName string) (matches bool, hotdrop bool)
}

// A Target is the interface for taking an action for a packet.
type Target interface {
	// Action takes an action on the packet and returns a verdict on how
	// traversal should (or should not) continue. If the return value is
	// Jump, it also returns the index of the rule to jump to.
	Action(packet tcpip.PacketBuffer) (RuleVerdict, int)
}
