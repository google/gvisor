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

package stack

import (
	"fmt"
	"time"

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

// reaperDelay is how long to wait before starting to reap connections.
const reaperDelay = 5 * time.Second

// DefaultTables returns a default set of tables. Each chain is set to accept
// all packets.
func DefaultTables() *IPTables {
	// TODO(gvisor.dev/issue/170): We may be able to swap out some strings for
	// iotas.
	return &IPTables{
		tables: map[string]Table{
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
		priorities: map[Hook][]string{
			Input:      []string{TablenameNat, TablenameFilter},
			Prerouting: []string{TablenameMangle, TablenameNat},
			Output:     []string{TablenameMangle, TablenameNat, TablenameFilter},
		},
		connections: ConnTrack{
			seed: generateRandUint32(),
		},
		reaperDone: make(chan struct{}, 1),
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

// GetTable returns table by name.
func (it *IPTables) GetTable(name string) (Table, bool) {
	it.mu.RLock()
	defer it.mu.RUnlock()
	t, ok := it.tables[name]
	return t, ok
}

// ReplaceTable replaces or inserts table by name.
func (it *IPTables) ReplaceTable(name string, table Table) {
	it.mu.Lock()
	defer it.mu.Unlock()
	// If iptables is being enabled, initialize the conntrack table and
	// reaper.
	if !it.modified {
		it.connections.buckets = make([]bucket, numBuckets)
		it.startReaper(reaperDelay)
	}
	it.modified = true
	it.tables[name] = table
}

// GetPriorities returns slice of priorities associated with hook.
func (it *IPTables) GetPriorities(hook Hook) []string {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.priorities[hook]
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
func (it *IPTables) Check(hook Hook, pkt *PacketBuffer, gso *GSO, r *Route, address tcpip.Address, nicName string) bool {
	// Many users never configure iptables. Spare them the cost of rule
	// traversal if rules have never been set.
	it.mu.RLock()
	if !it.modified {
		it.mu.RUnlock()
		return true
	}
	it.mu.RUnlock()

	// Packets are manipulated only if connection and matching
	// NAT rule exists.
	it.connections.handlePacket(pkt, hook, gso, r)

	// Go through each table containing the hook.
	for _, tablename := range it.GetPriorities(hook) {
		table, _ := it.GetTable(tablename)
		ruleIdx := table.BuiltinChains[hook]
		switch verdict := it.checkChain(hook, pkt, table, ruleIdx, gso, r, address, nicName); verdict {
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
			switch v, _ := underflow.Target.Action(pkt, &it.connections, hook, gso, r, address); v {
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

// beforeSave is invoked by stateify.
func (it *IPTables) beforeSave() {
	// Ensure the reaper exits cleanly.
	it.reaperDone <- struct{}{}
	// Prevent others from modifying the connection table.
	it.connections.mu.Lock()
}

// afterLoad is invoked by stateify.
func (it *IPTables) afterLoad() {
	it.startReaper(reaperDelay)
}

// startReaper starts a goroutine that wakes up periodically to reap timed out
// connections.
func (it *IPTables) startReaper(interval time.Duration) {
	go func() { // S/R-SAFE: reaperDone is signalled when iptables is saved.
		bucket := 0
		for {
			select {
			case <-it.reaperDone:
				return
			case <-time.After(interval):
				bucket, interval = it.connections.reapUnused(bucket, interval)
			}
		}
	}()
}

// CheckPackets runs pkts through the rules for hook and returns a map of packets that
// should not go forward.
//
// Preconditions:
// - pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// - pkt.NetworkHeader is not nil.
//
// NOTE: unlike the Check API the returned map contains packets that should be
// dropped.
func (it *IPTables) CheckPackets(hook Hook, pkts PacketBufferList, gso *GSO, r *Route, nicName string) (drop map[*PacketBuffer]struct{}, natPkts map[*PacketBuffer]struct{}) {
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if !pkt.NatDone {
			if ok := it.Check(hook, pkt, gso, r, "", nicName); !ok {
				if drop == nil {
					drop = make(map[*PacketBuffer]struct{})
				}
				drop[pkt] = struct{}{}
			}
			if pkt.NatDone {
				if natPkts == nil {
					natPkts = make(map[*PacketBuffer]struct{})
				}
				natPkts[pkt] = struct{}{}
			}
		}
	}
	return drop, natPkts
}

// Preconditions:
// - pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// - pkt.NetworkHeader is not nil.
func (it *IPTables) checkChain(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, gso *GSO, r *Route, address tcpip.Address, nicName string) chainVerdict {
	// Start from ruleIdx and walk the list of rules until a rule gives us
	// a verdict.
	for ruleIdx < len(table.Rules) {
		switch verdict, jumpTo := it.checkRule(hook, pkt, table, ruleIdx, gso, r, address, nicName); verdict {
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
			switch verdict := it.checkChain(hook, pkt, table, jumpTo, gso, r, address, nicName); verdict {
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

// Preconditions:
// - pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// - pkt.NetworkHeader is not nil.
func (it *IPTables) checkRule(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, gso *GSO, r *Route, address tcpip.Address, nicName string) (RuleVerdict, int) {
	rule := table.Rules[ruleIdx]

	// Check whether the packet matches the IP header filter.
	if !rule.Filter.match(header.IPv4(pkt.NetworkHeader), hook, nicName) {
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
	return rule.Target.Action(pkt, &it.connections, hook, gso, r, address)
}
