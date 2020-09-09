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

// tableID is an index into IPTables.tables.
type tableID int

const (
	natID tableID = iota
	mangleID
	filterID
	numTables
)

// Table names.
const (
	NATTable    = "nat"
	MangleTable = "mangle"
	FilterTable = "filter"
)

// nameToID is immutable.
var nameToID = map[string]tableID{
	NATTable:    natID,
	MangleTable: mangleID,
	FilterTable: filterID,
}

// HookUnset indicates that there is no hook set for an entrypoint or
// underflow.
const HookUnset = -1

// reaperDelay is how long to wait before starting to reap connections.
const reaperDelay = 5 * time.Second

// DefaultTables returns a default set of tables. Each chain is set to accept
// all packets.
func DefaultTables() *IPTables {
	return &IPTables{
		tables: [numTables]Table{
			natID: Table{
				Rules: []Rule{
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: ErrorTarget{}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
			},
			mangleID: Table{
				Rules: []Rule{
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: ErrorTarget{}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting: 0,
					Output:     1,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
			filterID: Table{
				Rules: []Rule{
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: AcceptTarget{}},
					Rule{Target: ErrorTarget{}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
			},
		},
		priorities: [NumHooks][]tableID{
			Prerouting: []tableID{mangleID, natID},
			Input:      []tableID{natID, filterID},
			Output:     []tableID{mangleID, natID, filterID},
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
		BuiltinChains: [NumHooks]int{
			Prerouting:  HookUnset,
			Postrouting: HookUnset,
		},
		Underflows: [NumHooks]int{
			Prerouting:  HookUnset,
			Postrouting: HookUnset,
		},
	}
}

// EmptyNATTable returns a Table with no rules and the filter table chains
// mapped to HookUnset.
func EmptyNATTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: [NumHooks]int{
			Forward: HookUnset,
		},
		Underflows: [NumHooks]int{
			Forward: HookUnset,
		},
	}
}

// GetTable returns a table by name.
func (it *IPTables) GetTable(name string, ipv6 bool) (Table, bool) {
	// TODO(gvisor.dev/issue/3549): Enable IPv6.
	if ipv6 {
		return Table{}, false
	}
	id, ok := nameToID[name]
	if !ok {
		return Table{}, false
	}
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.tables[id], true
}

// ReplaceTable replaces or inserts table by name.
func (it *IPTables) ReplaceTable(name string, table Table, ipv6 bool) *tcpip.Error {
	// TODO(gvisor.dev/issue/3549): Enable IPv6.
	if ipv6 {
		return tcpip.ErrInvalidOptionValue
	}
	id, ok := nameToID[name]
	if !ok {
		return tcpip.ErrInvalidOptionValue
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	// If iptables is being enabled, initialize the conntrack table and
	// reaper.
	if !it.modified {
		it.connections.buckets = make([]bucket, numBuckets)
		it.startReaper(reaperDelay)
	}
	it.modified = true
	it.tables[id] = table
	return nil
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
	defer it.mu.RUnlock()
	if !it.modified {
		return true
	}

	// Packets are manipulated only if connection and matching
	// NAT rule exists.
	shouldTrack := it.connections.handlePacket(pkt, hook, gso, r)

	// Go through each table containing the hook.
	priorities := it.priorities[hook]
	for _, tableID := range priorities {
		// If handlePacket already NATed the packet, we don't need to
		// check the NAT table.
		if tableID == natID && pkt.NatDone {
			continue
		}
		table := it.tables[tableID]
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

	// If this connection should be tracked, try to add an entry for it. If
	// traversing the nat table didn't end in adding an entry,
	// maybeInsertNoop will add a no-op entry for the connection. This is
	// needeed when establishing connections so that the SYN/ACK reply to an
	// outgoing SYN is delivered to the correct endpoint rather than being
	// redirected by a prerouting rule.
	//
	// From the iptables documentation: "If there is no rule, a `null'
	// binding is created: this usually does not map the packet, but exists
	// to ensure we don't map another stream over an existing one."
	if shouldTrack {
		it.connections.maybeInsertNoop(pkt, hook)
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
// * pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// * pkt.NetworkHeader is not nil.
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
// * pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// * pkt.NetworkHeader is not nil.
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
// * pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// * pkt.NetworkHeader is not nil.
func (it *IPTables) checkRule(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, gso *GSO, r *Route, address tcpip.Address, nicName string) (RuleVerdict, int) {
	rule := table.Rules[ruleIdx]

	// Check whether the packet matches the IP header filter.
	if !rule.Filter.match(header.IPv4(pkt.NetworkHeader().View()), hook, nicName) {
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

// OriginalDst returns the original destination of redirected connections. It
// returns an error if the connection doesn't exist or isn't redirected.
func (it *IPTables) OriginalDst(epID TransportEndpointID) (tcpip.Address, uint16, *tcpip.Error) {
	return it.connections.originalDst(epID)
}
