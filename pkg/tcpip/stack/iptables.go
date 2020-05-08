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
	"strings"

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
		connections: ConnTrackTable{
			CtMap: make(map[uint32]ConnTrackTupleHolder),
			Seed:  generateRandUint32(),
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
func (it *IPTables) Check(hook Hook, pkt *PacketBuffer, gso *GSO, r *Route, address tcpip.Address, nicName string) bool {
	// Packets are manipulated only if connection and matching
	// NAT rule exists.
	it.connections.HandlePacket(pkt, hook, gso, r)

	// Go through each table containing the hook.
	for _, tablename := range it.Priorities[hook] {
		table := it.Tables[tablename]
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

// CheckPackets runs pkts through the rules for hook and returns a map of packets that
// should not go forward.
//
// Precondition: pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
//
// TODO(gvisor.dev/issue/170): pk.NetworkHeader will always be set as a
// precondition.
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

// Precondition: pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// TODO(gvisor.dev/issue/170): pkt.NetworkHeader will always be set as a
// precondition.
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

// Precondition: pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// TODO(gvisor.dev/issue/170): pkt.NetworkHeader will always be set as a
// precondition.
func (it *IPTables) checkRule(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, gso *GSO, r *Route, address tcpip.Address, nicName string) (RuleVerdict, int) {
	rule := table.Rules[ruleIdx]

	// If pkt.NetworkHeader hasn't been set yet, it will be contained in
	// pkt.Data.
	if pkt.NetworkHeader == nil {
		var ok bool
		pkt.NetworkHeader, ok = pkt.Data.PullUp(header.IPv4MinimumSize)
		if !ok {
			// Precondition has been violated.
			panic(fmt.Sprintf("iptables checks require IPv4 headers of at least %d bytes", header.IPv4MinimumSize))
		}
	}

	// Check whether the packet matches the IP header filter.
	if !filterMatch(rule.Filter, header.IPv4(pkt.NetworkHeader), hook, nicName) {
		// Continue on to the next rule.
		return RuleJump, ruleIdx + 1
	}

	// Go through each rule matcher. If they all match, run
	// the rule target.
	for _, matcher := range rule.Matchers {
		matches, hotdrop := matcher.Match(hook, *pkt, "")
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

func filterMatch(filter IPHeaderFilter, hdr header.IPv4, hook Hook, nicName string) bool {
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

	// Check the output interface.
	// TODO(gvisor.dev/issue/170): Add the check for FORWARD and POSTROUTING
	// hooks after supported.
	if hook == Output {
		n := len(filter.OutputInterface)
		if n == 0 {
			return true
		}

		// If the interface name ends with '+', any interface which begins
		// with the name should be matched.
		ifName := filter.OutputInterface
		matches = true
		if strings.HasSuffix(ifName, "+") {
			matches = strings.HasPrefix(nicName, ifName[:n-1])
		} else {
			matches = nicName == ifName
		}
		return filter.OutputInterfaceInvert != matches
	}

	return true
}
