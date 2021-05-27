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

// Package netfilter helps the sentry interact with netstack's netfilter
// capabilities.
package netfilter

import (
	"bytes"
	"errors"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// enableLogging controls whether to log the (de)serialization of netfilter
// structs between userspace and netstack. These logs are useful when
// developing iptables, but can pollute sentry logs otherwise.
const enableLogging = false

// nflog logs messages related to the writing and reading of iptables.
func nflog(format string, args ...interface{}) {
	if enableLogging && log.IsLogging(log.Debug) {
		log.Debugf("netfilter: "+format, args...)
	}
}

// Table names.
const (
	natTable    = "nat"
	mangleTable = "mangle"
	filterTable = "filter"
)

// nameToID is immutable.
var nameToID = map[string]stack.TableID{
	natTable:    stack.NATID,
	mangleTable: stack.MangleID,
	filterTable: stack.FilterID,
}

// DefaultLinuxTables returns the rules of stack.DefaultTables() wrapped for
// compatibility with netfilter extensions.
func DefaultLinuxTables(seed uint32) *stack.IPTables {
	tables := stack.DefaultTables(seed)
	tables.VisitTargets(func(oldTarget stack.Target) stack.Target {
		switch val := oldTarget.(type) {
		case *stack.AcceptTarget:
			return &acceptTarget{AcceptTarget: *val}
		case *stack.DropTarget:
			return &dropTarget{DropTarget: *val}
		case *stack.ErrorTarget:
			return &errorTarget{ErrorTarget: *val}
		case *stack.UserChainTarget:
			return &userChainTarget{UserChainTarget: *val}
		case *stack.ReturnTarget:
			return &returnTarget{ReturnTarget: *val}
		case *stack.RedirectTarget:
			return &redirectTarget{RedirectTarget: *val}
		default:
			panic(fmt.Sprintf("Unknown rule in default iptables of type %T", val))
		}
	})
	return tables
}

// GetInfo returns information about iptables.
func GetInfo(t *kernel.Task, stack *stack.Stack, outPtr hostarch.Addr, ipv6 bool) (linux.IPTGetinfo, *syserr.Error) {
	// Read in the struct and table name.
	var info linux.IPTGetinfo
	if _, err := info.CopyIn(t, outPtr); err != nil {
		return linux.IPTGetinfo{}, syserr.FromError(err)
	}

	var err error
	if ipv6 {
		_, info, err = convertNetstackToBinary6(stack, info.Name)
	} else {
		_, info, err = convertNetstackToBinary4(stack, info.Name)
	}
	if err != nil {
		nflog("couldn't convert iptables: %v", err)
		return linux.IPTGetinfo{}, syserr.ErrInvalidArgument
	}

	nflog("returning info: %+v", info)
	return info, nil
}

// GetEntries4 returns netstack's iptables rules.
func GetEntries4(t *kernel.Task, stack *stack.Stack, outPtr hostarch.Addr, outLen int) (linux.KernelIPTGetEntries, *syserr.Error) {
	// Read in the struct and table name.
	var userEntries linux.IPTGetEntries
	if _, err := userEntries.CopyIn(t, outPtr); err != nil {
		nflog("couldn't copy in entries %q", userEntries.Name)
		return linux.KernelIPTGetEntries{}, syserr.FromError(err)
	}

	// Convert netstack's iptables rules to something that the iptables
	// tool can understand.
	entries, _, err := convertNetstackToBinary4(stack, userEntries.Name)
	if err != nil {
		nflog("couldn't read entries: %v", err)
		return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
	}
	if entries.SizeBytes() > outLen {
		nflog("insufficient GetEntries output size: %d", uintptr(outLen))
		return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
	}

	return entries, nil
}

// GetEntries6 returns netstack's ip6tables rules.
func GetEntries6(t *kernel.Task, stack *stack.Stack, outPtr hostarch.Addr, outLen int) (linux.KernelIP6TGetEntries, *syserr.Error) {
	// Read in the struct and table name. IPv4 and IPv6 utilize structs
	// with the same layout.
	var userEntries linux.IPTGetEntries
	if _, err := userEntries.CopyIn(t, outPtr); err != nil {
		nflog("couldn't copy in entries %q", userEntries.Name)
		return linux.KernelIP6TGetEntries{}, syserr.FromError(err)
	}

	// Convert netstack's iptables rules to something that the iptables
	// tool can understand.
	entries, _, err := convertNetstackToBinary6(stack, userEntries.Name)
	if err != nil {
		nflog("couldn't read entries: %v", err)
		return linux.KernelIP6TGetEntries{}, syserr.ErrInvalidArgument
	}
	if entries.SizeBytes() > outLen {
		nflog("insufficient GetEntries output size: %d", uintptr(outLen))
		return linux.KernelIP6TGetEntries{}, syserr.ErrInvalidArgument
	}

	return entries, nil
}

// setHooksAndUnderflow checks whether the rule at ruleIdx is a hook entrypoint
// or underflow, in which case it fills in info.HookEntry and info.Underflows.
func setHooksAndUnderflow(info *linux.IPTGetinfo, table stack.Table, offset uint32, ruleIdx int) {
	// Is this a chain entry point?
	for hook, hookRuleIdx := range table.BuiltinChains {
		if hookRuleIdx == ruleIdx {
			nflog("convert to binary: found hook %d at offset %d", hook, offset)
			info.HookEntry[hook] = offset
		}
	}
	// Is this a chain underflow point?
	for underflow, underflowRuleIdx := range table.Underflows {
		if underflowRuleIdx == ruleIdx {
			nflog("convert to binary: found underflow %d at offset %d", underflow, offset)
			info.Underflow[underflow] = offset
		}
	}
}

// SetEntries sets iptables rules for a single table. See
// net/ipv4/netfilter/ip_tables.c:translate_table for reference.
func SetEntries(stk *stack.Stack, optVal []byte, ipv6 bool) *syserr.Error {
	var replace linux.IPTReplace
	replaceBuf := optVal[:linux.SizeOfIPTReplace]
	optVal = optVal[linux.SizeOfIPTReplace:]
	replace.UnmarshalBytes(replaceBuf)

	// TODO(gvisor.dev/issue/170): Support other tables.
	var table stack.Table
	switch replace.Name.String() {
	case filterTable:
		table = stack.EmptyFilterTable()
	case natTable:
		table = stack.EmptyNATTable()
	default:
		nflog("we don't yet support writing to the %q table (gvisor.dev/issue/170)", replace.Name.String())
		return syserr.ErrInvalidArgument
	}

	var err *syserr.Error
	var offsets map[uint32]int
	if ipv6 {
		offsets, err = modifyEntries6(stk, optVal, &replace, &table)
	} else {
		offsets, err = modifyEntries4(stk, optVal, &replace, &table)
	}
	if err != nil {
		return err
	}

	// Go through the list of supported hooks for this table and, for each
	// one, set the rule it corresponds to.
	for hook := range replace.HookEntry {
		if table.ValidHooks()&(1<<hook) != 0 {
			hk := hookFromLinux(hook)
			table.BuiltinChains[hk] = stack.HookUnset
			table.Underflows[hk] = stack.HookUnset
			for offset, ruleIdx := range offsets {
				if offset == replace.HookEntry[hook] {
					table.BuiltinChains[hk] = ruleIdx
				}
				if offset == replace.Underflow[hook] {
					if !validUnderflow(table.Rules[ruleIdx], ipv6) {
						nflog("underflow for hook %d isn't an unconditional ACCEPT or DROP: %+v", ruleIdx)
						return syserr.ErrInvalidArgument
					}
					table.Underflows[hk] = ruleIdx
				}
			}
			if ruleIdx := table.BuiltinChains[hk]; ruleIdx == stack.HookUnset {
				nflog("hook %v is unset.", hk)
				return syserr.ErrInvalidArgument
			}
			if ruleIdx := table.Underflows[hk]; ruleIdx == stack.HookUnset {
				nflog("underflow %v is unset.", hk)
				return syserr.ErrInvalidArgument
			}
		}
	}

	// Check the user chains.
	for ruleIdx, rule := range table.Rules {
		if _, ok := rule.Target.(*stack.UserChainTarget); !ok {
			continue
		}

		// We found a user chain. Before inserting it into the table,
		// check that:
		// - There's some other rule after it.
		// - There are no matchers.
		if ruleIdx == len(table.Rules)-1 {
			nflog("user chain must have a rule or default policy")
			return syserr.ErrInvalidArgument
		}
		if len(table.Rules[ruleIdx].Matchers) != 0 {
			nflog("user chain's first node must have no matchers")
			return syserr.ErrInvalidArgument
		}
	}

	// Set each jump to point to the appropriate rule. Right now they hold byte
	// offsets.
	for ruleIdx, rule := range table.Rules {
		jump, ok := rule.Target.(*JumpTarget)
		if !ok {
			continue
		}

		// Find the rule corresponding to the jump rule offset.
		jumpTo, ok := offsets[jump.Offset]
		if !ok {
			nflog("failed to find a rule to jump to")
			return syserr.ErrInvalidArgument
		}
		jump.RuleNum = jumpTo
		rule.Target = jump
		table.Rules[ruleIdx] = rule
	}

	// TODO(gvisor.dev/issue/170): Support other chains.
	// Since we don't support FORWARD, yet, make sure all other chains point to
	// ACCEPT rules.
	for hook, ruleIdx := range table.BuiltinChains {
		if hook := stack.Hook(hook); hook == stack.Forward {
			if ruleIdx == stack.HookUnset {
				continue
			}
			if !isUnconditionalAccept(table.Rules[ruleIdx], ipv6) {
				nflog("hook %d is unsupported.", hook)
				return syserr.ErrInvalidArgument
			}
		}
	}

	// TODO(gvisor.dev/issue/170): Check the following conditions:
	// - There are no loops.
	// - There are no chains without an unconditional final rule.
	// - There are no chains without an unconditional underflow rule.

	return syserr.TranslateNetstackError(stk.IPTables().ReplaceTable(nameToID[replace.Name.String()], table, ipv6))
}

// parseMatchers parses 0 or more matchers from optVal. optVal should contain
// only the matchers.
func parseMatchers(filter stack.IPHeaderFilter, optVal []byte) ([]stack.Matcher, error) {
	nflog("set entries: parsing matchers of size %d", len(optVal))
	var matchers []stack.Matcher
	for len(optVal) > 0 {
		nflog("set entries: optVal has len %d", len(optVal))

		// Get the XTEntryMatch.
		if len(optVal) < linux.SizeOfXTEntryMatch {
			return nil, fmt.Errorf("optVal has insufficient size for entry match: %d", len(optVal))
		}
		var match linux.XTEntryMatch
		buf := optVal[:match.SizeBytes()]
		match.UnmarshalUnsafe(buf)
		nflog("set entries: parsed entry match %q: %+v", match.Name.String(), match)

		// Check some invariants.
		if match.MatchSize < linux.SizeOfXTEntryMatch {
			return nil, fmt.Errorf("match size is too small, must be at least %d", linux.SizeOfXTEntryMatch)
		}
		if len(optVal) < int(match.MatchSize) {
			return nil, fmt.Errorf("optVal has insufficient size for match: %d", len(optVal))
		}

		// Parse the specific matcher.
		matcher, err := unmarshalMatcher(match, filter, optVal[linux.SizeOfXTEntryMatch:match.MatchSize])
		if err != nil {
			return nil, fmt.Errorf("failed to create matcher: %v", err)
		}
		matchers = append(matchers, matcher)

		// TODO(gvisor.dev/issue/170): Check the revision field.
		optVal = optVal[match.MatchSize:]
	}

	if len(optVal) != 0 {
		return nil, errors.New("optVal should be exhausted after parsing matchers")
	}

	return matchers, nil
}

func validUnderflow(rule stack.Rule, ipv6 bool) bool {
	if len(rule.Matchers) != 0 {
		return false
	}
	if (ipv6 && rule.Filter != emptyIPv6Filter) || (!ipv6 && rule.Filter != emptyIPv4Filter) {
		return false
	}
	switch rule.Target.(type) {
	case *acceptTarget, *dropTarget:
		return true
	default:
		return false
	}
}

func isUnconditionalAccept(rule stack.Rule, ipv6 bool) bool {
	if !validUnderflow(rule, ipv6) {
		return false
	}
	_, ok := rule.Target.(*acceptTarget)
	return ok
}

func hookFromLinux(hook int) stack.Hook {
	switch hook {
	case linux.NF_INET_PRE_ROUTING:
		return stack.Prerouting
	case linux.NF_INET_LOCAL_IN:
		return stack.Input
	case linux.NF_INET_FORWARD:
		return stack.Forward
	case linux.NF_INET_LOCAL_OUT:
		return stack.Output
	case linux.NF_INET_POST_ROUTING:
		return stack.Postrouting
	}
	panic(fmt.Sprintf("Unknown hook %d does not correspond to a builtin chain", hook))
}

// TargetRevision returns a linux.XTGetRevision for a given target. It sets
// Revision to the highest supported value, unless the provided revision number
// is larger.
func TargetRevision(t *kernel.Task, revPtr hostarch.Addr, netProto tcpip.NetworkProtocolNumber) (linux.XTGetRevision, *syserr.Error) {
	// Read in the target name and version.
	var rev linux.XTGetRevision
	if _, err := rev.CopyIn(t, revPtr); err != nil {
		return linux.XTGetRevision{}, syserr.FromError(err)
	}
	maxSupported, ok := targetRevision(rev.Name.String(), netProto, rev.Revision)
	if !ok {
		return linux.XTGetRevision{}, syserr.ErrProtocolNotSupported
	}
	rev.Revision = maxSupported
	return rev, nil
}

func trimNullBytes(b []byte) []byte {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return b[:n]
}
