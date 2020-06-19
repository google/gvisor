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
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/usermem"
)

// errorTargetName is used to mark targets as error targets. Error targets
// shouldn't be reached - an error has occurred if we fall through to one.
const errorTargetName = "ERROR"

// redirectTargetName is used to mark targets as redirect targets. Redirect
// targets should be reached for only NAT and Mangle tables. These targets will
// change the destination port/destination IP for packets.
const redirectTargetName = "REDIRECT"

// enableLogging controls whether to log the (de)serialization of netfilter
// structs between userspace and netstack. These logs are useful when
// developing iptables, but can pollute sentry logs otherwise.
const enableLogging = false

// emptyFilter is for comparison with a rule's filters to determine whether it
// is also empty. It is immutable.
var emptyFilter = stack.IPHeaderFilter{
	Dst:     "\x00\x00\x00\x00",
	DstMask: "\x00\x00\x00\x00",
	Src:     "\x00\x00\x00\x00",
	SrcMask: "\x00\x00\x00\x00",
}

// nflog logs messages related to the writing and reading of iptables.
func nflog(format string, args ...interface{}) {
	if enableLogging && log.IsLogging(log.Debug) {
		log.Debugf("netfilter: "+format, args...)
	}
}

// GetInfo returns information about iptables.
func GetInfo(t *kernel.Task, stack *stack.Stack, outPtr usermem.Addr) (linux.IPTGetinfo, *syserr.Error) {
	// Read in the struct and table name.
	var info linux.IPTGetinfo
	if _, err := t.CopyIn(outPtr, &info); err != nil {
		return linux.IPTGetinfo{}, syserr.FromError(err)
	}

	_, info, err := convertNetstackToBinary(stack, info.Name)
	if err != nil {
		nflog("couldn't convert iptables: %v", err)
		return linux.IPTGetinfo{}, syserr.ErrInvalidArgument
	}

	nflog("returning info: %+v", info)
	return info, nil
}

// GetEntries returns netstack's iptables rules encoded for the iptables tool.
func GetEntries(t *kernel.Task, stack *stack.Stack, outPtr usermem.Addr, outLen int) (linux.KernelIPTGetEntries, *syserr.Error) {
	// Read in the struct and table name.
	var userEntries linux.IPTGetEntries
	if _, err := t.CopyIn(outPtr, &userEntries); err != nil {
		nflog("couldn't copy in entries %q", userEntries.Name)
		return linux.KernelIPTGetEntries{}, syserr.FromError(err)
	}

	// Convert netstack's iptables rules to something that the iptables
	// tool can understand.
	entries, _, err := convertNetstackToBinary(stack, userEntries.Name)
	if err != nil {
		nflog("couldn't read entries: %v", err)
		return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
	}
	if binary.Size(entries) > uintptr(outLen) {
		nflog("insufficient GetEntries output size: %d", uintptr(outLen))
		return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
	}

	return entries, nil
}

// convertNetstackToBinary converts the iptables as stored in netstack to the
// format expected by the iptables tool. Linux stores each table as a binary
// blob that can only be traversed by parsing a bit, reading some offsets,
// jumping to those offsets, parsing again, etc.
func convertNetstackToBinary(stack *stack.Stack, tablename linux.TableName) (linux.KernelIPTGetEntries, linux.IPTGetinfo, error) {
	table, ok := stack.IPTables().GetTable(tablename.String())
	if !ok {
		return linux.KernelIPTGetEntries{}, linux.IPTGetinfo{}, fmt.Errorf("couldn't find table %q", tablename)
	}

	var entries linux.KernelIPTGetEntries
	var info linux.IPTGetinfo
	info.ValidHooks = table.ValidHooks()

	// The table name has to fit in the struct.
	if linux.XT_TABLE_MAXNAMELEN < len(tablename) {
		return linux.KernelIPTGetEntries{}, linux.IPTGetinfo{}, fmt.Errorf("table name %q too long", tablename)
	}
	copy(info.Name[:], tablename[:])
	copy(entries.Name[:], tablename[:])

	for ruleIdx, rule := range table.Rules {
		nflog("convert to binary: current offset: %d", entries.Size)

		// Is this a chain entry point?
		for hook, hookRuleIdx := range table.BuiltinChains {
			if hookRuleIdx == ruleIdx {
				nflog("convert to binary: found hook %d at offset %d", hook, entries.Size)
				info.HookEntry[hook] = entries.Size
			}
		}
		// Is this a chain underflow point?
		for underflow, underflowRuleIdx := range table.Underflows {
			if underflowRuleIdx == ruleIdx {
				nflog("convert to binary: found underflow %d at offset %d", underflow, entries.Size)
				info.Underflow[underflow] = entries.Size
			}
		}

		// Each rule corresponds to an entry.
		entry := linux.KernelIPTEntry{
			IPTEntry: linux.IPTEntry{
				IP: linux.IPTIP{
					Protocol: uint16(rule.Filter.Protocol),
				},
				NextOffset:   linux.SizeOfIPTEntry,
				TargetOffset: linux.SizeOfIPTEntry,
			},
		}
		copy(entry.IPTEntry.IP.Dst[:], rule.Filter.Dst)
		copy(entry.IPTEntry.IP.DstMask[:], rule.Filter.DstMask)
		copy(entry.IPTEntry.IP.Src[:], rule.Filter.Src)
		copy(entry.IPTEntry.IP.SrcMask[:], rule.Filter.SrcMask)
		copy(entry.IPTEntry.IP.OutputInterface[:], rule.Filter.OutputInterface)
		copy(entry.IPTEntry.IP.OutputInterfaceMask[:], rule.Filter.OutputInterfaceMask)
		if rule.Filter.DstInvert {
			entry.IPTEntry.IP.InverseFlags |= linux.IPT_INV_DSTIP
		}
		if rule.Filter.SrcInvert {
			entry.IPTEntry.IP.InverseFlags |= linux.IPT_INV_SRCIP
		}
		if rule.Filter.OutputInterfaceInvert {
			entry.IPTEntry.IP.InverseFlags |= linux.IPT_INV_VIA_OUT
		}

		for _, matcher := range rule.Matchers {
			// Serialize the matcher and add it to the
			// entry.
			serialized := marshalMatcher(matcher)
			nflog("convert to binary: matcher serialized as: %v", serialized)
			if len(serialized)%8 != 0 {
				panic(fmt.Sprintf("matcher %T is not 64-bit aligned", matcher))
			}
			entry.Elems = append(entry.Elems, serialized...)
			entry.NextOffset += uint16(len(serialized))
			entry.TargetOffset += uint16(len(serialized))
		}

		// Serialize and append the target.
		serialized := marshalTarget(rule.Target)
		if len(serialized)%8 != 0 {
			panic(fmt.Sprintf("target %T is not 64-bit aligned", rule.Target))
		}
		entry.Elems = append(entry.Elems, serialized...)
		entry.NextOffset += uint16(len(serialized))

		nflog("convert to binary: adding entry: %+v", entry)

		entries.Size += uint32(entry.NextOffset)
		entries.Entrytable = append(entries.Entrytable, entry)
		info.NumEntries++
	}

	nflog("convert to binary: finished with an marshalled size of %d", info.Size)
	info.Size = entries.Size
	return entries, info, nil
}

func marshalTarget(target stack.Target) []byte {
	switch tg := target.(type) {
	case stack.AcceptTarget:
		return marshalStandardTarget(stack.RuleAccept)
	case stack.DropTarget:
		return marshalStandardTarget(stack.RuleDrop)
	case stack.ErrorTarget:
		return marshalErrorTarget(errorTargetName)
	case stack.UserChainTarget:
		return marshalErrorTarget(tg.Name)
	case stack.ReturnTarget:
		return marshalStandardTarget(stack.RuleReturn)
	case stack.RedirectTarget:
		return marshalRedirectTarget(tg)
	case JumpTarget:
		return marshalJumpTarget(tg)
	default:
		panic(fmt.Errorf("unknown target of type %T", target))
	}
}

func marshalStandardTarget(verdict stack.RuleVerdict) []byte {
	nflog("convert to binary: marshalling standard target")

	// The target's name will be the empty string.
	target := linux.XTStandardTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTStandardTarget,
		},
		Verdict: translateFromStandardVerdict(verdict),
	}

	ret := make([]byte, 0, linux.SizeOfXTStandardTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

func marshalErrorTarget(errorName string) []byte {
	// This is an error target named error
	target := linux.XTErrorTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTErrorTarget,
		},
	}
	copy(target.Name[:], errorName)
	copy(target.Target.Name[:], errorTargetName)

	ret := make([]byte, 0, linux.SizeOfXTErrorTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

func marshalRedirectTarget(rt stack.RedirectTarget) []byte {
	// This is a redirect target named redirect
	target := linux.XTRedirectTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTRedirectTarget,
		},
	}
	copy(target.Target.Name[:], redirectTargetName)

	ret := make([]byte, 0, linux.SizeOfXTRedirectTarget)
	target.NfRange.RangeSize = 1
	if rt.RangeProtoSpecified {
		target.NfRange.RangeIPV4.Flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}
	// Convert port from little endian to big endian.
	port := make([]byte, 2)
	binary.LittleEndian.PutUint16(port, rt.MinPort)
	target.NfRange.RangeIPV4.MinPort = binary.BigEndian.Uint16(port)
	binary.LittleEndian.PutUint16(port, rt.MaxPort)
	target.NfRange.RangeIPV4.MaxPort = binary.BigEndian.Uint16(port)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

func marshalJumpTarget(jt JumpTarget) []byte {
	nflog("convert to binary: marshalling jump target")

	// The target's name will be the empty string.
	target := linux.XTStandardTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTStandardTarget,
		},
		// Verdict is overloaded by the ABI. When positive, it holds
		// the jump offset from the start of the table.
		Verdict: int32(jt.Offset),
	}

	ret := make([]byte, 0, linux.SizeOfXTStandardTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

// translateFromStandardVerdict translates verdicts the same way as the iptables
// tool.
func translateFromStandardVerdict(verdict stack.RuleVerdict) int32 {
	switch verdict {
	case stack.RuleAccept:
		return -linux.NF_ACCEPT - 1
	case stack.RuleDrop:
		return -linux.NF_DROP - 1
	case stack.RuleReturn:
		return linux.NF_RETURN
	default:
		// TODO(gvisor.dev/issue/170): Support Jump.
		panic(fmt.Sprintf("unknown standard verdict: %d", verdict))
	}
}

// translateToStandardTarget translates from the value in a
// linux.XTStandardTarget to an stack.Verdict.
func translateToStandardTarget(val int32) (stack.Target, error) {
	// TODO(gvisor.dev/issue/170): Support other verdicts.
	switch val {
	case -linux.NF_ACCEPT - 1:
		return stack.AcceptTarget{}, nil
	case -linux.NF_DROP - 1:
		return stack.DropTarget{}, nil
	case -linux.NF_QUEUE - 1:
		return nil, errors.New("unsupported iptables verdict QUEUE")
	case linux.NF_RETURN:
		return stack.ReturnTarget{}, nil
	default:
		return nil, fmt.Errorf("unknown iptables verdict %d", val)
	}
}

// SetEntries sets iptables rules for a single table. See
// net/ipv4/netfilter/ip_tables.c:translate_table for reference.
func SetEntries(stk *stack.Stack, optVal []byte) *syserr.Error {
	// Get the basic rules data (struct ipt_replace).
	if len(optVal) < linux.SizeOfIPTReplace {
		nflog("optVal has insufficient size for replace %d", len(optVal))
		return syserr.ErrInvalidArgument
	}
	var replace linux.IPTReplace
	replaceBuf := optVal[:linux.SizeOfIPTReplace]
	optVal = optVal[linux.SizeOfIPTReplace:]
	binary.Unmarshal(replaceBuf, usermem.ByteOrder, &replace)

	// TODO(gvisor.dev/issue/170): Support other tables.
	var table stack.Table
	switch replace.Name.String() {
	case stack.TablenameFilter:
		table = stack.EmptyFilterTable()
	case stack.TablenameNat:
		table = stack.EmptyNatTable()
	default:
		nflog("we don't yet support writing to the %q table (gvisor.dev/issue/170)", replace.Name.String())
		return syserr.ErrInvalidArgument
	}

	nflog("set entries: setting entries in table %q", replace.Name.String())

	// Convert input into a list of rules and their offsets.
	var offset uint32
	// offsets maps rule byte offsets to their position in table.Rules.
	offsets := map[uint32]int{}
	for entryIdx := uint32(0); entryIdx < replace.NumEntries; entryIdx++ {
		nflog("set entries: processing entry at offset %d", offset)

		// Get the struct ipt_entry.
		if len(optVal) < linux.SizeOfIPTEntry {
			nflog("optVal has insufficient size for entry %d", len(optVal))
			return syserr.ErrInvalidArgument
		}
		var entry linux.IPTEntry
		buf := optVal[:linux.SizeOfIPTEntry]
		binary.Unmarshal(buf, usermem.ByteOrder, &entry)
		initialOptValLen := len(optVal)
		optVal = optVal[linux.SizeOfIPTEntry:]

		if entry.TargetOffset < linux.SizeOfIPTEntry {
			nflog("entry has too-small target offset %d", entry.TargetOffset)
			return syserr.ErrInvalidArgument
		}

		// TODO(gvisor.dev/issue/170): We should support more IPTIP
		// filtering fields.
		filter, err := filterFromIPTIP(entry.IP)
		if err != nil {
			nflog("bad iptip: %v", err)
			return syserr.ErrInvalidArgument
		}

		// TODO(gvisor.dev/issue/170): Matchers and targets can specify
		// that they only work for certain protocols, hooks, tables.
		// Get matchers.
		matchersSize := entry.TargetOffset - linux.SizeOfIPTEntry
		if len(optVal) < int(matchersSize) {
			nflog("entry doesn't have enough room for its matchers (only %d bytes remain)", len(optVal))
			return syserr.ErrInvalidArgument
		}
		matchers, err := parseMatchers(filter, optVal[:matchersSize])
		if err != nil {
			nflog("failed to parse matchers: %v", err)
			return syserr.ErrInvalidArgument
		}
		optVal = optVal[matchersSize:]

		// Get the target of the rule.
		targetSize := entry.NextOffset - entry.TargetOffset
		if len(optVal) < int(targetSize) {
			nflog("entry doesn't have enough room for its target (only %d bytes remain)", len(optVal))
			return syserr.ErrInvalidArgument
		}
		target, err := parseTarget(filter, optVal[:targetSize])
		if err != nil {
			nflog("failed to parse target: %v", err)
			return syserr.ErrInvalidArgument
		}
		optVal = optVal[targetSize:]

		table.Rules = append(table.Rules, stack.Rule{
			Filter:   filter,
			Target:   target,
			Matchers: matchers,
		})
		offsets[offset] = int(entryIdx)
		offset += uint32(entry.NextOffset)

		if initialOptValLen-len(optVal) != int(entry.NextOffset) {
			nflog("entry NextOffset is %d, but entry took up %d bytes", entry.NextOffset, initialOptValLen-len(optVal))
			return syserr.ErrInvalidArgument
		}
	}

	// Go through the list of supported hooks for this table and, for each
	// one, set the rule it corresponds to.
	for hook, _ := range replace.HookEntry {
		if table.ValidHooks()&(1<<hook) != 0 {
			hk := hookFromLinux(hook)
			for offset, ruleIdx := range offsets {
				if offset == replace.HookEntry[hook] {
					table.BuiltinChains[hk] = ruleIdx
				}
				if offset == replace.Underflow[hook] {
					if !validUnderflow(table.Rules[ruleIdx]) {
						nflog("underflow for hook %d isn't an unconditional ACCEPT or DROP", ruleIdx)
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

	// Add the user chains.
	for ruleIdx, rule := range table.Rules {
		target, ok := rule.Target.(stack.UserChainTarget)
		if !ok {
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
		table.UserChains[target.Name] = ruleIdx + 1
	}

	// Set each jump to point to the appropriate rule. Right now they hold byte
	// offsets.
	for ruleIdx, rule := range table.Rules {
		jump, ok := rule.Target.(JumpTarget)
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
	// Since we only support modifying the INPUT, PREROUTING and OUTPUT chain right now,
	// make sure all other chains point to ACCEPT rules.
	for hook, ruleIdx := range table.BuiltinChains {
		if hook == stack.Forward || hook == stack.Postrouting {
			if !isUnconditionalAccept(table.Rules[ruleIdx]) {
				nflog("hook %d is unsupported.", hook)
				return syserr.ErrInvalidArgument
			}
		}
	}

	// TODO(gvisor.dev/issue/170): Check the following conditions:
	// - There are no loops.
	// - There are no chains without an unconditional final rule.
	// - There are no chains without an unconditional underflow rule.

	stk.IPTables().ReplaceTable(replace.Name.String(), table)

	return nil
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
		buf := optVal[:linux.SizeOfXTEntryMatch]
		binary.Unmarshal(buf, usermem.ByteOrder, &match)
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

// parseTarget parses a target from optVal. optVal should contain only the
// target.
func parseTarget(filter stack.IPHeaderFilter, optVal []byte) (stack.Target, error) {
	nflog("set entries: parsing target of size %d", len(optVal))
	if len(optVal) < linux.SizeOfXTEntryTarget {
		return nil, fmt.Errorf("optVal has insufficient size for entry target %d", len(optVal))
	}
	var target linux.XTEntryTarget
	buf := optVal[:linux.SizeOfXTEntryTarget]
	binary.Unmarshal(buf, usermem.ByteOrder, &target)
	switch target.Name.String() {
	case "":
		// Standard target.
		if len(optVal) != linux.SizeOfXTStandardTarget {
			return nil, fmt.Errorf("optVal has wrong size for standard target %d", len(optVal))
		}
		var standardTarget linux.XTStandardTarget
		buf = optVal[:linux.SizeOfXTStandardTarget]
		binary.Unmarshal(buf, usermem.ByteOrder, &standardTarget)

		if standardTarget.Verdict < 0 {
			// A Verdict < 0 indicates a non-jump verdict.
			return translateToStandardTarget(standardTarget.Verdict)
		}
		// A verdict >= 0 indicates a jump.
		return JumpTarget{Offset: uint32(standardTarget.Verdict)}, nil

	case errorTargetName:
		// Error target.
		if len(optVal) != linux.SizeOfXTErrorTarget {
			return nil, fmt.Errorf("optVal has insufficient size for error target %d", len(optVal))
		}
		var errorTarget linux.XTErrorTarget
		buf = optVal[:linux.SizeOfXTErrorTarget]
		binary.Unmarshal(buf, usermem.ByteOrder, &errorTarget)

		// Error targets are used in 2 cases:
		// * An actual error case. These rules have an error
		//   named errorTargetName. The last entry of the table
		//   is usually an error case to catch any packets that
		//   somehow fall through every rule.
		// * To mark the start of a user defined chain. These
		//   rules have an error with the name of the chain.
		switch name := errorTarget.Name.String(); name {
		case errorTargetName:
			nflog("set entries: error target")
			return stack.ErrorTarget{}, nil
		default:
			// User defined chain.
			nflog("set entries: user-defined target %q", name)
			return stack.UserChainTarget{Name: name}, nil
		}

	case redirectTargetName:
		// Redirect target.
		if len(optVal) < linux.SizeOfXTRedirectTarget {
			return nil, fmt.Errorf("netfilter.SetEntries: optVal has insufficient size for redirect target %d", len(optVal))
		}

		if filter.Protocol != header.TCPProtocolNumber && filter.Protocol != header.UDPProtocolNumber {
			return nil, fmt.Errorf("netfilter.SetEntries: invalid argument")
		}

		var redirectTarget linux.XTRedirectTarget
		buf = optVal[:linux.SizeOfXTRedirectTarget]
		binary.Unmarshal(buf, usermem.ByteOrder, &redirectTarget)

		// Copy linux.XTRedirectTarget to stack.RedirectTarget.
		var target stack.RedirectTarget
		nfRange := redirectTarget.NfRange

		// RangeSize should be 1.
		if nfRange.RangeSize != 1 {
			return nil, fmt.Errorf("netfilter.SetEntries: invalid argument")
		}

		// TODO(gvisor.dev/issue/170): Check if the flags are valid.
		// Also check if we need to map ports or IP.
		// For now, redirect target only supports destination port change.
		// Port range and IP range are not supported yet.
		if nfRange.RangeIPV4.Flags&linux.NF_NAT_RANGE_PROTO_SPECIFIED == 0 {
			return nil, fmt.Errorf("netfilter.SetEntries: invalid argument")
		}
		target.RangeProtoSpecified = true

		target.MinIP = tcpip.Address(nfRange.RangeIPV4.MinIP[:])
		target.MaxIP = tcpip.Address(nfRange.RangeIPV4.MaxIP[:])

		// TODO(gvisor.dev/issue/170): Port range is not supported yet.
		if nfRange.RangeIPV4.MinPort != nfRange.RangeIPV4.MaxPort {
			return nil, fmt.Errorf("netfilter.SetEntries: invalid argument")
		}

		// Convert port from big endian to little endian.
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, nfRange.RangeIPV4.MinPort)
		target.MinPort = binary.LittleEndian.Uint16(port)

		binary.BigEndian.PutUint16(port, nfRange.RangeIPV4.MaxPort)
		target.MaxPort = binary.LittleEndian.Uint16(port)
		return target, nil
	}

	// Unknown target.
	return nil, fmt.Errorf("unknown target %q doesn't exist or isn't supported yet.", target.Name.String())
}

func filterFromIPTIP(iptip linux.IPTIP) (stack.IPHeaderFilter, error) {
	if containsUnsupportedFields(iptip) {
		return stack.IPHeaderFilter{}, fmt.Errorf("unsupported fields in struct iptip: %+v", iptip)
	}
	if len(iptip.Dst) != header.IPv4AddressSize || len(iptip.DstMask) != header.IPv4AddressSize {
		return stack.IPHeaderFilter{}, fmt.Errorf("incorrect length of destination (%d) and/or destination mask (%d) fields", len(iptip.Dst), len(iptip.DstMask))
	}
	if len(iptip.Src) != header.IPv4AddressSize || len(iptip.SrcMask) != header.IPv4AddressSize {
		return stack.IPHeaderFilter{}, fmt.Errorf("incorrect length of source (%d) and/or source mask (%d) fields", len(iptip.Src), len(iptip.SrcMask))
	}

	n := bytes.IndexByte([]byte(iptip.OutputInterface[:]), 0)
	if n == -1 {
		n = len(iptip.OutputInterface)
	}
	ifname := string(iptip.OutputInterface[:n])

	n = bytes.IndexByte([]byte(iptip.OutputInterfaceMask[:]), 0)
	if n == -1 {
		n = len(iptip.OutputInterfaceMask)
	}
	ifnameMask := string(iptip.OutputInterfaceMask[:n])

	return stack.IPHeaderFilter{
		Protocol:              tcpip.TransportProtocolNumber(iptip.Protocol),
		Dst:                   tcpip.Address(iptip.Dst[:]),
		DstMask:               tcpip.Address(iptip.DstMask[:]),
		DstInvert:             iptip.InverseFlags&linux.IPT_INV_DSTIP != 0,
		Src:                   tcpip.Address(iptip.Src[:]),
		SrcMask:               tcpip.Address(iptip.SrcMask[:]),
		SrcInvert:             iptip.InverseFlags&linux.IPT_INV_SRCIP != 0,
		OutputInterface:       ifname,
		OutputInterfaceMask:   ifnameMask,
		OutputInterfaceInvert: iptip.InverseFlags&linux.IPT_INV_VIA_OUT != 0,
	}, nil
}

func containsUnsupportedFields(iptip linux.IPTIP) bool {
	// The following features are supported:
	// - Protocol
	// - Dst and DstMask
	// - Src and SrcMask
	// - The inverse destination IP check flag
	// - OutputInterface, OutputInterfaceMask and its inverse.
	var emptyInterface = [linux.IFNAMSIZ]byte{}
	// Disable any supported inverse flags.
	inverseMask := uint8(linux.IPT_INV_DSTIP) | uint8(linux.IPT_INV_SRCIP) | uint8(linux.IPT_INV_VIA_OUT)
	return iptip.InputInterface != emptyInterface ||
		iptip.InputInterfaceMask != emptyInterface ||
		iptip.Flags != 0 ||
		iptip.InverseFlags&^inverseMask != 0
}

func validUnderflow(rule stack.Rule) bool {
	if len(rule.Matchers) != 0 {
		return false
	}
	if rule.Filter != emptyFilter {
		return false
	}
	switch rule.Target.(type) {
	case stack.AcceptTarget, stack.DropTarget:
		return true
	default:
		return false
	}
}

func isUnconditionalAccept(rule stack.Rule) bool {
	if !validUnderflow(rule) {
		return false
	}
	_, ok := rule.Target.(stack.AcceptTarget)
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
