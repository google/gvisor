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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/iptables"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// errorTargetName is used to mark targets as error targets. Error targets
// shouldn't be reached - an error has occurred if we fall through to one.
const errorTargetName = "ERROR"

// metadata is opaque to netstack. It holds data that we need to translate
// between Linux's and netstack's iptables representations.
// TODO(gvisor.dev/issue/170): This might be removable.
type metadata struct {
	HookEntry  [linux.NF_INET_NUMHOOKS]uint32
	Underflow  [linux.NF_INET_NUMHOOKS]uint32
	NumEntries uint32
	Size       uint32
}

// GetInfo returns information about iptables.
func GetInfo(t *kernel.Task, stack *stack.Stack, outPtr usermem.Addr) (linux.IPTGetinfo, *syserr.Error) {
	// Read in the struct and table name.
	var info linux.IPTGetinfo
	if _, err := t.CopyIn(outPtr, &info); err != nil {
		return linux.IPTGetinfo{}, syserr.FromError(err)
	}

	// Find the appropriate table.
	table, err := findTable(ep, info.Name)
	if err != nil {
		return linux.IPTGetinfo{}, err
	}

	// Get the hooks that apply to this table.
	info.ValidHooks = table.ValidHooks()

	// Grab the metadata struct, which is used to store information (e.g.
	// the number of entries) that applies to the user's encoding of
	// iptables, but not netstack's.
	metadata := table.Metadata().(metadata)

	// Set values from metadata.
	info.HookEntry = metadata.HookEntry
	info.Underflow = metadata.Underflow
	info.NumEntries = metadata.NumEntries
	info.Size = metadata.Size

	return info, nil
}

// GetEntries returns netstack's iptables rules encoded for the iptables tool.
func GetEntries(t *kernel.Task, stack *stack.Stack, outPtr usermem.Addr, outLen int) (linux.KernelIPTGetEntries, *syserr.Error) {
	// Read in the struct and table name.
	var userEntries linux.IPTGetEntries
	if _, err := t.CopyIn(outPtr, &userEntries); err != nil {
		return linux.KernelIPTGetEntries{}, syserr.FromError(err)
	}

	// Find the appropriate table.
	table, err := findTable(ep, userEntries.Name)
	if err != nil {
		return linux.KernelIPTGetEntries{}, err
	}

	// Convert netstack's iptables rules to something that the iptables
	// tool can understand.
	entries, _, err := convertNetstackToBinary(userEntries.Name.String(), table)
	if err != nil {
		return linux.KernelIPTGetEntries{}, err
	}
	if binary.Size(entries) > uintptr(outLen) {
		log.Warningf("Insufficient GetEntries output size: %d", uintptr(outLen))
		return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
	}

	return entries, nil
}

func findTable(ep tcpip.Endpoint, tablename linux.TableName) (iptables.Table, *syserr.Error) {
	ipt, err := ep.IPTables()
	if err != nil {
		return iptables.Table{}, syserr.FromError(err)
	}
	table, ok := ipt.Tables[tablename.String()]
	if !ok {
		return iptables.Table{}, syserr.ErrInvalidArgument
	}
	return table, nil
}

// FillDefaultIPTables sets stack's IPTables to the default tables and
// populates them with metadata.
func FillDefaultIPTables(stack *stack.Stack) {
	ipt := iptables.DefaultTables()

	// In order to fill in the metadata, we have to translate ipt from its
	// netstack format to Linux's giant-binary-blob format.
	for name, table := range ipt.Tables {
		_, metadata, err := convertNetstackToBinary(name, table)
		if err != nil {
			panic(fmt.Errorf("Unable to set default IP tables: %v", err))
		}
		table.SetMetadata(metadata)
		ipt.Tables[name] = table
	}

	stack.SetIPTables(ipt)
}

// convertNetstackToBinary converts the iptables as stored in netstack to the
// format expected by the iptables tool. Linux stores each table as a binary
// blob that can only be traversed by parsing a bit, reading some offsets,
// jumping to those offsets, parsing again, etc.
func convertNetstackToBinary(tablename string, table iptables.Table) (linux.KernelIPTGetEntries, metadata, *syserr.Error) {
	// Return values.
	var entries linux.KernelIPTGetEntries
	var meta metadata

	// The table name has to fit in the struct.
	if linux.XT_TABLE_MAXNAMELEN < len(tablename) {
		log.Warningf("Table name %q too long.", tablename)
		return linux.KernelIPTGetEntries{}, metadata{}, syserr.ErrInvalidArgument
	}
	copy(entries.Name[:], tablename)

	for ruleIdx, rule := range table.Rules {
		// Is this a chain entry point?
		for hook, hookRuleIdx := range table.BuiltinChains {
			if hookRuleIdx == ruleIdx {
				meta.HookEntry[hook] = entries.Size
			}
		}
		// Is this a chain underflow point?
		for underflow, underflowRuleIdx := range table.Underflows {
			if underflowRuleIdx == ruleIdx {
				meta.Underflow[underflow] = entries.Size
			}
		}

		// Each rule corresponds to an entry.
		entry := linux.KernelIPTEntry{
			IPTEntry: linux.IPTEntry{
				NextOffset:   linux.SizeOfIPTEntry,
				TargetOffset: linux.SizeOfIPTEntry,
			},
		}

		for _, matcher := range rule.Matchers {
			// Serialize the matcher and add it to the
			// entry.
			serialized := marshalMatcher(matcher)
			entry.Elems = append(entry.Elems, serialized...)
			entry.NextOffset += uint16(len(serialized))
			entry.TargetOffset += uint16(len(serialized))
		}

		// Serialize and append the target.
		serialized := marshalTarget(rule.Target)
		entry.Elems = append(entry.Elems, serialized...)
		entry.NextOffset += uint16(len(serialized))

		entries.Size += uint32(entry.NextOffset)
		entries.Entrytable = append(entries.Entrytable, entry)
		meta.NumEntries++
	}

	meta.Size = entries.Size
	return entries, meta, nil
}

func marshalMatcher(matcher iptables.Matcher) []byte {
	switch matcher.(type) {
	default:
		// TODO(gvisor.dev/issue/170): We don't support any matchers
		// yet, so any call to marshalMatcher will panic.
		panic(fmt.Errorf("unknown matcher of type %T", matcher))
	}
}

func marshalTarget(target iptables.Target) []byte {
	switch target.(type) {
	case iptables.UnconditionalAcceptTarget:
		return marshalStandardTarget(iptables.Accept)
	case iptables.UnconditionalDropTarget:
		return marshalStandardTarget(iptables.Drop)
	case iptables.ErrorTarget:
		return marshalErrorTarget()
	default:
		panic(fmt.Errorf("unknown target of type %T", target))
	}
}

func marshalStandardTarget(verdict iptables.Verdict) []byte {
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

func marshalErrorTarget() []byte {
	// This is an error target named error
	target := linux.XTErrorTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTErrorTarget,
		},
	}
	copy(target.Name[:], errorTargetName)
	copy(target.Target.Name[:], errorTargetName)

	ret := make([]byte, 0, linux.SizeOfXTErrorTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

// translateFromStandardVerdict translates verdicts the same way as the iptables
// tool.
func translateFromStandardVerdict(verdict iptables.Verdict) int32 {
	switch verdict {
	case iptables.Accept:
		return -linux.NF_ACCEPT - 1
	case iptables.Drop:
		return -linux.NF_DROP - 1
	case iptables.Queue:
		return -linux.NF_QUEUE - 1
	case iptables.Return:
		return linux.NF_RETURN
	case iptables.Jump:
		// TODO(gvisor.dev/issue/170): Support Jump.
		panic("Jump isn't supported yet")
	}
	panic(fmt.Sprintf("unknown standard verdict: %d", verdict))
}

// translateToStandardVerdict translates from the value in a
// linux.XTStandardTarget to an iptables.Verdict.
func translateToStandardVerdict(val int32) (iptables.Verdict, *syserr.Error) {
	// TODO(gvisor.dev/issue/170): Support other verdicts.
	switch val {
	case -linux.NF_ACCEPT - 1:
		return iptables.Accept, nil
	case -linux.NF_DROP - 1:
		return iptables.Drop, nil
	case -linux.NF_QUEUE - 1:
		log.Warningf("Unsupported iptables verdict QUEUE.")
	case linux.NF_RETURN:
		log.Warningf("Unsupported iptables verdict RETURN.")
	default:
		log.Warningf("Unknown iptables verdict %d.", val)
	}
	return iptables.Invalid, syserr.ErrInvalidArgument
}

// SetEntries sets iptables rules for a single table. See
// net/ipv4/netfilter/ip_tables.c:translate_table for reference.
func SetEntries(stack *stack.Stack, optVal []byte) *syserr.Error {
	printReplace(optVal)

	// Get the basic rules data (struct ipt_replace).
	if len(optVal) < linux.SizeOfIPTReplace {
		log.Warningf("netfilter.SetEntries: optVal has insufficient size for replace %d", len(optVal))
		return syserr.ErrInvalidArgument
	}
	var replace linux.IPTReplace
	replaceBuf := optVal[:linux.SizeOfIPTReplace]
	optVal = optVal[linux.SizeOfIPTReplace:]
	binary.Unmarshal(replaceBuf, usermem.ByteOrder, &replace)

	// TODO(gvisor.dev/issue/170): Support other tables.
	var table iptables.Table
	switch replace.Name.String() {
	case iptables.TablenameFilter:
		table = iptables.EmptyFilterTable()
	default:
		log.Warningf("We don't yet support writing to the %q table (gvisor.dev/issue/170)", replace.Name.String())
		return syserr.ErrInvalidArgument
	}

	// Convert input into a list of rules and their offsets.
	var offset uint32
	var offsets []uint32
	for entryIdx := uint32(0); entryIdx < replace.NumEntries; entryIdx++ {
		// Get the struct ipt_entry.
		if len(optVal) < linux.SizeOfIPTEntry {
			log.Warningf("netfilter: optVal has insufficient size for entry %d", len(optVal))
			return syserr.ErrInvalidArgument
		}
		var entry linux.IPTEntry
		buf := optVal[:linux.SizeOfIPTEntry]
		optVal = optVal[linux.SizeOfIPTEntry:]
		binary.Unmarshal(buf, usermem.ByteOrder, &entry)
		if entry.TargetOffset != linux.SizeOfIPTEntry {
			// TODO(gvisor.dev/issue/170): Support matchers.
			return syserr.ErrInvalidArgument
		}

		// TODO(gvisor.dev/issue/170): We should support IPTIP
		// filtering. We reject any nonzero IPTIP values for now.
		emptyIPTIP := linux.IPTIP{}
		if entry.IP != emptyIPTIP {
			log.Warningf("netfilter: non-empty struct iptip found")
			return syserr.ErrInvalidArgument
		}

		// Get the target of the rule.
		target, consumed, err := parseTarget(optVal)
		if err != nil {
			return err
		}
		optVal = optVal[consumed:]

		table.Rules = append(table.Rules, iptables.Rule{Target: target})
		offsets = append(offsets, offset)
		offset += linux.SizeOfIPTEntry + consumed
	}

	// Go through the list of supported hooks for this table and, for each
	// one, set the rule it corresponds to.
	for hook, _ := range replace.HookEntry {
		if table.ValidHooks()&uint32(hook) != 0 {
			hk := hookFromLinux(hook)
			for ruleIdx, offset := range offsets {
				if offset == replace.HookEntry[hook] {
					table.BuiltinChains[hk] = ruleIdx
				}
				if offset == replace.Underflow[hook] {
					table.Underflows[hk] = ruleIdx
				}
			}
			if ruleIdx := table.BuiltinChains[hk]; ruleIdx == iptables.HookUnset {
				log.Warningf("Hook %v is unset.", hk)
				return syserr.ErrInvalidArgument
			}
			if ruleIdx := table.Underflows[hk]; ruleIdx == iptables.HookUnset {
				log.Warningf("Underflow %v is unset.", hk)
				return syserr.ErrInvalidArgument
			}
		}
	}

	// TODO(gvisor.dev/issue/170): Check the following conditions:
	// - There are no loops.
	// - There are no chains without an unconditional final rule.

	ipt := stack.IPTables()
	table.SetMetadata(metadata{
		HookEntry:  replace.HookEntry,
		Underflow:  replace.Underflow,
		NumEntries: replace.NumEntries,
		Size:       replace.Size,
	})
	ipt.Tables[replace.Name.String()] = table
	stack.SetIPTables(ipt)

	return nil
}

// parseTarget parses a target from the start of optVal and returns the target
// along with the number of bytes it occupies in optVal.
func parseTarget(optVal []byte) (iptables.Target, uint32, *syserr.Error) {
	if len(optVal) < linux.SizeOfXTEntryTarget {
		log.Warningf("netfilter: optVal has insufficient size for entry target %d", len(optVal))
		return nil, 0, syserr.ErrInvalidArgument
	}
	var target linux.XTEntryTarget
	buf := optVal[:linux.SizeOfXTEntryTarget]
	binary.Unmarshal(buf, usermem.ByteOrder, &target)
	switch target.Name.String() {
	case "":
		// Standard target.
		if len(optVal) < linux.SizeOfXTStandardTarget {
			log.Warningf("netfilter.SetEntries: optVal has insufficient size for standard target %d", len(optVal))
			return nil, 0, syserr.ErrInvalidArgument
		}
		var standardTarget linux.XTStandardTarget
		buf = optVal[:linux.SizeOfXTStandardTarget]
		binary.Unmarshal(buf, usermem.ByteOrder, &standardTarget)

		verdict, err := translateToStandardVerdict(standardTarget.Verdict)
		if err != nil {
			return nil, 0, err
		}
		switch verdict {
		case iptables.Accept:
			return iptables.UnconditionalAcceptTarget{}, linux.SizeOfXTStandardTarget, nil
		case iptables.Drop:
			return iptables.UnconditionalDropTarget{}, linux.SizeOfXTStandardTarget, nil
		default:
			panic(fmt.Sprintf("Unknown verdict: %v", verdict))
		}

	case errorTargetName:
		// Error target.
		if len(optVal) < linux.SizeOfXTErrorTarget {
			log.Infof("netfilter.SetEntries: optVal has insufficient size for error target %d", len(optVal))
			return nil, 0, syserr.ErrInvalidArgument
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
		switch errorTarget.Name.String() {
		case errorTargetName:
			return iptables.ErrorTarget{}, linux.SizeOfXTErrorTarget, nil
		default:
			log.Infof("Unknown error target %q doesn't exist or isn't supported yet.", errorTarget.Name.String())
			return nil, 0, syserr.ErrInvalidArgument
		}
	}

	// Unknown target.
	log.Infof("Unknown target %q doesn't exist or isn't supported yet.", target.Name.String())
	return nil, 0, syserr.ErrInvalidArgument
}

func hookFromLinux(hook int) iptables.Hook {
	switch hook {
	case linux.NF_INET_PRE_ROUTING:
		return iptables.Prerouting
	case linux.NF_INET_LOCAL_IN:
		return iptables.Input
	case linux.NF_INET_FORWARD:
		return iptables.Forward
	case linux.NF_INET_LOCAL_OUT:
		return iptables.Output
	case linux.NF_INET_POST_ROUTING:
		return iptables.Postrouting
	}
	panic(fmt.Sprintf("Unknown hook %d does not correspond to a builtin chain"))
}

// printReplace prints information about the struct ipt_replace in optVal. It
// is only for debugging.
func printReplace(optVal []byte) {
	// Basic replace info.
	var replace linux.IPTReplace
	replaceBuf := optVal[:linux.SizeOfIPTReplace]
	optVal = optVal[linux.SizeOfIPTReplace:]
	binary.Unmarshal(replaceBuf, usermem.ByteOrder, &replace)
	log.Infof("Replacing table %q: %+v", replace.Name.String(), replace)

	// Read in the list of entries at the end of replace.
	var totalOffset uint16
	for entryIdx := uint32(0); entryIdx < replace.NumEntries; entryIdx++ {
		var entry linux.IPTEntry
		entryBuf := optVal[:linux.SizeOfIPTEntry]
		binary.Unmarshal(entryBuf, usermem.ByteOrder, &entry)
		log.Infof("Entry %d (total offset %d): %+v", entryIdx, totalOffset, entry)

		totalOffset += entry.NextOffset
		if entry.TargetOffset == linux.SizeOfIPTEntry {
			log.Infof("Entry has no matches.")
		} else {
			log.Infof("Entry has matches.")
		}

		var target linux.XTEntryTarget
		targetBuf := optVal[entry.TargetOffset : entry.TargetOffset+linux.SizeOfXTEntryTarget]
		binary.Unmarshal(targetBuf, usermem.ByteOrder, &target)
		log.Infof("Target named %q: %+v", target.Name.String(), target)

		switch target.Name.String() {
		case "":
			var standardTarget linux.XTStandardTarget
			stBuf := optVal[entry.TargetOffset : entry.TargetOffset+linux.SizeOfXTStandardTarget]
			binary.Unmarshal(stBuf, usermem.ByteOrder, &standardTarget)
			log.Infof("Standard target with verdict %q (%d).", linux.VerdictStrings[standardTarget.Verdict], standardTarget.Verdict)
		case errorTargetName:
			var errorTarget linux.XTErrorTarget
			etBuf := optVal[entry.TargetOffset : entry.TargetOffset+linux.SizeOfXTErrorTarget]
			binary.Unmarshal(etBuf, usermem.ByteOrder, &errorTarget)
			log.Infof("Error target with name %q.", errorTarget.Name.String())
		default:
			log.Infof("Unknown target type.")
		}

		optVal = optVal[entry.NextOffset:]
	}
}
