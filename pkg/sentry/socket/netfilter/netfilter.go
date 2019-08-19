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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/iptables"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// errorTargetName is used to mark targets as error targets. Error targets
// shouldn't be reached - an error has occurred if we fall through to one.
const errorTargetName = "ERROR"

// metadata is opaque to netstack. It holds data that we need to translate
// between Linux's and netstack's iptables representations.
type metadata struct {
	HookEntry  [linux.NF_INET_NUMHOOKS]uint32
	Underflow  [linux.NF_INET_NUMHOOKS]uint32
	NumEntries uint32
	Size       uint32
}

// GetInfo returns information about iptables.
func GetInfo(t *kernel.Task, ep tcpip.Endpoint, outPtr usermem.Addr) (linux.IPTGetinfo, *syserr.Error) {
	// Read in the struct and table name.
	var info linux.IPTGetinfo
	if _, err := t.CopyIn(outPtr, &info); err != nil {
		return linux.IPTGetinfo{}, syserr.FromError(err)
	}

	// Find the appropriate table.
	table, err := findTable(ep, info.TableName())
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
func GetEntries(t *kernel.Task, ep tcpip.Endpoint, outPtr usermem.Addr, outLen int) (linux.KernelIPTGetEntries, *syserr.Error) {
	// Read in the struct and table name.
	var userEntries linux.IPTGetEntries
	if _, err := t.CopyIn(outPtr, &userEntries); err != nil {
		return linux.KernelIPTGetEntries{}, syserr.FromError(err)
	}

	// Find the appropriate table.
	table, err := findTable(ep, userEntries.TableName())
	if err != nil {
		return linux.KernelIPTGetEntries{}, err
	}

	// Convert netstack's iptables rules to something that the iptables
	// tool can understand.
	entries, _, err := convertNetstackToBinary(userEntries.TableName(), table)
	if err != nil {
		return linux.KernelIPTGetEntries{}, err
	}
	if binary.Size(entries) > uintptr(outLen) {
		return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
	}

	return entries, nil
}

func findTable(ep tcpip.Endpoint, tableName string) (iptables.Table, *syserr.Error) {
	ipt, err := ep.IPTables()
	if err != nil {
		return iptables.Table{}, syserr.FromError(err)
	}
	table, ok := ipt.Tables[tableName]
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
func convertNetstackToBinary(name string, table iptables.Table) (linux.KernelIPTGetEntries, metadata, *syserr.Error) {
	// Return values.
	var entries linux.KernelIPTGetEntries
	var meta metadata

	// The table name has to fit in the struct.
	if linux.XT_TABLE_MAXNAMELEN < len(name) {
		return linux.KernelIPTGetEntries{}, metadata{}, syserr.ErrInvalidArgument
	}
	copy(entries.Name[:], name)

	// Deal with the built in chains first (INPUT, OUTPUT, etc.). Each of
	// these chains ends with an unconditional policy entry.
	for hook := iptables.Prerouting; hook < iptables.NumHooks; hook++ {
		chain, ok := table.BuiltinChains[hook]
		if !ok {
			// This table doesn't support this hook.
			continue
		}

		// Sanity check.
		if len(chain.Rules) < 1 {
			return linux.KernelIPTGetEntries{}, metadata{}, syserr.ErrInvalidArgument
		}

		for ruleIdx, rule := range chain.Rules {
			// If this is the first rule of a builtin chain, set
			// the metadata hook entry point.
			if ruleIdx == 0 {
				meta.HookEntry[hook] = entries.Size
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

			// The underflow rule is the last rule in the chain,
			// and is an unconditional rule (i.e. it matches any
			// packet). This is enforced when saving iptables.
			if ruleIdx == len(chain.Rules)-1 {
				meta.Underflow[hook] = entries.Size
			}

			entries.Size += uint32(entry.NextOffset)
			entries.Entrytable = append(entries.Entrytable, entry)
			meta.NumEntries++
		}

	}

	// TODO(gvisor.dev/issue/170): Deal with the user chains here. Each of
	// these starts with an error node holding the chain's name and ends
	// with an unconditional return.

	// Lastly, each table ends with an unconditional error target rule as
	// its final entry.
	errorEntry := linux.KernelIPTEntry{
		IPTEntry: linux.IPTEntry{
			NextOffset:   linux.SizeOfIPTEntry,
			TargetOffset: linux.SizeOfIPTEntry,
		},
	}
	var errorTarget linux.XTErrorTarget
	errorTarget.Target.TargetSize = linux.SizeOfXTErrorTarget
	copy(errorTarget.ErrorName[:], errorTargetName)
	copy(errorTarget.Target.Name[:], errorTargetName)

	// Serialize and add it to the list of entries.
	errorTargetBuf := make([]byte, 0, linux.SizeOfXTErrorTarget)
	serializedErrorTarget := binary.Marshal(errorTargetBuf, usermem.ByteOrder, errorTarget)
	errorEntry.Elems = append(errorEntry.Elems, serializedErrorTarget...)
	errorEntry.NextOffset += uint16(len(serializedErrorTarget))

	entries.Size += uint32(errorEntry.NextOffset)
	entries.Entrytable = append(entries.Entrytable, errorEntry)
	meta.NumEntries++
	meta.Size = entries.Size

	return entries, meta, nil
}

func marshalMatcher(matcher iptables.Matcher) []byte {
	switch matcher.(type) {
	default:
		// TODO(gvisor.dev/issue/170): We don't support any matchers yet, so
		// any call to marshalMatcher will panic.
		panic(fmt.Errorf("unknown matcher of type %T", matcher))
	}
}

func marshalTarget(target iptables.Target) []byte {
	switch target.(type) {
	case iptables.UnconditionalAcceptTarget:
		return marshalUnconditionalAcceptTarget()
	default:
		panic(fmt.Errorf("unknown target of type %T", target))
	}
}

func marshalUnconditionalAcceptTarget() []byte {
	// The target's name will be the empty string.
	target := linux.XTStandardTarget{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTStandardTarget,
		},
		Verdict: translateStandardVerdict(iptables.Accept),
	}

	ret := make([]byte, 0, linux.SizeOfXTStandardTarget)
	return binary.Marshal(ret, usermem.ByteOrder, target)
}

// translateStandardVerdict translates verdicts the same way as the iptables
// tool.
func translateStandardVerdict(verdict iptables.Verdict) int32 {
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
	default:
		panic(fmt.Sprintf("unknown standard verdict: %d", verdict))
	}
}
