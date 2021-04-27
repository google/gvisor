// Copyright 2020 The gVisor Authors.
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

package netfilter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// emptyIPv6Filter is for comparison with a rule's filters to determine whether
// it is also empty. It is immutable.
var emptyIPv6Filter = stack.IPHeaderFilter{
	Dst:     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	DstMask: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	Src:     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	SrcMask: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}

// convertNetstackToBinary6 converts the ip6tables as stored in netstack to the
// format expected by the iptables tool. Linux stores each table as a binary
// blob that can only be traversed by parsing a little data, reading some
// offsets, jumping to those offsets, parsing again, etc.
func convertNetstackToBinary6(stk *stack.Stack, tablename linux.TableName) (linux.KernelIP6TGetEntries, linux.IPTGetinfo, error) {
	// The table name has to fit in the struct.
	if linux.XT_TABLE_MAXNAMELEN < len(tablename) {
		return linux.KernelIP6TGetEntries{}, linux.IPTGetinfo{}, fmt.Errorf("table name %q too long", tablename)
	}

	id, ok := nameToID[tablename.String()]
	if !ok {
		return linux.KernelIP6TGetEntries{}, linux.IPTGetinfo{}, fmt.Errorf("couldn't find table %q", tablename)
	}

	// Setup the info struct, which is the same in IPv4 and IPv6.
	entries, info := getEntries6(stk.IPTables().GetTable(id, true), tablename)
	return entries, info, nil
}

func getEntries6(table stack.Table, tablename linux.TableName) (linux.KernelIP6TGetEntries, linux.IPTGetinfo) {
	var info linux.IPTGetinfo
	var entries linux.KernelIP6TGetEntries
	copy(info.Name[:], tablename[:])
	copy(entries.Name[:], info.Name[:])
	info.ValidHooks = table.ValidHooks()

	for ruleIdx, rule := range table.Rules {
		nflog("convert to binary: current offset: %d", entries.Size)

		setHooksAndUnderflow(&info, table, entries.Size, ruleIdx)
		// Each rule corresponds to an entry.
		entry := linux.KernelIP6TEntry{
			Entry: linux.IP6TEntry{
				IPv6: linux.IP6TIP{
					Protocol: uint16(rule.Filter.Protocol),
				},
				NextOffset:   linux.SizeOfIP6TEntry,
				TargetOffset: linux.SizeOfIP6TEntry,
			},
		}
		copy(entry.Entry.IPv6.Dst[:], rule.Filter.Dst)
		copy(entry.Entry.IPv6.DstMask[:], rule.Filter.DstMask)
		copy(entry.Entry.IPv6.Src[:], rule.Filter.Src)
		copy(entry.Entry.IPv6.SrcMask[:], rule.Filter.SrcMask)
		copy(entry.Entry.IPv6.OutputInterface[:], rule.Filter.OutputInterface)
		copy(entry.Entry.IPv6.OutputInterfaceMask[:], rule.Filter.OutputInterfaceMask)
		if rule.Filter.DstInvert {
			entry.Entry.IPv6.InverseFlags |= linux.IP6T_INV_DSTIP
		}
		if rule.Filter.SrcInvert {
			entry.Entry.IPv6.InverseFlags |= linux.IP6T_INV_SRCIP
		}
		if rule.Filter.OutputInterfaceInvert {
			entry.Entry.IPv6.InverseFlags |= linux.IP6T_INV_VIA_OUT
		}
		if rule.Filter.CheckProtocol {
			entry.Entry.IPv6.Flags |= linux.IP6T_F_PROTO
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
			entry.Entry.NextOffset += uint16(len(serialized))
			entry.Entry.TargetOffset += uint16(len(serialized))
		}

		// Serialize and append the target.
		serialized := marshalTarget(rule.Target)
		if len(serialized)%8 != 0 {
			panic(fmt.Sprintf("target %T is not 64-bit aligned", rule.Target))
		}
		entry.Elems = append(entry.Elems, serialized...)
		entry.Entry.NextOffset += uint16(len(serialized))

		nflog("convert to binary: adding entry: %+v", entry)

		entries.Size += uint32(entry.Entry.NextOffset)
		entries.Entrytable = append(entries.Entrytable, entry)
		info.NumEntries++
	}

	info.Size = entries.Size
	nflog("convert to binary: finished with an marshalled size of %d", info.Size)
	return entries, info
}

func modifyEntries6(stk *stack.Stack, optVal []byte, replace *linux.IPTReplace, table *stack.Table) (map[uint32]int, *syserr.Error) {
	nflog("set entries: setting entries in table %q", replace.Name.String())

	// Convert input into a list of rules and their offsets.
	var offset uint32
	// offsets maps rule byte offsets to their position in table.Rules.
	offsets := map[uint32]int{}
	for entryIdx := uint32(0); entryIdx < replace.NumEntries; entryIdx++ {
		nflog("set entries: processing entry at offset %d", offset)

		// Get the struct ipt_entry.
		if len(optVal) < linux.SizeOfIP6TEntry {
			nflog("optVal has insufficient size for entry %d", len(optVal))
			return nil, syserr.ErrInvalidArgument
		}
		var entry linux.IP6TEntry
		entry.UnmarshalUnsafe(optVal[:entry.SizeBytes()])
		initialOptValLen := len(optVal)
		optVal = optVal[entry.SizeBytes():]

		if entry.TargetOffset < linux.SizeOfIP6TEntry {
			nflog("entry has too-small target offset %d", entry.TargetOffset)
			return nil, syserr.ErrInvalidArgument
		}

		// TODO(gvisor.dev/issue/170): We should support more IPTIP
		// filtering fields.
		filter, err := filterFromIP6TIP(entry.IPv6)
		if err != nil {
			nflog("bad iptip: %v", err)
			return nil, syserr.ErrInvalidArgument
		}

		// TODO(gvisor.dev/issue/170): Matchers and targets can specify
		// that they only work for certain protocols, hooks, tables.
		// Get matchers.
		matchersSize := entry.TargetOffset - linux.SizeOfIP6TEntry
		if len(optVal) < int(matchersSize) {
			nflog("entry doesn't have enough room for its matchers (only %d bytes remain)", len(optVal))
			return nil, syserr.ErrInvalidArgument
		}
		matchers, err := parseMatchers(filter, optVal[:matchersSize])
		if err != nil {
			nflog("failed to parse matchers: %v", err)
			return nil, syserr.ErrInvalidArgument
		}
		optVal = optVal[matchersSize:]

		// Get the target of the rule.
		targetSize := entry.NextOffset - entry.TargetOffset
		if len(optVal) < int(targetSize) {
			nflog("entry doesn't have enough room for its target (only %d bytes remain)", len(optVal))
			return nil, syserr.ErrInvalidArgument
		}

		rule := stack.Rule{
			Filter:   filter,
			Matchers: matchers,
		}

		{
			target, err := parseTarget(filter, optVal[:targetSize], true /* ipv6 */)
			if err != nil {
				nflog("failed to parse target: %v", err)
				return nil, err
			}
			rule.Target = target
		}
		optVal = optVal[targetSize:]

		table.Rules = append(table.Rules, rule)
		offsets[offset] = int(entryIdx)
		offset += uint32(entry.NextOffset)

		if initialOptValLen-len(optVal) != int(entry.NextOffset) {
			nflog("entry NextOffset is %d, but entry took up %d bytes", entry.NextOffset, initialOptValLen-len(optVal))
			return nil, syserr.ErrInvalidArgument
		}
	}
	return offsets, nil
}

func filterFromIP6TIP(iptip linux.IP6TIP) (stack.IPHeaderFilter, error) {
	if containsUnsupportedFields6(iptip) {
		return stack.IPHeaderFilter{}, fmt.Errorf("unsupported fields in struct iptip: %+v", iptip)
	}
	if len(iptip.Dst) != header.IPv6AddressSize || len(iptip.DstMask) != header.IPv6AddressSize {
		return stack.IPHeaderFilter{}, fmt.Errorf("incorrect length of destination (%d) and/or destination mask (%d) fields", len(iptip.Dst), len(iptip.DstMask))
	}
	if len(iptip.Src) != header.IPv6AddressSize || len(iptip.SrcMask) != header.IPv6AddressSize {
		return stack.IPHeaderFilter{}, fmt.Errorf("incorrect length of source (%d) and/or source mask (%d) fields", len(iptip.Src), len(iptip.SrcMask))
	}

	return stack.IPHeaderFilter{
		Protocol: tcpip.TransportProtocolNumber(iptip.Protocol),
		// In ip6tables a flag controls whether to check the protocol.
		CheckProtocol:         iptip.Flags&linux.IP6T_F_PROTO != 0,
		Dst:                   tcpip.Address(iptip.Dst[:]),
		DstMask:               tcpip.Address(iptip.DstMask[:]),
		DstInvert:             iptip.InverseFlags&linux.IP6T_INV_DSTIP != 0,
		Src:                   tcpip.Address(iptip.Src[:]),
		SrcMask:               tcpip.Address(iptip.SrcMask[:]),
		SrcInvert:             iptip.InverseFlags&linux.IP6T_INV_SRCIP != 0,
		InputInterface:        string(trimNullBytes(iptip.InputInterface[:])),
		InputInterfaceMask:    string(trimNullBytes(iptip.InputInterfaceMask[:])),
		InputInterfaceInvert:  iptip.InverseFlags&linux.IP6T_INV_VIA_IN != 0,
		OutputInterface:       string(trimNullBytes(iptip.OutputInterface[:])),
		OutputInterfaceMask:   string(trimNullBytes(iptip.OutputInterfaceMask[:])),
		OutputInterfaceInvert: iptip.InverseFlags&linux.IP6T_INV_VIA_OUT != 0,
	}, nil
}

func containsUnsupportedFields6(iptip linux.IP6TIP) bool {
	// The following features are supported:
	// - Protocol
	// - Dst and DstMask
	// - Src and SrcMask
	// - The inverse destination IP check flag
	// - InputInterface, InputInterfaceMask and its inverse.
	// - OutputInterface, OutputInterfaceMask and its inverse.
	const flagMask = linux.IP6T_F_PROTO
	// Disable any supported inverse flags.
	const inverseMask = linux.IP6T_INV_DSTIP | linux.IP6T_INV_SRCIP |
		linux.IP6T_INV_VIA_IN | linux.IP6T_INV_VIA_OUT
	return iptip.Flags&^flagMask != 0 ||
		iptip.InverseFlags&^inverseMask != 0 ||
		iptip.TOS != 0
}
