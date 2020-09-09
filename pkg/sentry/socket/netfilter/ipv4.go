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
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/usermem"
)

// emptyIPv4Filter is for comparison with a rule's filters to determine whether
// it is also empty. It is immutable.
var emptyIPv4Filter = stack.IPHeaderFilter{
	Dst:     "\x00\x00\x00\x00",
	DstMask: "\x00\x00\x00\x00",
	Src:     "\x00\x00\x00\x00",
	SrcMask: "\x00\x00\x00\x00",
}

func getEntries4(table stack.Table, info *linux.IPTGetinfo) linux.KernelIPTGetEntries {
	var entries linux.KernelIPTGetEntries
	copy(entries.Name[:], info.Name[:])

	for ruleIdx, rule := range table.Rules {
		nflog("convert to binary: current offset: %d", entries.Size)

		setHooksAndUnderflow(info, table, entries.Size, ruleIdx)
		// Each rule corresponds to an entry.
		entry := linux.KernelIPTEntry{
			Entry: linux.IPTEntry{
				IP: linux.IPTIP{
					Protocol: uint16(rule.Filter.Protocol),
				},
				NextOffset:   linux.SizeOfIPTEntry,
				TargetOffset: linux.SizeOfIPTEntry,
			},
		}
		copy(entry.Entry.IP.Dst[:], rule.Filter.Dst)
		copy(entry.Entry.IP.DstMask[:], rule.Filter.DstMask)
		copy(entry.Entry.IP.Src[:], rule.Filter.Src)
		copy(entry.Entry.IP.SrcMask[:], rule.Filter.SrcMask)
		copy(entry.Entry.IP.OutputInterface[:], rule.Filter.OutputInterface)
		copy(entry.Entry.IP.OutputInterfaceMask[:], rule.Filter.OutputInterfaceMask)
		if rule.Filter.DstInvert {
			entry.Entry.IP.InverseFlags |= linux.IPT_INV_DSTIP
		}
		if rule.Filter.SrcInvert {
			entry.Entry.IP.InverseFlags |= linux.IPT_INV_SRCIP
		}
		if rule.Filter.OutputInterfaceInvert {
			entry.Entry.IP.InverseFlags |= linux.IPT_INV_VIA_OUT
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
	return entries
}

func modifyEntries4(stk *stack.Stack, optVal []byte, replace *linux.IPTReplace, table *stack.Table) (map[uint32]int, *syserr.Error) {
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
			return nil, syserr.ErrInvalidArgument
		}
		var entry linux.IPTEntry
		buf := optVal[:linux.SizeOfIPTEntry]
		binary.Unmarshal(buf, usermem.ByteOrder, &entry)
		initialOptValLen := len(optVal)
		optVal = optVal[linux.SizeOfIPTEntry:]

		if entry.TargetOffset < linux.SizeOfIPTEntry {
			nflog("entry has too-small target offset %d", entry.TargetOffset)
			return nil, syserr.ErrInvalidArgument
		}

		// TODO(gvisor.dev/issue/170): We should support more IPTIP
		// filtering fields.
		filter, err := filterFromIPTIP(entry.IP)
		if err != nil {
			nflog("bad iptip: %v", err)
			return nil, syserr.ErrInvalidArgument
		}

		// TODO(gvisor.dev/issue/170): Matchers and targets can specify
		// that they only work for certain protocols, hooks, tables.
		// Get matchers.
		matchersSize := entry.TargetOffset - linux.SizeOfIPTEntry
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
		target, err := parseTarget(filter, optVal[:targetSize])
		if err != nil {
			nflog("failed to parse target: %v", err)
			return nil, syserr.ErrInvalidArgument
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
			return nil, syserr.ErrInvalidArgument
		}
	}
	return offsets, nil
}

func filterFromIPTIP(iptip linux.IPTIP) (stack.IPHeaderFilter, error) {
	if containsUnsupportedFields4(iptip) {
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

func containsUnsupportedFields4(iptip linux.IPTIP) bool {
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
