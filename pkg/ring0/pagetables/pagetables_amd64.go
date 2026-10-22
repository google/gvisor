// Copyright 2018 The gVisor Authors.
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

package pagetables

import (
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// Address constraints.
var (
	lowerTop    uintptr = 0x00007fffffffffff
	upperBottom uintptr = 0xffff800000000000
	pgdShift            = 39
	pgdMask     uintptr = 0x1ff << pgdShift
	pgdSize     uintptr = 1 << pgdShift

	// la57Enabled gates whether InitArch promotes new PageTables to a
	// 5-level layout when the host CPU advertises LA57. Defaults to true
	// so existing behavior is unchanged; platforms whose hardware-
	// virtualization layer cannot walk a 5-level page table call
	// DisableLA57 once at startup to force 4-level.
	la57Enabled = true
)

// DisableLA57 forces all subsequently-created PageTables to use a 4-level
// layout regardless of host CPUID. Must be called before any PageTables is
// created.
func DisableLA57() {
	la57Enabled = false
}

const (
	pteShift = 12
	pmdShift = 21
	pudShift = 30
	p4dShift = 39

	pteMask = 0x1ff << pteShift
	pmdMask = 0x1ff << pmdShift
	pudMask = 0x1ff << pudShift
	p4dMask = 0x1ff << p4dShift

	pteSize = 1 << pteShift
	pmdSize = 1 << pmdShift
	pudSize = 1 << pudShift
	p4dSize = 1 << p4dShift

	executeDisable = 1 << 63
	entriesPerPage = 512
)

// InitArch does some additional initialization related to the architecture.
//
// +checkescape:hard,stack
//
//go:nosplit
func (p *PageTables) InitArch(allocator Allocator) {
	featureSet := cpuid.HostFeatureSet()
	if la57Enabled && featureSet.HasFeature(cpuid.X86FeatureLA57) {
		p.largeAddressesEnabled = true
		lowerTop = 0x00FFFFFFFFFFFFFF
		upperBottom = 0xFF00000000000000
		pgdShift = 48
		pgdMask = 0x1ff << pgdShift
		pgdSize = 1 << pgdShift
	}

	if p.upperSharedPageTables != nil {
		p.cloneUpperShared()
	}
}

//go:nosplit
func pgdIndex(upperStart uintptr) uintptr {
	if upperStart&(pgdSize-1) != 0 {
		panic("upperStart should be pgd size aligned")
	}
	if upperStart >= upperBottom {
		return entriesPerPage/2 + (upperStart-upperBottom)>>pgdShift
	}
	if upperStart < lowerTop {
		return upperStart >> pgdShift
	}
	panic("upperStart should be in canonical range")
}

// cloneUpperShared clone the upper from the upper shared page tables.
//
//go:nosplit
func (p *PageTables) cloneUpperShared() {
	start := pgdIndex(p.upperStart)
	copy(p.root[start:entriesPerPage], p.upperSharedPageTables.root[start:entriesPerPage])
}

// PTEs is a collection of entries.
type PTEs [entriesPerPage]PTE

// MapLarge is equivalent to Map, but maps the 1GiB-aligned interior of the
// range by writing 1GiB (PUD-level) entries directly instead of through the
// generic walker. This is much faster for very large ranges: the KVM platform
// maps the whole lower half of the address space (~131k 1GiB entries) every
// time it creates a VM, which takes 3-4 ms with Map.
//
// The fast path uses plain stores and falls back to Map as soon as it finds a
// valid entry in the range, so it must only be used on page tables that no CPU
// is using yet, e.g. right after New.
//
// Precondition: same as Map.
func (p *PageTables) MapLarge(addr hostarch.Addr, length uintptr, opts MapOpts, physical uintptr) bool {
	start := uintptr(addr)
	end := start + length
	if end < start {
		panic("addr & length overflow")
	}
	fillStart := (start + pudSize - 1) &^ (pudSize - 1)
	fillEnd := end &^ (pudSize - 1)
	if p.readOnlyShared || !opts.AccessType.Any() || (start-physical)&(pudSize-1) != 0 ||
		fillStart < start || fillStart >= fillEnd ||
		(p.upperSharedPageTables != nil && end > p.upperStart) {
		return p.Map(addr, length, opts, physical)
	}

	prev := false
	if fillStart > start {
		prev = p.Map(addr, fillStart-start, opts, physical)
	}

	// Compute the entry bits once.
	var tmpl PTE
	tmpl.SetSuper()
	tmpl.Set(0, opts)
	bits := uintptr(tmpl)

	s := fillStart
fill:
	for s < fillEnd {
		next := addrEnd(s, fillEnd, pudSize*entriesPerPage)
		puds := p.pudsFor(s)
		for ; s < next; s += pudSize {
			e := &puds[(s&pudMask)>>pudShift]
			if *e != 0 {
				// Something is already here: let Map deal with
				// the rest.
				break fill
			}
			*e = PTE(bits | (physical + (s - start)))
		}
	}
	if s < end {
		if p.Map(hostarch.Addr(s), end-s, opts, physical+(s-start)) {
			prev = true
		}
	}
	return prev
}

// pudsFor returns the table of PUD entries covering addr, allocating upper
// levels as needed.
func (p *PageTables) pudsFor(addr uintptr) *PTEs {
	pgdEntry := &p.root[(addr&pgdMask)>>pgdShift]
	var next *PTEs
	if !pgdEntry.Valid() {
		next = p.Allocator.NewPTEs()
		pgdEntry.setPageTable(p, next)
	} else {
		next = p.Allocator.LookupPTEs(pgdEntry.Address())
	}
	if !p.largeAddressesEnabled {
		return next
	}
	p4dEntry := &next[(addr&p4dMask)>>p4dShift]
	if !p4dEntry.Valid() {
		puds := p.Allocator.NewPTEs()
		p4dEntry.setPageTable(p, puds)
		return puds
	}
	return p.Allocator.LookupPTEs(p4dEntry.Address())
}
