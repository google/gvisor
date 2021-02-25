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

// Package pagetables provides a generic implementation of pagetables.
//
// The core functions must be safe to call from a nosplit context. Furthermore,
// this pagetables implementation goes to lengths to ensure that all functions
// are free from runtime allocation. Calls to NewPTEs/FreePTEs may be made
// during walks, but these can be cached elsewhere if required.
package pagetables

import (
	"gvisor.dev/gvisor/pkg/usermem"
)

// PageTables is a set of page tables.
type PageTables struct {
	// Allocator is used to allocate nodes.
	Allocator Allocator

	// root is the pagetable root.
	//
	// For same archs such as amd64, the upper of the PTEs is cloned
	// from and owned by upperSharedPageTables which are shared among
	// many PageTables if upperSharedPageTables is not nil.
	root *PTEs

	// rootPhysical is the cached physical address of the root.
	//
	// This is saved only to prevent constant translation.
	rootPhysical uintptr

	// archPageTables includes architecture-specific features.
	archPageTables

	// upperSharedPageTables represents a read-only shared upper
	// of the Pagetable. When it is not nil, the upper is not
	// allowed to be modified.
	upperSharedPageTables *PageTables

	// upperStart is the start address of the upper portion that
	// are shared from upperSharedPageTables
	upperStart uintptr

	// readOnlyShared indicates the Pagetables are read-only and
	// own the ranges that are shared with other Pagetables.
	readOnlyShared bool
}

// Init initializes a set of PageTables.
//
// +checkescape:hard,stack
//go:nosplit
func (p *PageTables) Init(allocator Allocator) {
	p.Allocator = allocator
	p.root = p.Allocator.NewPTEs()
	p.rootPhysical = p.Allocator.PhysicalFor(p.root)
}

// NewWithUpper returns new PageTables.
//
// upperSharedPageTables are used for mapping the upper of addresses,
// starting at upperStart. These pageTables should not be touched (as
// invalidations may be incorrect) after they are passed as an
// upperSharedPageTables. Only when all dependent PageTables are gone
// may they be used. The intenteded use case is for kernel page tables,
// which are static and fixed.
//
// Precondition: upperStart must be between canonical ranges.
// Precondition: upperStart must be pgdSize aligned.
// precondition: upperSharedPageTables must be marked read-only shared.
func NewWithUpper(a Allocator, upperSharedPageTables *PageTables, upperStart uintptr) *PageTables {
	p := new(PageTables)
	p.Init(a)

	if upperSharedPageTables != nil {
		if !upperSharedPageTables.readOnlyShared {
			panic("Only read-only shared pagetables can be used as upper")
		}
		p.upperSharedPageTables = upperSharedPageTables
		p.upperStart = upperStart
	}

	p.InitArch(a)
	return p
}

// New returns new PageTables.
func New(a Allocator) *PageTables {
	return NewWithUpper(a, nil, 0)
}

// mapVisitor is used for map.
type mapVisitor struct {
	target   uintptr // Input.
	physical uintptr // Input.
	opts     MapOpts // Input.
	prev     bool    // Output.
}

// visit is used for map.
//
//go:nosplit
func (v *mapVisitor) visit(start uintptr, pte *PTE, align uintptr) bool {
	p := v.physical + (start - uintptr(v.target))
	if pte.Valid() && (pte.Address() != p || pte.Opts() != v.opts) {
		v.prev = true
	}
	if p&align != 0 {
		// We will install entries at a smaller granulaity if we don't
		// install a valid entry here, however we must zap any existing
		// entry to ensure this happens.
		pte.Clear()
		return true
	}
	pte.Set(p, v.opts)
	return true
}

//go:nosplit
func (*mapVisitor) requiresAlloc() bool { return true }

//go:nosplit
func (*mapVisitor) requiresSplit() bool { return true }

// Map installs a mapping with the given physical address.
//
// True is returned iff there was a previous mapping in the range.
//
// Precondition: addr & length must be page-aligned, their sum must not overflow.
//
// +checkescape:hard,stack
//go:nosplit
func (p *PageTables) Map(addr usermem.Addr, length uintptr, opts MapOpts, physical uintptr) bool {
	if p.readOnlyShared {
		panic("Should not modify read-only shared pagetables.")
	}
	if uintptr(addr)+length < uintptr(addr) {
		panic("addr & length overflow")
	}
	if p.upperSharedPageTables != nil {
		// ignore change to the read-only upper shared portion.
		if uintptr(addr) >= p.upperStart {
			return false
		}
		if uintptr(addr)+length > p.upperStart {
			length = p.upperStart - uintptr(addr)
		}
	}
	w := mapWalker{
		pageTables: p,
		visitor: mapVisitor{
			target:   uintptr(addr),
			physical: physical,
			opts:     opts,
		},
	}
	w.iterateRange(uintptr(addr), uintptr(addr)+length)
	return w.visitor.prev
}

// unmapVisitor is used for unmap.
type unmapVisitor struct {
	count int
}

//go:nosplit
func (*unmapVisitor) requiresAlloc() bool { return false }

//go:nosplit
func (*unmapVisitor) requiresSplit() bool { return true }

// visit unmaps the given entry.
//
//go:nosplit
func (v *unmapVisitor) visit(start uintptr, pte *PTE, align uintptr) bool {
	pte.Clear()
	v.count++
	return true
}

// Unmap unmaps the given range.
//
// True is returned iff there was a previous mapping in the range.
//
// Precondition: addr & length must be page-aligned, their sum must not overflow.
//
// +checkescape:hard,stack
//go:nosplit
func (p *PageTables) Unmap(addr usermem.Addr, length uintptr) bool {
	if p.readOnlyShared {
		panic("Should not modify read-only shared pagetables.")
	}
	if uintptr(addr)+length < uintptr(addr) {
		panic("addr & length overflow")
	}
	// Extend the unmap range to ensure all the empty pmd, pud, and pgd
	// pagetables can be freed.
	moveBack := func(p *PageTables, curr, back usermem.Addr) usermem.Addr {
		if back < curr {
			first, _, _, _ := p.Lookup(back, true)
			if curr <= first {
				return back
			}
		}
		return curr
	}
	start := addr &^ usermem.Addr(usermem.PageSize-1)
	start = moveBack(p, start, start&^usermem.Addr(pgdSize-1))
	start = moveBack(p, start, start&^usermem.Addr(pudSize-1))
	start = moveBack(p, start, start&^usermem.Addr(pmdSize-1))
	end, _, _, _ := p.Lookup(usermem.Addr(uintptr(addr)+length), true)
	// It is possible when addr+length is not PageSize aligned.
	if end < usermem.Addr(uintptr(addr)+length) {
		end = usermem.Addr(uintptr(addr) + length)
	}
	if p.upperSharedPageTables != nil {
		// ignore change to the read-only upper shared portion.
		if uintptr(addr) >= p.upperStart {
			return false
		}
		if end > usermem.Addr(p.upperStart) {
			end = usermem.Addr(p.upperStart)
		}
	}
	w := unmapWalker{
		pageTables: p,
		visitor: unmapVisitor{
			count: 0,
		},
	}
	w.iterateRange(uintptr(start), uintptr(end))
	return w.visitor.count > 0
}

// emptyVisitor is used for emptiness checks.
type emptyVisitor struct {
	count int
}

//go:nosplit
func (*emptyVisitor) requiresAlloc() bool { return false }

//go:nosplit
func (*emptyVisitor) requiresSplit() bool { return false }

// visit unmaps the given entry.
//
//go:nosplit
func (v *emptyVisitor) visit(start uintptr, pte *PTE, align uintptr) bool {
	v.count++
	return true
}

// IsEmpty checks if the given range is empty.
//
// Precondition: addr & length must be page-aligned.
//
// +checkescape:hard,stack
//go:nosplit
func (p *PageTables) IsEmpty(addr usermem.Addr, length uintptr) bool {
	w := emptyWalker{
		pageTables: p,
	}
	w.iterateRange(uintptr(addr), uintptr(addr)+length)
	return w.visitor.count == 0
}

// lookupVisitor is used for lookup.
type lookupVisitor struct {
	target    uintptr // Input & Output.
	findFirst bool    // Input.
	physical  uintptr // Output.
	size      uintptr // Output.
	opts      MapOpts // Output.
}

// visit matches the given address.
//
//go:nosplit
func (v *lookupVisitor) visit(start uintptr, pte *PTE, align uintptr) bool {
	if !pte.Valid() {
		// If looking for the first, then we just keep iterating until
		// we find a valid entry.
		return v.findFirst
	}
	// Is this within the current range?
	v.target = start
	v.physical = pte.Address()
	v.size = (align + 1)
	v.opts = pte.Opts()
	return false
}

//go:nosplit
func (*lookupVisitor) requiresAlloc() bool { return false }

//go:nosplit
func (*lookupVisitor) requiresSplit() bool { return false }

// Lookup returns the physical address for the given virtual address.
//
// If findFirst is true, then the next valid address after addr is returned.
// If findFirst is false, then only a mapping for addr will be returned.
//
// Note that if size is zero, then no matching entry was found and the
// returned virtual is the original addr.
//
// +checkescape:hard,stack
//go:nosplit
func (p *PageTables) Lookup(addr usermem.Addr, findFirst bool) (virtual usermem.Addr, physical, size uintptr, opts MapOpts) {
	mask := uintptr(usermem.PageSize - 1)
	addr &^= usermem.Addr(mask)
	w := lookupWalker{
		pageTables: p,
		visitor: lookupVisitor{
			target:    uintptr(addr),
			findFirst: findFirst,
		},
	}
	end := ^usermem.Addr(0) &^ usermem.Addr(mask)
	if !findFirst {
		end = addr + 1
	}
	w.iterateRange(uintptr(addr), uintptr(end))
	return usermem.Addr(w.visitor.target), w.visitor.physical, w.visitor.size, w.visitor.opts
}

// MarkReadOnlyShared marks the pagetables read-only and can be shared.
//
// It is usually used on the pagetables that are used as the upper
func (p *PageTables) MarkReadOnlyShared() {
	p.readOnlyShared = true
}
