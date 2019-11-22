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
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// PageTables is a set of page tables.
type PageTables struct {
	// Allocator is used to allocate nodes.
	Allocator Allocator

	// root is the pagetable root.
	root *PTEs

	// rootPhysical is the cached physical address of the root.
	//
	// This is saved only to prevent constant translation.
	rootPhysical uintptr

	// archPageTables includes architecture-specific features.
	archPageTables
}

// New returns new PageTables.
func New(a Allocator) *PageTables {
	p := new(PageTables)
	p.Init(a)
	return p
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
func (v *mapVisitor) visit(start uintptr, pte *PTE, align uintptr) {
	p := v.physical + (start - uintptr(v.target))
	if pte.Valid() && (pte.Address() != p || pte.Opts() != v.opts) {
		v.prev = true
	}
	if p&align != 0 {
		// We will install entries at a smaller granulaity if we don't
		// install a valid entry here, however we must zap any existing
		// entry to ensure this happens.
		pte.Clear()
		return
	}
	pte.Set(p, v.opts)
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
//go:nosplit
func (p *PageTables) Map(addr usermem.Addr, length uintptr, opts MapOpts, physical uintptr) bool {
	if !opts.AccessType.Any() {
		return p.Unmap(addr, length)
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
func (v *unmapVisitor) visit(start uintptr, pte *PTE, align uintptr) {
	pte.Clear()
	v.count++
}

// Unmap unmaps the given range.
//
// True is returned iff there was a previous mapping in the range.
//
// Precondition: addr & length must be page-aligned.
//
//go:nosplit
func (p *PageTables) Unmap(addr usermem.Addr, length uintptr) bool {
	w := unmapWalker{
		pageTables: p,
		visitor: unmapVisitor{
			count: 0,
		},
	}
	w.iterateRange(uintptr(addr), uintptr(addr)+length)
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
func (v *emptyVisitor) visit(start uintptr, pte *PTE, align uintptr) {
	v.count++
}

// IsEmpty checks if the given range is empty.
//
// Precondition: addr & length must be page-aligned.
//
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
	target   uintptr // Input.
	physical uintptr // Output.
	opts     MapOpts // Output.
}

// visit matches the given address.
//
//go:nosplit
func (v *lookupVisitor) visit(start uintptr, pte *PTE, align uintptr) {
	if !pte.Valid() {
		return
	}
	v.physical = pte.Address() + (start - uintptr(v.target))
	v.opts = pte.Opts()
}

//go:nosplit
func (*lookupVisitor) requiresAlloc() bool { return false }

//go:nosplit
func (*lookupVisitor) requiresSplit() bool { return false }

// Lookup returns the physical address for the given virtual address.
//
//go:nosplit
func (p *PageTables) Lookup(addr usermem.Addr) (physical uintptr, opts MapOpts) {
	mask := uintptr(usermem.PageSize - 1)
	offset := uintptr(addr) & mask
	w := lookupWalker{
		pageTables: p,
		visitor: lookupVisitor{
			target: uintptr(addr &^ usermem.Addr(mask)),
		},
	}
	w.iterateRange(uintptr(addr), uintptr(addr)+1)
	return w.visitor.physical + offset, w.visitor.opts
}
