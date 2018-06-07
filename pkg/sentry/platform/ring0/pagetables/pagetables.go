// Copyright 2018 Google Inc.
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
package pagetables

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
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
	p := &PageTables{Allocator: a}
	p.root = p.Allocator.NewPTEs()
	p.rootPhysical = p.Allocator.PhysicalFor(p.root)
	return p
}

// Map installs a mapping with the given physical address.
//
// True is returned iff there was a previous mapping in the range.
//
// Precondition: addr & length must be aligned, their sum must not overflow.
func (p *PageTables) Map(addr usermem.Addr, length uintptr, opts MapOpts, physical uintptr) bool {
	if !opts.AccessType.Any() {
		return p.Unmap(addr, length)
	}
	prev := false
	end, ok := addr.AddLength(uint64(length))
	if !ok {
		panic("pagetables.Map: overflow")
	}
	p.iterateRange(uintptr(addr), uintptr(end), true, func(s, e uintptr, pte *PTE, align uintptr) {
		p := physical + (s - uintptr(addr))
		prev = prev || (pte.Valid() && (p != pte.Address() || opts != pte.Opts()))
		if p&align != 0 {
			// We will install entries at a smaller granulaity if
			// we don't install a valid entry here, however we must
			// zap any existing entry to ensure this happens.
			pte.Clear()
			return
		}
		pte.Set(p, opts)
	})
	return prev
}

// Unmap unmaps the given range.
//
// True is returned iff there was a previous mapping in the range.
func (p *PageTables) Unmap(addr usermem.Addr, length uintptr) bool {
	count := 0
	p.iterateRange(uintptr(addr), uintptr(addr)+length, false, func(s, e uintptr, pte *PTE, align uintptr) {
		pte.Clear()
		count++
	})
	return count > 0
}

// Lookup returns the physical address for the given virtual address.
func (p *PageTables) Lookup(addr usermem.Addr) (physical uintptr, opts MapOpts) {
	mask := uintptr(usermem.PageSize - 1)
	off := uintptr(addr) & mask
	addr = addr &^ usermem.Addr(mask)
	p.iterateRange(uintptr(addr), uintptr(addr+usermem.PageSize), false, func(s, e uintptr, pte *PTE, align uintptr) {
		if !pte.Valid() {
			return
		}
		physical = pte.Address() + (s - uintptr(addr)) + off
		opts = pte.Opts()
	})
	return
}
