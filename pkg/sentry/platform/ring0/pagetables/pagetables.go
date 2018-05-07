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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// Node is a single node within a set of page tables.
type Node struct {
	// unalignedData has unaligned data. Unfortunately, we can't really
	// rely on the allocator to give us what we want here. So we just throw
	// it at the wall and use the portion that matches. Gross. This may be
	// changed in the future to use a different allocation mechanism.
	//
	// Access must happen via functions found in pagetables_unsafe.go.
	unalignedData [(2 * usermem.PageSize) - 1]byte

	// physical is the translated address of these entries.
	//
	// This is filled in at creation time.
	physical uintptr
}

// PageTables is a set of page tables.
type PageTables struct {
	mu sync.Mutex

	// root is the pagetable root.
	root *Node

	// translator is the translator passed at creation.
	translator Translator

	// archPageTables includes architecture-specific features.
	archPageTables

	// allNodes is a set of nodes indexed by translator address.
	allNodes map[uintptr]*Node
}

// Translator translates to guest physical addresses.
type Translator interface {
	// TranslateToPhysical translates the given pointer object into a
	// "physical" address. We do not require that it translates back, the
	// reverse mapping is maintained internally.
	TranslateToPhysical(*PTEs) uintptr
}

// New returns new PageTables.
func New(t Translator, opts Opts) *PageTables {
	p := &PageTables{
		translator: t,
		allNodes:   make(map[uintptr]*Node),
	}
	p.root = p.allocNode()
	p.init(opts)
	return p
}

// New returns a new set of PageTables derived from the given one.
//
// This function should always be preferred to New if there are existing
// pagetables, as this function preserves architectural constraints relevant to
// managing multiple sets of pagetables.
func (p *PageTables) New() *PageTables {
	np := &PageTables{
		translator: p.translator,
		allNodes:   make(map[uintptr]*Node),
	}
	np.root = np.allocNode()
	np.initFrom(&p.archPageTables)
	return np
}

// setPageTable sets the given index as a page table.
func (p *PageTables) setPageTable(n *Node, index int, child *Node) {
	phys := p.translator.TranslateToPhysical(child.PTEs())
	p.allNodes[phys] = child
	pte := &n.PTEs()[index]
	pte.setPageTable(phys)
}

// clearPageTable clears the given entry.
func (p *PageTables) clearPageTable(n *Node, index int) {
	pte := &n.PTEs()[index]
	physical := pte.Address()
	pte.Clear()
	delete(p.allNodes, physical)
}

// getPageTable returns the page table entry.
func (p *PageTables) getPageTable(n *Node, index int) *Node {
	pte := &n.PTEs()[index]
	physical := pte.Address()
	child := p.allNodes[physical]
	return child
}

// Map installs a mapping with the given physical address.
//
// True is returned iff there was a previous mapping in the range.
//
// Precondition: addr & length must be aligned, their sum must not overflow.
func (p *PageTables) Map(addr usermem.Addr, length uintptr, user bool, at usermem.AccessType, physical uintptr) bool {
	if at == usermem.NoAccess {
		return p.Unmap(addr, length)
	}
	prev := false
	p.mu.Lock()
	end, ok := addr.AddLength(uint64(length))
	if !ok {
		panic("pagetables.Map: overflow")
	}
	p.iterateRange(uintptr(addr), uintptr(end), true, func(s, e uintptr, pte *PTE, align uintptr) {
		p := physical + (s - uintptr(addr))
		prev = prev || (pte.Valid() && (p != pte.Address() || at.Write != pte.Writeable() || at.Execute != pte.Executable()))
		if p&align != 0 {
			// We will install entries at a smaller granulaity if
			// we don't install a valid entry here, however we must
			// zap any existing entry to ensure this happens.
			pte.Clear()
			return
		}
		pte.Set(p, at.Write, at.Execute, user)
	})
	p.mu.Unlock()
	return prev
}

// Unmap unmaps the given range.
//
// True is returned iff there was a previous mapping in the range.
func (p *PageTables) Unmap(addr usermem.Addr, length uintptr) bool {
	p.mu.Lock()
	count := 0
	p.iterateRange(uintptr(addr), uintptr(addr)+length, false, func(s, e uintptr, pte *PTE, align uintptr) {
		pte.Clear()
		count++
	})
	p.mu.Unlock()
	return count > 0
}

// Release releases this address space.
//
// This must be called to release the PCID.
func (p *PageTables) Release() {
	// Clear all pages.
	p.Unmap(0, ^uintptr(0))
	p.release()
}

// Lookup returns the physical address for the given virtual address.
func (p *PageTables) Lookup(addr usermem.Addr) (physical uintptr, accessType usermem.AccessType) {
	mask := uintptr(usermem.PageSize - 1)
	off := uintptr(addr) & mask
	addr = addr &^ usermem.Addr(mask)
	p.iterateRange(uintptr(addr), uintptr(addr+usermem.PageSize), false, func(s, e uintptr, pte *PTE, align uintptr) {
		if !pte.Valid() {
			return
		}
		physical = pte.Address() + (s - uintptr(addr)) + off
		accessType = usermem.AccessType{
			Read:    true,
			Write:   pte.Writeable(),
			Execute: pte.Executable(),
		}
	})
	return physical, accessType
}

// allocNode allocates a new page.
func (p *PageTables) allocNode() *Node {
	n := new(Node)
	n.physical = p.translator.TranslateToPhysical(n.PTEs())
	return n
}
