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

// +build amd64

package pagetables

import (
	"fmt"
	"sync/atomic"
)

// Address constraints.
//
// The lowerTop and upperBottom currently apply to four-level pagetables;
// additional refactoring would be necessary to support five-level pagetables.
const (
	lowerTop    = 0x00007fffffffffff
	upperBottom = 0xffff800000000000

	pteShift = 12
	pmdShift = 21
	pudShift = 30
	pgdShift = 39

	pteMask = 0x1ff << pteShift
	pmdMask = 0x1ff << pmdShift
	pudMask = 0x1ff << pudShift
	pgdMask = 0x1ff << pgdShift

	pteSize = 1 << pteShift
	pmdSize = 1 << pmdShift
	pudSize = 1 << pudShift
	pgdSize = 1 << pgdShift
)

// Bits in page table entries.
const (
	present        = 0x001
	writable       = 0x002
	user           = 0x004
	writeThrough   = 0x008
	cacheDisable   = 0x010
	accessed       = 0x020
	dirty          = 0x040
	super          = 0x080
	executeDisable = 1 << 63
)

// PTE is a page table entry.
type PTE uint64

// Clear clears this PTE, including super page information.
func (p *PTE) Clear() {
	atomic.StoreUint64((*uint64)(p), 0)
}

// Valid returns true iff this entry is valid.
func (p *PTE) Valid() bool {
	return atomic.LoadUint64((*uint64)(p))&present != 0
}

// Writeable returns true iff the page is writable.
func (p *PTE) Writeable() bool {
	return atomic.LoadUint64((*uint64)(p))&writable != 0
}

// User returns true iff the page is user-accessible.
func (p *PTE) User() bool {
	return atomic.LoadUint64((*uint64)(p))&user != 0
}

// Executable returns true iff the page is executable.
func (p *PTE) Executable() bool {
	return atomic.LoadUint64((*uint64)(p))&executeDisable == 0
}

// SetSuper sets this page as a super page.
//
// The page must not be valid or a panic will result.
func (p *PTE) SetSuper() {
	if p.Valid() {
		// This is not allowed.
		panic("SetSuper called on valid page!")
	}
	atomic.StoreUint64((*uint64)(p), super)
}

// IsSuper returns true iff this page is a super page.
func (p *PTE) IsSuper() bool {
	return atomic.LoadUint64((*uint64)(p))&super != 0
}

// Set sets this PTE value.
func (p *PTE) Set(addr uintptr, write, execute bool, userAccessible bool) {
	v := uint64(addr)&^uint64(0xfff) | present | accessed
	if userAccessible {
		v |= user
	}
	if !execute {
		v |= executeDisable
	}
	if write {
		v |= writable | dirty
	}
	if p.IsSuper() {
		v |= super
	}
	atomic.StoreUint64((*uint64)(p), v)
}

// setPageTable sets this PTE value and forces the write bit and super bit to
// be cleared. This is used explicitly for breaking super pages.
func (p *PTE) setPageTable(addr uintptr) {
	v := uint64(addr)&^uint64(0xfff) | present | user | writable | accessed | dirty
	atomic.StoreUint64((*uint64)(p), v)
}

// Address extracts the address. This should only be used if Valid returns true.
func (p *PTE) Address() uintptr {
	return uintptr(atomic.LoadUint64((*uint64)(p)) & ^uint64(executeDisable|0xfff))
}

// entriesPerPage is the number of PTEs per page.
const entriesPerPage = 512

// PTEs is a collection of entries.
type PTEs [entriesPerPage]PTE

// next returns the next address quantized by the given size.
func next(start uint64, size uint64) uint64 {
	start &= ^(size - 1)
	start += size
	return start
}

// iterateRange iterates over all appropriate levels of page tables for the given range.
//
// If alloc is set, then Set _must_ be called on all given PTEs. The exception
// is super pages. If a valid super page cannot be installed, then the walk
// will continue to individual entries.
//
// This algorithm will attempt to maximize the use of super pages whenever
// possible. Whether a super page is provided will be clear through the range
// provided in the callback.
//
// Note that if alloc set, then no gaps will be present. However, if alloc is
// not set, then the iteration will likely be full of gaps.
//
// Note that this function should generally be avoided in favor of Map, Unmap,
// etc. when not necessary.
//
// Precondition: startAddr and endAddr must be page-aligned.
//
// Precondition: startStart must be less than endAddr.
//
// Precondition: If alloc is set, then startAddr and endAddr should not span
// non-canonical ranges. If they do, a panic will result.
func (p *PageTables) iterateRange(startAddr, endAddr uintptr, alloc bool, fn func(s, e uintptr, pte *PTE, align uintptr)) {
	start := uint64(startAddr)
	end := uint64(endAddr)
	if start%pteSize != 0 {
		panic(fmt.Sprintf("unaligned start: %v", start))
	}
	if start > end {
		panic(fmt.Sprintf("start > end (%v > %v))", start, end))
	}

	// Deal with cases where we traverse the "gap".
	//
	// These are all explicitly disallowed if alloc is set, and we must
	// traverse an entry for each address explicitly.
	switch {
	case start < lowerTop && end > lowerTop && end < upperBottom:
		if alloc {
			panic(fmt.Sprintf("alloc [%x, %x) spans non-canonical range", start, end))
		}
		p.iterateRange(startAddr, lowerTop, false, fn)
		return
	case start < lowerTop && end > lowerTop:
		if alloc {
			panic(fmt.Sprintf("alloc [%x, %x) spans non-canonical range", start, end))
		}
		p.iterateRange(startAddr, lowerTop, false, fn)
		p.iterateRange(upperBottom, endAddr, false, fn)
		return
	case start > lowerTop && end < upperBottom:
		if alloc {
			panic(fmt.Sprintf("alloc [%x, %x) spans non-canonical range", start, end))
		}
		return
	case start > lowerTop && start < upperBottom && end > upperBottom:
		if alloc {
			panic(fmt.Sprintf("alloc [%x, %x) spans non-canonical range", start, end))
		}
		p.iterateRange(upperBottom, endAddr, false, fn)
		return
	}

	for pgdIndex := int((start & pgdMask) >> pgdShift); start < end && pgdIndex < entriesPerPage; pgdIndex++ {
		pgdEntry := &p.root.PTEs()[pgdIndex]
		if !pgdEntry.Valid() {
			if !alloc {
				// Skip over this entry.
				start = next(start, pgdSize)
				continue
			}

			// Allocate a new pgd.
			p.setPageTable(p.root, pgdIndex, p.allocNode())
		}

		// Map the next level.
		pudNode := p.getPageTable(p.root, pgdIndex)
		clearPUDEntries := 0

		for pudIndex := int((start & pudMask) >> pudShift); start < end && pudIndex < entriesPerPage; pudIndex++ {
			pudEntry := &(pudNode.PTEs()[pudIndex])
			if !pudEntry.Valid() {
				if !alloc {
					// Skip over this entry.
					clearPUDEntries++
					start = next(start, pudSize)
					continue
				}

				// This level has 1-GB super pages. Is this
				// entire region contained in a single PUD
				// entry? If so, we can skip allocating a new
				// page for the pmd.
				if start&(pudSize-1) == 0 && end-start >= pudSize {
					pudEntry.SetSuper()
					fn(uintptr(start), uintptr(start+pudSize), pudEntry, pudSize-1)
					if pudEntry.Valid() {
						start = next(start, pudSize)
						continue
					}
				}

				// Allocate a new pud.
				p.setPageTable(pudNode, pudIndex, p.allocNode())

			} else if pudEntry.IsSuper() {
				// Does this page need to be split?
				if start&(pudSize-1) != 0 || end < next(start, pudSize) {
					currentAddr := uint64(pudEntry.Address())
					writeable := pudEntry.Writeable()
					executable := pudEntry.Executable()
					user := pudEntry.User()

					// Install the relevant entries.
					pmdNode := p.allocNode()
					pmdEntries := pmdNode.PTEs()
					for index := 0; index < entriesPerPage; index++ {
						pmdEntry := &pmdEntries[index]
						pmdEntry.SetSuper()
						pmdEntry.Set(uintptr(currentAddr), writeable, executable, user)
						currentAddr += pmdSize
					}

					// Reset to point to the new page.
					p.setPageTable(pudNode, pudIndex, pmdNode)
				} else {
					// A super page to be checked directly.
					fn(uintptr(start), uintptr(start+pudSize), pudEntry, pudSize-1)

					// Might have been cleared.
					if !pudEntry.Valid() {
						clearPUDEntries++
					}

					// Note that the super page was changed.
					start = next(start, pudSize)
					continue
				}
			}

			// Map the next level, since this is valid.
			pmdNode := p.getPageTable(pudNode, pudIndex)
			clearPMDEntries := 0

			for pmdIndex := int((start & pmdMask) >> pmdShift); start < end && pmdIndex < entriesPerPage; pmdIndex++ {
				pmdEntry := &pmdNode.PTEs()[pmdIndex]
				if !pmdEntry.Valid() {
					if !alloc {
						// Skip over this entry.
						clearPMDEntries++
						start = next(start, pmdSize)
						continue
					}

					// This level has 2-MB huge pages. If this
					// region is contined in a single PMD entry?
					// As above, we can skip allocating a new page.
					if start&(pmdSize-1) == 0 && end-start >= pmdSize {
						pmdEntry.SetSuper()
						fn(uintptr(start), uintptr(start+pmdSize), pmdEntry, pmdSize-1)
						if pmdEntry.Valid() {
							start = next(start, pmdSize)
							continue
						}
					}

					// Allocate a new pmd.
					p.setPageTable(pmdNode, pmdIndex, p.allocNode())

				} else if pmdEntry.IsSuper() {
					// Does this page need to be split?
					if start&(pmdSize-1) != 0 || end < next(start, pmdSize) {
						currentAddr := uint64(pmdEntry.Address())
						writeable := pmdEntry.Writeable()
						executable := pmdEntry.Executable()
						user := pmdEntry.User()

						// Install the relevant entries.
						pteNode := p.allocNode()
						pteEntries := pteNode.PTEs()
						for index := 0; index < entriesPerPage; index++ {
							pteEntry := &pteEntries[index]
							pteEntry.Set(uintptr(currentAddr), writeable, executable, user)
							currentAddr += pteSize
						}

						// Reset to point to the new page.
						p.setPageTable(pmdNode, pmdIndex, pteNode)
					} else {
						// A huge page to be checked directly.
						fn(uintptr(start), uintptr(start+pmdSize), pmdEntry, pmdSize-1)

						// Might have been cleared.
						if !pmdEntry.Valid() {
							clearPMDEntries++
						}

						// Note that the huge page was changed.
						start = next(start, pmdSize)
						continue
					}
				}

				// Map the next level, since this is valid.
				pteNode := p.getPageTable(pmdNode, pmdIndex)
				clearPTEEntries := 0

				for pteIndex := int((start & pteMask) >> pteShift); start < end && pteIndex < entriesPerPage; pteIndex++ {
					pteEntry := &pteNode.PTEs()[pteIndex]
					if !pteEntry.Valid() && !alloc {
						clearPTEEntries++
						start += pteSize
						continue
					}

					// At this point, we are guaranteed that start%pteSize == 0.
					fn(uintptr(start), uintptr(start+pteSize), pteEntry, pteSize-1)
					if !pteEntry.Valid() {
						if alloc {
							panic("PTE not set after iteration with alloc=true!")
						}
						clearPTEEntries++
					}

					// Note that the pte was changed.
					start += pteSize
					continue
				}

				// Check if we no longer need this page.
				if clearPTEEntries == entriesPerPage {
					p.clearPageTable(pmdNode, pmdIndex)
					clearPMDEntries++
				}
			}

			// Check if we no longer need this page.
			if clearPMDEntries == entriesPerPage {
				p.clearPageTable(pudNode, pudIndex)
				clearPUDEntries++
			}
		}

		// Check if we no longer need this page.
		if clearPUDEntries == entriesPerPage {
			p.clearPageTable(p.root, pgdIndex)
		}
	}
}
