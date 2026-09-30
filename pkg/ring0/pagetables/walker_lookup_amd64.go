//go:build amd64
// +build amd64

package pagetables

// When walking page tables, get the address of the next boundary,
// or the end address of the range if that comes earlier.
// addrEnd calculates the end of the address range for the given size covering addr.
// addrEnd is a power of two.
//
//go:nosplit
func lookupaddrEnd(addr, end, size uintptr) uintptr {
	next := (addr + size) &^ (size - 1)
	if next < addr || next > end {
		return end
	}
	return next
}

// walkPTEs iterates over the PTEs in the given range and calls the visitor for each one.
// Clear entries are counted if the visitor does not require allocation.
//
// Returns:
//   - ok: whether the walk was successful.
//   - clearEntries: number of clear entries.
//
//go:nosplit
func (w *lookupWalker) walkPTEs(entries *PTEs, start, end uintptr) (bool, uint16) {
	var clearEntries uint16
	for start < end {
		pteIndex := uint16((start & pteMask) >> pteShift)
		entry := &entries[pteIndex]
		if !entry.Valid() && !w.visitor.requiresAlloc() {
			clearEntries++
			start += pteSize
			continue
		}

		// At this point, we are guaranteed that start%pteSize == 0.
		if !w.visitor.visit(uintptr(start&^(pteSize-1)), entry, pteSize-1) {
			return false, clearEntries
		}
		if !entry.Valid() && !w.visitor.requiresAlloc() {
			clearEntries++
		}

		// Note that the pte was changed.
		start += pteSize
	}
	return true, clearEntries
}

// walkPMDs iterates over the PMD entries in the given range.
//
// This function implements the algorithm to maximize the use of super/sect pages whenever
// possible. Whether a super page is provided will be clear through the range
// provided in the callback.
//
// Returns:
//   - ok: whether the walk was successful.
//   - clearEntries: number of clear entries.
//
//go:nosplit
func (w *lookupWalker) walkPMDs(pmdEntries *PTEs, start, end uintptr) (bool, uint16) {
	var clearEntries uint16
	for start < end {
		var pteEntries *PTEs
		nextBoundary := lookupaddrEnd(start, end, pmdSize)
		pmdIndex := uint16((start & pmdMask) >> pmdShift)
		pmdEntry := &pmdEntries[pmdIndex]
		if !pmdEntry.Valid() {
			if !w.visitor.requiresAlloc() {
				// Skip over this entry.
				clearEntries++
				start = nextBoundary
				continue
			}

			// This level has 2-MB huge pages. If this
			// region is continued in a single PMD entry?
			// As above, we can skip allocating a new page.
			if start&(pmdSize-1) == 0 && end-start >= pmdSize {
				pmdEntry.SetSuper()
				if !w.visitor.visit(uintptr(start&^(pmdSize-1)), pmdEntry, pmdSize-1) {
					return false, clearEntries
				}
				if pmdEntry.Valid() {
					start = nextBoundary
					continue
				}
			}

			// Allocate a new pmd.
			pteEntries = w.pageTables.Allocator.NewPTEs() // escapes: see above.
			pmdEntry.setPageTable(w.pageTables, pteEntries)

		} else if pmdEntry.IsSuper() {
			// Does this page need to be split?
			if w.visitor.requiresSplit() && (start&(pmdSize-1) != 0 || end < lookupnext(start, pmdSize)) {
				// Install the relevant entries.
				pteEntries = w.pageTables.Allocator.NewPTEs()
				for index := uint16(0); index < entriesPerPage; index++ {
					pteEntries[index].Set(
						pmdEntry.Address()+(pteSize*uintptr(index)),
						pmdEntry.Opts())
				}
				pmdEntry.setPageTable(w.pageTables, pteEntries)
			} else {
				// A huge page to be checked directly.
				if !w.visitor.visit(uintptr(start&^(pmdSize-1)), pmdEntry, pmdSize-1) {
					return false, clearEntries
				}

				// Might have been cleared.
				if !pmdEntry.Valid() {
					clearEntries++
				}

				// Note that the huge page was changed.
				start = nextBoundary
				continue
			}
		} else {
			pteEntries = w.pageTables.Allocator.LookupPTEs(pmdEntry.Address()) // escapes: see above.
		}

		// Map the next level, since this is valid.
		ok, clearPTEntries := w.walkPTEs(pteEntries, start, nextBoundary)
		if !ok {
			return false, clearEntries
		}

		// Check if we no longer need this page.
		if clearPTEntries == entriesPerPage {
			pmdEntry.Clear()
			w.pageTables.Allocator.FreePTEs(pteEntries) // escapes: see above.
			clearEntries++
		}

		start = nextBoundary
	}
	return true, clearEntries
}

// walkPUDs iterates over the PUD entries in the given range.
//
// This function implements the algorithm to maximize the use of super/sect pages whenever
// possible. Whether a super page is provided will be clear through the range
// provided in the callback.
//
// Returns:
//   - ok: whether the walk was successful.
//   - clearEntries: number of clear entries.
//
//go:nosplit
func (w *lookupWalker) walkPUDs(pudEntries *PTEs, start, end uintptr) (bool, uint16) {
	var clearEntries uint16
	for start < end {
		var pmdEntries *PTEs
		nextBoundary := lookupaddrEnd(start, end, pudSize)
		pudIndex := uint16((start & pudMask) >> pudShift)
		pudEntry := &pudEntries[pudIndex]
		if !pudEntry.Valid() {
			if !w.visitor.requiresAlloc() {
				// Skip over this entry.
				clearEntries++
				start = nextBoundary
				continue
			}

			// This level has 1-GB super pages. Is this
			// entire region at least as large as a single
			// PUD entry?  If so, we can skip allocating a
			// new page for the pmd.
			if start&(pudSize-1) == 0 && end-start >= pudSize {
				pudEntry.SetSuper()
				if !w.visitor.visit(uintptr(start&^(pudSize-1)), pudEntry, pudSize-1) {
					return false, clearEntries
				}
				if pudEntry.Valid() {
					// Skip over this entry.
					start = nextBoundary
					continue
				}
			}

			// Allocate a new pud.
			pmdEntries = w.pageTables.Allocator.NewPTEs() // escapes: see above.
			pudEntry.setPageTable(w.pageTables, pmdEntries)

		} else if pudEntry.IsSuper() {
			// Does this page need to be split?
			if w.visitor.requiresSplit() && (start&(pudSize-1) != 0 || end < lookupnext(start, pudSize)) {
				// Install the relevant entries.
				pmdEntries = w.pageTables.Allocator.NewPTEs() // escapes: see above.
				for index := uint16(0); index < entriesPerPage; index++ {
					pmdEntries[index].SetSuper()
					pmdEntries[index].Set(
						pudEntry.Address()+(pmdSize*uintptr(index)),
						pudEntry.Opts())
				}
				pudEntry.setPageTable(w.pageTables, pmdEntries)
			} else {
				// A super page to be checked directly.
				if !w.visitor.visit(uintptr(start&^(pudSize-1)), pudEntry, pudSize-1) {
					return false, clearEntries
				}

				// Might have been cleared.
				if !pudEntry.Valid() {
					clearEntries++
				}

				// Note that the super page was changed.
				start = nextBoundary
				continue
			}
		} else {
			pmdEntries = w.pageTables.Allocator.LookupPTEs(pudEntry.Address()) // escapes: see above.
		}

		// Map the next level, since this is valid.
		ok, clearPMDEntries := w.walkPMDs(pmdEntries, start, nextBoundary)
		if !ok {
			return false, clearEntries
		}

		// Check if we no longer need this page.
		if clearPMDEntries == entriesPerPage {
			pudEntry.Clear()
			w.pageTables.Allocator.FreePTEs(pmdEntries) // escapes: see above.
			clearEntries++
		}

		start = nextBoundary
	}
	return true, clearEntries
}

// iterateRangeCanonical iterates over all appropriate levels of page tables for the given range.
// see walker_generic.go for more details.
//
//go:nosplit
func (w *lookupWalker) iterateRangeCanonical(start, end uintptr) bool {
	// Start at very top level of page tables and walk down.
	for start < end {
		var pudEntries *PTEs
		nextBoundary := lookupaddrEnd(start, end, pgdSize)
		pgdIndex := uint16((start & pgdMask) >> pgdShift)
		pgdEntry := &w.pageTables.root[pgdIndex]
		if !w.pageTables.largeAddressesEnabled {
			if !pgdEntry.Valid() {
				if !w.visitor.requiresAlloc() {
					// Skip over this entry.
					start = nextBoundary
					continue
				}

				// Allocate a new pgd.
				pudEntries = w.pageTables.Allocator.NewPTEs() // escapes: depends on allocator.
				pgdEntry.setPageTable(w.pageTables, pudEntries)
			} else {
				pudEntries = w.pageTables.Allocator.LookupPTEs(pgdEntry.Address()) // escapes: see above.
			}
			// Map the next level.
			ok, clearPUDEntries := w.walkPUDs(pudEntries, start, nextBoundary)
			if !ok {
				return false
			}

			// Check if we no longer need this page table.
			if clearPUDEntries == entriesPerPage {
				pgdEntry.Clear()
				w.pageTables.Allocator.FreePTEs(pudEntries) // escapes: see above.
			}
		} else {
			var p4dEntries *PTEs
			if !pgdEntry.Valid() {
				if !w.visitor.requiresAlloc() {
					// Skip over this entry.
					start = nextBoundary
					continue
				}

				// Allocate a new pgd.
				p4dEntries = w.pageTables.Allocator.NewPTEs() // escapes: depends on allocator.
				pgdEntry.setPageTable(w.pageTables, p4dEntries)
			} else {
				p4dEntries = w.pageTables.Allocator.LookupPTEs(pgdEntry.Address()) // escapes: see above.
			}
			var clearP4DEntries uint16 = 0
			p4dStart := start
			p4dEnd := nextBoundary
			for p4dStart < p4dEnd {
				nextP4DBoundary := lookupaddrEnd(p4dStart, p4dEnd, p4dSize)
				p4dIndex := uint16((p4dStart & p4dMask) >> p4dShift)
				p4dEntry := &p4dEntries[p4dIndex]
				if !p4dEntry.Valid() {
					if !w.visitor.requiresAlloc() {
						// Skip over this entry.
						clearP4DEntries++
						p4dStart = nextP4DBoundary
						continue
					}
					// Allocate a new pud.
					pudEntries = w.pageTables.Allocator.NewPTEs() // escapes: depends on allocator.
					p4dEntry.setPageTable(w.pageTables, pudEntries)
				} else {
					pudEntries = w.pageTables.Allocator.LookupPTEs(p4dEntry.Address()) // escapes: see above.
				}

				ok, clearPUDEntries := w.walkPUDs(pudEntries, p4dStart, nextP4DBoundary)
				if !ok {
					return false
				}
				if clearPUDEntries == entriesPerPage {
					p4dEntry.Clear()
					w.pageTables.Allocator.FreePTEs(pudEntries) // escapes: see above.
					clearP4DEntries++
				}

				p4dStart = nextP4DBoundary
			}

			// Check if we no longer need this page table.
			if clearP4DEntries == entriesPerPage {
				pgdEntry.Clear()
				w.pageTables.Allocator.FreePTEs(p4dEntries) // escapes: see above.
			}
		}

		// Advance to the next PGD entry's range for the next loop.
		start = nextBoundary
	}
	return true
}

// Walker walks page tables.
type lookupWalker struct {
	// pageTables are the tables to walk.
	pageTables *PageTables

	// Visitor is the set of arguments.
	visitor lookupVisitor
}

// iterateRange iterates over all appropriate levels of page tables for the given range.
//
// If requiresAlloc is true, then Set _must_ be called on all given PTEs. The
// exception is super pages. If a valid super page (huge or jumbo) cannot be
// installed, then the walk will continue to individual entries.
//
// This algorithm will attempt to maximize the use of super/sect pages whenever
// possible. Whether a super page is provided will be clear through the range
// provided in the callback.
//
// Note that if requiresAlloc is true, then no gaps will be present. However,
// if alloc is not set, then the iteration will likely be full of gaps.
//
// Note that this function should generally be avoided in favor of Map, Unmap,
// etc. when not necessary.
//
// Precondition: start must be page-aligned.
// Precondition: start must be less than end.
// Precondition: If requiresAlloc is true, then start and end should not span
// non-canonical ranges. If they do, a panic will result.
//
//go:nosplit
func (w *lookupWalker) iterateRange(start, end uintptr) {
	if start%pteSize != 0 {
		panic("unaligned start")
	}
	if end < start {
		panic("start > end")
	}
	if start < lowerTop {
		if end <= lowerTop {
			w.iterateRangeCanonical(start, end)
		} else if end > lowerTop && end <= upperBottom {
			if w.visitor.requiresAlloc() {
				panic("alloc spans non-canonical range")
			}
			w.iterateRangeCanonical(start, lowerTop)
		} else {
			if w.visitor.requiresAlloc() {
				panic("alloc spans non-canonical range")
			}
			if !w.iterateRangeCanonical(start, lowerTop) {
				return
			}
			w.iterateRangeCanonical(upperBottom, end)
		}
	} else if start < upperBottom {
		if end <= upperBottom {
			if w.visitor.requiresAlloc() {
				panic("alloc spans non-canonical range")
			}
		} else {
			if w.visitor.requiresAlloc() {
				panic("alloc spans non-canonical range")
			}
			w.iterateRangeCanonical(upperBottom, end)
		}
	} else {
		w.iterateRangeCanonical(start, end)
	}
}

// next returns the next address quantized by the given size.
//
//go:nosplit
func lookupnext(start uintptr, size uintptr) uintptr {
	start &= ^(size - 1)
	start += size
	return start
}
