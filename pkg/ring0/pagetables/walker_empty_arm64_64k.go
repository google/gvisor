//go:build arm64 && pagesize_64k
// +build arm64,pagesize_64k

package pagetables

// iterateRangeCanonical walks a canonical range.
//
// This is a 3-level page table walker for 64K pages:
// PGD -> PMD -> PTE (no PUD level)
//
//go:nosplit
func (w *emptyWalker) iterateRangeCanonical(start, end uintptr) bool {
	pgdEntryIndex := w.pageTables.root
	if start >= upperBottom {
		pgdEntryIndex = w.pageTables.archPageTables.root
	}

	for pgdIndex := (uint16((start & pgdMask) >> pgdShift)); start < end && pgdIndex < entriesPerPage; pgdIndex++ {
		var (
			pgdEntry   = &pgdEntryIndex[pgdIndex]
			pmdEntries *PTEs
		)
		if !pgdEntry.Valid() {
			if !w.visitor.requiresAlloc() {

				start = emptynext(start, pgdSize)
				continue
			}

			pmdEntries = w.pageTables.Allocator.NewPTEs()
			pgdEntry.setPageTable(w.pageTables, pmdEntries)
		} else {
			pmdEntries = w.pageTables.Allocator.LookupPTEs(pgdEntry.Address())
		}

		clearPMDEntries := uint16(0)

		for pmdIndex := uint16((start & pmdMask) >> pmdShift); start < end && pmdIndex < entriesPerPage; pmdIndex++ {
			var (
				pmdEntry   = &pmdEntries[pmdIndex]
				pteEntries *PTEs
			)
			if !pmdEntry.Valid() {
				if !w.visitor.requiresAlloc() {

					clearPMDEntries++
					start = emptynext(start, pmdSize)
					continue
				}

				if start&(pmdSize-1) == 0 && end-start >= pmdSize {
					pmdEntry.SetSect()
					if !w.visitor.visit(uintptr(start), pmdEntry, pmdSize-1) {
						return false
					}
					if pmdEntry.Valid() {
						start = emptynext(start, pmdSize)
						continue
					}
				}

				pteEntries = w.pageTables.Allocator.NewPTEs()
				pmdEntry.setPageTable(w.pageTables, pteEntries)

			} else if pmdEntry.IsSect() {

				if w.visitor.requiresSplit() && (start&(pmdSize-1) != 0 || end < emptynext(start, pmdSize)) {

					pteEntries = w.pageTables.Allocator.NewPTEs()
					for index := uint16(0); index < entriesPerPage; index++ {
						pteEntries[index].Set(
							pmdEntry.Address()+(pteSize*uintptr(index)),
							pmdEntry.Opts())
					}
					pmdEntry.setPageTable(w.pageTables, pteEntries)
				} else {

					if !w.visitor.visit(uintptr(start), pmdEntry, pmdSize-1) {
						return false
					}

					if !pmdEntry.Valid() {
						clearPMDEntries++
					}

					start = emptynext(start, pmdSize)
					continue
				}

			} else {
				pteEntries = w.pageTables.Allocator.LookupPTEs(pmdEntry.Address())
			}

			clearPTEEntries := uint16(0)

			for pteIndex := uint16((start & pteMask) >> pteShift); start < end && pteIndex < entriesPerPage; pteIndex++ {
				var (
					pteEntry = &pteEntries[pteIndex]
				)
				if !pteEntry.Valid() && !w.visitor.requiresAlloc() {
					clearPTEEntries++
					start += pteSize
					continue
				}

				if !w.visitor.visit(uintptr(start), pteEntry, pteSize-1) {
					return false
				}
				if !pteEntry.Valid() {
					if w.visitor.requiresAlloc() {
						panic("PTE not set after iteration with requiresAlloc!")
					}
					clearPTEEntries++
				}

				start += pteSize
				continue
			}

			if clearPTEEntries == entriesPerPage {
				pmdEntry.Clear()
				w.pageTables.Allocator.FreePTEs(pteEntries)
				clearPMDEntries++
			}
		}

		if clearPMDEntries == entriesPerPage {
			pgdEntry.Clear()
			w.pageTables.Allocator.FreePTEs(pmdEntries)
		}
	}
	return true
}

// Walker walks page tables.
type emptyWalker struct {
	// pageTables are the tables to walk.
	pageTables *PageTables

	// Visitor is the set of arguments.
	visitor emptyVisitor
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
func (w *emptyWalker) iterateRange(start, end uintptr) {
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
func emptynext(start uintptr, size uintptr) uintptr {
	start &= ^(size - 1)
	start += size
	return start
}
