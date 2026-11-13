//go:build arm64 && arm64
// +build arm64,arm64

package pagetables

// iterateRangeCanonical walks a canonical range.
//
// With the 64K granule, it calls iterateRangeCanonical64K. Otherwise, it walks
// 4-level page tables (PGD -> PUD -> PMD -> PTE) inline, to avoid a call.
//
//go:nosplit
func (w *mapWalker) iterateRangeCanonical(start, end uintptr) bool {
	switch activeGranule {
	case granule64K:
		return w.iterateRangeCanonical64K(start, end)
	case granule4K:
	default:
		panic("unknown translation granule")
	}

	pgdEntryIndex := w.pageTables.root
	if start >= upperBottom {
		pgdEntryIndex = w.pageTables.archPageTables.root
	}

	for pgdIndex := (uint16((start & pgdMask4K) >> pgdShift4K)); start < end && pgdIndex < entriesPerPage4K; pgdIndex++ {
		var (
			pgdEntry   = &pgdEntryIndex[pgdIndex]
			pudEntries *PTEs
		)
		if !pgdEntry.Valid() {
			if !w.visitor.requiresAlloc() {
				// Skip over this entry.
				start = mapnext(start, pgdSize4K)
				continue
			}

			// Allocate a new pgd.
			pudEntries = w.pageTables.Allocator.NewPTEs()
			pgdEntry.setPageTable(w.pageTables, pudEntries)
		} else {
			pudEntries = w.pageTables.Allocator.LookupPTEs(pgdEntry.Address())
		}

		// Map the next level.
		clearPUDEntries := uint16(0)

		for pudIndex := uint16((start & pudMask4K) >> pudShift4K); start < end && pudIndex < entriesPerPage4K; pudIndex++ {
			var (
				pudEntry   = &pudEntries[pudIndex]
				pmdEntries *PTEs
			)
			if !pudEntry.Valid() {
				if !w.visitor.requiresAlloc() {
					// Skip over this entry.
					clearPUDEntries++
					start = mapnext(start, pudSize4K)
					continue
				}

				// This level has 1-GB sect pages. Is this
				// entire region at least as large as a single
				// PUD entry?  If so, we can skip allocating a
				// new page for the pmd.
				if start&(pudSize4K-1) == 0 && end-start >= pudSize4K {
					pudEntry.SetSect()
					if !w.visitor.visit(uintptr(start), pudEntry, pudSize4K-1) {
						return false
					}
					if pudEntry.Valid() {
						start = mapnext(start, pudSize4K)
						continue
					}
				}

				// Allocate a new pud.
				pmdEntries = w.pageTables.Allocator.NewPTEs()
				pudEntry.setPageTable(w.pageTables, pmdEntries)

			} else if pudEntry.IsSect() {
				// Does this page need to be split?
				if w.visitor.requiresSplit() && (start&(pudSize4K-1) != 0 || end < mapnext(start, pudSize4K)) {
					// Install the relevant entries.
					pmdEntries = w.pageTables.Allocator.NewPTEs()
					for index := uint16(0); index < entriesPerPage4K; index++ {
						pmdEntries[index].SetSect()
						pmdEntries[index].Set(
							pudEntry.Address()+(pmdSize4K*uintptr(index)),
							pudEntry.Opts())
					}
					pudEntry.setPageTable(w.pageTables, pmdEntries)
				} else {
					// A sect page to be checked directly.
					if !w.visitor.visit(uintptr(start), pudEntry, pudSize4K-1) {
						return false
					}

					// Might have been cleared.
					if !pudEntry.Valid() {
						clearPUDEntries++
					}

					// Note that the sect page was changed.
					start = mapnext(start, pudSize4K)
					continue
				}

			} else {
				pmdEntries = w.pageTables.Allocator.LookupPTEs(pudEntry.Address())
			}

			// Map the next level, since this is valid.
			clearPMDEntries := uint16(0)

			for pmdIndex := uint16((start & pmdMask4K) >> pmdShift4K); start < end && pmdIndex < entriesPerPage4K; pmdIndex++ {
				var (
					pmdEntry   = &pmdEntries[pmdIndex]
					pteEntries *PTEs
				)
				if !pmdEntry.Valid() {
					if !w.visitor.requiresAlloc() {
						// Skip over this entry.
						clearPMDEntries++
						start = mapnext(start, pmdSize4K)
						continue
					}

					// This level has 2-MB huge pages. If this
					// region is continued in a single PMD entry?
					// As above, we can skip allocating a new page.
					if start&(pmdSize4K-1) == 0 && end-start >= pmdSize4K {
						pmdEntry.SetSect()
						if !w.visitor.visit(uintptr(start), pmdEntry, pmdSize4K-1) {
							return false
						}
						if pmdEntry.Valid() {
							start = mapnext(start, pmdSize4K)
							continue
						}
					}

					// Allocate a new pmd.
					pteEntries = w.pageTables.Allocator.NewPTEs()
					pmdEntry.setPageTable(w.pageTables, pteEntries)

				} else if pmdEntry.IsSect() {
					// Does this page need to be split?
					if w.visitor.requiresSplit() && (start&(pmdSize4K-1) != 0 || end < mapnext(start, pmdSize4K)) {
						// Install the relevant entries.
						pteEntries = w.pageTables.Allocator.NewPTEs()
						for index := uint16(0); index < entriesPerPage4K; index++ {
							pteEntries[index].Set(
								pmdEntry.Address()+(pteSize4K*uintptr(index)),
								pmdEntry.Opts())
						}
						pmdEntry.setPageTable(w.pageTables, pteEntries)
					} else {
						// A huge page to be checked directly.
						if !w.visitor.visit(uintptr(start), pmdEntry, pmdSize4K-1) {
							return false
						}

						// Might have been cleared.
						if !pmdEntry.Valid() {
							clearPMDEntries++
						}

						// Note that the huge page was changed.
						start = mapnext(start, pmdSize4K)
						continue
					}

				} else {
					pteEntries = w.pageTables.Allocator.LookupPTEs(pmdEntry.Address())
				}

				// Map the next level, since this is valid.
				clearPTEEntries := uint16(0)

				for pteIndex := uint16((start & pteMask4K) >> pteShift4K); start < end && pteIndex < entriesPerPage4K; pteIndex++ {
					var (
						pteEntry = &pteEntries[pteIndex]
					)
					if !pteEntry.Valid() && !w.visitor.requiresAlloc() {
						clearPTEEntries++
						start += pteSize4K
						continue
					}

					// At this point, we are guaranteed that start%pteSize4K == 0.
					if !w.visitor.visit(uintptr(start), pteEntry, pteSize4K-1) {
						return false
					}
					if !pteEntry.Valid() {
						if w.visitor.requiresAlloc() {
							panic("PTE not set after iteration with requiresAlloc!")
						}
						clearPTEEntries++
					}

					// Note that the pte was changed.
					start += pteSize4K
					continue
				}

				// Check if we no longer need this page.
				if clearPTEEntries == entriesPerPage4K {
					pmdEntry.Clear()
					w.pageTables.Allocator.FreePTEs(pteEntries)
					clearPMDEntries++
				}
			}

			// Check if we no longer need this page.
			if clearPMDEntries == entriesPerPage4K {
				pudEntry.Clear()
				w.pageTables.Allocator.FreePTEs(pmdEntries)
				clearPUDEntries++
			}
		}

		// Check if we no longer need this page.
		if clearPUDEntries == entriesPerPage4K {
			pgdEntry.Clear()
			w.pageTables.Allocator.FreePTEs(pudEntries)
		}
	}
	return true
}

// iterateRangeCanonical64K walks a canonical range in 64K granule page
// tables.
//
// This is a 3-level page table walker for 64K pages:
// PGD -> PMD -> PTE (no PUD level)
//
//go:nosplit
func (w *mapWalker) iterateRangeCanonical64K(start, end uintptr) bool {
	pgdEntryIndex := w.pageTables.root.as64K()
	if start >= upperBottom {
		pgdEntryIndex = w.pageTables.archPageTables.root.as64K()
	}

	for pgdIndex := (uint16((start & pgdMask64K) >> pgdShift64K)); start < end && pgdIndex < entriesPerPage64K; pgdIndex++ {
		var (
			pgdEntry   = &pgdEntryIndex[pgdIndex]
			pmdEntries *ptes64K
		)
		if !pgdEntry.Valid() {
			if !w.visitor.requiresAlloc() {
				// Skip over this entry.
				start = mapnext(start, pgdSize64K)
				continue
			}

			// Allocate a new pgd.
			pmdEntries = w.pageTables.Allocator.NewPTEs().as64K()
			pgdEntry.setPageTable(w.pageTables, pmdEntries.ptes())
		} else {
			pmdEntries = w.pageTables.Allocator.LookupPTEs(pgdEntry.Address()).as64K()
		}

		// Map the next level (PMD -> PTE, no PUD in 64K page mode).
		clearPMDEntries := uint16(0)

		for pmdIndex := uint16((start & pmdMask64K) >> pmdShift64K); start < end && pmdIndex < entriesPerPage64K; pmdIndex++ {
			var (
				pmdEntry   = &pmdEntries[pmdIndex]
				pteEntries *ptes64K
			)
			if !pmdEntry.Valid() {
				if !w.visitor.requiresAlloc() {
					// Skip over this entry.
					clearPMDEntries++
					start = mapnext(start, pmdSize64K)
					continue
				}

				// This level has 512-MB sect pages (for 64K page size).
				// If this region is contained in a single PMD entry,
				// we can skip allocating a new page.
				if start&(pmdSize64K-1) == 0 && end-start >= pmdSize64K {
					pmdEntry.SetSect()
					if !w.visitor.visit(uintptr(start), pmdEntry, pmdSize64K-1) {
						return false
					}
					if pmdEntry.Valid() {
						start = mapnext(start, pmdSize64K)
						continue
					}
				}

				// Allocate a new pmd.
				pteEntries = w.pageTables.Allocator.NewPTEs().as64K()
				pmdEntry.setPageTable(w.pageTables, pteEntries.ptes())

			} else if pmdEntry.IsSect() {
				// Does this page need to be split?
				if w.visitor.requiresSplit() && (start&(pmdSize64K-1) != 0 || end < mapnext(start, pmdSize64K)) {
					// Install the relevant entries.
					pteEntries = w.pageTables.Allocator.NewPTEs().as64K()
					for index := uint16(0); index < entriesPerPage64K; index++ {
						pteEntries[index].Set(
							pmdEntry.Address()+(pteSize64K*uintptr(index)),
							pmdEntry.Opts())
					}
					pmdEntry.setPageTable(w.pageTables, pteEntries.ptes())
				} else {
					// A sect page to be checked directly.
					if !w.visitor.visit(uintptr(start), pmdEntry, pmdSize64K-1) {
						return false
					}

					// Might have been cleared.
					if !pmdEntry.Valid() {
						clearPMDEntries++
					}

					// Note that the sect page was changed.
					start = mapnext(start, pmdSize64K)
					continue
				}

			} else {
				pteEntries = w.pageTables.Allocator.LookupPTEs(pmdEntry.Address()).as64K()
			}

			// Map the next level, since this is valid.
			clearPTEEntries := uint16(0)

			for pteIndex := uint16((start & pteMask64K) >> pteShift64K); start < end && pteIndex < entriesPerPage64K; pteIndex++ {
				var (
					pteEntry = &pteEntries[pteIndex]
				)
				if !pteEntry.Valid() && !w.visitor.requiresAlloc() {
					clearPTEEntries++
					start += pteSize64K
					continue
				}

				// At this point, we are guaranteed that start%pteSize64K == 0.
				if !w.visitor.visit(uintptr(start), pteEntry, pteSize64K-1) {
					return false
				}
				if !pteEntry.Valid() {
					if w.visitor.requiresAlloc() {
						panic("PTE not set after iteration with requiresAlloc!")
					}
					clearPTEEntries++
				}

				// Note that the pte was changed.
				start += pteSize64K
				continue
			}

			// Check if we no longer need this page.
			if clearPTEEntries == entriesPerPage64K {
				pmdEntry.Clear()
				w.pageTables.Allocator.FreePTEs(pteEntries.ptes())
				clearPMDEntries++
			}
		}

		// Check if we no longer need this page.
		if clearPMDEntries == entriesPerPage64K {
			pgdEntry.Clear()
			w.pageTables.Allocator.FreePTEs(pmdEntries.ptes())
		}
	}
	return true
}

// Walker walks page tables.
type mapWalker struct {
	// pageTables are the tables to walk.
	pageTables *PageTables

	// Visitor is the set of arguments.
	visitor mapVisitor
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
func (w *mapWalker) iterateRange(start, end uintptr) {
	if start&(pteSize-1) != 0 {
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
func mapnext(start uintptr, size uintptr) uintptr {
	start &= ^(size - 1)
	start += size
	return start
}
