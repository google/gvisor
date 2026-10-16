// Copyright 2019 The gVisor Authors.
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

//go:build arm64
// +build arm64

package pagetables

// iterateRangeCanonical walks a canonical range.
//
// The page table layout depends on the translation granule, which is
// selected at runtime to match the host page size. With 64K pages, the walk
// is delegated to iterateRangeCanonical64K. With 4K pages, this is a 4-level
// page table walker: PGD -> PUD -> PMD -> PTE. (It is implemented here rather
// than in a separate function to avoid an additional call on that path.)
//
//go:nosplit
func (w *Walker) iterateRangeCanonical(start, end uintptr) bool {
	if granule64K {
		return w.iterateRangeCanonical64K(start, end)
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
				start = next(start, pgdSize4K)
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
					start = next(start, pudSize4K)
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
						start = next(start, pudSize4K)
						continue
					}
				}

				// Allocate a new pud.
				pmdEntries = w.pageTables.Allocator.NewPTEs()
				pudEntry.setPageTable(w.pageTables, pmdEntries)

			} else if pudEntry.IsSect() {
				// Does this page need to be split?
				if w.visitor.requiresSplit() && (start&(pudSize4K-1) != 0 || end < next(start, pudSize4K)) {
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
					start = next(start, pudSize4K)
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
						start = next(start, pmdSize4K)
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
							start = next(start, pmdSize4K)
							continue
						}
					}

					// Allocate a new pmd.
					pteEntries = w.pageTables.Allocator.NewPTEs()
					pmdEntry.setPageTable(w.pageTables, pteEntries)

				} else if pmdEntry.IsSect() {
					// Does this page need to be split?
					if w.visitor.requiresSplit() && (start&(pmdSize4K-1) != 0 || end < next(start, pmdSize4K)) {
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
						start = next(start, pmdSize4K)
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
