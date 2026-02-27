// Copyright 2026 The gVisor Authors.
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

//go:build arm64 && pagesize_64k
// +build arm64,pagesize_64k

package pagetables

// iterateRangeCanonical walks a canonical range.
//
// This is a 3-level page table walker for 64K pages:
// PGD -> PMD -> PTE (no PUD level)
//
//go:nosplit
func (w *Walker) iterateRangeCanonical(start, end uintptr) bool {
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
				// Skip over this entry.
				start = next(start, pgdSize)
				continue
			}

			// Allocate a new pgd.
			pmdEntries = w.pageTables.Allocator.NewPTEs()
			pgdEntry.setPageTable(w.pageTables, pmdEntries)
		} else {
			pmdEntries = w.pageTables.Allocator.LookupPTEs(pgdEntry.Address())
		}

		// Map the next level (PMD -> PTE, no PUD in 64K page mode).
		clearPMDEntries := uint16(0)

		for pmdIndex := uint16((start & pmdMask) >> pmdShift); start < end && pmdIndex < entriesPerPage; pmdIndex++ {
			var (
				pmdEntry   = &pmdEntries[pmdIndex]
				pteEntries *PTEs
			)
			if !pmdEntry.Valid() {
				if !w.visitor.requiresAlloc() {
					// Skip over this entry.
					clearPMDEntries++
					start = next(start, pmdSize)
					continue
				}

				// This level has 512-MB sect pages (for 64K page size).
				// If this region is contained in a single PMD entry,
				// we can skip allocating a new page.
				if start&(pmdSize-1) == 0 && end-start >= pmdSize {
					pmdEntry.SetSect()
					if !w.visitor.visit(uintptr(start), pmdEntry, pmdSize-1) {
						return false
					}
					if pmdEntry.Valid() {
						start = next(start, pmdSize)
						continue
					}
				}

				// Allocate a new pmd.
				pteEntries = w.pageTables.Allocator.NewPTEs()
				pmdEntry.setPageTable(w.pageTables, pteEntries)

			} else if pmdEntry.IsSect() {
				// Does this page need to be split?
				if w.visitor.requiresSplit() && (start&(pmdSize-1) != 0 || end < next(start, pmdSize)) {
					// Install the relevant entries.
					pteEntries = w.pageTables.Allocator.NewPTEs()
					for index := uint16(0); index < entriesPerPage; index++ {
						pteEntries[index].Set(
							pmdEntry.Address()+(pteSize*uintptr(index)),
							pmdEntry.Opts())
					}
					pmdEntry.setPageTable(w.pageTables, pteEntries)
				} else {
					// A sect page to be checked directly.
					if !w.visitor.visit(uintptr(start), pmdEntry, pmdSize-1) {
						return false
					}

					// Might have been cleared.
					if !pmdEntry.Valid() {
						clearPMDEntries++
					}

					// Note that the sect page was changed.
					start = next(start, pmdSize)
					continue
				}

			} else {
				pteEntries = w.pageTables.Allocator.LookupPTEs(pmdEntry.Address())
			}

			// Map the next level, since this is valid.
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

				// At this point, we are guaranteed that start%pteSize == 0.
				if !w.visitor.visit(uintptr(start), pteEntry, pteSize-1) {
					return false
				}
				if !pteEntry.Valid() {
					if w.visitor.requiresAlloc() {
						panic("PTE not set after iteration with requiresAlloc!")
					}
					clearPTEEntries++
				}

				// Note that the pte was changed.
				start += pteSize
				continue
			}

			// Check if we no longer need this page.
			if clearPTEEntries == entriesPerPage {
				pmdEntry.Clear()
				w.pageTables.Allocator.FreePTEs(pteEntries)
				clearPMDEntries++
			}
		}

		// Check if we no longer need this page.
		if clearPMDEntries == entriesPerPage {
			pgdEntry.Clear()
			w.pageTables.Allocator.FreePTEs(pmdEntries)
		}
	}
	return true
}
