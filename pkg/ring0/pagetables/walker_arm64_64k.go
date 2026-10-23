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

//go:build arm64
// +build arm64

package pagetables

// iterateRangeCanonical64K walks a canonical range in 64K granule page
// tables.
//
// This is a 3-level page table walker for 64K pages:
// PGD -> PMD -> PTE (no PUD level)
//
// Each page table page holds entriesPerPage64K entries. They are allocated
// and passed around as *PTEs (see allocator.go), and accessed through a
// *ptes64K view here.
//
//go:nosplit
func (w *Walker) iterateRangeCanonical64K(start, end uintptr) bool {
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
				start = next(start, pgdSize64K)
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
					start = next(start, pmdSize64K)
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
						start = next(start, pmdSize64K)
						continue
					}
				}

				// Allocate a new pmd.
				pteEntries = w.pageTables.Allocator.NewPTEs().as64K()
				pmdEntry.setPageTable(w.pageTables, pteEntries.ptes())

			} else if pmdEntry.IsSect() {
				// Does this page need to be split?
				if w.visitor.requiresSplit() && (start&(pmdSize64K-1) != 0 || end < next(start, pmdSize64K)) {
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
					start = next(start, pmdSize64K)
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
