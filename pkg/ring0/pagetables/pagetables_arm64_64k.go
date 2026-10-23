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

package pagetables

// Page table constants for the 64K translation granule (3-level page tables).
//
// With 64K pages, we use a 3-level page table structure:
// - PGD (Page Global Directory)
// - PMD (Page Middle Directory)
// - PTE (Page Table Entry)
//
// Each page table page contains 8192 entries (64K / 8 bytes).
// Each level uses 13 bits for indexing.
//
// Virtual address layout (48-bit):
// [47:42] - PGD index (6 bits, 64 entries at top level)
// [41:29] - PMD index (13 bits, 8192 entries)
// [28:16] - PTE index (13 bits, 8192 entries)
// [15:0]  - Page offset (16 bits, 64K page)
const (
	pteShift64K = 16
	pmdShift64K = 29
	pgdShift64K = 42

	// Mask for 13-bit index (8192 entries)
	pteMask64K = 0x1fff << pteShift64K
	pmdMask64K = 0x1fff << pmdShift64K
	// Top level only has 6 bits (64 entries) for 48-bit VA
	pgdMask64K = 0x3f << pgdShift64K

	pteSize64K = 1 << pteShift64K // 64K
	pmdSize64K = 1 << pmdShift64K // 512M
	pgdSize64K = 1 << pgdShift64K // 4T

	entriesPerPage64K = 8192
)

// ptes64K is a page table page with the 64K translation granule.
//
// Page table pages are allocated and passed around (e.g. through Allocator)
// as *PTEs; use PTEs.as64K to access all of their entries.
type ptes64K [entriesPerPage64K]PTE
