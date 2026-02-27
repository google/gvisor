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

package pagetables

// Page table constants for 64K page size (3-level page tables).
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
	pteShift = 16
	pmdShift = 29
	pgdShift = 42

	// Mask for 13-bit index (8192 entries)
	pteMask = 0x1fff << pteShift
	pmdMask = 0x1fff << pmdShift
	// Top level only has 6 bits (64 entries) for 48-bit VA
	pgdMask = 0x3f << pgdShift

	pteSize = 1 << pteShift // 64K
	pmdSize = 1 << pmdShift // 512M
	pgdSize = 1 << pgdShift // 4T

	entriesPerPage = 8192
)

// PTEs is a collection of entries.
type PTEs [entriesPerPage]PTE
