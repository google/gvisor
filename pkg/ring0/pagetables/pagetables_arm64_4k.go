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

// Page table constants for the 4K translation granule (4-level page tables).
const (
	pteShift4K = 12
	pmdShift4K = 21
	pudShift4K = 30
	pgdShift4K = 39

	pteMask4K = 0x1ff << pteShift4K
	pmdMask4K = 0x1ff << pmdShift4K
	pudMask4K = 0x1ff << pudShift4K
	pgdMask4K = 0x1ff << pgdShift4K

	pteSize4K = 1 << pteShift4K
	pmdSize4K = 1 << pmdShift4K
	pudSize4K = 1 << pudShift4K
	pgdSize4K = 1 << pgdShift4K

	entriesPerPage4K = 512
)

// PTEs is a collection of entries.
//
// With the 4K translation granule, a page table page is exactly one PTEs.
// With the 64K translation granule, a page table page holds entriesPerPage64K
// entries, and only its first entriesPerPage4K entries can be accessed
// through a PTEs; see ptes64K.
type PTEs [entriesPerPage4K]PTE
