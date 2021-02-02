// Copyright 2018 The gVisor Authors.
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

package pagetables

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

	executeDisable = 1 << 63
	entriesPerPage = 512
)

// InitArch does some additional initialization related to the architecture.
//
// +checkescape:hard,stack
//go:nosplit
func (p *PageTables) InitArch(allocator Allocator) {
	if p.upperSharedPageTables != nil {
		p.cloneUpperShared()
	}
}

//go:nosplit
func pgdIndex(upperStart uintptr) uintptr {
	if upperStart&(pgdSize-1) != 0 {
		panic("upperStart should be pgd size aligned")
	}
	if upperStart >= upperBottom {
		return entriesPerPage/2 + (upperStart-upperBottom)/pgdSize
	}
	if upperStart < lowerTop {
		return upperStart / pgdSize
	}
	panic("upperStart should be in canonical range")
}

// cloneUpperShared clone the upper from the upper shared page tables.
//
//go:nosplit
func (p *PageTables) cloneUpperShared() {
	start := pgdIndex(p.upperStart)
	copy(p.root[start:entriesPerPage], p.upperSharedPageTables.root[start:entriesPerPage])
}

// PTEs is a collection of entries.
type PTEs [entriesPerPage]PTE
