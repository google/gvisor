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

package pagetables

// Address constraints.
//
// The lowerTop and upperBottom currently apply to four-level pagetables;
// additional refactoring would be necessary to support five-level pagetables.
const (
	lowerTop    = 0x0000ffffffffffff
	upperBottom = 0xffff000000000000
	pteShift    = 12
	pmdShift    = 21
	pudShift    = 30
	pgdShift    = 39

	pteMask = 0x1ff << pteShift
	pmdMask = 0x1ff << pmdShift
	pudMask = 0x1ff << pudShift
	pgdMask = 0x1ff << pgdShift

	pteSize = 1 << pteShift
	pmdSize = 1 << pmdShift
	pudSize = 1 << pudShift
	pgdSize = 1 << pgdShift

	ttbrASIDOffset = 48
	ttbrASIDMask   = 0xff

	entriesPerPage = 512
)

// InitArch does some additional initialization related to the architecture.
//
// +checkescape:hard,stack
//
//go:nosplit
func (p *PageTables) InitArch(allocator Allocator) {
	if p.upperSharedPageTables != nil {
		p.cloneUpperShared()
	} else {
		p.archPageTables.root = p.Allocator.NewPTEs()
		p.archPageTables.rootPhysical = p.Allocator.PhysicalFor(p.archPageTables.root)
	}
}

// cloneUpperShared clone the upper from the upper shared page tables.
//
//go:nosplit
func (p *PageTables) cloneUpperShared() {
	if p.upperStart != upperBottom {
		panic("upperStart should be the same as upperBottom")
	}

	p.archPageTables.root = p.upperSharedPageTables.archPageTables.root
	p.archPageTables.rootPhysical = p.upperSharedPageTables.archPageTables.rootPhysical
}

// PTEs is a collection of entries.
type PTEs [entriesPerPage]PTE
