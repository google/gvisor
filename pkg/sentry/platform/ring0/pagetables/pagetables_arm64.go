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

	ttbrASIDOffset = 55
	ttbrASIDMask   = 0xff

	entriesPerPage = 512
)

// Init initializes a set of PageTables.
//
//go:nosplit
func (p *PageTables) Init(allocator Allocator) {
	p.Allocator = allocator
	p.root = p.Allocator.NewPTEs()
	p.rootPhysical = p.Allocator.PhysicalFor(p.root)
	p.archPageTables.root = p.Allocator.NewPTEs()
	p.archPageTables.rootPhysical = p.Allocator.PhysicalFor(p.archPageTables.root)
}

// PTEs is a collection of entries.
type PTEs [entriesPerPage]PTE
