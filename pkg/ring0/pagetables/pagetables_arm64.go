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

package pagetables

import (
	"gvisor.dev/gvisor/pkg/hostarch"
)

// Address space layout constants shared by all ARM64 page sizes.
const (
	lowerTop    = 0x0001000000000000
	upperBottom = 0xffff000000000000

	ttbrASIDOffset = 48
	ttbrASIDMask   = 0xff
)

// granule identifies an ARM64 translation granule.
type granule uint8

const (
	granule4K granule = iota
	granule64K
)

// pageSize returns the page size for g.
func (g granule) pageSize() uintptr {
	switch g {
	case granule4K:
		return pteSize4K
	case granule64K:
		return pteSize64K
	default:
		panic("unknown translation granule")
	}
}

func hostGranule() granule {
	switch hostarch.PageSize {
	case pteSize4K:
		return granule4K
	case pteSize64K:
		return granule64K
	default:
		panic("unsupported host page size")
	}
}

// The translation granule (and thus the page table layout) is selected at
// runtime to match the host page size.
var (
	// activeGranule is the translation granule in use. It matches
	// hostarch.PageSize and only tests change it.
	activeGranule = hostGranule()

	// pteSize is the size of the memory mapped by a last-level page table
	// entry (i.e. the page size), which is also the size of a page table
	// page.
	pteSize uintptr = activeGranule.pageSize()
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
