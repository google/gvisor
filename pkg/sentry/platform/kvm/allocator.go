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

package kvm

import (
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables"
)

type allocator struct {
	base *pagetables.RuntimeAllocator
}

// newAllocator is used to define the allocator.
func newAllocator() allocator {
	return allocator{
		base: pagetables.NewRuntimeAllocator(),
	}
}

// NewPTEs implements pagetables.Allocator.NewPTEs.
//
//go:nosplit
func (a allocator) NewPTEs() *pagetables.PTEs {
	return a.base.NewPTEs()
}

// PhysicalFor returns the physical address for a set of PTEs.
//
//go:nosplit
func (a allocator) PhysicalFor(ptes *pagetables.PTEs) uintptr {
	virtual := a.base.PhysicalFor(ptes)
	physical, _, ok := translateToPhysical(virtual)
	if !ok {
		panic(fmt.Sprintf("PhysicalFor failed for %p", ptes))
	}
	return physical
}

// LookupPTEs implements pagetables.Allocator.LookupPTEs.
//
//go:nosplit
func (a allocator) LookupPTEs(physical uintptr) *pagetables.PTEs {
	virtualStart, physicalStart, _, ok := calculateBluepillFault(physical)
	if !ok {
		panic(fmt.Sprintf("LookupPTEs failed for 0x%x", physical))
	}
	return a.base.LookupPTEs(virtualStart + (physical - physicalStart))
}

// FreePTEs implements pagetables.Allocator.FreePTEs.
//
//go:nosplit
func (a allocator) FreePTEs(ptes *pagetables.PTEs) {
	a.base.FreePTEs(ptes)
}

// Recycle implements pagetables.Allocator.Recycle.
//
//go:nosplit
func (a allocator) Recycle() {
	a.base.Recycle()
}
