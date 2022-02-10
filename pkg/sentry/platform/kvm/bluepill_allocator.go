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

	"gvisor.dev/gvisor/pkg/ring0/pagetables"
)

type allocator struct {
	base pagetables.RuntimeAllocator

	// cpu must be set prior to any pagetable operation.
	//
	// Due to the way KVM's shadow paging implementation works,
	// modifications to the page tables while in host mode may not be
	// trapped, leading to the shadow pages being out of sync.  Therefore,
	// we need to ensure that we are in guest mode for page table
	// modifications. See the call to bluepill, below.
	cpu *vCPU
}

// newAllocator is used to define the allocator.
func newAllocator() *allocator {
	a := new(allocator)
	a.base.Init()
	return a
}

// NewPTEs implements pagetables.Allocator.NewPTEs.
//
// +checkescape:all
//
//go:nosplit
func (a *allocator) NewPTEs() *pagetables.PTEs {
	ptes := a.base.NewPTEs() // escapes: bluepill below.
	if a.cpu != nil {
		bluepill(a.cpu)
	}
	return ptes
}

// PhysicalFor returns the physical address for a set of PTEs.
//
// +checkescape:all
//
//go:nosplit
func (a *allocator) PhysicalFor(ptes *pagetables.PTEs) uintptr {
	virtual := a.base.PhysicalFor(ptes)
	physical, _, ok := translateToPhysical(virtual)
	if !ok {
		panic(fmt.Sprintf("PhysicalFor failed for %p", ptes)) // escapes: panic.
	}
	return physical
}

// LookupPTEs implements pagetables.Allocator.LookupPTEs.
//
// +checkescape:all
//
//go:nosplit
func (a *allocator) LookupPTEs(physical uintptr) *pagetables.PTEs {
	virtualStart, physicalStart, _, pr := calculateBluepillFault(physical, physicalRegions)
	if pr == nil {
		panic(fmt.Sprintf("LookupPTEs failed for 0x%x", physical)) // escapes: panic.
	}
	return a.base.LookupPTEs(virtualStart + (physical - physicalStart))
}

// FreePTEs implements pagetables.Allocator.FreePTEs.
//
// +checkescape:all
//
//go:nosplit
func (a *allocator) FreePTEs(ptes *pagetables.PTEs) {
	a.base.FreePTEs(ptes) // escapes: bluepill below.
	if a.cpu != nil {
		bluepill(a.cpu)
	}
}

// Recycle implements pagetables.Allocator.Recycle.
//
//go:nosplit
func (a *allocator) Recycle() {
	a.base.Recycle()
}
