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

package slimvm

import (
	"sync"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

type vCPUBitArray [(_SLIMVM_NR_VCPUS + 63) / 64]atomicbitops.Uint64
type vCPUBitArrayLocal [(_SLIMVM_NR_VCPUS + 63) / 64]uint64

// dirtySet tracks vCPUs for invalidation.
type dirtySet struct {
	vCPUs vCPUBitArray
}

// forEach iterates over all CPUs in the dirty set.
func (ds *dirtySet) forEach(m *machine, fn func(c *vCPU)) {
	var localSet vCPUBitArrayLocal
	for index := 0; index < len(ds.vCPUs); index++ {
		// Clear the dirty set, copy to the local one.
		localSet[index] = ds.vCPUs[index].Swap(0)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.vCPUs {
		index := uint64(c.id) / 64
		bit := uint64(1) << uint(c.id%64)

		// Call the function if it was set.
		if localSet[index]&bit != 0 {
			fn(c)
		}
	}
}

// mark marks the given vCPU as dirty and returns whether it was previously
// clean. Being previously clean implies that a flush is needed on entry.
func (ds *dirtySet) mark(c *vCPU) bool {
	index := uint64(c.id) / 64
	bit := uint64(1) << uint(c.id%64)

	oldValue := ds.vCPUs[index].Load()
	if oldValue&bit != 0 {
		return false // Not clean.
	}

	// Set the bit unilaterally, and ensure that a flush takes place. Note
	// that it's possible for races to occur here, but since the flush is
	// taking place long after these lines there's no race in practice.
	atomicbitops.OrUint64(&ds.vCPUs[index], bit)
	return true // Previously clean.
}

// addressSpace is a wrapper for PageTables.
type addressSpace struct {
	platform.NoAddressSpaceIO

	// mu is the lock for modifications to the address space.
	//
	// Note that the page tables themselves are not locked.
	mu sync.Mutex

	// machine is the underlying machine.
	machine *machine

	// pageTables are for this particular address space.
	pageTables *pagetables.PageTables

	// dirtySet is the set of dirty vCPUs.
	dirtySet dirtySet

	// pcid associated with this address space.
	pcid uint16
}

// invalidate is the implementation for Invalidate.
func (as *addressSpace) invalidate() {
	as.dirtySet.forEach(as.machine, func(c *vCPU) {
		if c.active.get() == as { // If this happens to be active,
			c.BounceToKernel() // ... force a kernel transition.
		}
	})
}

// Invalidate interrupts all dirty contexts.
func (as *addressSpace) Invalidate() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.invalidate()
}

// Touch adds the given vCPU to the dirty list.
//
// The return value indicates whether a flush is required.
func (as *addressSpace) Touch(c *vCPU) bool {
	return as.dirtySet.mark(c)
}

type hostMapEntry struct {
	addr   uintptr
	length uintptr
}

func (as *addressSpace) mapHost(addr hostarch.Addr, m hostMapEntry, at hostarch.AccessType) (inv bool) {
	for m.length > 0 {
		physical, length, ok := translateToPhysical(m.addr)
		if !ok {
			panic("unable to translate segment")
		}
		if length > m.length {
			length = m.length
		}

		inv = as.pageTables.Map(addr, length, pagetables.MapOpts{
			AccessType: at,
			User:       true,
		}, physical) || inv
		m.addr += length
		m.length -= length
		addr += hostarch.Addr(length)
	}

	return inv
}

// MapFile implements platform.AddressSpace.MapFile.
func (as *addressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	// Get mappings in the sentry's address space, which are guaranteed to be
	// valid as long as a reference is held on the mapped pages (which is in
	// turn required by AddressSpace.MapFile precondition).
	//
	// If precommit is true, we will touch mappings to commit them, so ensure
	// that mappings are readable from sentry context.
	//
	// We don't execute from application file-mapped memory, and guest page
	// tables don't care if we have execute permission (but they do need pages
	// to be readable).
	bs, err := f.MapInternal(fr, hostarch.AccessType{
		Read:  at.Read || at.Execute || precommit,
		Write: at.Write,
	})
	if err != nil {
		return err
	}

	// Map the mappings in the sentry's address space (guest physical memory)
	// into the application's address space (guest virtual memory).
	inv := false
	for !bs.IsEmpty() {
		b := bs.Head()
		bs = bs.Tail()
		// Since fr was page-aligned, b should also be page-aligned. We do the
		// lookup in our host page tables for this translation.
		if precommit {
			s := b.ToSlice()
			for i := 0; i < len(s); i += hostarch.PageSize {
				_ = s[i] // Touch to commit.
			}
		}
		prev := as.mapHost(addr, hostMapEntry{
			addr:   b.Addr(),
			length: uintptr(b.Len()),
		}, at)
		inv = inv || prev
		addr += hostarch.Addr(b.Len())
	}
	if inv {
		as.invalidate()
	}

	return nil
}

// Unmap unmaps the given range by calling pagetables.PageTables.Unmap.
func (as *addressSpace) Unmap(addr hostarch.Addr, length uint64) {
	as.mu.Lock()
	defer as.mu.Unlock()

	if as.pageTables.Unmap(addr, uintptr(length)) {
		as.invalidate()

		// Recycle any freed intermediate pages.
		as.pageTables.Allocator.Recycle()
	}
}

// PreFork implements platform.AddressSpace.PreFork.
func (as *addressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (as *addressSpace) PostFork() {}
