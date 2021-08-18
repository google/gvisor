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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sync"
)

// dirtySet tracks vCPUs for invalidation.
type dirtySet struct {
	vCPUMasks []uint64
}

// forEach iterates over all CPUs in the dirty set.
//
//go:nosplit
func (ds *dirtySet) forEach(m *machine, fn func(c *vCPU)) {
	for index := range ds.vCPUMasks {
		mask := atomic.SwapUint64(&ds.vCPUMasks[index], 0)
		if mask != 0 {
			for bit := 0; bit < 64; bit++ {
				if mask&(1<<uint64(bit)) == 0 {
					continue
				}
				id := 64*index + bit
				fn(m.vCPUsByID[id])
			}
		}
	}
}

// mark marks the given vCPU as dirty and returns whether it was previously
// clean. Being previously clean implies that a flush is needed on entry.
func (ds *dirtySet) mark(c *vCPU) bool {
	index := uint64(c.id) / 64
	bit := uint64(1) << uint(c.id%64)

	oldValue := atomic.LoadUint64(&ds.vCPUMasks[index])
	if oldValue&bit != 0 {
		return false // Not clean.
	}

	// Set the bit unilaterally, and ensure that a flush takes place. Note
	// that it's possible for races to occur here, but since the flush is
	// taking place long after these lines there's no race in practice.
	atomicbitops.OrUint64(&ds.vCPUMasks[index], bit)
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
	dirtySet *dirtySet
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

// mapLocked maps the given host entry.
//
// +checkescape:hard,stack
//
//go:nosplit
func (as *addressSpace) mapLocked(addr hostarch.Addr, m hostMapEntry, at hostarch.AccessType) (inv bool) {
	for m.length > 0 {
		physical, length, ok := translateToPhysical(m.addr)
		if !ok {
			panic("unable to translate segment")
		}
		if length > m.length {
			length = m.length
		}

		// Install the page table mappings. Note that the ordering is
		// important; if the pagetable mappings were installed before
		// ensuring the physical pages were available, then some other
		// thread could theoretically access them.
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

	// See block in mapLocked.
	as.pageTables.Allocator.(*allocator).cpu = as.machine.Get()
	defer as.machine.Put(as.pageTables.Allocator.(*allocator).cpu)

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

		// See bluepill_allocator.go.
		bluepill(as.pageTables.Allocator.(*allocator).cpu)

		// Perform the mapping.
		prev := as.mapLocked(addr, hostMapEntry{
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

// unmapLocked is an escape-checked wrapped around Unmap.
//
// +checkescape:hard,stack
//
//go:nosplit
func (as *addressSpace) unmapLocked(addr hostarch.Addr, length uint64) bool {
	return as.pageTables.Unmap(addr, uintptr(length))
}

// Unmap unmaps the given range by calling pagetables.PageTables.Unmap.
func (as *addressSpace) Unmap(addr hostarch.Addr, length uint64) {
	as.mu.Lock()
	defer as.mu.Unlock()

	// See above & bluepill_allocator.go.
	as.pageTables.Allocator.(*allocator).cpu = as.machine.Get()
	defer as.machine.Put(as.pageTables.Allocator.(*allocator).cpu)
	bluepill(as.pageTables.Allocator.(*allocator).cpu)

	if prev := as.unmapLocked(addr, length); prev {
		// Invalidate all active vCPUs.
		as.invalidate()

		// Recycle any freed intermediate pages.
		as.pageTables.Allocator.Recycle()
	}
}

// Release releases the page tables.
func (as *addressSpace) Release() {
	as.Unmap(0, ^uint64(0))

	// Free all pages from the allocator.
	as.pageTables.Allocator.(*allocator).base.Drain()

	// Drop all cached machine references.
	as.machine.dropPageTables(as.pageTables)
}

// PreFork implements platform.AddressSpace.PreFork.
func (as *addressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (as *addressSpace) PostFork() {}
