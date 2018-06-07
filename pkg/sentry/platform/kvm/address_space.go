// Copyright 2018 Google Inc.
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
	"reflect"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/filemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// addressSpace is a wrapper for PageTables.
type addressSpace struct {
	platform.NoAddressSpaceIO

	// mu is the lock for modifications to the address space.
	//
	// Note that the page tables themselves are not locked.
	mu sync.Mutex

	// filemem is the memory instance.
	filemem *filemem.FileMem

	// machine is the underlying machine.
	machine *machine

	// pageTables are for this particular address space.
	pageTables *pagetables.PageTables

	// dirtySet is the set of dirty vCPUs.
	//
	// These are actually vCPU pointers that are stored iff the vCPU is
	// dirty. If the vCPU is not dirty and requires invalidation, then a
	// nil value is stored here instead.
	dirtySet dirtySet

	// files contains files mapped in the host address space.
	//
	// See host_map.go for more information.
	files hostMap
}

// invalidate is the implementation for Invalidate.
func (as *addressSpace) invalidate() {
	for i := 0; i < as.dirtySet.size(); i++ {
		if c := as.dirtySet.swap(i, nil); c != nil && c.active.get() == as {
			c.BounceToKernel() // Force a kernel transition.
		}
	}
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
	if old := as.dirtySet.swap(c.id, c); old == nil {
		return true // Flush is required.
	}
	// Already dirty: no flush required.
	return false
}

func (as *addressSpace) mapHost(addr usermem.Addr, m hostMapEntry, at usermem.AccessType) (inv bool) {
	for m.length > 0 {
		physical, length, ok := translateToPhysical(m.addr)
		if !ok {
			panic("unable to translate segment")
		}
		if length > m.length {
			length = m.length
		}

		// Ensure that this map has physical mappings. If the page does
		// not have physical mappings, the KVM module may inject
		// spurious exceptions when emulation fails (i.e. it tries to
		// emulate because the RIP is pointed at those pages).
		as.machine.mapPhysical(physical, length)

		// Install the page table mappings. Note that the ordering is
		// important; if the pagetable mappings were installed before
		// ensuring the physical pages were available, then some other
		// thread could theoretically access them.
		prev := as.pageTables.Map(addr, length, pagetables.MapOpts{
			AccessType: at,
			User:       true,
		}, physical)
		inv = inv || prev
		m.addr += length
		m.length -= length
		addr += usermem.Addr(length)
	}

	return inv
}

func (as *addressSpace) mapHostFile(addr usermem.Addr, fd int, fr platform.FileRange, at usermem.AccessType) error {
	// Create custom host mappings.
	ms, err := as.files.CreateMappings(usermem.AddrRange{
		Start: addr,
		End:   addr + usermem.Addr(fr.End-fr.Start),
	}, at, fd, fr.Start)
	if err != nil {
		return err
	}

	inv := false
	for _, m := range ms {
		// The host mapped slices are guaranteed to be aligned.
		prev := as.mapHost(addr, m, at)
		inv = inv || prev
		addr += usermem.Addr(m.length)
	}
	if inv {
		as.invalidate()
	}

	return nil
}

func (as *addressSpace) mapFilemem(addr usermem.Addr, fr platform.FileRange, at usermem.AccessType, precommit bool) error {
	// TODO: Lock order at the platform level is not sufficiently
	// well-defined to guarantee that the caller (FileMem.MapInto) is not
	// holding any locks that FileMem.MapInternal may take.

	// Retrieve mappings for the underlying filemem. Note that the
	// permissions here are largely irrelevant, since it corresponds to
	// physical memory for the guest. We enforce the given access type
	// below, in the guest page tables.
	bs, err := as.filemem.MapInternal(fr, usermem.AccessType{
		Read:  true,
		Write: true,
	})
	if err != nil {
		return err
	}

	// Save the original range for invalidation.
	orig := usermem.AddrRange{
		Start: addr,
		End:   addr + usermem.Addr(fr.End-fr.Start),
	}

	inv := false
	for !bs.IsEmpty() {
		b := bs.Head()
		bs = bs.Tail()
		// Since fr was page-aligned, b should also be page-aligned. We do the
		// lookup in our host page tables for this translation.
		s := b.ToSlice()
		if precommit {
			for i := 0; i < len(s); i += usermem.PageSize {
				_ = s[i] // Touch to commit.
			}
		}
		prev := as.mapHost(addr, hostMapEntry{
			addr:   reflect.ValueOf(&s[0]).Pointer(),
			length: uintptr(len(s)),
		}, at)
		inv = inv || prev
		addr += usermem.Addr(len(s))
	}
	if inv {
		as.invalidate()
		as.files.DeleteMapping(orig)
	}

	return nil
}

// MapFile implements platform.AddressSpace.MapFile.
func (as *addressSpace) MapFile(addr usermem.Addr, fd int, fr platform.FileRange, at usermem.AccessType, precommit bool) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	// Create an appropriate mapping. If this is filemem, we don't create
	// custom mappings for each in-application mapping. For files however,
	// we create distinct mappings for each address space. Unfortunately,
	// there's not a better way to manage this here. The file underlying
	// this fd can change at any time, so we can't actually index the file
	// and share between address space. Oh well. It's all referring to the
	// same physical pages, hopefully we don't run out of address space.
	if fd != int(as.filemem.File().Fd()) {
		// N.B. precommit is ignored for host files.
		return as.mapHostFile(addr, fd, fr, at)
	}

	return as.mapFilemem(addr, fr, at, precommit)
}

// Unmap unmaps the given range by calling pagetables.PageTables.Unmap.
func (as *addressSpace) Unmap(addr usermem.Addr, length uint64) {
	as.mu.Lock()
	defer as.mu.Unlock()

	if prev := as.pageTables.Unmap(addr, uintptr(length)); prev {
		as.invalidate()
		as.files.DeleteMapping(usermem.AddrRange{
			Start: addr,
			End:   addr + usermem.Addr(length),
		})
	}
}

// Release releases the page tables.
func (as *addressSpace) Release() {
	as.Unmap(0, ^uint64(0))

	// Free all pages from the allocator.
	as.pageTables.Allocator.(allocator).base.Drain()

	// Drop all cached machine references.
	as.machine.dropPageTables(as.pageTables)
}
