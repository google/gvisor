// Copyright 2018 Google LLC
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

package mm

import (
	"fmt"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/atomicbitops"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// AddressSpace returns the platform.AddressSpace bound to mm.
//
// Preconditions: The caller must have called mm.Activate().
func (mm *MemoryManager) AddressSpace() platform.AddressSpace {
	if atomic.LoadInt32(&mm.active) == 0 {
		panic("trying to use inactive address space?")
	}
	return mm.as
}

// Activate ensures this MemoryManager has a platform.AddressSpace.
//
// The caller must not hold any locks when calling Activate.
//
// When this MemoryManager is no longer needed by a task, it should call
// Deactivate to release the reference.
func (mm *MemoryManager) Activate() error {
	// Fast path: the MemoryManager already has an active
	// platform.AddressSpace, and we just need to indicate that we need it too.
	if atomicbitops.IncUnlessZeroInt32(&mm.active) {
		return nil
	}

	for {
		// Slow path: may need to synchronize with other goroutines changing
		// mm.active to or from zero.
		mm.activeMu.Lock()
		// Inline Unlock instead of using a defer for performance since this
		// method is commonly in the hot-path.

		// Check if we raced with another goroutine performing activation.
		if atomic.LoadInt32(&mm.active) > 0 {
			// This can't race; Deactivate can't decrease mm.active from 1 to 0
			// without holding activeMu.
			atomic.AddInt32(&mm.active, 1)
			mm.activeMu.Unlock()
			return nil
		}

		// Do we have a context? If so, then we never unmapped it. This can
		// only be the case if !mm.p.CooperativelySchedulesAddressSpace().
		if mm.as != nil {
			atomic.StoreInt32(&mm.active, 1)
			mm.activeMu.Unlock()
			return nil
		}

		// Get a new address space. We must force unmapping by passing nil to
		// NewAddressSpace if requested. (As in the nil interface object, not a
		// typed nil.)
		mappingsID := (interface{})(mm)
		if mm.unmapAllOnActivate {
			mappingsID = nil
		}
		as, c, err := mm.p.NewAddressSpace(mappingsID)
		if err != nil {
			mm.activeMu.Unlock()
			return err
		}
		if as == nil {
			// AddressSpace is unavailable, we must wait.
			//
			// activeMu must not be held while waiting, as the user
			// of the address space we are waiting on may attempt
			// to take activeMu.
			//
			// Don't call UninterruptibleSleepStart to register the
			// wait to allow the watchdog stuck task to trigger in
			// case a process is starved waiting for the address
			// space.
			mm.activeMu.Unlock()
			<-c
			continue
		}

		// Okay, we could restore all mappings at this point.
		// But forget that. Let's just let them fault in.
		mm.as = as

		// Unmapping is done, if necessary.
		mm.unmapAllOnActivate = false

		// Now that m.as has been assigned, we can set m.active to a non-zero value
		// to enable the fast path.
		atomic.StoreInt32(&mm.active, 1)

		mm.activeMu.Unlock()
		return nil
	}
}

// Deactivate releases a reference to the MemoryManager.
func (mm *MemoryManager) Deactivate() {
	// Fast path: this is not the last goroutine to deactivate the
	// MemoryManager.
	if atomicbitops.DecUnlessOneInt32(&mm.active) {
		return
	}

	mm.activeMu.Lock()
	// Same as Activate.

	// Still active?
	if atomic.AddInt32(&mm.active, -1) > 0 {
		mm.activeMu.Unlock()
		return
	}

	// Can we hold on to the address space?
	if !mm.p.CooperativelySchedulesAddressSpace() {
		mm.activeMu.Unlock()
		return
	}

	// Release the address space.
	mm.as.Release()

	// Lost it.
	mm.as = nil
	mm.activeMu.Unlock()
}

// mapASLocked maps addresses in ar into mm.as. If precommit is true, mappings
// for all addresses in ar should be precommitted.
//
// Preconditions: mm.activeMu must be locked. mm.as != nil. ar.Length() != 0.
// ar must be page-aligned. pseg.Range().Contains(ar.Start).
func (mm *MemoryManager) mapASLocked(pseg pmaIterator, ar usermem.AddrRange, precommit bool) error {
	// By default, map entire pmas at a time, under the assumption that there
	// is no cost to mapping more of a pma than necessary.
	mapAR := usermem.AddrRange{0, ^usermem.Addr(usermem.PageSize - 1)}
	if precommit {
		// When explicitly precommitting, only map ar, since overmapping may
		// incur unexpected resource usage.
		mapAR = ar
	} else if mapUnit := mm.p.MapUnit(); mapUnit != 0 {
		// Limit the range we map to ar, aligned to mapUnit.
		mapMask := usermem.Addr(mapUnit - 1)
		mapAR.Start = ar.Start &^ mapMask
		// If rounding ar.End up overflows, just keep the existing mapAR.End.
		if end := (ar.End + mapMask) &^ mapMask; end >= ar.End {
			mapAR.End = end
		}
	}
	if checkInvariants {
		if !mapAR.IsSupersetOf(ar) {
			panic(fmt.Sprintf("mapAR %#v is not a superset of ar %#v", mapAR, ar))
		}
	}

	for {
		pma := pseg.ValuePtr()
		pmaAR := pseg.Range()
		pmaMapAR := pmaAR.Intersect(mapAR)
		perms := pma.vmaEffectivePerms
		if pma.needCOW {
			perms.Write = false
		}
		if err := pma.file.MapInto(mm.as, pmaMapAR.Start, pseg.fileRangeOf(pmaMapAR), perms, precommit); err != nil {
			return err
		}
		// Since this checks ar.End and not mapAR.End, we will never map a pma
		// that is not required.
		if ar.End <= pmaAR.End {
			return nil
		}
		pseg = pseg.NextSegment()
	}
}

// unmapASLocked removes all AddressSpace mappings for addresses in ar.
//
// Preconditions: mm.activeMu must be locked.
func (mm *MemoryManager) unmapASLocked(ar usermem.AddrRange) {
	if mm.as == nil {
		// No AddressSpace? Force all mappings to be unmapped on the next
		// Activate.
		mm.unmapAllOnActivate = true
		return
	}

	// unmapASLocked doesn't require vmas or pmas to exist for ar, so it can be
	// passed ranges that include addresses that can't be mapped by the
	// application.
	ar = ar.Intersect(mm.applicationAddrRange())

	// Note that this AddressSpace may or may not be active. If the
	// platform does not require cooperative sharing of AddressSpaces, they
	// are retained between Deactivate/Activate calls. Despite not being
	// active, it is still valid to perform operations on these address
	// spaces.
	mm.as.Unmap(ar.Start, uint64(ar.Length()))
}
