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

package mm

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// AddressSpace returns the platform.AddressSpace bound to mm.
//
// Preconditions: The caller must have called mm.Activate().
func (mm *MemoryManager) AddressSpace() platform.AddressSpace {
	if mm.active.Load() == 0 {
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
func (mm *MemoryManager) Activate(ctx context.Context) error {
	// Fast path: the MemoryManager already has an active
	// platform.AddressSpace, and we just need to indicate that we need it too.
	for {
		active := mm.active.Load()
		if active == 0 {
			// Fall back to the slow path.
			break
		}
		if mm.active.CompareAndSwap(active, active+1) {
			return nil
		}
	}

	for {
		// Slow path: may need to synchronize with other goroutines changing
		// mm.active to or from zero.
		mm.activeMu.Lock()
		// Inline Unlock instead of using a defer for performance since this
		// method is commonly in the hot-path.

		// Check if we raced with another goroutine performing activation.
		if mm.active.Load() > 0 {
			// This can't race; Deactivate can't decrease mm.active from 1 to 0
			// without holding activeMu.
			mm.active.Add(1)
			mm.activeMu.Unlock()
			return nil
		}

		// Do we have a context? If so, then we never unmapped it. This can
		// only be the case if !mm.p.CooperativelySchedulesAddressSpace().
		if mm.as != nil {
			mm.active.Store(1)
			mm.activeMu.Unlock()
			return nil
		}

		// Get a new address space. We must force unmapping by passing nil to
		// NewAddressSpace if requested. (As in the nil interface object, not a
		// typed nil.)
		mappingsID := (any)(mm)
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
			// activeMu must not be held while waiting, as the user of the address
			// space we are waiting on may attempt to take activeMu.
			mm.activeMu.Unlock()

			sleep := mm.p.CooperativelySchedulesAddressSpace() && mm.sleepForActivation
			if sleep {
				// Mark this task sleeping while waiting for the address space to
				// prevent the watchdog from reporting it as a stuck task.
				ctx.UninterruptibleSleepStart(false)
			}
			<-c
			if sleep {
				ctx.UninterruptibleSleepFinish(false)
			}
			continue
		}

		// Okay, we could restore all mappings at this point.
		// But forget that. Let's just let them fault in.
		mm.as = as

		// Unmapping is done, if necessary.
		mm.unmapAllOnActivate = false

		// Now that m.as has been assigned, we can set m.active to a non-zero value
		// to enable the fast path.
		mm.active.Store(1)

		mm.activeMu.Unlock()
		return nil
	}
}

// Deactivate releases a reference to the MemoryManager.
func (mm *MemoryManager) Deactivate() {
	// Fast path: this is not the last goroutine to deactivate the
	// MemoryManager.
	for {
		active := mm.active.Load()
		if active == 1 {
			// Fall back to the slow path.
			break
		}
		if mm.active.CompareAndSwap(active, active-1) {
			return
		}
	}

	mm.activeMu.Lock()
	// Same as Activate.

	// Still active?
	if mm.active.Add(-1) > 0 {
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

// mapASLocked maps addresses in ar into mm.as.
//
// Preconditions:
//   - mm.activeMu must be locked.
//   - mm.as != nil.
//   - ar.Length() != 0.
//   - ar must be page-aligned.
//   - pseg == mm.pmas.LowerBoundSegment(ar.Start).
func (mm *MemoryManager) mapASLocked(ctx context.Context, pseg pmaIterator, ar hostarch.AddrRange, platformEffect memmap.MMapPlatformEffect) error {
	if platformEffect == memmap.PlatformEffectCommit && ar.Length() > (1<<30) {
		// FIXME(b/445932215, b/445939339): Don't precommit very large ranges
		// via platform.AddressSpace.MapFile() for now, since holding locks
		// while doing so causes problems.
		platformEffect = memmap.PlatformEffectPopulate
	}
	// By default, map entire pmas at a time, under the assumption that there
	// is no cost to mapping more of a pma than necessary.
	mapAR := hostarch.AddrRange{0, ^hostarch.Addr(hostarch.PageSize - 1)}
	setMapUnit := func(mapUnit uint64) {
		mapMask := hostarch.Addr(mapUnit - 1)
		mapAR.Start = ar.Start &^ mapMask
		// If rounding ar.End up overflows, just keep the existing mapAR.End.
		if end := (ar.End + mapMask) &^ mapMask; end >= ar.End {
			mapAR.End = end
		}
	}
	if platformEffect != memmap.PlatformEffectDefault {
		// When explicitly committing, only map ar, since overmapping may incur
		// unexpected resource usage. When explicitly populating, do the same
		// since an underlying device file may be sensitive to the mapped
		// range.
		mapAR = ar
	} else if mapUnit := mm.p.MapUnit(); mapUnit != 0 {
		// Limit the range we map to ar, aligned to mapUnit.
		setMapUnit(mapUnit)
	} else if mf, ok := pseg.ValuePtr().file.(*pgalloc.MemoryFile); ok && mf.IsAsyncLoading() {
		// Impose an arbitrary mapUnit in order to avoid calling
		// platform.AddressSpace.MapFile() => mf.DataFD() or mf.MapInternal()
		// with unnecessarily large ranges, resulting in unnecessarily long
		// waits.
		setMapUnit(32 << 20)
	}
	if checkInvariants {
		if !mapAR.IsSupersetOf(ar) {
			panic(fmt.Sprintf("mapAR %#v is not a superset of ar %#v", mapAR, ar))
		}
	}

	// Since this checks ar.End and not mapAR.End, we will never map a pma that
	// is not required.
	for pseg.Ok() && pseg.Start() < ar.End {
		pma := pseg.ValuePtr()
		pmaAR := pseg.Range()
		pmaMapAR := pmaAR.Intersect(mapAR)
		perms := pma.effectivePerms
		if pma.needCOW {
			perms.Write = false
		}
		if perms.Any() { // MapFile precondition
			// If the length of the mapping exceeds singleMapThreshold, call
			// AddressSpace.MapFile() on singleMapThreshold-aligned chunks so
			// we can check ctx.Killed() reasonably frequently.
			const singleMapThreshold = 1 << 30
			if pmaMapAR.Length() <= singleMapThreshold {
				if err := mm.as.MapFile(pmaMapAR.Start, pma.file, pseg.fileRangeOf(pmaMapAR), perms, platformEffect == memmap.PlatformEffectCommit); err != nil {
					return err
				}
				if ctx.Killed() {
					return linuxerr.EINTR
				}
			} else {
				for windowStart := pmaMapAR.Start &^ (singleMapThreshold - 1); windowStart < pmaMapAR.End; windowStart += singleMapThreshold {
					windowAR := hostarch.AddrRange{windowStart, windowStart + singleMapThreshold}
					thisMapAR := pmaMapAR.Intersect(windowAR)
					if err := mm.as.MapFile(thisMapAR.Start, pma.file, pseg.fileRangeOf(thisMapAR), perms, platformEffect == memmap.PlatformEffectCommit); err != nil {
						return err
					}
					if ctx.Killed() {
						return linuxerr.EINTR
					}
				}
			}
		}
		pseg = pseg.NextSegment()
	}
	return nil
}

// unmapASLocked removes all AddressSpace mappings for addresses in ar.
//
// Preconditions: mm.activeMu must be locked.
func (mm *MemoryManager) unmapASLocked(ar hostarch.AddrRange) {
	if ar.Length() == 0 {
		return
	}
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
