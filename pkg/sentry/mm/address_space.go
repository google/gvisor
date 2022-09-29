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

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// AddressSpace returns the platform.AddressSpace bound to mm.
//
// Preconditions: mm.users != 0.
func (mm *MemoryManager) AddressSpace() platform.AddressSpace {
	return mm.as
}

// mapASLocked maps addresses in ar into mm.as. If precommit is true, mappings
// for all addresses in ar should be precommitted.
//
// Preconditions:
//   - mm.activeMu must be locked.
//   - ar.Length() != 0.
//   - ar must be page-aligned.
//   - pseg == mm.pmas.LowerBoundSegment(ar.Start).
func (mm *MemoryManager) mapASLocked(pseg pmaIterator, ar hostarch.AddrRange, precommit bool) error {
	// By default, map entire pmas at a time, under the assumption that there
	// is no cost to mapping more of a pma than necessary.
	mapAR := hostarch.AddrRange{0, ^hostarch.Addr(hostarch.PageSize - 1)}
	if precommit {
		// When explicitly precommitting, only map ar, since overmapping may
		// incur unexpected resource usage.
		mapAR = ar
	} else if mapUnit := mm.p.MapUnit(); mapUnit != 0 {
		// Limit the range we map to ar, aligned to mapUnit.
		mapMask := hostarch.Addr(mapUnit - 1)
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
			if err := mm.as.MapFile(pmaMapAR.Start, pma.file, pseg.fileRangeOf(pmaMapAR), perms, precommit); err != nil {
				return err
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
	if mm.as == nil {
		// Being called from mm.DecUsers() after AddressSpace release.
		return
	}
	// unmapASLocked doesn't require vmas or pmas to exist for ar, so it can be
	// passed ranges that include addresses that can't be mapped by the
	// application.
	ar = ar.Intersect(mm.applicationAddrRange())
	mm.as.Unmap(ar.Start, uint64(ar.Length()))
}
