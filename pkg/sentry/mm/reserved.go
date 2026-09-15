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

package mm

import (
	"gvisor.dev/gvisor/pkg/hostarch"
)

// reserveLocked records ar as reserved, coalescing with existing
// reservations. Overlapping reservations are permitted.
//
// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) reserveLocked(ar hostarch.AddrRange) {
	mm.reservedRanges.RemoveRange(ar)
	mm.reservedRanges.InsertRange(ar, reservedSetValue{})
}

// isReservedLocked returns true if any part of ar is reserved.
//
// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) isReservedLocked(ar hostarch.AddrRange) bool {
	return mm.reservedRanges.SpanRange(ar) != 0
}

// forEachUnreservedLocked calls f on each maximal sub-range of ar that is
// not reserved, in ascending order if ascending is true and in descending
// order otherwise, until f returns false. It returns false if f returned
// false.
//
// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) forEachUnreservedLocked(ar hostarch.AddrRange, ascending bool, f func(hostarch.AddrRange) bool) bool {
	if ar.Length() == 0 {
		return true
	}
	if mm.reservedRanges.IsEmpty() {
		return f(ar)
	}
	if ascending {
		for gap := mm.reservedRanges.LowerBoundGap(ar.Start); gap.Ok() && gap.Start() < ar.End; gap = gap.NextGap() {
			if gr := gap.Range().Intersect(ar); gr.Length() > 0 && !f(gr) {
				return false
			}
		}
		return true
	}
	for gap := mm.reservedRanges.UpperBoundGap(ar.End - 1); gap.Ok() && gap.End() > ar.Start; gap = gap.PrevGap() {
		if gr := gap.Range().Intersect(ar); gr.Length() > 0 && !f(gr) {
			return false
		}
	}
	return true
}

// reservedSetValue is the value type of reservedSet.
type reservedSetValue struct{}

// reservedSetFunctions implements segment.Functions for reservedSet.
type reservedSetFunctions struct{}

func (reservedSetFunctions) MinKey() hostarch.Addr {
	return 0
}

func (reservedSetFunctions) MaxKey() hostarch.Addr {
	return ^hostarch.Addr(0)
}

func (reservedSetFunctions) ClearValue(val *reservedSetValue) {
}

func (reservedSetFunctions) Merge(_ hostarch.AddrRange, _ reservedSetValue, _ hostarch.AddrRange, _ reservedSetValue) (reservedSetValue, bool) {
	return reservedSetValue{}, true
}

func (reservedSetFunctions) Split(_ hostarch.AddrRange, _ reservedSetValue, _ hostarch.Addr) (reservedSetValue, reservedSetValue) {
	return reservedSetValue{}, reservedSetValue{}
}
