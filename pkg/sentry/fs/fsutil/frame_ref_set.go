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

package fsutil

import (
	"math"

	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// FrameRefSetFunctions implements segment.Functions for FrameRefSet.
type FrameRefSetFunctions struct{}

// MinKey implements segment.Functions.MinKey.
func (FrameRefSetFunctions) MinKey() uint64 {
	return 0
}

// MaxKey implements segment.Functions.MaxKey.
func (FrameRefSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

// ClearValue implements segment.Functions.ClearValue.
func (FrameRefSetFunctions) ClearValue(val *uint64) {
}

// Merge implements segment.Functions.Merge.
func (FrameRefSetFunctions) Merge(_ memmap.FileRange, val1 uint64, _ memmap.FileRange, val2 uint64) (uint64, bool) {
	if val1 != val2 {
		return 0, false
	}
	return val1, true
}

// Split implements segment.Functions.Split.
func (FrameRefSetFunctions) Split(_ memmap.FileRange, val uint64, _ uint64) (uint64, uint64) {
	return val, val
}

// IncRefAndAccount adds a reference on the range fr. All newly inserted segments
// are accounted as host page cache memory mappings.
func (refs *FrameRefSet) IncRefAndAccount(fr memmap.FileRange) {
	seg, gap := refs.Find(fr.Start)
	for {
		switch {
		case seg.Ok() && seg.Start() < fr.End:
			seg = refs.Isolate(seg, fr)
			seg.SetValue(seg.Value() + 1)
			seg, gap = seg.NextNonEmpty()
		case gap.Ok() && gap.Start() < fr.End:
			newRange := gap.Range().Intersect(fr)
			usage.MemoryAccounting.Inc(newRange.Length(), usage.Mapped)
			seg, gap = refs.InsertWithoutMerging(gap, newRange, 1).NextNonEmpty()
		default:
			refs.MergeAdjacent(fr)
			return
		}
	}
}

// DecRefAndAccount removes a reference on the range fr and untracks segments
// that are removed from memory accounting.
func (refs *FrameRefSet) DecRefAndAccount(fr memmap.FileRange) {
	seg := refs.FindSegment(fr.Start)

	for seg.Ok() && seg.Start() < fr.End {
		seg = refs.Isolate(seg, fr)
		if old := seg.Value(); old == 1 {
			usage.MemoryAccounting.Dec(seg.Range().Length(), usage.Mapped)
			seg = refs.Remove(seg).NextSegment()
		} else {
			seg.SetValue(old - 1)
			seg = seg.NextSegment()
		}
	}
	refs.MergeAdjacent(fr)
}
