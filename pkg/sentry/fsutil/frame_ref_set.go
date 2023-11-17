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

// FrameRefSegInfo holds reference count and memory cgroup id of the segment.
type FrameRefSegInfo struct {
	// refs indicates the reference count of the segment.
	refs uint64
	// memCgID is the memory cgroup id of the first task which touches the
	// segment. This will not be changed over the lifetime of the segment.
	memCgID uint32
}

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
func (FrameRefSetFunctions) ClearValue(val *FrameRefSegInfo) {
}

// Merge implements segment.Functions.Merge.
func (FrameRefSetFunctions) Merge(_ memmap.FileRange, val1 FrameRefSegInfo, _ memmap.FileRange, val2 FrameRefSegInfo) (FrameRefSegInfo, bool) {
	if val1 != val2 {
		return FrameRefSegInfo{}, false
	}
	return val1, true
}

// Split implements segment.Functions.Split.
func (FrameRefSetFunctions) Split(_ memmap.FileRange, val FrameRefSegInfo, _ uint64) (FrameRefSegInfo, FrameRefSegInfo) {
	return val, val
}

// IncRefAndAccount adds a reference on the range fr. All newly inserted segments
// are accounted as host page cache memory mappings. The new segments will be
// associated with the memCgID, if the segment already exists then the memCgID
// will not be changed.
func (s *FrameRefSet) IncRefAndAccount(fr memmap.FileRange, memCgID uint32) {
	seg, gap := s.Find(fr.Start)
	for {
		switch {
		case seg.Ok() && seg.Start() < fr.End:
			seg = s.Isolate(seg, fr)
			seg.ValuePtr().refs++
			seg, gap = seg.NextNonEmpty()
		case gap.Ok() && gap.Start() < fr.End:
			newRange := gap.Range().Intersect(fr)
			usage.MemoryAccounting.Inc(newRange.Length(), usage.Mapped, memCgID)
			frInfo := FrameRefSegInfo{refs: 1, memCgID: memCgID}
			seg, gap = s.InsertWithoutMerging(gap, newRange, frInfo).NextNonEmpty()
		default:
			s.MergeOutsideRange(fr)
			return
		}
	}
}

// DecRefAndAccount removes a reference on the range fr and untracks segments
// that are removed from memory accounting.
func (s *FrameRefSet) DecRefAndAccount(fr memmap.FileRange) {
	seg := s.FindSegment(fr.Start)

	for seg.Ok() && seg.Start() < fr.End {
		seg = s.Isolate(seg, fr)
		if old := seg.ValuePtr().refs; old == 1 {
			usage.MemoryAccounting.Dec(seg.Range().Length(), usage.Mapped, seg.ValuePtr().memCgID)
			seg = s.Remove(seg).NextSegment()
		} else {
			seg.ValuePtr().refs--
			seg = seg.NextSegment()
		}
	}
	s.MergeOutsideRange(fr)
}
