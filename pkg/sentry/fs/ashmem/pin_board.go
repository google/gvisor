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

package ashmem

import "gvisor.googlesource.com/gvisor/pkg/abi/linux"

const maxUint64 = ^uint64(0)

// setFunctions implements segment.Functions generated from segment.Functions for
// uint64 Key and noValue Value. For more information, see the build file and
// segment set implementation at pkg/segment/set.go.
type setFunctions struct{}

// noValue is a type of range attached value, which is irrelevant here.
type noValue struct{}

// MinKey implements segment.Functions.MinKey.
func (setFunctions) MinKey() uint64 {
	return 0
}

// MaxKey implements segment.Functions.MaxKey.
func (setFunctions) MaxKey() uint64 {
	return maxUint64
}

// ClearValue implements segment.Functions.ClearValue.
func (setFunctions) ClearValue(*noValue) {
	return
}

// Merge implements segment.Functions.Merge.
func (setFunctions) Merge(Range, noValue, Range, noValue) (noValue, bool) {
	return noValue{}, true
}

// Split implements segment.Functions.Split.
func (setFunctions) Split(Range, noValue, uint64) (noValue, noValue) {
	return noValue{}, noValue{}
}

// PinBoard represents a set of pinned ranges in ashmem.
//
// segment.Set is used for implementation where segments represent
// ranges of pinned bytes, while gaps represent ranges of unpinned
// bytes. All ranges are page-aligned.
//
// +stateify savable
type PinBoard struct {
	Set
}

// NewPinBoard creates a new pin board with all pages pinned.
func NewPinBoard() *PinBoard {
	var pb PinBoard
	pb.PinRange(Range{0, maxUint64})
	return &pb
}

// PinRange pins all pages in the specified range and returns true
// if there are any newly pinned pages.
func (pb *PinBoard) PinRange(r Range) bool {
	pinnedPages := false
	for gap := pb.LowerBoundGap(r.Start); gap.Ok() && gap.Start() < r.End; {
		common := gap.Range().Intersect(r)
		if common.Length() == 0 {
			gap = gap.NextGap()
			continue
		}
		pinnedPages = true
		gap = pb.Insert(gap, common, noValue{}).NextGap()
	}
	return pinnedPages
}

// UnpinRange unpins all pages in the specified range.
func (pb *PinBoard) UnpinRange(r Range) {
	for seg := pb.LowerBoundSegment(r.Start); seg.Ok() && seg.Start() < r.End; {
		common := seg.Range().Intersect(r)
		if common.Length() == 0 {
			seg = seg.NextSegment()
			continue
		}
		seg = pb.RemoveRange(common).NextSegment()
	}
}

// RangePinnedStatus returns false if there's at least one unpinned page in the
// specified range.
func (pb *PinBoard) RangePinnedStatus(r Range) bool {
	for gap := pb.LowerBoundGap(r.Start); gap.Ok() && gap.Start() < r.End; {
		common := gap.Range().Intersect(r)
		if common.Length() == 0 {
			gap = gap.NextGap()
			continue
		}
		return false
	}
	return true
}

// RangeFromAshmemPin converts ashmem's original pin structure
// to Range.
func RangeFromAshmemPin(ap linux.AshmemPin) Range {
	if ap.Len == 0 {
		return Range{
			uint64(ap.Offset),
			maxUint64,
		}
	}
	return Range{
		uint64(ap.Offset),
		uint64(ap.Offset) + uint64(ap.Len),
	}
}
