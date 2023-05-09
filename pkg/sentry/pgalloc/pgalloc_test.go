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

package pgalloc

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

const (
	page     = hostarch.PageSize
	hugepage = hostarch.HugePageSize
	topPage  = (1 << 63) - page
)

func TestFindUnallocatedRange(t *testing.T) {
	for _, test := range []struct {
		name       string
		usage      *usageSegmentDataSlices
		fileSize   int64
		length     uint64
		alignment  uint64
		direction  Direction
		want       uint64
		expectFail bool
	}{
		{
			name:      "Initial allocation succeeds",
			usage:     &usageSegmentDataSlices{},
			length:    page,
			alignment: page,
			direction: BottomUp,
			want:      0,
		},
		{
			name:      "Initial allocation succeeds",
			usage:     &usageSegmentDataSlices{},
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      chunkSize - page, // Grows by chunkSize, allocate down.
		},
		{
			name: "Allocation begins at start of file",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page},
				End:    []uint64{2 * page},
				Values: []usageInfo{{refs: 1}},
			},
			length:    page,
			alignment: page,
			direction: BottomUp,
			want:      0,
		},
		{
			name: "Allocation finds empty space at start of file",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page},
				End:    []uint64{2 * page},
				Values: []usageInfo{{refs: 1}},
			},
			fileSize:  2 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
		},
		{
			name: "Allocation finds empty space at end of file",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0},
				End:    []uint64{page},
				Values: []usageInfo{{refs: 1}},
			},
			fileSize:  2 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      page,
		},
		{
			name: "In-use frames are not allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, page},
				End:    []uint64{page, 2 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			length:    page,
			alignment: page,
			direction: BottomUp,
			want:      2 * page,
		},
		{
			name: "In-use frames are not allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, page},
				End:    []uint64{page, 2 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			fileSize:  2 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      3 * page, // Double fileSize, allocate top-down.
		},
		{
			name: "Reclaimable frames are not allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, page, 2 * page},
				End:    []uint64{page, 2 * page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 0}, {refs: 1}},
			},
			length:    page,
			alignment: page,
			direction: BottomUp,
			want:      3 * page,
		},
		{
			name: "Reclaimable frames are not allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, page, 2 * page},
				End:    []uint64{page, 2 * page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 0}, {refs: 1}},
			},
			fileSize:  3 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      5 * page, // Double fileSize, grow down.
		},
		{
			name: "Gaps between in-use frames are allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 2 * page},
				End:    []uint64{page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			length:    page,
			alignment: page,
			direction: BottomUp,
			want:      page,
		},
		{
			name: "Gaps between in-use frames are allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 2 * page},
				End:    []uint64{page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  3 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      page,
		},
		{
			name: "Inadequately-sized gaps are rejected",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 2 * page},
				End:    []uint64{page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			length:    2 * page,
			alignment: page,
			direction: BottomUp,
			want:      3 * page,
		},
		{
			name: "Inadequately-sized gaps are rejected",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 2 * page},
				End:    []uint64{page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  3 * page,
			length:    2 * page,
			alignment: page,
			direction: TopDown,
			want:      4 * page, // Double fileSize, grow down.
		},
		{
			name: "Alignment is honored at end of file",
			usage: &usageSegmentDataSlices{
				Start: []uint64{0, hugepage + page},
				// Hugepage-sized gap here that shouldn't be allocated from
				// since it's incorrectly aligned.
				End:    []uint64{page, hugepage + 2*page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			length:    hugepage,
			alignment: hugepage,
			direction: BottomUp,
			want:      2 * hugepage,
		},
		{
			name: "Alignment is honored at end of file",
			usage: &usageSegmentDataSlices{
				Start: []uint64{0, hugepage + page},
				// Hugepage-sized gap here that shouldn't be allocated from
				// since it's incorrectly aligned.
				End:    []uint64{page, hugepage + 2*page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  hugepage + 2*page,
			length:    hugepage,
			alignment: hugepage,
			direction: TopDown,
			want:      3 * hugepage, // Double fileSize until alignment is satisfied, grow down.
		},
		{
			name: "Alignment is honored before end of file",
			usage: &usageSegmentDataSlices{
				Start: []uint64{0, 2*hugepage + page},
				// Page will need to be shifted down from top.
				End:    []uint64{page, 2*hugepage + 2*page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  2*hugepage + 2*page,
			length:    hugepage,
			alignment: hugepage,
			direction: TopDown,
			want:      hugepage,
		},
		{
			name:      "Allocation doubles file size more than once if necessary",
			usage:     &usageSegmentDataSlices{},
			fileSize:  page,
			length:    4 * page,
			alignment: page,
			direction: BottomUp,
			want:      0,
		},
		{
			name:      "Allocation doubles file size more than once if necessary",
			usage:     &usageSegmentDataSlices{},
			fileSize:  page,
			length:    4 * page,
			alignment: page,
			direction: TopDown,
			want:      0,
		},
		{
			name: "Allocations are compact if possible",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 3 * page},
				End:    []uint64{2 * page, 4 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			fileSize:  4 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      2 * page,
		},
		{
			name: "Top-down allocation within one gap",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 4 * page, 7 * page},
				End:    []uint64{2 * page, 5 * page, 8 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}, {refs: 1}},
			},
			fileSize:  8 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      6 * page,
		},
		{
			name: "Top-down allocation between multiple gaps",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 3 * page, 5 * page},
				End:    []uint64{2 * page, 4 * page, 6 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}, {refs: 1}},
			},
			fileSize:  6 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      4 * page,
		},
		{
			name: "Top-down allocation with large top gap",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 3 * page},
				End:    []uint64{2 * page, 4 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			fileSize:  8 * page,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      7 * page,
		},
		{
			name: "Gaps found with possible overflow",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, topPage - page},
				End:    []uint64{2 * page, topPage},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  topPage,
			length:    page,
			alignment: page,
			direction: TopDown,
			want:      topPage - 2*page,
		},
		{
			name: "Overflow detected",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page},
				End:    []uint64{topPage},
				Values: []usageInfo{{refs: 1}},
			},
			fileSize:   topPage,
			length:     2 * page,
			alignment:  page,
			direction:  BottomUp,
			expectFail: true,
		},
		{
			name: "Overflow detected",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page},
				End:    []uint64{topPage},
				Values: []usageInfo{{refs: 1}},
			},
			fileSize:   topPage,
			length:     2 * page,
			alignment:  page,
			direction:  TopDown,
			expectFail: true,
		},
		{
			name: "start may be in the middle of segment",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 3 * page},
				End:    []uint64{2 * page, 4 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			length:    page,
			alignment: page,
			direction: BottomUp,
			want:      2 * page,
		},
	} {
		name := fmt.Sprintf("%s (%v)", test.name, test.direction)
		t.Run(name, func(t *testing.T) {
			f := MemoryFile{fileSize: test.fileSize}
			if err := f.usage.ImportSortedSlices(test.usage); err != nil {
				t.Fatalf("Failed to initialize usage from %v: %v", test.usage, err)
			}
			if fr, ok := f.findAvailableRange(test.length, test.alignment, test.direction); ok {
				if test.expectFail {
					t.Fatalf("findAvailableRange(%v, %x, %x, %x, %v): got: %x, want: fail", test.usage, test.fileSize, test.length, test.alignment, test.direction, fr.Start)
				}
				if fr.Start != test.want {
					t.Errorf("findAvailableRange(%v, %x, %x, %x, %v): got: start=%x, want: %x", test.usage, test.fileSize, test.length, test.alignment, test.direction, fr.Start, test.want)
				}
				if fr.End != test.want+test.length {
					t.Errorf("findAvailableRange(%v, %x, %x, %x, %v): got: end=%x, want: %x", test.usage, test.fileSize, test.length, test.alignment, test.direction, fr.End, test.want+test.length)
				}
			} else if !test.expectFail {
				t.Fatalf("findAvailableRange(%v, %x, %x, %x, %v): failed, want: %x", test.usage, test.fileSize, test.length, test.alignment, test.direction, test.want)
			}
		})
	}
}
