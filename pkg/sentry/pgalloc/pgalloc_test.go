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
		desc       string
		usage      *usageSegmentDataSlices
		fileSize   int64
		length     uint64
		alignment  uint64
		start      uint64
		expectFail bool
	}{
		{
			desc:      "Initial allocation succeeds",
			usage:     &usageSegmentDataSlices{},
			length:    page,
			alignment: page,
			start:     chunkSize - page, // Grows by chunkSize, allocate down.
		},
		{
			desc: "Allocation finds empty space at start of file",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page},
				End:    []uint64{2 * page},
				Values: []usageInfo{{refs: 1}},
			},
			fileSize:  2 * page,
			length:    page,
			alignment: page,
			start:     0,
		},
		{
			desc: "Allocation finds empty space at end of file",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0},
				End:    []uint64{page},
				Values: []usageInfo{{refs: 1}},
			},
			fileSize:  2 * page,
			length:    page,
			alignment: page,
			start:     page,
		},
		{
			desc: "In-use frames are not allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, page},
				End:    []uint64{page, 2 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			fileSize:  2 * page,
			length:    page,
			alignment: page,
			start:     3 * page, // Double fileSize, allocate top-down.
		},
		{
			desc: "Reclaimable frames are not allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, page, 2 * page},
				End:    []uint64{page, 2 * page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 0}, {refs: 1}},
			},
			fileSize:  3 * page,
			length:    page,
			alignment: page,
			start:     5 * page, // Double fileSize, grow down.
		},
		{
			desc: "Gaps between in-use frames are allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 2 * page},
				End:    []uint64{page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  3 * page,
			length:    page,
			alignment: page,
			start:     page,
		},
		{
			desc: "Inadequately-sized gaps are rejected",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 2 * page},
				End:    []uint64{page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  3 * page,
			length:    2 * page,
			alignment: page,
			start:     4 * page, // Double fileSize, grow down.
		},
		{
			desc: "Alignment is honored at end of file",
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
			start:     3 * hugepage, // Double fileSize until alignment is satisfied, grow down.
		},
		{
			desc: "Alignment is honored before end of file",
			usage: &usageSegmentDataSlices{
				Start: []uint64{0, 2*hugepage + page},
				// Page will need to be shifted down from top.
				End:    []uint64{page, 2*hugepage + 2*page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  2*hugepage + 2*page,
			length:    hugepage,
			alignment: hugepage,
			start:     hugepage,
		},
		{
			desc:      "Allocation doubles file size more than once if necessary",
			usage:     &usageSegmentDataSlices{},
			fileSize:  page,
			length:    4 * page,
			alignment: page,
			start:     0,
		},
		{
			desc: "Allocations are compact if possible",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 3 * page},
				End:    []uint64{2 * page, 4 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			fileSize:  4 * page,
			length:    page,
			alignment: page,
			start:     2 * page,
		},
		{
			desc: "Top-down allocation within one gap",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 4 * page, 7 * page},
				End:    []uint64{2 * page, 5 * page, 8 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}, {refs: 1}},
			},
			fileSize:  8 * page,
			length:    page,
			alignment: page,
			start:     6 * page,
		},
		{
			desc: "Top-down allocation between multiple gaps",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 3 * page, 5 * page},
				End:    []uint64{2 * page, 4 * page, 6 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}, {refs: 1}},
			},
			fileSize:  6 * page,
			length:    page,
			alignment: page,
			start:     4 * page,
		},
		{
			desc: "Top-down allocation with large top gap",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 3 * page},
				End:    []uint64{2 * page, 4 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			fileSize:  8 * page,
			length:    page,
			alignment: page,
			start:     7 * page,
		},
		{
			desc: "Gaps found with possible overflow",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, topPage - page},
				End:    []uint64{2 * page, topPage},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			fileSize:  topPage,
			length:    page,
			alignment: page,
			start:     topPage - 2*page,
		},
		{
			desc: "Overflow detected",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page},
				End:    []uint64{topPage},
				Values: []usageInfo{{refs: 1}},
			},
			fileSize:   topPage,
			length:     2 * page,
			alignment:  page,
			expectFail: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			var usage usageSet
			if err := usage.ImportSortedSlices(test.usage); err != nil {
				t.Fatalf("Failed to initialize usage from %v: %v", test.usage, err)
			}
			fr, ok := findAvailableRange(&usage, test.fileSize, test.length, test.alignment)
			if !test.expectFail && !ok {
				t.Fatalf("findAvailableRange(%v, %x, %x, %x): got %x, false wanted %x, true", test.usage, test.fileSize, test.length, test.alignment, fr.Start, test.start)
			}
			if test.expectFail && ok {
				t.Fatalf("findAvailableRange(%v, %x, %x, %x): got %x, true wanted %x, false", test.usage, test.fileSize, test.length, test.alignment, fr.Start, test.start)
			}
			if ok && fr.Start != test.start {
				t.Errorf("findAvailableRange(%v, %x, %x, %x): got start=%x, wanted %x", test.usage, test.fileSize, test.length, test.alignment, fr.Start, test.start)
			}
			if ok && fr.End != test.start+test.length {
				t.Errorf("findAvailableRange(%v, %x, %x, %x): got end=%x, wanted %x", test.usage, test.fileSize, test.length, test.alignment, fr.End, test.start+test.length)
			}
		})
	}
}
