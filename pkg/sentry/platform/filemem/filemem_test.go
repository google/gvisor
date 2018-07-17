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

package filemem

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

const (
	page     = usermem.PageSize
	hugepage = usermem.HugePageSize
)

func TestFindUnallocatedRange(t *testing.T) {
	for _, test := range []struct {
		desc           string
		usage          *usageSegmentDataSlices
		start          uint64
		length         uint64
		alignment      uint64
		unallocated    uint64
		minUnallocated uint64
	}{
		{
			desc:           "Initial allocation succeeds",
			usage:          &usageSegmentDataSlices{},
			start:          0,
			length:         page,
			alignment:      page,
			unallocated:    0,
			minUnallocated: 0,
		},
		{
			desc: "Allocation begins at start of file",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page},
				End:    []uint64{2 * page},
				Values: []usageInfo{{refs: 1}},
			},
			start:          0,
			length:         page,
			alignment:      page,
			unallocated:    0,
			minUnallocated: 0,
		},
		{
			desc: "In-use frames are not allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, page},
				End:    []uint64{page, 2 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			start:          0,
			length:         page,
			alignment:      page,
			unallocated:    2 * page,
			minUnallocated: 2 * page,
		},
		{
			desc: "Reclaimable frames are not allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, page, 2 * page},
				End:    []uint64{page, 2 * page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 0}, {refs: 1}},
			},
			start:          0,
			length:         page,
			alignment:      page,
			unallocated:    3 * page,
			minUnallocated: 3 * page,
		},
		{
			desc: "Gaps between in-use frames are allocatable",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 2 * page},
				End:    []uint64{page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			start:          0,
			length:         page,
			alignment:      page,
			unallocated:    page,
			minUnallocated: page,
		},
		{
			desc: "Inadequately-sized gaps are rejected",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 2 * page},
				End:    []uint64{page, 3 * page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			start:          0,
			length:         2 * page,
			alignment:      page,
			unallocated:    3 * page,
			minUnallocated: page,
		},
		{
			desc: "Hugepage alignment is honored",
			usage: &usageSegmentDataSlices{
				Start: []uint64{0, hugepage + page},
				// Hugepage-sized gap here that shouldn't be allocated from
				// since it's incorrectly aligned.
				End:    []uint64{page, hugepage + 2*page},
				Values: []usageInfo{{refs: 1}, {refs: 1}},
			},
			start:          0,
			length:         hugepage,
			alignment:      hugepage,
			unallocated:    2 * hugepage,
			minUnallocated: page,
		},
		{
			desc: "Pages before start ignored",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{page, 3 * page},
				End:    []uint64{2 * page, 4 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			start:          page,
			length:         page,
			alignment:      page,
			unallocated:    2 * page,
			minUnallocated: 2 * page,
		},
		{
			desc: "start may be in the middle of segment",
			usage: &usageSegmentDataSlices{
				Start:  []uint64{0, 3 * page},
				End:    []uint64{2 * page, 4 * page},
				Values: []usageInfo{{refs: 1}, {refs: 2}},
			},
			start:          page,
			length:         page,
			alignment:      page,
			unallocated:    2 * page,
			minUnallocated: 2 * page,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			var usage usageSet
			if err := usage.ImportSortedSlices(test.usage); err != nil {
				t.Fatalf("Failed to initialize usage from %v: %v", test.usage, err)
			}
			unallocated, minUnallocated := findUnallocatedRange(&usage, test.start, test.length, test.alignment)
			if unallocated != test.unallocated {
				t.Errorf("findUnallocatedRange(%v, %x, %x, %x): got unallocated %x, wanted %x", test.usage, test.start, test.length, test.alignment, unallocated, test.unallocated)
			}
			if minUnallocated != test.minUnallocated {
				t.Errorf("findUnallocatedRange(%v, %x, %x, %x): got minUnallocated %x, wanted %x", test.usage, test.start, test.length, test.alignment, minUnallocated, test.minUnallocated)
			}
		})
	}
}
