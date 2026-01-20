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
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func TestDirtySet(t *testing.T) {
	var set DirtySet
	set.MarkDirty(memmap.MappableRange{0, 2 * hostarch.PageSize})
	set.KeepDirty(memmap.MappableRange{hostarch.PageSize, 2 * hostarch.PageSize})
	set.MarkClean(memmap.MappableRange{0, 2 * hostarch.PageSize})
	want := []DirtyFlatSegment{
		{hostarch.PageSize, 2 * hostarch.PageSize, DirtyInfo{Keep: true}},
	}
	if got := set.ExportSlice(); !slices.Equal(got, want) {
		t.Errorf("set:\n\tgot %v,\n\twant %v", got, want)
	}
}

func TestDirtySetAccounting(t *testing.T) {
	// Reset accounting for this test
	initialDirty, _ := usage.DirtyMemoryAccounting.Copy()

	var set DirtySet

	// Mark 2 pages dirty - should increment dirty counter
	set.MarkDirty(memmap.MappableRange{0, 2 * hostarch.PageSize})
	dirty, _ := usage.DirtyMemoryAccounting.Copy()
	expectedDirty := initialDirty + 2*hostarch.PageSize
	if dirty != expectedDirty {
		t.Errorf("after MarkDirty: dirty = %d, want %d", dirty, expectedDirty)
	}

	// Mark overlapping range dirty - should not double-count
	set.MarkDirty(memmap.MappableRange{0, hostarch.PageSize})
	dirty, _ = usage.DirtyMemoryAccounting.Copy()
	if dirty != expectedDirty {
		t.Errorf("after overlapping MarkDirty: dirty = %d, want %d", dirty, expectedDirty)
	}

	// Mark 1 more page dirty
	set.MarkDirty(memmap.MappableRange{2 * hostarch.PageSize, 3 * hostarch.PageSize})
	dirty, _ = usage.DirtyMemoryAccounting.Copy()
	expectedDirty += hostarch.PageSize
	if dirty != expectedDirty {
		t.Errorf("after extending MarkDirty: dirty = %d, want %d", dirty, expectedDirty)
	}

	// MarkClean should decrement (but not for Keep segments)
	set.KeepDirty(memmap.MappableRange{hostarch.PageSize, 2 * hostarch.PageSize})
	set.MarkClean(memmap.MappableRange{0, 3 * hostarch.PageSize})
	dirty, _ = usage.DirtyMemoryAccounting.Copy()
	// Only the Keep segment remains, so we lost 2 pages (0-1 and 2-3)
	expectedDirty -= 2 * hostarch.PageSize
	if dirty != expectedDirty {
		t.Errorf("after MarkClean: dirty = %d, want %d", dirty, expectedDirty)
	}

	// RemoveAllAndAccount should remove remaining
	set.RemoveAllAndAccount()
	dirty, _ = usage.DirtyMemoryAccounting.Copy()
	expectedDirty -= hostarch.PageSize
	if dirty != expectedDirty {
		t.Errorf("after RemoveAllAndAccount: dirty = %d, want %d", dirty, expectedDirty)
	}
}
