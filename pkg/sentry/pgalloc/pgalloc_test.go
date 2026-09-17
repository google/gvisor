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

//go:build !pagesize_64k

package pgalloc

import (
	"bytes"
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

const (
	page     = hostarch.PageSize
	hugepage = hostarch.HugePageSize
)

// existingSegment represents a range of pages in a test MemoryFile that is not
// void or free.
type existingSegment struct {
	start uint64
	end   uint64
	state int
}

// Possible values for existingSegment.state:
const (
	existingUnspecified = iota
	existingUsed
	existingWaste
	existingReleasing // or sub-releasing
)

func TestFindAllocatable(t *testing.T) {
	for _, test := range []struct {
		name string
		// Initial state:
		chunkHuge []bool
		existing  []existingSegment
		// Allocation parameters:
		length  uint64
		huge    bool
		recycle bool
		dir     Direction
		// Expected outcome:
		want uint64
	}{
		{
			name:   "initial small allocation, bottom-up",
			length: page,
			want:   0,
		},
		{
			name:   "initial small allocation, top-down",
			length: page,
			dir:    TopDown,
			want:   chunkSize - page,
		},
		{
			name:   "initial small allocation, multiple pages, top-down",
			length: 2 * page,
			dir:    TopDown,
			want:   chunkSize - 2*page,
		},
		{
			name:    "initial small allocation, recycling enabled, bottom-up",
			length:  page,
			recycle: true,
			want:    0,
		},
		{
			name:   "initial huge allocation, bottom-up",
			length: hugepage,
			huge:   true,
			want:   0,
		},
		{
			name:   "initial huge allocation, top-down",
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - hugepage,
		},
		{
			name:   "initial huge allocation, multiple pages, top-down",
			length: 2 * hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 2*hugepage,
		},
		{
			name:    "initial huge allocation, recycling enabled, bottom-up",
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    0,
		},
		{
			name:      "huge allocation uses huge pages in new chunk",
			chunkHuge: []bool{false},
			length:    hugepage,
			huge:      true,
			want:      chunkSize,
		},
		{
			name:      "huge allocation uses huge pages in existing chunk",
			chunkHuge: []bool{false, true},
			length:    hugepage,
			huge:      true,
			want:      chunkSize,
		},
		{
			name:      "hugepage-sized non-huge allocation uses small pages in new chunk",
			chunkHuge: []bool{true},
			length:    hugepage,
			want:      chunkSize,
		},
		{
			name:      "hugepage-sized non-huge allocation uses small pages in existing chunk",
			chunkHuge: []bool{true, false},
			length:    hugepage,
			want:      chunkSize,
		},
		{
			name:      "bottom-up small allocation begins at start of file",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{page, 2 * page, existingUsed},
			},
			length: page,
			want:   0,
		},
		{
			name:      "top-down small allocation begins at end of last chunk",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - 2*page, chunkSize - page, existingUsed},
			},
			length: page,
			dir:    TopDown,
			want:   chunkSize - page,
		},
		{
			name:      "bottom-up huge allocation begins at start of file",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{hugepage, 2 * hugepage, existingUsed},
			},
			length: hugepage,
			huge:   true,
			want:   0,
		},
		{
			name:      "top-down huge allocation begins at end of last chunk",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - 2*hugepage, chunkSize - hugepage, existingUsed},
			},
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - hugepage,
		},
		{
			name:      "bottom-up small allocation can extend multiple chunks",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize/2 - page, chunkSize / 2, existingUsed},
			},
			length: 2*chunkSize + page,
			want:   chunkSize / 2,
		},
		{
			name:      "top-down small allocation can extend multiple chunks",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize/2 - page, chunkSize / 2, existingUsed},
			},
			length: 2*chunkSize + page,
			dir:    TopDown,
			want:   chunkSize - page,
		},
		{
			name:      "bottom-up huge allocation can extend multiple chunks",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize/2 - hugepage, chunkSize / 2, existingUsed},
			},
			length: 2*chunkSize + hugepage,
			huge:   true,
			want:   chunkSize / 2,
		},
		{
			name:      "top-down huge allocation can extend multiple chunks",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize/2 - hugepage, chunkSize / 2, existingUsed},
			},
			length: 2*chunkSize + hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - hugepage,
		},
		{
			name:      "bottom-up small allocation finds first free gap",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingUsed},
				{2 * page, 3 * page, existingUsed},
			},
			length: page,
			want:   page,
		},
		{
			name:      "top-down small allocation finds last free gap",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingUsed},
				{chunkSize - 3*page, chunkSize - 2*page, existingUsed},
			},
			length: page,
			dir:    TopDown,
			want:   chunkSize - 2*page,
		},
		{
			name:      "bottom-up huge allocation finds first free gap",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingUsed},
				{2 * hugepage, 3 * hugepage, existingUsed},
			},
			length: hugepage,
			huge:   true,
			want:   hugepage,
		},
		{
			name:      "top-down huge allocation finds last free gap",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingUsed},
				{chunkSize - 3*hugepage, chunkSize - 2*hugepage, existingUsed},
			},
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 2*hugepage,
		},
		{
			name:      "bottom-up small allocation skips undersized free gap",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingUsed},
				{2 * page, 3 * page, existingUsed},
			},
			length: 2 * page,
			want:   3 * page,
		},
		{
			name:      "top-down small allocation skips undersized free gap",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingUsed},
				{chunkSize - 3*page, chunkSize - 2*page, existingUsed},
			},
			length: 2 * page,
			dir:    TopDown,
			want:   chunkSize - 5*page,
		},
		{
			name:      "bottom-up huge allocation skips undersized free gap",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingUsed},
				{2 * hugepage, 3 * hugepage, existingUsed},
			},
			length: 2 * hugepage,
			huge:   true,
			want:   3 * hugepage,
		},
		{
			name:      "top-down huge allocation skips undersized free gap",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingUsed},
				{chunkSize - 3*hugepage, chunkSize - 2*hugepage, existingUsed},
			},
			length: 2 * hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 5*hugepage,
		},
		{
			name:      "recycling bottom-up small allocation skips used pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingUsed},
			},
			length:  page,
			recycle: true,
			want:    page,
		},
		{
			name:      "recycling top-down small allocation skips used pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingUsed},
			},
			length:  page,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*page,
		},
		{
			name:      "recycling bottom-up huge allocation skips used pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingUsed},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    hugepage,
		},
		{
			name:      "recycling top-down huge allocation skips used pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingUsed},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*hugepage,
		},
		{
			name:      "non-recycling bottom-up small allocation skips waste pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingWaste},
			},
			length: page,
			want:   page,
		},
		{
			name:      "non-recycling top-down small allocation skips waste pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingWaste},
			},
			length: page,
			dir:    TopDown,
			want:   chunkSize - 2*page,
		},
		{
			name:      "non-recycling bottom-up huge allocation skips waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingWaste},
			},
			length: hugepage,
			huge:   true,
			want:   hugepage,
		},
		{
			name:      "non-recycling top-down huge allocation skips waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingWaste},
			},
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 2*hugepage,
		},
		{
			name:      "recycling bottom-up small allocation recycles waste pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingWaste},
			},
			length:  page,
			recycle: true,
			want:    0,
		},
		{
			name:      "recycling top-down small allocation recycles waste pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingWaste},
			},
			length:  page,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - page,
		},
		{
			name:      "recycling bottom-up huge allocation recycles waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingWaste},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    0,
		},
		{
			name:      "recycling top-down huge allocation recycles waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingWaste},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - hugepage,
		},
		{
			name:      "non-recycling bottom-up small allocation skips releasing pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingReleasing},
			},
			length: page,
			want:   page,
		},
		{
			name:      "non-recycling top-down small allocation skips releasing pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingReleasing},
			},
			length: page,
			dir:    TopDown,
			want:   chunkSize - 2*page,
		},
		{
			name:      "non-recycling bottom-up huge allocation skips releasing pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingReleasing},
			},
			length: hugepage,
			huge:   true,
			want:   hugepage,
		},
		{
			name:      "non-recycling top-down huge allocation skips releasing pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingReleasing},
			},
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 2*hugepage,
		},
		{
			name:      "recycling bottom-up small allocation skips releasing pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingReleasing},
			},
			length:  page,
			recycle: true,
			want:    page,
		},
		{
			name:      "recycling top-down small allocation skips releasing pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingReleasing},
			},
			length:  page,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*page,
		},
		{
			name:      "recycling bottom-up huge allocation skips releasing pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingReleasing},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    hugepage,
		},
		{
			name:      "recycling top-down huge allocation skips releasing pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingReleasing},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*hugepage,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Build the fake MemoryFile.
			f := &MemoryFile{
				opts: MemoryFileOpts{
					ExpectHugepages:         true,
					DisableMemoryAccounting: true,
				},
			}
			f.initFields()
			chunks := make([]chunkInfo, len(test.chunkHuge))
			for i, huge := range test.chunkHuge {
				chunks[i].huge = huge
				chunkFR := memmap.FileRange{uint64(i) * chunkSize, uint64(i+1) * chunkSize}
				if huge {
					f.unfreeHuge.RemoveRange(chunkFR)
				} else {
					f.unfreeSmall.RemoveRange(chunkFR)
				}
			}
			f.chunks.Store(&chunks)
			for _, es := range test.existing {
				f.forEachChunk(memmap.FileRange{es.start, es.end}, func(chunk *chunkInfo, chunkFR memmap.FileRange) bool {
					unwaste, unfree := &f.unwasteSmall, &f.unfreeSmall
					if chunk.huge {
						unwaste, unfree = &f.unwasteHuge, &f.unfreeHuge
					}
					switch es.state {
					case existingUsed:
						unfree.InsertRange(chunkFR, unfreeInfo{refs: 1})
					case existingWaste:
						unfree.InsertRange(chunkFR, unfreeInfo{refs: 0})
						unwaste.RemoveRange(chunkFR)
					case existingReleasing:
						unfree.InsertRange(chunkFR, unfreeInfo{refs: 0})
					default:
						t.Fatalf("existingSegment %+v has unknown state", es)
					}
					f.memAcct.InsertRange(chunkFR, memAcctInfo{
						wasteOrReleasing: es.state != existingUsed,
					})
					return true
				})
			}

			// Perform the test allocation.
			alloc := allocState{
				length: test.length,
				opts: AllocOpts{
					Huge: test.huge,
					Dir:  test.dir,
				},
				huge: test.huge,
			}
			if test.recycle {
				alloc.opts.Mode = AllocateCallerIndirectCommit
				alloc.willCommit = true
			}
			fr, err := f.findAllocatableAndMarkUsed(&alloc)
			if err != nil {
				t.Fatalf("findAllocatableAndMarkUsed(%+v): failed: %v, want: %#x\n%v", alloc, err, test.want, f)
			}
			if fr.Start != test.want {
				t.Errorf("findAllocatableAndMarkUsed(%+v): got: start=%#x, want: %#x\n%v", alloc, fr.Start, test.want, f)
			}
			if wantEnd := test.want + test.length; fr.End != wantEnd {
				t.Errorf("findAllocatableAndMarkUsed(%+v): got: end=%#x, want: %#x\n%v", alloc, fr.End, wantEnd, f)
			}
		})
	}
}

func TestReserve(t *testing.T) {
	f := &MemoryFile{
		opts: MemoryFileOpts{
			DisableMemoryAccounting: true,
		},
	}
	f.initFields()

	fr1, err := f.Reserve(2*page, AllocOpts{Dir: BottomUp})
	if err != nil {
		t.Fatalf("Reserve(2 pages): %v", err)
	}
	fr2, err := f.Reserve(page, AllocOpts{Dir: BottomUp})
	if err != nil {
		t.Fatalf("Reserve(1 page): %v", err)
	}
	if fr1.Start < fr2.End && fr2.Start < fr1.End {
		t.Fatalf("overlapping reservations: %v and %v", fr1, fr2)
	}

	// PreferStart should extend a span when the next pages are still free.
	wantNext := fr1.End
	if fr2.Start == fr1.End {
		wantNext = fr2.End
	}
	fr3, err := f.Reserve(page, AllocOpts{
		Dir:            BottomUp,
		PreferStart:    true,
		PreferredStart: wantNext,
	})
	if err != nil {
		t.Fatalf("Reserve PreferStart: %v", err)
	}
	if fr3.Start != wantNext {
		t.Errorf("PreferStart got %#x want %#x", fr3.Start, wantNext)
	}

	// PreferStart falls back to Dir when the preferred offset is occupied.
	frMiss, err := f.Reserve(page, AllocOpts{
		Dir:            BottomUp,
		PreferStart:    true,
		PreferredStart: fr1.Start,
	})
	if err != nil {
		t.Fatalf("Reserve PreferStart occupied: %v", err)
	}
	if frMiss.Start == fr1.Start {
		t.Errorf("PreferStart occupied still returned %#x", frMiss.Start)
	}
	f.DecRef(frMiss)

	if !f.HasExactRefs(fr1, 1) {
		t.Errorf("HasExactRefs(%v, 1) got false want true", fr1)
	}
	if !f.HasUniqueRef(fr1) {
		t.Errorf("HasUniqueRef(%v) got false want true", fr1)
	}
	f.IncRef(fr1, 0)
	if !f.HasExactRefs(fr1, 2) {
		t.Errorf("after IncRef, HasExactRefs(%v, 2) got false want true", fr1)
	}
	if f.HasUniqueRef(fr1) {
		t.Errorf("after IncRef, HasUniqueRef(%v) got true want false", fr1)
	}
	f.DecRef(fr1)

	f.DecRef(fr1)
	seg := f.unfreeSmall.FindSegment(fr1.Start)
	if !seg.Ok() {
		t.Fatalf("no unfree segment covering released range %v", fr1)
	}
	if refs := seg.ValuePtr().refs; refs != 0 {
		t.Errorf("after DecRef, refs=%d want 0 (span leaked as used)", refs)
	}
}

func implicitZeroAt(f *MemoryFile, off uint64) bool {
	seg := f.memAcct.FindSegment(off)
	return seg.Ok() && seg.ValuePtr().implicitZero
}

func TestReserveSaveSkipsUnfaultedPages(t *testing.T) {
	f := &MemoryFile{
		opts: MemoryFileOpts{
			DisableMemoryAccounting: true,
		},
	}
	f.initFields()

	const length = 4 << 20
	fr, err := f.Reserve(length, AllocOpts{Dir: BottomUp})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if !implicitZeroAt(f, fr.Start) {
		t.Fatal("Reserve left implicitZero false")
	}

	var buf bytes.Buffer
	if err := f.SaveTo(context.Background(), &buf, &SaveOpts{}); err != nil {
		t.Fatalf("SaveTo unfaulted reserve: %v", err)
	}
	seg := f.memAcct.FindSegment(fr.Start)
	if !seg.Ok() {
		t.Fatal("memAcct lost reserved span after SaveTo")
	}
	if seg.ValuePtr().knownCommitted {
		t.Fatal("SaveTo marked unfaulted reserved pages knownCommitted")
	}
	if !seg.ValuePtr().implicitZero {
		t.Fatal("SaveTo cleared implicitZero")
	}

	touched := memmap.FileRange{Start: fr.Start, End: fr.Start + page}
	f.IncRef(touched, 0)
	if implicitZeroAt(f, touched.Start) {
		t.Fatal("IncRef left implicitZero true")
	}
	if !implicitZeroAt(f, touched.End) {
		t.Fatal("IncRef cleared implicitZero on untouched pages")
	}

	f.DecRef(touched)
	f.MarkImplicitZero(touched)
	if !implicitZeroAt(f, touched.Start) {
		t.Fatal("MarkImplicitZero left implicitZero false")
	}

	pb := f.exportMetadataProto()
	var found bool
	for _, ma := range pb.MemAcct {
		if ma.Start <= fr.Start && fr.Start < ma.End {
			found = true
			if !ma.ImplicitZero {
				t.Fatal("exportMetadataProto dropped implicitZero")
			}
		}
	}
	if !found {
		t.Fatal("exportMetadataProto omitted reserved span")
	}

	f2 := &MemoryFile{
		opts: MemoryFileOpts{DisableMemoryAccounting: true},
	}
	f2.initFields()
	if err := f2.importMetadataProto(pb); err != nil {
		t.Fatalf("importMetadataProto: %v", err)
	}
	if !implicitZeroAt(f2, fr.Start) {
		t.Fatal("importMetadataProto dropped implicitZero")
	}
}

func TestReserveHugeUsesHugeUnfree(t *testing.T) {
	f := &MemoryFile{
		opts: MemoryFileOpts{
			ExpectHugepages:         true,
			DisableMemoryAccounting: true,
		},
	}
	f.initFields()

	fr, err := f.Reserve(hugepage, AllocOpts{Huge: true, Dir: BottomUp})
	if err != nil {
		t.Fatalf("Reserve huge: %v", err)
	}
	if !f.IsHugeChunk(fr.Start) {
		t.Fatalf("Reserve(Huge) chunk at %#x is not huge", fr.Start)
	}
	seg := f.unfreeHuge.FindSegment(fr.Start)
	if !seg.Ok() {
		t.Fatal("Reserve(Huge) did not insert into unfreeHuge")
	}
	if refs := seg.ValuePtr().refs; refs != 1 {
		t.Errorf("unfreeHuge refs=%d want 1", refs)
	}
}
