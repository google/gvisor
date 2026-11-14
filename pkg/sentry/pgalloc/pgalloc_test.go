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
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
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

// TestFindAllocatable tests allocation for 4K page size. See
// TestFindAllocatable64K for 64K page size.
func TestFindAllocatable(t *testing.T) {
	use4KPagesForTest(t)
	page, hugepage := uint64(hostarch.PageSize), uint64(hostarch.HugePageSize)
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
			name:      "recycling bottom-up huge allocation aligns within unaligned waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, page, existingUsed},
				{page, 2 * hugepage, existingWaste},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    hugepage,
		},
		{
			name:      "recycling top-down huge allocation aligns within unaligned waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - 2*hugepage, chunkSize - page, existingWaste},
				{chunkSize - page, chunkSize, existingUsed},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*hugepage,
		},
		{
			name:      "recycling bottom-up huge allocation aligns within barely large enough waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{hugepage - page, 2 * hugepage, existingWaste},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    hugepage,
		},
		{
			name:      "recycling top-down huge allocation aligns within barely large enough waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - 2*hugepage, chunkSize - hugepage + page, existingWaste},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*hugepage,
		},
		{
			name:      "recycling bottom-up huge allocation skips unaligned waste pages that can't fit",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, page, existingUsed},
				{page, hugepage + page, existingWaste},
				{hugepage + page, 2 * hugepage, existingUsed},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    2 * hugepage,
		},
		{
			name:      "recycling bottom-up huge allocation skips to later waste pages that fit",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, page, existingUsed},
				{page, hugepage + page, existingWaste},
				{hugepage + page, 2 * hugepage, existingUsed},
				{2 * hugepage, 4 * hugepage, existingWaste},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    2 * hugepage,
		},
		{
			name:      "recycling top-down huge allocation skips to earlier waste pages that fit",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - 4*hugepage, chunkSize - 2*hugepage, existingWaste},
				{chunkSize - 2*hugepage, chunkSize - hugepage - page, existingUsed},
				{chunkSize - hugepage - page, chunkSize - page, existingWaste},
				{chunkSize - page, chunkSize, existingUsed},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 3*hugepage,
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

// mapFileWithReadOnlyPage returns a file of three pages filled with ones,
// except that the middle page is filled with b, and a shared mapping of the
// file in which the middle page is read-only. Writes to the middle page fault,
// like writes to a page of a disk-backed file that the host cannot allocate
// disk space for.
func mapFileWithReadOnlyPage(t *testing.T, b byte) (int, []byte) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "pgalloc")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	page := int(hostarch.PageSize)
	data := make([]byte, 3*page)
	for i := range data {
		data[i] = 1
	}
	for i := page; i < 2*page; i++ {
		data[i] = b
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	m, err := unix.Mmap(int(f.Fd()), 0, 3*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)
	}
	t.Cleanup(func() { unix.Munmap(m) })
	if err := unix.Mprotect(m[page:2*page], unix.PROT_READ); err != nil {
		t.Fatalf("Mprotect failed: %v", err)
	}
	return int(f.Fd()), m
}

func TestZeroDiskBackedSkipsZeroUnwritablePage(t *testing.T) {
	fd, m := mapFileWithReadOnlyPage(t, 0)
	// Start at the second page, so that file offsets differ from offsets in
	// the zeroed slice.
	page := int(hostarch.PageSize)
	if zeroDiskBacked(fd, uint64(page), m[page:]) {
		t.Errorf("zeroDiskBacked returned true after skipping a page")
	}
	if i := slices.IndexFunc(m[page:], func(b byte) bool { return b != 0 }); i >= 0 {
		t.Errorf("zeroDiskBacked left byte %d nonzero", page+i)
	}
}

func TestZeroDiskBackedPanicsOnNonzeroUnwritablePage(t *testing.T) {
	fd, m := mapFileWithReadOnlyPage(t, 1)
	defer func() {
		if recover() == nil {
			t.Errorf("zeroDiskBacked did not panic")
		}
	}()
	zeroDiskBacked(fd, 0, m)
}

func BenchmarkMemoryFileRefAccounting(b *testing.B) {
	pageSize := uint64(hostarch.PageSize)
	for _, bc := range []struct {
		name        string
		pages       int
		stride      uint64
		singleRange bool
		fragmented  bool
	}{
		{name: "contiguous-range", pages: 1024, singleRange: true},
		{name: "adjacent-single-pages", pages: 1024, stride: 1},
		{name: "sparse-single-pages", pages: 1024, stride: 4},
		{name: "whole-fragmented-range-1024", pages: 1024, singleRange: true, fragmented: true},
		{name: "whole-fragmented-range-65536", pages: 65536, singleRange: true, fragmented: true},
	} {
		b.Run(bc.name, func(b *testing.B) {
			file := openSaveTestFile(b, "")
			f, err := NewMemoryFile(file, MemoryFileOpts{
				DelayedEviction:         DelayedEvictionDisabled,
				DisableMemoryAccounting: true,
			})
			if err != nil {
				file.Close()
				b.Fatalf("NewMemoryFile: %v", err)
			}
			backing, err := f.Allocate(4*uint64(bc.pages)*pageSize, AllocOpts{Mode: AllocateUncommitted})
			if err != nil {
				f.Destroy()
				b.Fatalf("Allocate: %v", err)
			}
			b.Cleanup(func() {
				if bc.fragmented {
					for i := 0; i < bc.pages; i++ {
						start := backing.Start + uint64(i)*pageSize
						fr := memmap.FileRange{Start: start, End: start + pageSize}
						f.DecRef(fr)
						if i%2 == 0 {
							f.DecRef(fr)
						}
					}
				}
				f.DecRef(backing)
				f.Destroy()
			})

			var ranges []memmap.FileRange
			if bc.singleRange {
				ranges = make([]memmap.FileRange, 1)
				ranges[0] = memmap.FileRange{Start: backing.Start, End: backing.Start + uint64(bc.pages)*pageSize}
			} else {
				ranges = make([]memmap.FileRange, bc.pages)
				for i := range ranges {
					start := backing.Start + uint64(i)*bc.stride*pageSize
					ranges[i] = memmap.FileRange{Start: start, End: start + pageSize}
				}
			}

			checkFragmentedCounts := func(stage string) {
				if !bc.fragmented {
					return
				}
				f.mu.Lock()
				metadata := f.exportMetadataProto()
				f.mu.Unlock()
				pageIndex := 0
				for _, r := range metadata.UnfreeSmall {
					for start := max(r.Start, backing.Start); start < min(r.End, ranges[0].End); start += pageSize {
						want := uint64(3 - pageIndex%2)
						if r.Refs != want {
							b.Fatalf("%s: page %d has %d references, want %d", stage, pageIndex, r.Refs, want)
						}
						pageIndex++
					}
				}
				if pageIndex != bc.pages {
					b.Fatalf("%s: found %d pages, want %d", stage, pageIndex, bc.pages)
				}
			}

			if bc.fragmented {
				for i := 0; i < bc.pages; i++ {
					start := backing.Start + uint64(i)*pageSize
					fr := memmap.FileRange{Start: start, End: start + pageSize}
					f.IncRef(fr, 0)
					if i%2 == 0 {
						f.IncRef(fr, 0)
					}
				}
				checkFragmentedCounts("after setup")
			} else {
				if !f.HasUniqueRef(backing) {
					b.Fatal("backing allocation is not initially unique")
				}
				for _, fr := range ranges {
					f.IncRef(fr, 0)
				}
				for _, fr := range ranges {
					if f.HasUniqueRef(fr) {
						b.Fatalf("range %v is unique after IncRef", fr)
					}
				}
				for _, fr := range ranges {
					f.DecRef(fr)
				}
				if !f.HasUniqueRef(backing) {
					b.Fatal("backing allocation is not unique after DecRef")
				}
			}

			b.ReportAllocs()
			for b.Loop() {
				for _, fr := range ranges {
					f.IncRef(fr, 0)
				}
				for _, fr := range ranges {
					f.DecRef(fr)
				}
			}
			if bc.fragmented {
				checkFragmentedCounts("after benchmark loop")
			} else if !f.HasUniqueRef(backing) {
				b.Fatal("backing allocation is not unique after benchmark loop")
			}
		})
	}
}

func TestMemoryFileRefAccountingMatchesPerPageModel(t *testing.T) {
	f := newSaveTestMemoryFile(t, "", false)
	const numPages = 64
	backing, err := f.Allocate(numPages*uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	owned := backing
	t.Cleanup(func() { f.DecRef(owned) })

	counts := make([]int, numPages)
	for i := range counts {
		counts[i] = 1
	}
	fileRange := func(start, end int) memmap.FileRange {
		return memmap.FileRange{
			Start: backing.Start + uint64(start*hostarch.PageSize),
			End:   backing.Start + uint64(end*hostarch.PageSize),
		}
	}
	verify := func(stage string) {
		for start := 0; start < numPages; start++ {
			for end := start + 1; end <= numPages; end++ {
				fr := fileRange(start, end)
				wantUnique := true
				firstShared := -1
				for i := start; i < end; i++ {
					if counts[i] > 1 {
						wantUnique = false
						if firstShared < 0 {
							firstShared = i
						}
					}
				}
				if got := f.HasUniqueRef(fr); got != wantUnique {
					t.Errorf("%s: HasUniqueRef(%v) = %t, want %t", stage, fr, got, wantUnique)
				}
				gotShared, ok := f.FirstSharedRange(fr)
				if firstShared < 0 {
					if ok {
						t.Errorf("%s: FirstSharedRange(%v) = %v, want no shared range", stage, fr, gotShared)
					}
					continue
				}
				sharedEnd := firstShared
				for sharedEnd < end && counts[sharedEnd] > 1 {
					sharedEnd++
				}
				wantShared := fileRange(firstShared, sharedEnd)
				if !ok || gotShared != wantShared {
					t.Errorf("%s: FirstSharedRange(%v) = (%v, %t), want (%v, true)", stage, fr, gotShared, ok, wantShared)
				}
			}
		}
	}
	inc := func(start, end int) {
		f.IncRef(fileRange(start, end), 0)
		for i := start; i < end; i++ {
			counts[i]++
		}
	}
	dec := func(start, end int) {
		f.DecRef(fileRange(start, end))
		for i := start; i < end; i++ {
			counts[i]--
		}
	}

	// A surviving reference must keep the page live after another reference is
	// released.
	pageRange := fileRange(0, 1)
	write, err := f.MapInternal(pageRange, hostarch.Write)
	if err != nil {
		t.Fatalf("MapInternal for write: %v", err)
	}
	const contents = byte(0x5a)
	if n, err := safemem.CopySeq(write, safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte{contents}))); err != nil || n != 1 {
		t.Fatalf("write page: copied %d bytes, err %v", n, err)
	}
	inc(0, 1)
	dec(0, 1)
	read, err := f.MapInternal(pageRange, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal for read: %v", err)
	}
	gotContents := []byte{0}
	if n, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(gotContents)), read); err != nil || n != 1 {
		t.Fatalf("read page: copied %d bytes, err %v", n, err)
	}
	if gotContents[0] != contents {
		t.Fatalf("page contents after releasing one of two references = %#x, want %#x", gotContents[0], contents)
	}
	verify("after releasing one of two references")

	inc(2, 6)
	verify("after first overlapping reference")
	inc(4, 7)
	verify("after second overlapping reference")
	inc(3, 5)
	verify("after third overlapping reference")
	dec(3, 6)
	verify("after partial release")
	for i := 0; i < numPages; i++ {
		inc(i, i+1)
		if i%2 == 0 {
			inc(i, i+1)
		}
	}
	verify("after fragmented references")
	dec(0, numPages)
	verify("after whole-range decrement to mixed references")
	inc(0, numPages)
	verify("after whole-range increment through gaps")
	inc(0, numPages)
	verify("after whole-range increment")
	dec(0, numPages)
	verify("after whole-range decrement")
	for i := 0; i < numPages; i++ {
		dec(i, i+1)
		if i%2 == 0 {
			dec(i, i+1)
		}
	}
	verify("after removing fragmented references")
	dec(3, 4)
	verify("after making a gap in shared pages")
	dec(4, 5)
	verify("after reducing a count greater than two")
	dec(4, 5)
	verify("after releasing the last extra reference on a page")
	dec(2, 3)
	dec(5, 7)
	verify("after balancing references")

	// Dropping the final owner must stop serializing that page as live while
	// preserving the neighboring allocation.
	dec(0, 1)
	owned.Start = pageRange.End
	neighbor := fileRange(1, 2)
	f.mu.Lock()
	metadata := f.exportMetadataProto()
	f.mu.Unlock()
	neighborLive := false
	for _, r := range metadata.UnfreeSmall {
		if r.Refs == 0 {
			continue
		}
		if r.Start < pageRange.End && pageRange.Start < r.End {
			t.Errorf("released page %v is serialized with %d references", pageRange, r.Refs)
		}
		if r.Start <= neighbor.Start && neighbor.End <= r.End {
			neighborLive = true
			if r.Refs != 1 {
				t.Errorf("neighbor %v has %d references, want 1", neighbor, r.Refs)
			}
		}
	}
	if !neighborLive {
		t.Error("live neighbor is absent from serialized ownership")
	}
	probe, err := f.Allocate(uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate after final release: %v", err)
	}
	t.Cleanup(func() { f.DecRef(probe) })
	if probe.Start < owned.End && owned.Start < probe.End {
		t.Errorf("allocation %v overlaps still-owned backing %v", probe, owned)
	}
}

func TestMemoryFileRefAccountingAcrossChunks(t *testing.T) {
	f := newSaveTestMemoryFile(t, "", false)
	pageSize := uint64(hostarch.PageSize)
	backing, err := f.Allocate(chunkSize+2*pageSize, AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate across chunks: %v", err)
	}
	owned := []memmap.FileRange{backing}
	t.Cleanup(func() {
		for _, fr := range owned {
			f.DecRef(fr)
		}
	})
	boundary := (backing.Start/chunkSize + 1) * chunkSize
	cross := memmap.FileRange{Start: boundary - pageSize, End: boundary + pageSize}
	f.IncRef(cross, 0)
	if got, ok := f.FirstSharedRange(backing); !ok || got != cross {
		t.Fatalf("FirstSharedRange across chunks = (%v, %t), want (%v, true)", got, ok, cross)
	}
	f.DecRef(cross)
	if !f.HasUniqueRef(backing) {
		t.Fatal("backing remains shared after balancing the cross-chunk reference")
	}
	f.DecRef(cross)
	owned = []memmap.FileRange{
		{Start: backing.Start, End: cross.Start},
		{Start: cross.End, End: backing.End},
	}
	f.mu.Lock()
	metadata := f.exportMetadataProto()
	f.mu.Unlock()
	for _, r := range metadata.UnfreeSmall {
		if r.Refs != 0 && r.Start < cross.End && cross.Start < r.End {
			t.Errorf("released cross-chunk pages %v are serialized with %d references", cross, r.Refs)
		}
	}
	for _, fr := range owned {
		if !f.HasUniqueRef(fr) {
			t.Errorf("remaining owned range %v is not unique", fr)
		}
	}
}
