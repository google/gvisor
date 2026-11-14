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
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/test/testutil"
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

// newInitializerTestMemoryFile has no background releaser, so a freed range
// remains available for deterministic tests of dirty-page reuse.
func newInitializerTestMemoryFile(t *testing.T) *MemoryFile {
	t.Helper()
	f := &MemoryFile{
		file: openSaveTestFile(t, ""),
		opts: MemoryFileOpts{DisableMemoryAccounting: true},
	}
	f.initFields()
	t.Cleanup(func() {
		f.mu.Lock()
		f.destroyed = true
		f.releaserDestroyLocked()
		f.mu.Unlock()
	})
	return f
}

func TestAllocateInitializerPrefix(t *testing.T) {
	for _, tc := range []struct {
		name        string
		initialized uint64
		err         error
	}{
		{name: "complete", initialized: 3 * page},
		{name: "partial page", initialized: page + 17, err: io.EOF},
		{name: "no complete page", initialized: 17, err: io.ErrUnexpectedEOF},
		{name: "complete page with error", initialized: page, err: io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInitializerTestMemoryFile(t)
			const length = 3 * page
			old, err := f.Allocate(length, AllocOpts{Mode: AllocateAndWritePopulate})
			if err != nil {
				t.Fatal(err)
			}
			f.forEachMappingSlice(old, func(bs []byte) {
				for i := range bs {
					bs[i] = 0xa5
				}
			})
			f.DecRef(old)
			payload := bytes.Repeat([]byte{0x37}, int(tc.initialized))
			var done uint64
			fr, err := f.Allocate(length, AllocOpts{
				Mode: AllocateAndWritePopulate,
				ReaderFunc: func(dsts safemem.BlockSeq) (uint64, error) {
					// Exercise repeated successful partial initialization too.
					next := min(tc.initialized-done, uint64(791))
					n, copyErr := safemem.CopySeq(dsts.TakeFirst64(next), safemem.BlockSeqOf(safemem.BlockFromSafeSlice(payload[done:done+next])))
					done += n
					if copyErr != nil {
						return n, copyErr
					}
					if done == tc.initialized {
						return n, tc.err
					}
					return n, nil
				},
			})
			if err != tc.err {
				t.Fatalf("Allocate error = %v, want %v", err, tc.err)
			}
			if want := uint64(hostarch.Addr(tc.initialized).RoundDown()); fr.Length() != want {
				t.Fatalf("returned length = %d, want %d", fr.Length(), want)
			}
			if fr.Length() != 0 {
				if fr.Start != old.Start {
					t.Fatal("test did not exercise dirty-range recycling")
				}
				f.forEachMappingSlice(fr, func(bs []byte) {
					if !bytes.Equal(bs, bytes.Repeat([]byte{0x37}, len(bs))) {
						t.Error("returned prefix contains uninitialized bytes")
					}
				})
				f.DecRef(fr)
			}
			// A subsequent ordinary allocation must clear both an initialized
			// prefix and any discarded, partially written dirty suffix.
			zeroed, err := f.Allocate(length, AllocOpts{Mode: AllocateAndWritePopulate})
			if err != nil {
				t.Fatal(err)
			}
			f.forEachMappingSlice(zeroed, func(bs []byte) {
				if !bytes.Equal(bs, make([]byte, len(bs))) {
					t.Error("ordinary allocation exposed dirty bytes")
				}
			})
			f.DecRef(zeroed)
		})
	}
}

func TestAllocateInitializerInvalidProgress(t *testing.T) {
	for _, tooLarge := range []bool{false, true} {
		f := newInitializerTestMemoryFile(t)
		fr, err := f.Allocate(page, AllocOpts{
			Mode: AllocateAndWritePopulate,
			ReaderFunc: func(dsts safemem.BlockSeq) (uint64, error) {
				if tooLarge {
					return dsts.NumBytes() + 1, nil
				}
				return 0, nil
			},
		})
		if err == nil || fr.Length() != 0 {
			t.Fatalf("invalid initializer returned (%v, %v), want empty range and error", fr, err)
		}
		if !tooLarge && err != io.ErrNoProgress {
			t.Errorf("zero-progress error = %v, want %v", err, io.ErrNoProgress)
		}
	}
}

func BenchmarkMemoryFilePrivateInitialization(b *testing.B) {
	const (
		readBytes   = 80 << 20
		extentBytes = 2 << 20
		windowBytes = 1 << 20
	)
	for _, policy := range []string{"uncommitted", "zeroed", "initialized"} {
		b.Run(policy, func(b *testing.B) {
			file := openSaveTestFile(b, "")
			f, err := NewMemoryFile(file, MemoryFileOpts{
				DelayedEviction:         DelayedEvictionDisabled,
				DisableMemoryAccounting: true,
				ExpectHugepages:         true,
				AdviseHugepage:          true,
			})
			if err != nil {
				file.Close()
				b.Fatal(err)
			}
			b.Cleanup(f.Destroy)
			sourceFR, err := f.Allocate(readBytes, AllocOpts{Mode: AllocateAndWritePopulate})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { f.DecRef(sourceFR) })
			f.forEachMappingSlice(sourceFR, func(bs []byte) {
				for i := range bs {
					bs[i] = 1
				}
			})
			source, err := f.MapInternal(sourceFR, hostarch.Read)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(readBytes)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				remaining := source
				var held [readBytes / extentBytes]memmap.FileRange
				heldCount := 0
				failed := false
				for !remaining.IsEmpty() {
					reader := safemem.BlockSeqReader{Blocks: remaining.TakeFirst64(extentBytes)}
					initialize := func(dsts safemem.BlockSeq) (uint64, error) {
						return reader.ReadToBlocks(dsts.TakeFirst64(windowBytes))
					}
					opts := AllocOpts{Mode: AllocateUncommitted, Huge: true}
					if policy != "uncommitted" {
						opts.Mode = AllocateAndWritePopulate
					}
					if policy == "initialized" {
						opts.ReaderFunc = initialize
					}
					fr, err := f.Allocate(extentBytes, opts)
					if fr.Length() != 0 {
						held[heldCount] = fr
						heldCount++
					}
					if err != nil {
						b.Errorf("Allocate: %v", err)
						failed = true
						break
					}
					if fr.Length() != extentBytes {
						b.Errorf("Allocate returned %d bytes, want %d", fr.Length(), extentBytes)
						failed = true
						break
					}
					if policy != "initialized" {
						dsts, err := f.MapInternal(fr, hostarch.Write)
						if err == nil {
							var n uint64
							n, err = safemem.ReadFullToBlocks(initialize, dsts)
							if n != extentBytes && err == nil {
								err = io.ErrUnexpectedEOF
							}
						}
						if err != nil {
							b.Errorf("copy: %v", err)
							failed = true
							break
						}
					}
					remaining = remaining.DropFirst64(extentBytes)
				}
				for _, fr := range held[:heldCount] {
					f.DecRef(fr)
				}
				if failed {
					break
				}
			}
			b.StopTimer()
			// Include pending destination reclamation in process CPU measurements.
			if err := testutil.Poll(func() error {
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.haveWaste {
					return fmt.Errorf("destination reclamation remains pending")
				}
				return nil
			}, time.Minute); err != nil {
				b.Error(err)
			}
		})
	}
}
