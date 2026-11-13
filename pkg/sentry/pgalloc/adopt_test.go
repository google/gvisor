// Copyright 2026 The gVisor Authors.
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
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func createAdoptTestFD(t *testing.T) int {
	t.Helper()
	fd, err := memutil.CreateMemFD("pgalloc-adopt-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	return fd
}

func newAdoptTestMemoryFile(t *testing.T, fd int, keep bool) *MemoryFile {
	t.Helper()
	file := os.NewFile(uintptr(fd), "pgalloc-adopt-test")
	f, err := NewMemoryFile(file, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		KeepFileContents:        keep,
	})
	if err != nil {
		file.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)
	return f
}

func fillRange(t *testing.T, f *MemoryFile, fr memmap.FileRange, b byte) {
	t.Helper()
	f.forEachMappingSlice(fr, func(bs []byte) {
		for i := range bs {
			bs[i] = b
		}
	})
}

func checkRange(t *testing.T, f *MemoryFile, fr memmap.FileRange, b byte) {
	t.Helper()
	f.forEachMappingSlice(fr, func(bs []byte) {
		for i, got := range bs {
			if got != b {
				t.Fatalf("byte %d of %v: got %#x, want %#x", i, fr, got, b)
			}
		}
	})
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", name)
		}
	}()
	fn()
}

func TestAdoptExisting(t *testing.T) {
	fd := createAdoptTestFD(t)
	fd2, err := unix.Dup(fd)
	if err != nil {
		unix.Close(fd)
		t.Fatalf("Dup: %v", err)
	}

	// Allocate four ranges in the first MemoryFile and fill them.
	f1 := newAdoptTestMemoryFile(t, fd, false /* keep */)
	pg := uint64(hostarch.PageSize)
	var frs [4]memmap.FileRange
	for i, n := range []uint64{4, 3, 5, 2} {
		fr, err := f1.Allocate(n*pg, AllocOpts{Kind: usage.Tmpfs})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		fillRange(t, f1, fr, byte(i+1))
		frs[i] = fr
	}

	// Adopt the first and third ranges as used, and the fourth as unsaved.
	// The second range is neither, so it must be zeroed.
	used := []memmap.FileRange{frs[0], frs[2]}
	unsaved := []memmap.FileRange{frs[3]}
	f2 := newAdoptTestMemoryFile(t, fd2, true /* keep */)
	if err := f2.AdoptExisting(used, unsaved, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	checkRange(t, f2, frs[0], 1)
	checkRange(t, f2, frs[2], 3)
	checkRange(t, f2, frs[3], 4)
	checkRange(t, f2, frs[1], 0)
	if !f2.HasUniqueRef(frs[0]) || !f2.HasUniqueRef(frs[2]) {
		t.Errorf("adopted ranges do not have exactly one reference")
	}

	// New allocations must not overlap either used or unsaved ranges and must
	// read as zeros.
	for i := 0; i < 8; i++ {
		fr, err := f2.Allocate(2*pg, AllocOpts{Kind: usage.Tmpfs})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		for _, u := range append(append([]memmap.FileRange(nil), used...), unsaved...) {
			if fr.Overlaps(u) {
				t.Fatalf("new allocation %v overlaps reserved range %v", fr, u)
			}
		}
		checkRange(t, f2, fr, 0)
		fillRange(t, f2, fr, 0xff)
	}
	checkRange(t, f2, frs[0], 1)
	checkRange(t, f2, frs[2], 3)
	checkRange(t, f2, frs[3], 4)

	// Freeing an adopted range and an unsaved range returns them to the
	// allocator.
	f2.DecRef(frs[0])
	f2.FreeUnsaved(frs[3])
	checkRange(t, f2, frs[3], 0)
}

func TestAdoptExistingEmpty(t *testing.T) {
	fd := createAdoptTestFD(t)
	// Leave garbage in the file, then adopt nothing.
	if err := unix.Ftruncate(fd, 3*int64(hostarch.PageSize)); err != nil {
		unix.Close(fd)
		t.Fatalf("Ftruncate: %v", err)
	}
	if _, err := unix.Pwrite(fd, []byte{1, 2, 3}, 0); err != nil {
		unix.Close(fd)
		t.Fatalf("Pwrite: %v", err)
	}
	f := newAdoptTestMemoryFile(t, fd, true /* keep */)
	if err := f.AdoptExisting(nil, nil, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	fr, err := f.Allocate(uint64(hostarch.PageSize), AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	checkRange(t, f, fr, 0)
}

func TestAdoptExistingLifecycle(t *testing.T) {
	pg := uint64(hostarch.PageSize)

	// Allocating before AdoptExisting on a KeepFileContents MemoryFile must
	// panic rather than serve unzeroed backing file contents.
	fdUnadopted := createAdoptTestFD(t)
	if err := unix.Ftruncate(fdUnadopted, int64(pg)); err != nil {
		unix.Close(fdUnadopted)
		t.Fatalf("Ftruncate: %v", err)
	}
	fUnadopted := newAdoptTestMemoryFile(t, fdUnadopted, true /* keep */)
	mustPanic(t, "Allocate before AdoptExisting", func() {
		_, _ = fUnadopted.Allocate(pg, AllocOpts{Kind: usage.Tmpfs})
	})

	// Adopting a 0-byte backing file succeeds once, allows subsequent
	// allocations, and rejects a second AdoptExisting call.
	fZero := newAdoptTestMemoryFile(t, createAdoptTestFD(t), true /* keep */)
	if err := fZero.AdoptExisting(nil, nil, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting on empty file: %v", err)
	}
	if err := fZero.AdoptExisting(nil, nil, usage.Tmpfs); err == nil {
		t.Errorf("second AdoptExisting on empty file succeeded, want error")
	}
	fr, err := fZero.Allocate(pg, AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate after empty AdoptExisting: %v", err)
	}
	checkRange(t, fZero, fr, 0)
	fZero.DecRef(fr)

	// Calling AdoptExisting a second time on a non-empty file also fails.
	fdNonEmpty := createAdoptTestFD(t)
	if err := unix.Ftruncate(fdNonEmpty, int64(pg)); err != nil {
		unix.Close(fdNonEmpty)
		t.Fatalf("Ftruncate: %v", err)
	}
	fNonEmpty := newAdoptTestMemoryFile(t, fdNonEmpty, true /* keep */)
	if err := fNonEmpty.AdoptExisting(nil, nil, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	if err := fNonEmpty.AdoptExisting(nil, nil, usage.Tmpfs); err == nil {
		t.Errorf("second AdoptExisting succeeded, want error")
	}
}

func TestAdoptExistingValidation(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	for _, tc := range []struct {
		name    string
		used    []memmap.FileRange
		unsaved []memmap.FileRange
	}{
		{name: "unaligned", used: []memmap.FileRange{{Start: 1, End: pg}}},
		{name: "empty", used: []memmap.FileRange{{Start: pg, End: pg}}},
		{name: "unsorted", used: []memmap.FileRange{{Start: 2 * pg, End: 3 * pg}, {Start: 0, End: pg}}},
		{name: "overlapping", used: []memmap.FileRange{{Start: 0, End: 2 * pg}, {Start: pg, End: 3 * pg}}},
		{name: "beyond_eof", used: []memmap.FileRange{{Start: 0, End: 5 * pg}}},
		{name: "unsaved_unaligned", unsaved: []memmap.FileRange{{Start: 1, End: pg}}},
		{
			name:    "used_overlaps_unsaved",
			used:    []memmap.FileRange{{Start: pg, End: 3 * pg}},
			unsaved: []memmap.FileRange{{Start: 2 * pg, End: 4 * pg}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd := createAdoptTestFD(t)
			if err := unix.Ftruncate(fd, 4*int64(pg)); err != nil {
				unix.Close(fd)
				t.Fatalf("Ftruncate: %v", err)
			}
			f := newAdoptTestMemoryFile(t, fd, true /* keep */)
			if err := f.AdoptExisting(tc.used, tc.unsaved, usage.Tmpfs); err == nil {
				t.Errorf("AdoptExisting(%v, %v) succeeded, want error", tc.used, tc.unsaved)
			}
		})
	}
}

func TestAdoptExistingRequiresKeepFileContents(t *testing.T) {
	f := newAdoptTestMemoryFile(t, createAdoptTestFD(t), false /* keep */)
	if err := f.AdoptExisting(nil, nil, usage.Tmpfs); err == nil {
		t.Errorf("AdoptExisting succeeded without KeepFileContents")
	}
}

func TestUnsavedLifecycleAndPanics(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	f := newAdoptTestMemoryFile(t, createAdoptTestFD(t), false /* keep */)
	ufr, err := f.AllocateUnsaved(3 * pg)
	if err != nil {
		t.Fatalf("AllocateUnsaved: %v", err)
	}
	fillRange(t, f, ufr, 0x5a)

	mustPanic(t, "IncRef on unsaved range", func() {
		f.IncRef(ufr, 0)
	})
	mustPanic(t, "DecRef on unsaved range", func() {
		f.DecRef(ufr)
	})

	// Freeing a middle subrange splits the unsaved reservation cleanly.
	mid := memmap.FileRange{Start: ufr.Start + pg, End: ufr.Start + 2*pg}
	f.FreeUnsaved(mid)
	checkRange(t, f, memmap.FileRange{Start: ufr.Start, End: mid.Start}, 0x5a)
	checkRange(t, f, mid, 0)
	checkRange(t, f, memmap.FileRange{Start: mid.End, End: ufr.End}, 0x5a)

	mustPanic(t, "duplicate FreeUnsaved", func() {
		f.FreeUnsaved(mid)
	})

	f.FreeUnsaved(memmap.FileRange{Start: ufr.Start, End: mid.Start})
	f.FreeUnsaved(memmap.FileRange{Start: mid.End, End: ufr.End})
}

func TestUnsavedExcludedFromSaveRestore(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	for _, async := range []bool{false, true} {
		name := "inline"
		if async {
			name = "async_pages_file"
		}
		t.Run(name, func(t *testing.T) {
			f1 := newAdoptTestMemoryFile(t, createAdoptTestFD(t), false /* keep */)
			if err := f1.ClaimFirstPageUnsaved(); err != nil {
				t.Fatalf("ClaimFirstPageUnsaved: %v", err)
			}
			firstFR := memmap.FileRange{Start: 0, End: pg}
			fillRange(t, f1, firstFR, 0xaa)

			ufr, err := f1.AllocateUnsaved(2 * pg)
			if err != nil {
				t.Fatalf("AllocateUnsaved: %v", err)
			}
			fillRange(t, f1, ufr, 0xbb)

			dataFR, err := f1.Allocate(pg, AllocOpts{Kind: usage.Tmpfs})
			if err != nil {
				t.Fatalf("Allocate: %v", err)
			}
			t.Cleanup(func() { f1.DecRef(dataFR) })
			fillRange(t, f1, dataFR, 0xcc)

			// ClaimFirstPageUnsaved must fail now that page 0 is claimed.
			if err := f1.ClaimFirstPageUnsaved(); err == nil {
				t.Fatalf("second ClaimFirstPageUnsaved succeeded")
			}

			var metaBuf bytes.Buffer
			var pagesBuf bytes.Buffer
			if async {
				saveDone := make(chan error, 1)
				apfs, err := StartAsyncPagesFileSave(
					stateio.NewIOWriter(&pagesBuf, pg, 1 /* maxRanges */, 2 /* maxParallel */),
					func(err error) { saveDone <- err },
				)
				if err != nil {
					t.Fatalf("StartAsyncPagesFileSave: %v", err)
				}
				saveErr := f1.SaveTo(t.Context(), &metaBuf, &SaveOpts{PagesFile: apfs})
				apfs.MemoryFilesDone()
				if asyncErr := <-saveDone; saveErr != nil || asyncErr != nil {
					t.Fatalf("SaveTo: saveErr=%v asyncErr=%v", saveErr, asyncErr)
				}
			} else {
				if err := f1.SaveTo(t.Context(), &metaBuf, &SaveOpts{}); err != nil {
					t.Fatalf("SaveTo: %v", err)
				}
			}

			// Save-resume: unsaved reservations and their contents remain intact
			// in the source MemoryFile after SaveTo returns.
			checkRange(t, f1, firstFR, 0xaa)
			checkRange(t, f1, ufr, 0xbb)
			postSaveFR, err := f1.Allocate(pg, AllocOpts{Kind: usage.Tmpfs})
			if err != nil {
				t.Fatalf("Allocate after SaveTo: %v", err)
			}
			t.Cleanup(func() { f1.DecRef(postSaveFR) })
			if postSaveFR.Overlaps(firstFR) || postSaveFR.Overlaps(ufr) {
				t.Fatalf("post-SaveTo allocation %v overlaps unsaved reservations", postSaveFR)
			}

			f2 := newAdoptTestMemoryFile(t, createAdoptTestFD(t), false /* keep */)
			if async {
				loadDone := make(chan error, 1)
				apfl, err := StartAsyncPagesFileLoad(
					stateio.NewIOReader(bytes.NewReader(pagesBuf.Bytes()), pg, 1 /* maxRanges */, 2 /* maxParallel */),
					func(err error) { loadDone <- err },
					nil,
					AsyncPagesFileLoadOpts{},
				)
				if err != nil {
					t.Fatalf("StartAsyncPagesFileLoad: %v", err)
				}
				loadErr := f2.LoadFrom(t.Context(), bytes.NewReader(metaBuf.Bytes()), &LoadOpts{PagesFile: apfl})
				apfl.MemoryFilesDone()
				if asyncErr := <-loadDone; loadErr != nil || asyncErr != nil {
					t.Fatalf("LoadFrom: loadErr=%v asyncErr=%v", loadErr, asyncErr)
				}
			} else {
				if err := f2.LoadFrom(t.Context(), &metaBuf, &LoadOpts{}); err != nil {
					t.Fatalf("LoadFrom: %v", err)
				}
			}
			t.Cleanup(func() { f2.DecRef(dataFR) })
			checkRange(t, f2, dataFR, 0xcc)
			// Unsaved ranges were omitted from the checkpoint, so page 0 is free
			// again in the restored MemoryFile.
			if err := f2.ClaimFirstPageUnsaved(); err != nil {
				t.Fatalf("ClaimFirstPageUnsaved after restore: %v", err)
			}
		})
	}
}
