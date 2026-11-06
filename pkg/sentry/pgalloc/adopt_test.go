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
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

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

func TestAdoptExisting(t *testing.T) {
	fd, err := memutil.CreateMemFD("pgalloc-adopt-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	fd2, err := unix.Dup(fd)
	if err != nil {
		t.Fatalf("Dup: %v", err)
	}

	// Allocate three ranges in the first MemoryFile and fill them.
	f1 := newAdoptTestMemoryFile(t, fd, false /* keep */)
	pg := uint64(hostarch.PageSize)
	var frs [3]memmap.FileRange
	for i, n := range []uint64{4, 3, 5} {
		fr, err := f1.Allocate(n*pg, AllocOpts{Kind: usage.Tmpfs})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		fillRange(t, f1, fr, byte(i+1))
		frs[i] = fr
	}

	// Adopt the first and third ranges in a second MemoryFile on the same
	// file. The second range is not adopted, so it must be zeroed.
	used := []memmap.FileRange{frs[0], frs[2]}
	f2 := newAdoptTestMemoryFile(t, fd2, true /* keep */)
	if err := f2.AdoptExisting(used, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	checkRange(t, f2, frs[0], 1)
	checkRange(t, f2, frs[2], 3)
	checkRange(t, f2, frs[1], 0)
	if !f2.HasUniqueRef(frs[0]) || !f2.HasUniqueRef(frs[2]) {
		t.Errorf("adopted ranges do not have exactly one reference")
	}

	// New allocations must not overlap the adopted ranges and must read as
	// zeros.
	for i := 0; i < 8; i++ {
		fr, err := f2.Allocate(2*pg, AllocOpts{Kind: usage.Tmpfs})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		for _, u := range used {
			if fr.Overlaps(u) {
				t.Fatalf("new allocation %v overlaps adopted range %v", fr, u)
			}
		}
		checkRange(t, f2, fr, 0)
		fillRange(t, f2, fr, 0xff)
	}
	checkRange(t, f2, frs[0], 1)
	checkRange(t, f2, frs[2], 3)

	// Freeing an adopted range returns it to the allocator.
	f2.DecRef(frs[0])
}

func TestAdoptExistingEmpty(t *testing.T) {
	fd, err := memutil.CreateMemFD("pgalloc-adopt-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	// Leave garbage in the file, then adopt nothing.
	if err := unix.Ftruncate(fd, 3*int64(hostarch.PageSize)); err != nil {
		t.Fatalf("Ftruncate: %v", err)
	}
	if _, err := unix.Pwrite(fd, []byte{1, 2, 3}, 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	f := newAdoptTestMemoryFile(t, fd, true /* keep */)
	if err := f.AdoptExisting(nil, usage.Tmpfs); err != nil {
		t.Fatalf("AdoptExisting: %v", err)
	}
	fr, err := f.Allocate(uint64(hostarch.PageSize), AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	checkRange(t, f, fr, 0)
}

func TestAdoptExistingValidation(t *testing.T) {
	pg := uint64(hostarch.PageSize)
	for _, tc := range []struct {
		name string
		used []memmap.FileRange
	}{
		{name: "unaligned", used: []memmap.FileRange{{Start: 1, End: pg}}},
		{name: "empty", used: []memmap.FileRange{{Start: pg, End: pg}}},
		{name: "unsorted", used: []memmap.FileRange{{Start: 2 * pg, End: 3 * pg}, {Start: 0, End: pg}}},
		{name: "overlapping", used: []memmap.FileRange{{Start: 0, End: 2 * pg}, {Start: pg, End: 3 * pg}}},
		{name: "beyond EOF", used: []memmap.FileRange{{Start: 0, End: 5 * pg}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := memutil.CreateMemFD("pgalloc-adopt-test", 0)
			if err != nil {
				t.Fatalf("CreateMemFD: %v", err)
			}
			if err := unix.Ftruncate(fd, 4*int64(pg)); err != nil {
				t.Fatalf("Ftruncate: %v", err)
			}
			f := newAdoptTestMemoryFile(t, fd, true /* keep */)
			if err := f.AdoptExisting(tc.used, usage.Tmpfs); err == nil {
				t.Errorf("AdoptExisting(%v) succeeded, want error", tc.used)
			}
		})
	}
}

func TestAdoptExistingRequiresKeepFileContents(t *testing.T) {
	fd, err := memutil.CreateMemFD("pgalloc-adopt-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	f := newAdoptTestMemoryFile(t, fd, false /* keep */)
	if err := f.AdoptExisting(nil, usage.Tmpfs); err == nil {
		t.Errorf("AdoptExisting succeeded without KeepFileContents")
	}
}
