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

package fsutil

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

type testMmapFile struct {
	MmapCachedFile
	path string
}

func newTestMmapFile(t *testing.T, size uint64) *testMmapFile {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &testMmapFile{path: filepath.Join(dir, "mmap")}
	fd, err := unix.Open(f.path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.SetFD(fd)
	t.Cleanup(f.MappableRelease)
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		t.Fatal(err)
	}
	return f
}

// mapAndDrop returns the first host address for comparison across mappings.
func (f *testMmapFile) mapAndDrop(t *testing.T, fr memmap.FileRange) uintptr {
	t.Helper()
	ar := hostarch.AddrRange{End: hostarch.Addr(fr.Length())}
	f.AddMapping(ar, fr.Start)
	defer f.RemoveMapping(ar, fr.Start)
	bs, err := f.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatal(err)
	}
	return bs.Head().Addr()
}

// checkMappings checks the starting file offsets of all host VMAs of f.
func (f *testMmapFile) checkMappings(t *testing.T, offsets ...uint64) {
	t.Helper()
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	var got []uint64
	for _, line := range strings.Split(string(maps), "\n") {
		if strings.HasSuffix(line, " "+f.path) {
			off, err := strconv.ParseUint(strings.Fields(line)[2], 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, off)
		}
	}
	if !slices.Equal(got, offsets) {
		t.Errorf("%s mapped offsets: got %v, want %v", f.path, got, offsets)
	}
}

func TestMmapCachedFileEvictsLeastRecentlyUnreferenced(t *testing.T) {
	chunkCache.mu.Lock()
	oldMax := chunkCache.maxBytes
	chunkCache.maxBytes = 3 * chunkSize()
	chunkCache.mu.Unlock()
	defer func() {
		chunkCache.mu.Lock()
		chunkCache.maxBytes = oldMax
		chunkCache.mu.Unlock()
	}()

	page := memmap.FileRange{End: hostarch.PageSize}
	a, b := newTestMmapFile(t, page.End), newTestMmapFile(t, page.End)
	c, d := newTestMmapFile(t, page.End), newTestMmapFile(t, page.End)
	for _, f := range []*testMmapFile{a, b, c, d} {
		f.KeepUnreferencedMappings()
	}
	addr := a.mapAndDrop(t, page)
	_ = b.mapAndDrop(t, page)
	_ = c.mapAndDrop(t, page)
	a.checkMappings(t, 0) // The oldest mapping survives at exactly the cap.
	if got := a.mapAndDrop(t, page); got != addr {
		t.Errorf("reused mapping address: got %#x, want %#x", got, addr)
	}
	_ = d.mapAndDrop(t, page)
	a.checkMappings(t, 0)
	b.checkMappings(t)
	c.checkMappings(t)
	d.checkMappings(t, 0)

	// A file that was not asked to keep unreferenced mappings does not.
	e := newTestMmapFile(t, page.End)
	_ = e.mapAndDrop(t, page)
	e.checkMappings(t)
}

func TestMmapCachedFileUnmapsAfterRelease(t *testing.T) {
	if err := usage.Init(); err != nil {
		t.Fatal(err)
	}
	pinned := memmap.FileRange{Start: chunkSize(), End: chunkSize() + hostarch.PageSize}
	f := newTestMmapFile(t, pinned.End)
	f.KeepUnreferencedMappings()
	func() {
		f.IncRef(pinned, 0)
		defer f.DecRef(pinned)
		_ = f.mapAndDrop(t, memmap.FileRange{Start: chunkSize() - hostarch.PageSize, End: pinned.End})
		f.MappableRelease()
		f.checkMappings(t, pinned.Start)
		if _, err := f.DataFD(pinned); err != nil {
			t.Errorf("DataFD with outstanding reference: %v", err)
		}
	}()
	f.checkMappings(t)
}
