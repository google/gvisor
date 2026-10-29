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
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// newTestMmapCachedFile returns a MmapCachedFile for a temporary file of the
// given number of chunks.
func newTestMmapCachedFile(t *testing.T, chunks uint64) *MmapCachedFile {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "mmap")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer tmp.Close()
	if err := tmp.Truncate(int64(chunks * chunkSize())); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	fd, err := unix.Dup(int(tmp.Fd()))
	if err != nil {
		t.Fatalf("Dup: %v", err)
	}
	var f MmapCachedFile
	f.SetFD(fd)
	return &f
}

// mapChunk adds an application mapping of the chunk at chunkStart and returns
// the address of its internal mapping.
func mapChunk(t *testing.T, f *MmapCachedFile, chunkStart uint64) uintptr {
	t.Helper()
	f.AddMapping(hostarch.AddrRange{Start: 0, End: hostarch.Addr(chunkSize())}, chunkStart)
	bs, err := f.MapInternal(memmap.FileRange{Start: chunkStart, End: chunkStart + hostarch.PageSize}, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	return bs.Head().Addr()
}

func unmapChunk(f *MmapCachedFile, chunkStart uint64) {
	f.RemoveMapping(hostarch.AddrRange{Start: 0, End: hostarch.Addr(chunkSize())}, chunkStart)
}

func numMappings(f *MmapCachedFile) int {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()
	return len(f.mappings)
}

func TestMmapCachedFileReusesUnreferencedMapping(t *testing.T) {
	f := newTestMmapCachedFile(t, 1)
	before := retainedChunks.Load()

	addr := mapChunk(t, f, 0)
	unmapChunk(f, 0)
	if got := retainedChunks.Load() - before; got != 1 {
		t.Errorf("retained chunks after unmap: got %d, want 1", got)
	}
	if got := mapChunk(t, f, 0); got != addr {
		t.Errorf("remapped chunk address: got %#x, want %#x", got, addr)
	}
	if got := retainedChunks.Load() - before; got != 0 {
		t.Errorf("retained chunks after remap: got %d, want 0", got)
	}

	unmapChunk(f, 0)
	f.MappableRelease()
	if got := numMappings(f); got != 0 {
		t.Errorf("mappings after release: got %d, want 0", got)
	}
	if got := retainedChunks.Load() - before; got != 0 {
		t.Errorf("retained chunks after release: got %d, want 0", got)
	}
}

func TestMmapCachedFileRetainLimit(t *testing.T) {
	oldMax := maxRetainedChunks
	maxRetainedChunks = retainedChunks.Load() + 1
	defer func() { maxRetainedChunks = oldMax }()
	f := newTestMmapCachedFile(t, 2)

	mapChunk(t, f, 0)
	mapChunk(t, f, chunkSize())
	unmapChunk(f, 0)
	unmapChunk(f, chunkSize())
	if got := numMappings(f); got != 1 {
		t.Errorf("mappings over the limit: got %d, want 1", got)
	}

	f.MappableRelease()
	if got := numMappings(f); got != 0 {
		t.Errorf("mappings after release: got %d, want 0", got)
	}
}

func TestMmapCachedFileUnmapsAfterRelease(t *testing.T) {
	f := newTestMmapCachedFile(t, 1)
	before := retainedChunks.Load()

	mapChunk(t, f, 0)
	f.MappableRelease()
	unmapChunk(f, 0)
	if got := numMappings(f); got != 0 {
		t.Errorf("mappings: got %d, want 0", got)
	}
	if got := retainedChunks.Load() - before; got != 0 {
		t.Errorf("retained chunks: got %d, want 0", got)
	}
}
