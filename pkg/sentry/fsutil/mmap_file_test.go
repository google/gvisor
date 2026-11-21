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
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func createSizedFile(t testing.TB, size uint64, prefix []byte) string {
	t.Helper()
	if err := usage.Init(); err != nil {
		t.Fatalf("usage.Init failed: %v", err)
	}
	p := filepath.Join(t.TempDir(), "backing")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	defer f.Close()
	if err := f.Truncate(int64(size)); err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}
	if len(prefix) > 0 {
		if _, err := f.WriteAt(prefix, 0); err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
	}
	return p
}

func readFileAt(t testing.TB, path string, offset int64, n int) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%q) failed: %v", path, err)
	}
	defer f.Close()
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, offset); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt(%q, %d) failed: %v", path, offset, err)
	}
	return buf
}

func oldMappingsSlice(mf *MmapCachedFile, chunkStart uint64) []uintptr {
	mf.mapsMu.Lock()
	defer mf.mapsMu.Unlock()
	om, ok := mf.oldMappings[chunkStart]
	if !ok {
		return nil
	}
	res := make([]uintptr, 0, 1+len(om.more))
	res = append(res, om.addr)
	res = append(res, om.more...)
	return res
}

func procMapsPathname(line string) string {
	s := line
	for i := 0; i < 5; i++ {
		s = strings.TrimLeft(s, " \t")
		idx := strings.IndexAny(s, " \t")
		if idx < 0 {
			return ""
		}
		s = s[idx:]
	}
	return strings.TrimLeft(s, " \t")
}

// assertFileUnmapped checks that no mapping in the current process maps the
// file at path. Only the test maps its backing files, so the check is not
// affected by other mappings that reuse the unmapped addresses.
func assertFileUnmapped(t *testing.T, path string) {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) failed: %v", path, err)
	}
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("ReadFile(/proc/self/maps) failed: %v", err)
	}
	for _, line := range strings.Split(string(maps), "\n") {
		if procMapsPathname(line) == resolved {
			t.Fatalf("%q is still mapped: %s", resolved, line)
		}
	}
}

func TestMmapCachedFileFailedWriteUpgradePreservesReadMapping(t *testing.T) {
	want := []byte("readonly-content")
	p := createSizedFile(t, chunkSize(), want)
	roFD, err := unix.Open(p, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("unix.Open failed: %v", err)
	}

	var mf MmapCachedFile
	mf.SetFD(roFD)
	fr := memmap.FileRange{Start: 0, End: pageSize}
	mf.IncRef(fr, 1)
	defer func() {
		mf.DecRef(fr)
		mf.MappableRelease()
	}()

	roSeq, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal(Read) failed: %v", err)
	}
	roAddr := roSeq.Head().Addr()

	// Both mprotect and fallback mmap fail with EACCES on a read-only FD.
	if _, err := mf.MapInternal(fr, hostarch.ReadWrite); !errors.Is(err, unix.EACCES) {
		t.Fatalf("MapInternal(ReadWrite) err = %v, want %v", err, unix.EACCES)
	}

	// Replace the FD via dup3 with a read-write socketpair FD so mprotect
	// returns EACCES and the fallback mmap fails with ENODEV.
	socks, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("unix.Socketpair failed: %v", err)
	}
	defer func() { _ = unix.Close(socks[1]) }()
	if err := unix.Dup3(socks[0], roFD, 0); err != nil {
		_ = unix.Close(socks[0])
		t.Fatalf("unix.Dup3 failed: %v", err)
	}
	_ = unix.Close(socks[0])

	if _, err := mf.MapInternal(fr, hostarch.ReadWrite); !errors.Is(err, unix.ENODEV) {
		t.Fatalf("MapInternal(ReadWrite) on socket FD err = %v, want %v", err, unix.ENODEV)
	}

	mf.mapsMu.Lock()
	m, ok := mf.mappings[0]
	mf.mapsMu.Unlock()
	if !ok {
		t.Fatalf("cached mapping missing after failed write upgrade")
	}
	if m.addr != roAddr || m.writable {
		t.Fatalf("cached mapping = %+v, want addr=%#x writable=false", m, roAddr)
	}
	if oldCount := len(oldMappingsSlice(&mf, 0)); oldCount != 0 {
		t.Fatalf("oldMappings count = %d, want 0", oldCount)
	}
	if got := roSeq.Head().ToSlice()[:len(want)]; !bytes.Equal(got, want) {
		t.Errorf("read mapping bytes = %q, want %q", got, want)
	}
}

func TestMmapCachedFileWriteUpgradeInPlace(t *testing.T) {
	initial := []byte("before")
	updated := []byte("after!")
	p := createSizedFile(t, chunkSize(), initial)
	rwFD, err := unix.Open(p, unix.O_RDWR, 0)
	if err != nil {
		t.Fatalf("unix.Open failed: %v", err)
	}

	var mf MmapCachedFile
	mf.SetFD(rwFD)
	fr := memmap.FileRange{Start: 0, End: pageSize}
	mf.IncRef(fr, 1)
	defer mf.MappableRelease()

	roSeq, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal(Read) failed: %v", err)
	}
	roAddr := roSeq.Head().Addr()

	rwSeq, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal(ReadWrite) failed: %v", err)
	}
	rwAddr := rwSeq.Head().Addr()
	if rwAddr != roAddr {
		t.Fatalf("write upgrade on O_RDWR FD changed address: got %#x, want %#x", rwAddr, roAddr)
	}

	if oldCount := len(oldMappingsSlice(&mf, 0)); oldCount != 0 {
		t.Fatalf("oldMappings count = %d, want 0", oldCount)
	}

	copy(rwSeq.Head().ToSlice()[:len(updated)], updated)
	if got := readFileAt(t, p, 0, len(updated)); !bytes.Equal(got, updated) {
		t.Fatalf("file bytes = %q, want %q", got, updated)
	}

	mf.DecRef(fr)
	assertFileUnmapped(t, p)
}

func TestMmapCachedFileWriteUpgradeAfterDup3RetainsOldMappingUntilDecRef(t *testing.T) {
	initial := []byte("before")
	updated := []byte("after!")
	p := createSizedFile(t, chunkSize(), initial)
	roFD, err := unix.Open(p, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("unix.Open(O_RDONLY) failed: %v", err)
	}

	var mf MmapCachedFile
	mf.SetFD(roFD)
	fr := memmap.FileRange{Start: 0, End: pageSize}
	mf.IncRef(fr, 1)
	defer mf.MappableRelease()

	roSeq, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal(Read) failed: %v", err)
	}
	roAddr := roSeq.Head().Addr()

	// Upgrade the FD description from O_RDONLY to O_RDWR via dup3, matching
	// fsimpl/gofer's handle upgrade path where the initial VMA lacks VM_MAYWRITE.
	rwFD, err := unix.Open(p, unix.O_RDWR, 0)
	if err != nil {
		t.Fatalf("unix.Open(O_RDWR) failed: %v", err)
	}
	if err := unix.Dup3(rwFD, roFD, 0); err != nil {
		_ = unix.Close(rwFD)
		t.Fatalf("unix.Dup3 failed: %v", err)
	}
	_ = unix.Close(rwFD)

	rwSeq, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal(ReadWrite) failed: %v", err)
	}
	rwAddr := rwSeq.Head().Addr()
	if rwAddr == roAddr {
		t.Fatalf("write upgrade reused non-VM_MAYWRITE address %#x", roAddr)
	}

	copy(rwSeq.Head().ToSlice()[:len(updated)], updated)
	if got := roSeq.Head().ToSlice()[:len(updated)]; !bytes.Equal(got, updated) {
		t.Fatalf("retained read mapping bytes = %q, want %q", got, updated)
	}

	old := oldMappingsSlice(&mf, 0)
	if len(old) != 1 || old[0] != roAddr {
		t.Fatalf("oldMappings[0] = %#x, want [%#x]", old, roAddr)
	}

	mf.DecRef(fr)

	mf.mapsMu.Lock()
	_, stillMapped := mf.mappings[0]
	_, stillOld := mf.oldMappings[0]
	mf.mapsMu.Unlock()
	if stillMapped || stillOld {
		t.Fatalf("mappings remain after DecRef: mapped=%t old=%t", stillMapped, stillOld)
	}
	// Both roAddr and rwAddr map p.
	assertFileUnmapped(t, p)
}

func TestMmapCachedFileRegenerateMappings(t *testing.T) {
	first := []byte("first-file")
	second := []byte("secondfile")
	const numChunks = 8
	p1 := createSizedFile(t, numChunks*chunkSize(), first)
	p2 := createSizedFile(t, numChunks*chunkSize(), second)

	fd, err := unix.Open(p1, unix.O_RDWR, 0)
	if err != nil {
		t.Fatalf("unix.Open(p1) failed: %v", err)
	}

	var mf MmapCachedFile
	mf.SetFD(fd)
	if err := mf.RegenerateMappings(); err != nil {
		t.Fatalf("RegenerateMappings() with empty mappings failed: %v", err)
	}
	mf.mapsMu.Lock()
	if mf.mappings != nil {
		mf.mapsMu.Unlock()
		t.Fatalf("RegenerateMappings() allocated mappings map when empty")
	}
	mf.mapsMu.Unlock()

	var allRanges []memmap.FileRange
	for i := uint64(0); i < numChunks; i++ {
		fr := memmap.FileRange{Start: i * chunkSize(), End: i*chunkSize() + pageSize}
		mf.IncRef(fr, 1)
		allRanges = append(allRanges, fr)
	}
	defer mf.MappableRelease()

	// Map chunk 0 ReadWrite and chunks 1..numChunks-1 Read so a failed
	// RegenerateMappings against a read-only FD exercises partial staging cleanup.
	seq1, err := mf.MapInternal(allRanges[0], hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal(ReadWrite) failed: %v", err)
	}
	addr1 := seq1.Head().Addr()
	for i := 1; i < numChunks; i++ {
		if _, err := mf.MapInternal(allRanges[i], hostarch.Read); err != nil {
			t.Fatalf("MapInternal(Read, chunk %d) failed: %v", i, err)
		}
	}

	// Replace the underlying file description with a read-only one;
	// RegenerateMappings must fail because chunk 0 is writable, and must leave
	// all existing mappings intact.
	roFD2, err := unix.Open(p2, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("unix.Open(p2, O_RDONLY) failed: %v", err)
	}
	if err := unix.Dup3(roFD2, fd, 0); err != nil {
		_ = unix.Close(roFD2)
		t.Fatalf("Dup3(roFD2) failed: %v", err)
	}
	_ = unix.Close(roFD2)

	if err := mf.RegenerateMappings(); !errors.Is(err, unix.EACCES) {
		t.Fatalf("RegenerateMappings() with read-only FD err = %v, want %v", err, unix.EACCES)
	}
	assertFileUnmapped(t, p2)
	mf.mapsMu.Lock()
	oldLen := len(mf.oldMappings)
	mf.mapsMu.Unlock()
	if oldLen != 0 {
		t.Fatalf("oldMappings non-empty after failed RegenerateMappings: %d", oldLen)
	}
	if got := seq1.Head().ToSlice()[:len(first)]; !bytes.Equal(got, first) {
		t.Fatalf("mapping after failed RegenerateMappings = %q, want %q", got, first)
	}

	// Replace the file description with a read-write one for p2.
	rwFD2, err := unix.Open(p2, unix.O_RDWR, 0)
	if err != nil {
		t.Fatalf("unix.Open(p2, O_RDWR) failed: %v", err)
	}
	if err := unix.Dup3(rwFD2, fd, 0); err != nil {
		_ = unix.Close(rwFD2)
		t.Fatalf("Dup3(rwFD2) failed: %v", err)
	}
	_ = unix.Close(rwFD2)

	if err := mf.RegenerateMappings(); err != nil {
		t.Fatalf("RegenerateMappings() failed: %v", err)
	}

	// Previously returned seq1 remains valid until DecRef, while new mappings
	// reflect p2.
	if got := seq1.Head().ToSlice()[:len(first)]; !bytes.Equal(got, first) {
		t.Fatalf("retained mapping after RegenerateMappings = %q, want %q", got, first)
	}
	seq2, err := mf.MapInternal(allRanges[0], hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal(Read) after RegenerateMappings failed: %v", err)
	}
	addr2 := seq2.Head().Addr()
	if addr2 == addr1 {
		t.Fatalf("RegenerateMappings reused old address %#x", addr1)
	}
	if got := seq2.Head().ToSlice()[:len(second)]; !bytes.Equal(got, second) {
		t.Fatalf("new mapping after RegenerateMappings = %q, want %q", got, second)
	}

	for _, fr := range allRanges {
		mf.DecRef(fr)
	}
	assertFileUnmapped(t, p1)
	assertFileUnmapped(t, p2)
}

func TestMmapPreciseFileWriteUpgrade(t *testing.T) {
	initial := []byte("precise-ro")
	updated := []byte("precise-rw")
	fullRange := memmap.FileRange{Start: 0, End: 3 * pageSize}
	midPage := memmap.FileRange{Start: pageSize, End: 2 * pageSize}
	p := createSizedFile(t, fullRange.End, initial)

	// Verify a failed write upgrade on a read-only FD preserves the read mapping
	// and does not leave f.mappings fragmented.
	roFD, err := unix.Open(p, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("unix.Open(O_RDONLY) failed: %v", err)
	}
	var roFile MmapPreciseFile
	roFile.SetFD(roFD)
	roFile.IncRef(fullRange, 1)
	roSeq, err := roFile.MapInternal(fullRange, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal(Read) failed: %v", err)
	}
	if _, err := roFile.MapInternal(midPage, hostarch.ReadWrite); !errors.Is(err, unix.EACCES) {
		t.Fatalf("MapInternal(ReadWrite) on O_RDONLY FD err = %v, want %v", err, unix.EACCES)
	}
	if got := roSeq.Head().ToSlice()[:len(initial)]; !bytes.Equal(got, initial) {
		t.Fatalf("read mapping after failed upgrade = %q, want %q", got, initial)
	}
	roFile.mapsMu.Lock()
	firstSeg := roFile.mappings.FirstSegment()
	unfragmented := firstSeg.Ok() && firstSeg.Range() == fullRange && !firstSeg.Value().writable && !firstSeg.NextSegment().Ok()
	roFile.mapsMu.Unlock()
	if !unfragmented {
		t.Fatalf("read-only mapping remained fragmented or writable after failed upgrade")
	}
	roFile.DecRef(fullRange)
	roFile.MappableRelease()
	assertFileUnmapped(t, p)

	// Verify write upgrades on a read-write FD succeed in place via mprotect and
	// merge adjacent writable segments (including simultaneous left+right merge).
	rwFD, err := unix.Open(p, unix.O_RDWR, 0)
	if err != nil {
		t.Fatalf("unix.Open(O_RDWR) failed: %v", err)
	}
	var rwFile MmapPreciseFile
	rwFile.SetFD(rwFD)
	rwFile.IncRef(fullRange, 1)
	defer rwFile.MappableRelease()

	seq1, err := rwFile.MapInternal(fullRange, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal(Read) failed: %v", err)
	}
	for _, start := range []uint64{0, 2 * pageSize, pageSize} {
		pageRange := memmap.FileRange{Start: start, End: start + pageSize}
		seq2, err := rwFile.MapInternal(pageRange, hostarch.ReadWrite)
		if err != nil {
			t.Fatalf("MapInternal(ReadWrite, %v) failed: %v", pageRange, err)
		}
		wantAddr := seq1.Head().Addr() + uintptr(start)
		if seq2.Head().Addr() != wantAddr {
			t.Fatalf("MmapPreciseFile changed address on upgrade: %#x != %#x", seq2.Head().Addr(), wantAddr)
		}
	}

	rwFile.mapsMu.Lock()
	firstRWSeg := rwFile.mappings.FirstSegment()
	merged := firstRWSeg.Ok() && firstRWSeg.Range() == fullRange && firstRWSeg.Value().writable && !firstRWSeg.NextSegment().Ok()
	rwFile.mapsMu.Unlock()
	if !merged {
		t.Fatalf("writable segments did not merge back into fullRange")
	}

	fullSlice := seq1.Head().ToSlice()
	for _, off := range []uint64{0, pageSize, 2 * pageSize} {
		copy(fullSlice[off:off+uint64(len(updated))], updated)
		if got := readFileAt(t, p, int64(off), len(updated)); !bytes.Equal(got, updated) {
			t.Errorf("file bytes at %d = %q, want %q", off, got, updated)
		}
	}

	rwFile.DecRef(fullRange)
	assertFileUnmapped(t, p)
}

func TestMmapCachedFileConcurrentReadAndUpgrade(t *testing.T) {
	want := []byte("concurrent-test-payload")
	p := createSizedFile(t, chunkSize(), want)

	for iter := 0; iter < 32; iter++ {
		roFD, err := unix.Open(p, unix.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("unix.Open(O_RDONLY) failed: %v", err)
		}
		var mf MmapCachedFile
		mf.SetFD(roFD)
		fr := memmap.FileRange{Start: 0, End: pageSize}
		mf.IncRef(fr, 1)

		roSeq, err := mf.MapInternal(fr, hostarch.Read)
		if err != nil {
			t.Fatalf("MapInternal(Read) failed: %v", err)
		}

		rwFD, err := unix.Open(p, unix.O_RDWR, 0)
		if err != nil {
			t.Fatalf("unix.Open(O_RDWR) failed: %v", err)
		}
		if err := unix.Dup3(rwFD, roFD, 0); err != nil {
			_ = unix.Close(rwFD)
			t.Fatalf("unix.Dup3 failed: %v", err)
		}
		_ = unix.Close(rwFD)

		var (
			ready     sync.WaitGroup
			writersWG sync.WaitGroup
			readerWG  sync.WaitGroup
			done      atomic.Bool
			startCh   = make(chan struct{})
		)
		ready.Add(3)
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			ready.Done()
			<-startCh
			for !done.Load() {
				if got := roSeq.Head().ToSlice()[:len(want)]; !bytes.Equal(got, want) {
					t.Errorf("concurrent reader saw %q, want %q", got, want)
					return
				}
			}
		}()
		writersWG.Add(2)
		go func() {
			defer writersWG.Done()
			ready.Done()
			<-startCh
			if _, err := mf.MapInternal(fr, hostarch.ReadWrite); err != nil {
				t.Errorf("MapInternal(ReadWrite) failed: %v", err)
			}
		}()
		go func() {
			defer writersWG.Done()
			ready.Done()
			<-startCh
			if err := mf.RegenerateMappings(); err != nil {
				t.Errorf("RegenerateMappings() failed: %v", err)
			}
		}()
		ready.Wait()
		close(startCh)
		writersWG.Wait()
		done.Store(true)
		readerWG.Wait()

		mf.DecRef(fr)
		mf.MappableRelease()
		assertFileUnmapped(t, p)
	}
}
