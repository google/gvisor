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

package journal

import (
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

const testFilestore = 8 << 20

func testOpts() Options {
	return Options{
		BuildID:       "build-1",
		ImageID:       "image-1",
		RegionSize:    64 << 10,
		FilestoreSize: testFilestore,
	}
}

// filestores maps the descriptor of each test journal file to the descriptor
// of its filestore.
var filestores = map[int]int{}

func newMemFD(t *testing.T, name string) int {
	t.Helper()
	fd, err := memutil.CreateMemFD(name, 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// newTestFile returns a new journal memfd, with a new filestore memfd of size
// testFilestore. The test owns the returned descriptor.
func newTestFile(t *testing.T) int {
	t.Helper()
	fd := newMemFD(t, "journal-test")
	data := newMemFD(t, "journal-test-filestore")
	if err := unix.Ftruncate(data, testFilestore); err != nil {
		t.Fatalf("Ftruncate: %v", err)
	}
	filestores[fd] = data
	t.Cleanup(func() { delete(filestores, fd) })
	return fd
}

// newTestMF returns a new MemoryFile backed by the filestore of the journal
// in fd.
func newTestMF(t *testing.T, fd int, keep bool) *pgalloc.MemoryFile {
	t.Helper()
	data := filestores[fd]
	var size int64
	if !keep {
		var stat unix.Stat_t
		if err := unix.Fstat(data, &stat); err != nil {
			t.Fatalf("Fstat: %v", err)
		}
		size = stat.Size
	}
	f := dupFile(t, data)
	mf, err := pgalloc.NewMemoryFile(f, pgalloc.MemoryFileOpts{
		DelayedEviction:         pgalloc.DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		KeepFileContents:        keep,
	})
	if err != nil {
		f.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	if !keep {
		// NewMemoryFile truncated the filestore. Restore its size so that
		// Open accepts extents within it.
		if err := unix.Ftruncate(data, size); err != nil {
			t.Fatalf("Ftruncate: %v", err)
		}
	}
	return mf
}

// mustCreate creates a fresh journal in fd, and a new MemoryFile backed by its
// filestore.
func mustCreate(t *testing.T, fd int, opts Options) (*pgalloc.MemoryFile, *Journal) {
	t.Helper()
	mf := newTestMF(t, fd, false /* keep */)
	f := dupFile(t, fd)
	j, err := Create(f, opts)
	if err != nil {
		f.Close()
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(j.Close)
	return mf, j
}

func dupFile(t *testing.T, fd int) *os.File {
	t.Helper()
	dup, err := unix.Dup(fd)
	if err != nil {
		t.Fatalf("Dup: %v", err)
	}
	return os.NewFile(uintptr(dup), "journal")
}

func TestFreshJournal(t *testing.T) {
	fd := newTestFile(t)
	mustCreate(t, fd, testOpts())
	var h [headerSize]byte
	if _, err := unix.Pread(fd, h[:], 0); err != nil {
		t.Fatalf("Pread: %v", err)
	}
	if string(h[:8]) != string(headerMagic[:]) {
		t.Fatalf("magic = %q, want %q", h[:8], headerMagic[:])
	}
	if got, want := binary.LittleEndian.Uint32(h[headerCRCOff:]), headerCRC(h[:], headerMagic); got != want {
		t.Fatalf("crc = %#x, want %#x", got, want)
	}
}
