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
	"errors"
	"os"
	"strings"
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

// open opens the journal in fd, adopting pages into a new MemoryFile backed by
// its filestore.
func open(t *testing.T, fd int, opts Options) (*pgalloc.MemoryFile, *Journal, *State, error) {
	t.Helper()
	mf := newTestMF(t, fd, true /* keep */)
	f := dupFile(t, fd)
	j, st, err := Open(mf, f, opts, true /* keepJournal */)
	if err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	t.Cleanup(j.Close)
	return mf, j, st, nil
}

func mustOpen(t *testing.T, fd int, opts Options) (*pgalloc.MemoryFile, *Journal, *State) {
	t.Helper()
	mf, j, st, err := open(t, fd, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return mf, j, st
}

func TestFreshJournal(t *testing.T) {
	fd := newTestFile(t)
	// Opening an uninitialized 0-byte file returns ErrIncomplete.
	if _, _, _, err := open(t, fd, testOpts()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Open of empty file: got %v, want ErrIncomplete", err)
	}
	mustCreate(t, fd, testOpts())
	// Reopening a created journal with no snapshot returns an empty State.
	_, _, st := mustOpen(t, fd, testOpts())
	if !st.Empty() {
		t.Fatalf("reopened journal has state %+v", st)
	}
}

func TestHeaderValidation(t *testing.T) {
	fd := newTestFile(t)
	mustCreate(t, fd, testOpts())

	opts := testOpts()
	opts.ImageID = ""
	if _, _, _, err := open(t, fd, opts); err != nil {
		t.Errorf("Open with empty ImageID (check disabled): got %v, want nil", err)
	}

	opts = testOpts()
	opts.ImageID = "image-2"
	_, _, _, err := open(t, fd, opts)
	var mismatch *ImageMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("Open with another image ID: got %v, want ImageMismatchError", err)
	}

	opts = testOpts()
	opts.BuildID = "build-2"
	if _, _, _, err := open(t, fd, opts); err == nil {
		t.Errorf("Open with another build ID succeeded")
	}

	// A garbage header is refused.
	if _, err := unix.Pwrite(fd, []byte("garbage!"), 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, _, _, err := open(t, fd, testOpts()); err == nil {
		t.Errorf("Open with a garbage header succeeded")
	}

	// A header that is all zeros was never completely written and returns
	// ErrIncomplete.
	if _, err := unix.Pwrite(fd, make([]byte, headerSize), 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, _, _, err := open(t, fd, testOpts()); !errors.Is(err, ErrIncomplete) {
		t.Errorf("Open with a zero header: got %v, want ErrIncomplete", err)
	}
}

func dupFile(t *testing.T, fd int) *os.File {
	t.Helper()
	dup, err := unix.Dup(fd)
	if err != nil {
		t.Fatalf("Dup: %v", err)
	}
	return os.NewFile(uintptr(dup), "journal")
}

func TestFormatVersion(t *testing.T) {
	fd := newTestFile(t)
	mustCreate(t, fd, testOpts())
	// Rewrite the header with format version 2 and a valid checksum.
	var h [headerSize]byte
	if _, err := unix.Pread(fd, h[:], 0); err != nil {
		t.Fatalf("Pread: %v", err)
	}
	binary.LittleEndian.PutUint32(h[8:], 2)
	binary.LittleEndian.PutUint32(h[headerCRCOff:], headerCRC(h[:], headerMagic))
	if _, err := unix.Pwrite(fd, h[:], 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, _, _, err := open(t, fd, testOpts()); err == nil || !strings.Contains(err.Error(), "format version is 2") {
		t.Fatalf("Open of a version 2 journal: got %v, want a format version error", err)
	}
}
