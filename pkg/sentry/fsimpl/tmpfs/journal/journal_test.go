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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

const (
	pg            = uint64(hostarch.PageSize)
	testFilestore = 8 << 20
	// dataBase is a page offset well past the default 64 KiB test regions.
)

func testOpts() Options {
	return Options{
		BuildID:       "build-1",
		ImageID:       "image-1",
		RegionSize:    64 << 10,
		FilestoreSize: testFilestore,
	}
}

// newTestFile returns a new memfd. The test owns the returned descriptor.
func newTestFile(t *testing.T) int {
	t.Helper()
	fd, err := memutil.CreateMemFD("journal-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func newTestMF(t *testing.T, fd int, keep bool) *pgalloc.MemoryFile {
	t.Helper()
	f := dupFile(t, fd)
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
	return mf
}

// mustCreate creates a fresh journal in a new MemoryFile backed by fd.
func mustCreate(t *testing.T, fd int, opts Options) (*pgalloc.MemoryFile, *Journal) {
	t.Helper()
	mf := newTestMF(t, fd, false /* keep */)
	j, err := Create(mf, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(j.Close)
	return mf, j
}

// open opens the journal in a new MemoryFile backed by a duplicate of fd.
func open(t *testing.T, fd int, opts Options) (*pgalloc.MemoryFile, *Journal, *State, error) {
	t.Helper()
	mf := newTestMF(t, fd, true /* keep */)
	j, st, err := Open(mf, opts, true /* keepJournal */)
	if err != nil {
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

func dirRec(ino uint64) *InodeRecord {
	return &InodeRecord{Ino: ino, Mode: modeDir | 0755, UID: 1, GID: 2, Atime: 10, Mtime: 11, Ctime: 12, Btime: 13}
}

func regRec(ino, size uint64) *InodeRecord {
	return &InodeRecord{Ino: ino, Mode: modeRegular | 0644, Size: size, Mtime: 20}
}

// initRoot writes a snapshot that holds only the root directory, inode 1.
func initRoot(t *testing.T, j *Journal) {
	t.Helper()
	s, err := j.BeginSnapshot(1, 2, 0)
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	s.Inode(dirRec(1))
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
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


func TestSnapshotTooLarge(t *testing.T) {
	fd := newTestFile(t)
	opts := testOpts()
	opts.RegionSize = 4 * pg
	_, j := mustCreate(t, fd, opts)
	initRoot(t, j)
	s, err := j.BeginSnapshot(1, 2, 0)
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	s.Inode(dirRec(1))
	for i := uint64(2); i < 1000; i++ {
		s.Inode(regRec(i, 0))
	}
	if err := s.Commit(); err == nil {
		t.Fatalf("Commit of an oversized snapshot succeeded")
	}
	_, _, st := mustOpen(t, fd, opts)
	if n := len(st.Inodes); n != 1 {
		t.Fatalf("got %d inodes, want 1", n)
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

func TestRegionValidation(t *testing.T) {
	fd := newTestFile(t)
	_, j := mustCreate(t, fd, testOpts())
	initRoot(t, j)

	// The active region is region 0 after initRoot. A descriptor beyond
	// FilestoreSize / filestoreEnd is refused.
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:], headerSize)
	binary.LittleEndian.PutUint64(b[8:], 1<<30)
	if _, err := unix.Pwrite(fd, b[:], regionDescOff); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, _, _, err := open(t, fd, testOpts()); err == nil {
		t.Fatalf("Open with a bad region descriptor succeeded, want error")
	}
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
