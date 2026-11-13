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
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
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

func children(st *State, ino uint64) map[string]uint64 {
	return st.Inodes[ino].Children
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

func TestRoundTrip(t *testing.T) {
	fd := newTestFile(t)
	mf1, j := mustCreate(t, fd, testOpts())
	initRoot(t, j)

	// Allocate actual data pages from the same MemoryFile to verify non-overlap
	// with the journal header and regions.
	frA, err := mf1.Allocate(2*pg, pgalloc.AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	frGone, err := mf1.Allocate(2*pg, pgalloc.AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	j.Inode(regRec(2, 0))
	j.DirentAdd(1, "a", 2)
	j.ExtentSet(2, 0, pg, frA.Start)
	j.ExtentSet(2, pg, pg, frA.Start+pg)
	j.Inode(regRec(2, pg+100))
	j.Inode(dirRec(3))
	j.DirentAdd(1, "d", 3)
	j.Inode(&InodeRecord{Ino: 4, Mode: modeSymlink | 0777, Target: "../a"})
	j.DirentAdd(3, "l", 4)
	xattrs := []Xattr{{Name: "trusted.overlay.opaque", Value: "y"}, {Name: "user.empty", Value: ""}}
	j.Inode(&InodeRecord{Ino: 5, Mode: modeChar, RdevMajor: 0, RdevMinor: 0, Xattrs: xattrs})
	j.DirentAdd(3, "wh", 5)
	j.Inode(&InodeRecord{Ino: 6, Mode: modeChar | 0600, RdevMajor: 1, RdevMinor: 3})
	j.DirentAdd(1, "null", 6)
	j.DirentAdd(1, "hard", 2)
	j.Rename(1, "a", 3, "b", false /* exchange */)
	j.DirentDel(1, "hard")
	// An unlinked inode that is still open is dropped on replay.
	j.Inode(regRec(7, 0))
	j.DirentAdd(1, "tmp", 7)
	j.ExtentSet(7, 0, pg, frGone.Start)
	j.DirentDel(1, "tmp")
	// A freed inode is gone.
	j.Inode(regRec(8, 0))
	j.DirentAdd(1, "gone", 8)
	j.ExtentSet(8, 0, pg, frGone.Start+pg)
	j.DirentDel(1, "gone")
	j.ExtentClear(8, 0, pg)
	j.InodeFree(8)

	mf2, _, st := mustOpen(t, fd, testOpts())
	if st.Root != 1 || st.NextIno != 9 {
		t.Errorf("root %d, next inode %d; want 1, 9", st.Root, st.NextIno)
	}
	if got, want := children(st, 1), map[string]uint64{"d": 3, "null": 6}; !reflect.DeepEqual(got, want) {
		t.Errorf("root entries %v, want %v", got, want)
	}
	if got, want := children(st, 3), map[string]uint64{"l": 4, "wh": 5, "b": 2}; !reflect.DeepEqual(got, want) {
		t.Errorf("d entries %v, want %v", got, want)
	}
	if n := len(st.Inodes); n != 6 {
		t.Errorf("got %d inodes, want 6", n)
	}
	f := st.Inodes[2]
	if f.Nlink != 1 || f.Size != pg+100 || f.Mtime != 20 {
		t.Errorf("file: nlink %d size %d mtime %d", f.Nlink, f.Size, f.Mtime)
	}
	if want := []Extent{{Off: 0, Len: 2 * pg, MFOff: frA.Start}}; !reflect.DeepEqual(f.Extents, want) {
		t.Errorf("file extents %v, want %v", f.Extents, want)
	}
	if st.Inodes[1].Nlink != 3 || st.Inodes[3].Nlink != 2 {
		t.Errorf("directory link counts %d, %d; want 3, 2", st.Inodes[1].Nlink, st.Inodes[3].Nlink)
	}
	if st.Inodes[4].Target != "../a" {
		t.Errorf("symlink target %q", st.Inodes[4].Target)
	}
	if !reflect.DeepEqual(st.Inodes[5].Xattrs, xattrs) {
		t.Errorf("xattrs %v, want %v", st.Inodes[5].Xattrs, xattrs)
	}
	if d := st.Inodes[6]; d.RdevMajor != 1 || d.RdevMinor != 3 {
		t.Errorf("device %d:%d", d.RdevMajor, d.RdevMinor)
	}
	if got, want := st.UsedRanges(), []memmap.FileRange{frA}; !reflect.DeepEqual(got, want) {
		t.Errorf("used ranges %v, want %v", got, want)
	}
	if !mf2.HasUniqueRef(frA) {
		t.Errorf("adopted range %v does not have a unique reference", frA)
	}
}

func TestOpenWithoutKeepingJournal(t *testing.T) {
	fd := newTestFile(t)
	mf1, j := mustCreate(t, fd, testOpts())
	initRoot(t, j)
	fr, err := mf1.Allocate(pg, pgalloc.AllocOpts{Kind: usage.Tmpfs})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	j.Inode(regRec(2, pg))
	j.DirentAdd(1, "f", 2)
	j.ExtentSet(2, 0, pg, fr.Start)

	mf2 := newTestMF(t, fd, true /* keep */)
	j2, st, err := Open(mf2, testOpts(), false /* keepJournal */)
	if err != nil {
		t.Fatalf("Open(keepJournal=false): %v", err)
	}
	if j2 != nil {
		t.Fatalf("Open(keepJournal=false) returned non-nil Journal")
	}
	if got, want := children(st, 1), map[string]uint64{"f": 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root entries %v, want %v", got, want)
	}
	// Because keepJournal=false freed page 0 and the journal region, the file
	// no longer has a valid journal header and cannot be re-imported after
	// unjournaled mutations.
	if _, _, _, err := open(t, fd, testOpts()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("reopening after keepJournal=false: got %v, want ErrIncomplete", err)
	}
}

func TestRenameExchangeAndReplace(t *testing.T) {
	fd := newTestFile(t)
	_, j := mustCreate(t, fd, testOpts())
	initRoot(t, j)
	j.Inode(dirRec(2))
	j.DirentAdd(1, "d", 2)
	j.Inode(regRec(3, 0))
	j.DirentAdd(1, "f", 3)
	j.Inode(regRec(4, 0))
	j.DirentAdd(2, "g", 4)
	j.Rename(1, "f", 2, "g", true /* exchange */)
	j.Inode(regRec(5, 0))
	j.DirentAdd(1, "h", 5)
	j.Rename(1, "h", 1, "f", false /* exchange */)

	_, _, st := mustOpen(t, fd, testOpts())
	if got, want := children(st, 1), map[string]uint64{"d": 2, "f": 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("root entries %v, want %v", got, want)
	}
	if got, want := children(st, 2), map[string]uint64{"g": 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("d entries %v, want %v", got, want)
	}
	if _, ok := st.Inodes[4]; ok {
		t.Errorf("replaced inode 4 was not dropped")
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
