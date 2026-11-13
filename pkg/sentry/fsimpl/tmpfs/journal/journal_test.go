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
	dataBase = 64 * pg
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

func TestTornTail(t *testing.T) {
	fd := newTestFile(t)
	_, j := mustCreate(t, fd, testOpts())
	initRoot(t, j)
	j.Inode(regRec(2, 0))
	j.DirentAdd(1, "f", 2)
	j.Inode(regRec(3, 0))
	j.mu.Lock()
	lastStart := j.active.tail
	activeMap := j.active.mapping
	j.mu.Unlock()
	j.DirentAdd(1, "torn", 3)
	j.mu.Lock()
	lastEnd := j.active.tail
	j.mu.Unlock()
	// The covered bytes of the last record: header, payload and checksum.
	covered := recordHeaderSize + uint64(len("torn")) + 18 + recordCRCSize

	// Snapshot the whole file so Open's hole-punching of unused ranges doesn't
	// clobber anything we restore.
	fileSnap := make([]byte, dataBase*pg)
	if n, err := unix.Pread(fd, fileSnap, 0); err != nil {
		t.Fatalf("Pread: %v", err)
	} else {
		fileSnap = fileSnap[:n]
	}
	restore := func() {
		if _, err := unix.Pwrite(fd, fileSnap, 0); err != nil {
			t.Fatalf("Pwrite: %v", err)
		}
	}

	check := func(t *testing.T, what string) {
		t.Helper()
		_, _, st, err := open(t, fd, testOpts())
		if err != nil {
			t.Fatalf("%s: Open: %v", what, err)
		}
		if got, want := children(st, 1), map[string]uint64{"f": 2}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: root entries %v, want %v", what, got, want)
		}
	}

	// Truncate the last record: zero its second half.
	clear(activeMap[lastStart+covered/2 : lastEnd])
	check(t, "truncated")
	restore()

	// Remove the magic only.
	clear(activeMap[lastStart : lastStart+4])
	check(t, "no magic")
	restore()

	// Flip each covered byte of the last record in turn.
	for k := uint64(0); k < covered; k++ {
		activeMap[lastStart+k] ^= 0x5a
		check(t, "flipped byte")
		restore()
	}

	// Without damage, the last record is replayed.
	_, _, st := mustOpen(t, fd, testOpts())
	if got, want := children(st, 1), map[string]uint64{"f": 2, "torn": 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root entries %v, want %v", got, want)
	}
}

func TestStaleRecordsAfterCompaction(t *testing.T) {
	fd := newTestFile(t)
	_, j := mustCreate(t, fd, testOpts())
	initRoot(t, j)
	for i := uint64(0); i < 100; i++ {
		j.Inode(regRec(2, i))
	}
	for k := 0; k < 2; k++ {
		s, err := j.BeginSnapshot(1, 2, 0)
		if err != nil {
			t.Fatalf("BeginSnapshot: %v", err)
		}
		s.Inode(dirRec(1))
		if err := s.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}
	_, _, st := mustOpen(t, fd, testOpts())
	if n := len(st.Inodes); n != 1 {
		t.Fatalf("got %d inodes, want 1", n)
	}
}

func TestCompaction(t *testing.T) {
	fd := newTestFile(t)
	_, j := mustCreate(t, fd, testOpts())
	requested := 0
	j.SetCompactionRequester(func() { requested++ })
	initRoot(t, j)
	j.Inode(regRec(2, 0))
	j.DirentAdd(1, "f", 2)
	for i := uint64(0); requested == 0; i++ {
		if i > 10000 {
			t.Fatalf("compaction was never requested")
		}
		j.ExtentSet(2, 0, pg, dataBase+(i%16)*pg)
	}
	targetOff := dataBase + 5*pg
	j.ExtentSet(2, 0, pg, targetOff)
	j.Inode(regRec(2, 100))
	if requested != 1 {
		t.Fatalf("compaction requested %d times, want 1", requested)
	}

	j.mu.Lock()
	oldGen := j.gen
	j.mu.Unlock()
	s, err := j.BeginSnapshot(1, 3, 0)
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	s.Inode(dirRec(1))
	s.Inode(regRec(2, 100))
	s.ExtentSet(2, 0, pg, targetOff)
	s.DirentAdd(1, "f", 2)
	// A record appended during compaction goes to both regions.
	j.Inode(regRec(2, 200))

	// Copy fd to inspect crash-before-Commit without hole-punching j's inactive
	// region in fd!
	crashFD := copyFD(t, fd)
	_, _, st := mustOpen(t, crashFD, testOpts())
	if f := st.Inodes[2]; f.Size != 200 || !reflect.DeepEqual(f.Extents, []Extent{{0, pg, targetOff}}) {
		t.Fatalf("before commit: file %+v", f)
	}

	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	j.mu.Lock()
	newGen, tail, size := j.gen, j.active.tail, j.active.size
	j.mu.Unlock()
	if newGen != oldGen+1 || tail > size/4 {
		t.Fatalf("after commit: generation %d (was %d), tail %d", newGen, oldGen, tail)
	}
	j.Inode(regRec(2, 300))
	_, _, st = mustOpen(t, fd, testOpts())
	if f := st.Inodes[2]; f.Size != 300 || !reflect.DeepEqual(f.Extents, []Extent{{0, pg, targetOff}}) {
		t.Fatalf("after commit: file %+v", f)
	}
	if got, want := children(st, 1), map[string]uint64{"f": 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after commit: root entries %v, want %v", got, want)
	}
}

func copyFD(t *testing.T, srcFD int) int {
	t.Helper()
	end := uint64(2 << 20)
	buf := make([]byte, hostarch.MustPageRoundUp(end))
	n, err := unix.Pread(srcFD, buf, 0)
	if err != nil {
		t.Fatalf("Pread: %v", err)
	}
	dst := newTestFile(t)
	if _, err := unix.Pwrite(dst, buf[:n], 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	return dst
}

func TestOverflow(t *testing.T) {
	fd := newTestFile(t)
	opts := testOpts()
	opts.RegionSize = 4 * pg
	_, j := mustCreate(t, fd, opts)
	initRoot(t, j)
	for !j.Broken() {
		j.Inode(regRec(2, 0))
	}
	if _, _, _, err := open(t, fd, opts); err == nil || !strings.Contains(err.Error(), "overflowed") {
		t.Fatalf("Open of an overflowed journal: got %v, want overflow error", err)
	}
	s, err := j.BeginSnapshot(1, 2, 0)
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	s.Inode(dirRec(1))
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if j.Broken() {
		t.Fatalf("journal still broken after compaction")
	}
	mustOpen(t, fd, opts)
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

func TestValidationFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records func(j *Journal)
	}{
		{
			name: "cycle",
			records: func(j *Journal) {
				j.Inode(dirRec(2))
				j.DirentAdd(1, "a", 2)
				j.Inode(dirRec(3))
				j.DirentAdd(2, "b", 3)
				j.Rename(1, "a", 3, "a", false)
			},
		},
		{
			name: "shared page",
			records: func(j *Journal) {
				j.Inode(regRec(2, pg))
				j.DirentAdd(1, "a", 2)
				j.Inode(regRec(3, pg))
				j.DirentAdd(1, "b", 3)
				j.ExtentSet(2, 0, pg, dataBase)
				j.ExtentSet(3, 0, pg, dataBase)
			},
		},
		{
			name: "shared page in one file",
			records: func(j *Journal) {
				j.Inode(regRec(2, 2*pg))
				j.DirentAdd(1, "a", 2)
				j.ExtentSet(2, 0, pg, dataBase)
				j.ExtentSet(2, pg, pg, dataBase)
			},
		},
		{
			name: "extent overlaps journal header",
			records: func(j *Journal) {
				j.Inode(regRec(2, pg))
				j.DirentAdd(1, "a", 2)
				j.ExtentSet(2, 0, pg, 0)
			},
		},
		{
			name: "extent overlaps active journal region",
			records: func(j *Journal) {
				j.Inode(regRec(2, pg))
				j.DirentAdd(1, "a", 2)
				j.ExtentSet(2, 0, pg, headerSize)
			},
		},
		{
			name: "name with slash",
			records: func(j *Journal) {
				j.Inode(regRec(2, 0))
				j.DirentAdd(1, "a/b", 2)
			},
		},
		{
			name: "dot name",
			records: func(j *Journal) {
				j.Inode(dirRec(2))
				j.DirentAdd(1, "..", 2)
			},
		},
		{
			name: "empty name",
			records: func(j *Journal) {
				j.Inode(regRec(2, 0))
				j.DirentAdd(1, "", 2)
			},
		},
		{
			name: "extent beyond filestore",
			records: func(j *Journal) {
				j.Inode(regRec(2, pg))
				j.DirentAdd(1, "a", 2)
				j.ExtentSet(2, 0, pg, testFilestore)
			},
		},
		{
			name: "unaligned extent",
			records: func(j *Journal) {
				j.Inode(regRec(2, pg))
				j.DirentAdd(1, "a", 2)
				j.ExtentSet(2, 0, pg, dataBase+1)
			},
		},
		{
			name: "extent on directory",
			records: func(j *Journal) {
				j.Inode(dirRec(2))
				j.DirentAdd(1, "a", 2)
				j.ExtentSet(2, 0, pg, dataBase)
			},
		},
		{
			name: "entry for missing inode",
			records: func(j *Journal) {
				j.DirentAdd(1, "a", 9)
			},
		},
		{
			name: "directory hard link",
			records: func(j *Journal) {
				j.Inode(dirRec(2))
				j.DirentAdd(1, "a", 2)
				j.DirentAdd(1, "b", 2)
			},
		},
		{
			name: "duplicate entry",
			records: func(j *Journal) {
				j.Inode(regRec(2, 0))
				j.DirentAdd(1, "a", 2)
				j.DirentAdd(1, "a", 2)
			},
		},
		{
			name: "type change",
			records: func(j *Journal) {
				j.Inode(regRec(2, 0))
				j.Inode(dirRec(2))
			},
		},
		{
			name: "free linked inode",
			records: func(j *Journal) {
				j.Inode(regRec(2, 0))
				j.DirentAdd(1, "a", 2)
				j.InodeFree(2)
			},
		},
		{
			name: "invalid mode",
			records: func(j *Journal) {
				j.Inode(&InodeRecord{Ino: 2, Mode: 0777})
			},
		},
		{
			name: "duplicate xattr",
			records: func(j *Journal) {
				j.Inode(&InodeRecord{Ino: 2, Mode: modeRegular, Xattrs: []Xattr{{"user.a", "1"}, {"user.a", "2"}}})
			},
		},
		{
			name: "second root record",
			records: func(j *Journal) {
				j.mu.Lock()
				defer j.mu.Unlock()
				if buf := j.reserve(&j.active, 16); buf != nil {
					binary.LittleEndian.PutUint64(buf[0:], 1)
					binary.LittleEndian.PutUint64(buf[8:], 2)
					j.seal(&j.active, RecordRoot, 16)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd := newTestFile(t)
			_, j := mustCreate(t, fd, testOpts())
			initRoot(t, j)
			tc.records(j)
			if _, _, st, err := open(t, fd, testOpts()); err == nil {
				t.Fatalf("Open succeeded with state %+v, want error", st)
			}
		})
	}
}

func TestIncomplete(t *testing.T) {
	fd := newTestFile(t)
	f := dupFile(t, fd)
	defer f.Close()
	if incomplete, err := Incomplete(f); err != nil || incomplete {
		t.Fatalf("Incomplete on empty file: %t, %v; want false", incomplete, err)
	}

	mf := newTestMF(t, fd, false /* keep */)
	j, err := CreateIncomplete(mf, testOpts())
	if err != nil {
		t.Fatalf("CreateIncomplete: %v", err)
	}
	t.Cleanup(j.Close)
	if incomplete, err := Incomplete(f); err != nil || !incomplete {
		t.Fatalf("Incomplete: %t, %v; want true", incomplete, err)
	}
	if _, _, _, err := open(t, fd, testOpts()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Open of an incomplete journal: got %v, want ErrIncomplete", err)
	}

	s, err := j.BeginSnapshot(1, 4, 0)
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	s.Inode(dirRec(1))
	s.Inode(regRec(3, pg))
	s.ExtentSet(3, 0, pg, dataBase)
	s.DirentAdd(1, "g", 3)
	// A crash before Commit leaves the journal incomplete.
	if _, _, _, err := open(t, fd, testOpts()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Open before Commit: got %v, want ErrIncomplete", err)
	}
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if incomplete, err := Incomplete(f); err != nil || incomplete {
		t.Fatalf("Incomplete after Commit: %t, %v; want false", incomplete, err)
	}
	_, _, st := mustOpen(t, fd, testOpts())
	if got, want := children(st, 1), map[string]uint64{"g": 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root entries after Commit: %v, want %v", got, want)
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

func TestMaxInodeRejected(t *testing.T) {
	fd := newTestFile(t)
	_, j := mustCreate(t, fd, testOpts())
	initRoot(t, j)
	j.Inode(&InodeRecord{Ino: ^uint64(0), Mode: modeRegular | 0644})
	j.DirentAdd(1, "max", ^uint64(0))
	if _, _, _, err := open(t, fd, testOpts()); err == nil || !strings.Contains(err.Error(), "overflows next inode counter") {
		t.Fatalf("Open with MaxUint64 inode: got %v, want overflow error", err)
	}
}
