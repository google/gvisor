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
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

const (
	pg            = uint64(hostarch.PageSize)
	testFilestore = 1 << 20
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

// open opens the journal in a duplicate of fd.
func open(t *testing.T, fd int, opts Options) (*Journal, *State, error) {
	t.Helper()
	dup, err := unix.Dup(fd)
	if err != nil {
		t.Fatalf("Dup: %v", err)
	}
	f := os.NewFile(uintptr(dup), "journal")
	j, st, err := Open(f, opts)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	// Leave the journal open without Close, as after a crash. The test
	// cleanup unmaps it.
	t.Cleanup(j.Close)
	return j, st, nil
}

func mustOpen(t *testing.T, fd int, opts Options) (*Journal, *State) {
	t.Helper()
	j, st, err := open(t, fd, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return j, st
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
	_, st := mustOpen(t, fd, testOpts())
	if !st.Empty() {
		t.Fatalf("new journal has state %+v", st)
	}
	// Reopening an initialized journal with no snapshot is also empty.
	_, st = mustOpen(t, fd, testOpts())
	if !st.Empty() {
		t.Fatalf("reopened journal has state %+v", st)
	}
}

func TestRoundTrip(t *testing.T) {
	fd := newTestFile(t)
	j, _ := mustOpen(t, fd, testOpts())
	initRoot(t, j)

	j.Inode(regRec(2, 0))
	j.DirentAdd(1, "a", 2)
	j.ExtentSet(2, 0, pg, 2*pg)
	j.ExtentSet(2, pg, pg, 3*pg)
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
	j.ExtentSet(7, 0, pg, 8*pg)
	j.DirentDel(1, "tmp")
	// A freed inode is gone.
	j.Inode(regRec(8, 0))
	j.DirentAdd(1, "gone", 8)
	j.ExtentSet(8, 0, pg, 9*pg)
	j.DirentDel(1, "gone")
	j.ExtentClear(8, 0, pg)
	j.InodeFree(8)

	_, st := mustOpen(t, fd, testOpts())
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
	if want := []Extent{{Off: 0, Len: 2 * pg, MFOff: 2 * pg}}; !reflect.DeepEqual(f.Extents, want) {
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
	if got, want := st.UsedRanges(), []memmap.FileRange{{Start: 2 * pg, End: 4 * pg}}; !reflect.DeepEqual(got, want) {
		t.Errorf("used ranges %v, want %v", got, want)
	}
}

func TestRenameExchangeAndReplace(t *testing.T) {
	fd := newTestFile(t)
	j, _ := mustOpen(t, fd, testOpts())
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

	_, st := mustOpen(t, fd, testOpts())
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

// appendTail appends records that create /f, and returns the offset of the
// last record and the offset of the end of the log.
func appendTail(t *testing.T, j *Journal) (uint64, uint64) {
	t.Helper()
	j.Inode(regRec(2, 0))
	j.mu.Lock()
	last := j.active.base + j.active.tail
	j.mu.Unlock()
	j.DirentAdd(1, "f", 2)
	j.mu.Lock()
	end := j.active.base + j.active.tail
	j.mu.Unlock()
	return last, end
}

func TestTornTail(t *testing.T) {
	fd := newTestFile(t)
	j, _ := mustOpen(t, fd, testOpts())
	initRoot(t, j)
	_, last := appendTail(t, j)
	j.Inode(regRec(3, 0))
	j.mu.Lock()
	lastStart := j.active.base + j.active.tail
	j.mu.Unlock()
	j.DirentAdd(1, "torn", 3)
	_ = last
	j.mu.Lock()
	lastEnd := j.active.base + j.active.tail
	j.mu.Unlock()
	// The covered bytes of the last record: header, payload and checksum.
	covered := recordHeaderSize + uint64(len("torn")) + 18 + recordCRCSize

	orig := make([]byte, lastEnd-lastStart)
	copy(orig, j.mapping[lastStart:lastEnd])
	restore := func() { copy(j.mapping[lastStart:lastEnd], orig) }

	check := func(t *testing.T, what string) {
		t.Helper()
		_, st, err := open(t, fd, testOpts())
		if err != nil {
			t.Fatalf("%s: Open: %v", what, err)
		}
		if got, want := children(st, 1), map[string]uint64{"f": 2}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: root entries %v, want %v", what, got, want)
		}
	}

	// Truncate the last record: zero its second half.
	clear(j.mapping[lastStart+covered/2 : lastEnd])
	check(t, "truncated")
	restore()

	// Remove the magic only.
	clear(j.mapping[lastStart : lastStart+4])
	check(t, "no magic")
	restore()

	// Flip each covered byte of the last record in turn.
	for k := uint64(0); k < covered; k++ {
		j.mapping[lastStart+k] ^= 0x5a
		check(t, "flipped byte")
		restore()
	}

	// Without damage, the last record is replayed.
	_, st := mustOpen(t, fd, testOpts())
	if got, want := children(st, 1), map[string]uint64{"f": 2, "torn": 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root entries %v, want %v", got, want)
	}
}

func TestStaleRecordsAfterCompaction(t *testing.T) {
	fd := newTestFile(t)
	j, _ := mustOpen(t, fd, testOpts())
	initRoot(t, j)
	// Fill region 1 with records, compact to region 0, then compact back to
	// region 1. Region 1 then holds a short snapshot followed by stale
	// records, which must be ignored.
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
	_, st := mustOpen(t, fd, testOpts())
	if n := len(st.Inodes); n != 1 {
		t.Fatalf("got %d inodes, want 1", n)
	}
}

func TestCompaction(t *testing.T) {
	fd := newTestFile(t)
	j, _ := mustOpen(t, fd, testOpts())
	requested := 0
	j.SetCompactionRequester(func() { requested++ })
	initRoot(t, j)
	j.Inode(regRec(2, 0))
	j.DirentAdd(1, "f", 2)
	for i := uint64(0); requested == 0; i++ {
		if i > 10000 {
			t.Fatalf("compaction was never requested")
		}
		j.ExtentSet(2, 0, pg, (i%16)*pg)
	}
	j.ExtentSet(2, 0, pg, 5*pg)
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
	s.ExtentSet(2, 0, pg, 5*pg)
	s.DirentAdd(1, "f", 2)
	// A record appended during compaction goes to both regions.
	j.Inode(regRec(2, 200))

	// A crash before Commit replays the old region.
	_, st := mustOpen(t, fd, testOpts())
	if f := st.Inodes[2]; f.Size != 200 || !reflect.DeepEqual(f.Extents, []Extent{{0, pg, 5 * pg}}) {
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
	_, st = mustOpen(t, fd, testOpts())
	if f := st.Inodes[2]; f.Size != 300 || !reflect.DeepEqual(f.Extents, []Extent{{0, pg, 5 * pg}}) {
		t.Fatalf("after commit: file %+v", f)
	}
	if got, want := children(st, 1), map[string]uint64{"f": 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after commit: root entries %v, want %v", got, want)
	}
}

func TestOverflow(t *testing.T) {
	fd := newTestFile(t)
	opts := testOpts()
	opts.RegionSize = 4 * pg
	j, _ := mustOpen(t, fd, opts)
	initRoot(t, j)
	for !j.Broken() {
		j.Inode(regRec(2, 0))
	}
	if _, _, err := open(t, fd, opts); err == nil || !strings.Contains(err.Error(), "overflowed") {
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
	j, _ := mustOpen(t, fd, opts)
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
	_, st := mustOpen(t, fd, opts)
	if n := len(st.Inodes); n != 1 {
		t.Fatalf("got %d inodes, want 1", n)
	}
}

func TestHeaderValidation(t *testing.T) {
	fd := newTestFile(t)
	mustOpen(t, fd, testOpts())

	opts := testOpts()
	opts.ImageID = "image-2"
	_, _, err := open(t, fd, opts)
	var mismatch *ImageMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("Open with another image ID: got %v, want ImageMismatchError", err)
	}

	opts = testOpts()
	opts.BuildID = "build-2"
	if _, _, err := open(t, fd, opts); err == nil {
		t.Errorf("Open with another build ID succeeded")
	}

	// A garbage header is refused, not reinitialized.
	if _, err := unix.Pwrite(fd, []byte("garbage!"), 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, _, err := open(t, fd, testOpts()); err == nil {
		t.Errorf("Open with a garbage header succeeded")
	}

	// A header that is all zeros was never completely written.
	if _, err := unix.Pwrite(fd, make([]byte, headerSize), 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, st, err := open(t, fd, testOpts()); err != nil || !st.Empty() {
		t.Errorf("Open with a zero header: state %+v, error %v; want empty state", st, err)
	}

	// Initialization writes the magic last. A header without a magic was
	// never completely written, even if other fields are set.
	if _, err := unix.Pwrite(fd, make([]byte, len(headerMagic)), 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, st, err := open(t, fd, testOpts()); err != nil || !st.Empty() {
		t.Errorf("Open with a header without a magic: state %+v, error %v; want empty state", st, err)
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
				j.ExtentSet(2, 0, pg, 4*pg)
				j.ExtentSet(3, 0, pg, 4*pg)
			},
		},
		{
			name: "shared page in one file",
			records: func(j *Journal) {
				j.Inode(regRec(2, 2*pg))
				j.DirentAdd(1, "a", 2)
				j.ExtentSet(2, 0, pg, 4*pg)
				j.ExtentSet(2, pg, pg, 4*pg)
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
				j.ExtentSet(2, 0, pg, 1)
			},
		},
		{
			name: "extent on directory",
			records: func(j *Journal) {
				j.Inode(dirRec(2))
				j.DirentAdd(1, "a", 2)
				j.ExtentSet(2, 0, pg, 0)
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
			j, _ := mustOpen(t, fd, testOpts())
			initRoot(t, j)
			tc.records(j)
			if _, st, err := open(t, fd, testOpts()); err == nil {
				t.Fatalf("Open succeeded with state %+v, want error", st)
			}
		})
	}
}

func TestIncomplete(t *testing.T) {
	fd := newTestFile(t)

	// The host creates an incomplete journal before an image populates the
	// filestore.
	f := dupFile(t, fd)
	defer f.Close()
	if err := CreateIncomplete(f, testOpts()); err != nil {
		t.Fatalf("CreateIncomplete: %v", err)
	}
	if incomplete, err := Incomplete(f); err != nil || !incomplete {
		t.Fatalf("Incomplete: %t, %v; want true", incomplete, err)
	}
	if _, _, err := open(t, fd, testOpts()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Open of an incomplete journal: got %v, want ErrIncomplete", err)
	}
	// The mark is checked before the build ID, which the host may not
	// share with the sandbox.
	opts := testOpts()
	opts.BuildID = "other-build"
	if _, _, err := open(t, fd, opts); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Open of an incomplete journal with another build ID: got %v, want ErrIncomplete", err)
	}
	if _, ok := filestoreEnd(t, fd); ok {
		t.Errorf("incomplete journal has a filestore end mark")
	}

	// Reinit keeps the mark until the first snapshot commits.
	j, err := Reinit(dupFile(t, fd), testOpts())
	if err != nil {
		t.Fatalf("Reinit: %v", err)
	}
	t.Cleanup(j.Close)
	if _, _, err := open(t, fd, testOpts()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Open after Reinit: got %v, want ErrIncomplete", err)
	}
	s, err := j.BeginSnapshot(1, 4, 0)
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	s.Inode(dirRec(1))
	s.Inode(regRec(3, pg))
	s.ExtentSet(3, 0, pg, 2*pg)
	s.DirentAdd(1, "g", 3)
	// A crash before Commit leaves the journal incomplete.
	if _, _, err := open(t, fd, testOpts()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Open before Commit: got %v, want ErrIncomplete", err)
	}
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if incomplete, err := Incomplete(f); err != nil || incomplete {
		t.Fatalf("Incomplete after Commit: %t, %v; want false", incomplete, err)
	}
	_, st := mustOpen(t, fd, testOpts())
	if got, want := children(st, 1), map[string]uint64{"g": 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("root entries after Commit: %v, want %v", got, want)
	}
	if end, ok := filestoreEnd(t, fd); !ok || end != 3*pg {
		t.Fatalf("filestore end mark %#x, ok %t; want %#x, true", end, ok, 3*pg)
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

// filestoreEnd returns the filestore end mark of the journal in fd, as the
// host reads it.
func filestoreEnd(t *testing.T, fd int) (uint64, bool) {
	t.Helper()
	f := dupFile(t, fd)
	defer f.Close()
	end, ok, err := FilestoreEnd(f)
	if err != nil {
		t.Fatalf("FilestoreEnd: %v", err)
	}
	return end, ok
}

// openShrunk opens the journal in fd as after the host shrank the filestore
// to the filestore end mark.
func openShrunk(t *testing.T, fd int) (*State, error) {
	t.Helper()
	end, ok := filestoreEnd(t, fd)
	if !ok {
		t.Fatalf("FilestoreEnd: no valid mark")
	}
	opts := testOpts()
	opts.FilestoreSize = min(opts.FilestoreSize, hostarch.MustPageRoundUp(end))
	_, st, err := open(t, fd, opts)
	return st, err
}

func TestFilestoreEnd(t *testing.T) {
	fd := newTestFile(t)
	j, _ := mustOpen(t, fd, testOpts())
	if end, ok := filestoreEnd(t, fd); !ok || end != 0 {
		t.Fatalf("new journal: mark %#x, ok %t; want 0, true", end, ok)
	}
	initRoot(t, j)
	j.Inode(regRec(2, 0))
	j.DirentAdd(1, "big", 2)
	j.Inode(regRec(3, 0))
	j.DirentAdd(1, "small", 3)

	// The mark covers every EXTENT_SET record, including extents that were
	// replaced later.
	j.ExtentSet(2, 0, 4*pg, 40*pg)
	j.ExtentSet(3, 0, pg, 2*pg)
	j.ExtentSet(2, 0, 4*pg, 10*pg)
	if end, ok := filestoreEnd(t, fd); !ok || end != 44*pg {
		t.Fatalf("after extents: mark %#x, ok %t; want %#x, true", end, ok, 44*pg)
	}
	if _, err := openShrunk(t, fd); err != nil {
		t.Fatalf("Open after shrinking to the mark: %v", err)
	}

	// Delete the big file. The mark only shrinks after compaction.
	j.DirentDel(1, "big")
	j.ExtentClear(2, 0, 4*pg)
	j.InodeFree(2)
	if end, _ := filestoreEnd(t, fd); end != 44*pg {
		t.Fatalf("after delete: mark %#x, want %#x", end, 44*pg)
	}

	s, err := j.BeginSnapshot(1, 5, 0)
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	s.Inode(dirRec(1))
	s.Inode(regRec(3, pg))
	s.ExtentSet(3, 0, pg, 2*pg)
	s.DirentAdd(1, "small", 3)
	// A crash before Commit replays the old region, which the mark still
	// covers.
	if end, _ := filestoreEnd(t, fd); end != 44*pg {
		t.Fatalf("during compaction: mark %#x, want %#x", end, 44*pg)
	}
	if _, err := openShrunk(t, fd); err != nil {
		t.Fatalf("Open during compaction: %v", err)
	}
	// An extent appended during compaction goes to both regions.
	j.Inode(regRec(4, pg))
	j.DirentAdd(1, "new", 4)
	j.ExtentSet(4, 0, pg, 6*pg)
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if end, _ := filestoreEnd(t, fd); end != 7*pg {
		t.Fatalf("after compaction: mark %#x, want %#x", end, 7*pg)
	}
	st, err := openShrunk(t, fd)
	if err != nil {
		t.Fatalf("Open after compaction: %v", err)
	}
	if got, want := st.UsedRanges(), []memmap.FileRange{{Start: 2 * pg, End: 3 * pg}, {Start: 6 * pg, End: 7 * pg}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("used ranges %v, want %v", got, want)
	}

	// A mark that is too low makes Open fail, even if the filestore is
	// large enough.
	var low [8]byte
	binary.LittleEndian.PutUint64(low[:], 3*pg)
	if _, err := unix.Pwrite(fd, low[:], filestoreEndOff); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, _, err := open(t, fd, testOpts()); err == nil || !strings.Contains(err.Error(), "filestore end mark") {
		t.Fatalf("Open with a low mark: got %v, want filestore end mark error", err)
	}
}

func TestFilestoreEndInvalid(t *testing.T) {
	// An empty file has no mark.
	fd := newTestFile(t)
	if _, ok := filestoreEnd(t, fd); ok {
		t.Errorf("empty file has a mark")
	}

	j, _ := mustOpen(t, fd, testOpts())
	initRoot(t, j)

	// A broken journal has no mark.
	opts := testOpts()
	opts.RegionSize = 4 * pg
	bfd := newTestFile(t)
	bj, _ := mustOpen(t, bfd, opts)
	initRoot(t, bj)
	for !bj.Broken() {
		bj.ExtentSet(2, 0, pg, 0)
	}
	if _, ok := filestoreEnd(t, bfd); ok {
		t.Errorf("broken journal has a mark")
	}

	// A header with a bad checksum has no mark. The mark itself is not
	// covered by the checksum.
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], 5*pg)
	if _, err := unix.Pwrite(fd, b[:], filestoreEndOff); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if end, ok := filestoreEnd(t, fd); !ok || end != 5*pg {
		t.Errorf("mark %#x, ok %t; want %#x, true", end, ok, 5*pg)
	}
	if _, err := unix.Pwrite(fd, []byte{0xff}, imageIDOff+2); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, ok := filestoreEnd(t, fd); ok {
		t.Errorf("header with a bad checksum has a mark")
	}
}

// writeTree writes a snapshot of a root directory with n regular files, each
// with one extent, to w.
func writeTree(w interface {
	Inode(r *InodeRecord)
	DirentAdd(parent uint64, name string, child uint64)
	ExtentSet(ino, off, length, mfOff uint64)
}, n uint64) {
	w.Inode(dirRec(1))
	for i := uint64(0); i < n; i++ {
		ino := 2 + i
		w.Inode(regRec(ino, pg))
		w.ExtentSet(ino, 0, pg, i*pg)
		w.DirentAdd(1, fmt.Sprintf("file-%d", i), ino)
	}
}

// compactTree compacts j to a snapshot of writeTree(n), with the size from
// SnapshotSizer.
func compactTree(t *testing.T, j *Journal, n uint64) {
	t.Helper()
	var z SnapshotSizer
	writeTree(&z, n)
	s, err := j.BeginSnapshot(1, n+2, z.Size())
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	writeTree(s, n)
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func fileSize(t *testing.T, fd int) int64 {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatalf("Fstat: %v", err)
	}
	return stat.Size
}

func (j *Journal) regionsForTest() [2]region {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.regions
}

func TestRegionRelocation(t *testing.T) {
	fd := newTestFile(t)
	opts := testOpts()
	opts.RegionSize = 4 * pg
	j, _ := mustOpen(t, fd, opts)
	initRoot(t, j)
	initial := fileSize(t, fd)
	const n = 200
	var z SnapshotSizer
	writeTree(&z, n)
	if z.Size() < 4*pg {
		t.Fatalf("test snapshot size %d is not larger than the region", z.Size())
	}

	// The snapshot does not fit in the region, so the inactive region
	// moves to a larger range at the end of the file.
	s, err := j.BeginSnapshot(1, n+2, z.Size())
	if err != nil {
		t.Fatalf("BeginSnapshot: %v", err)
	}
	writeTree(s, n)
	if got := fileSize(t, fd); got <= initial {
		t.Fatalf("journal size %d after relocation, want more than %d", got, initial)
	}
	regs := j.regionsForTest()
	if regs[1].size < 2*z.Size() || regs[1].off != regs[0].end() {
		t.Fatalf("regions after relocation: %+v", regs)
	}
	// A crash before Commit replays the old region.
	_, st := mustOpen(t, fd, opts)
	if len(st.Inodes) != 1 {
		t.Fatalf("before commit: got %d inodes, want 1", len(st.Inodes))
	}
	if err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// A crash after Commit replays the new region.
	_, st = mustOpen(t, fd, opts)
	if len(st.Inodes) != n+1 {
		t.Fatalf("after commit: got %d inodes, want %d", len(st.Inodes), n+1)
	}
	if end, ok := filestoreEnd(t, fd); !ok || end != n*pg {
		t.Fatalf("filestore end mark %#x, ok %t; want %#x, true", end, ok, uint64(n*pg))
	}

	// The next compaction moves the other region, which is too small, after
	// the active one. The start of the file stays unused.
	j.Inode(regRec(2, 2*pg))
	compactTree(t, j, n)
	regs = j.regionsForTest()
	if regs[0].off != regs[1].end() || regs[0].size < 2*z.Size() {
		t.Fatalf("regions after the second compaction: %+v", regs)
	}
	grown := fileSize(t, fd)

	// The next compaction reuses the region.
	compactTree(t, j, n)
	if got := j.regionsForTest(); got != regs {
		t.Fatalf("regions after the third compaction: %+v, want %+v", got, regs)
	}
	if got := fileSize(t, fd); got != grown {
		t.Fatalf("journal size %d after the third compaction, want %d", got, grown)
	}
	_, st = mustOpen(t, fd, opts)
	if len(st.Inodes) != n+1 {
		t.Fatalf("after the third compaction: got %d inodes, want %d", len(st.Inodes), n+1)
	}

	// A small snapshot moves the oversized inactive region to the start of
	// the file, and the file shrinks to end with the active region.
	compactTree(t, j, 0)
	regs = j.regionsForTest()
	if regs[0].off != headerSize || regs[0].size != 4*pg {
		t.Fatalf("regions after the small compaction: %+v", regs)
	}
	if got, want := fileSize(t, fd), int64(regs[1].end()); got != want {
		t.Fatalf("journal size %d after the small compaction, want %d", got, want)
	}
	_, st = mustOpen(t, fd, opts)
	if len(st.Inodes) != 1 {
		t.Fatalf("after the small compaction: got %d inodes, want 1", len(st.Inodes))
	}
	if end, _ := filestoreEnd(t, fd); end != 0 {
		t.Fatalf("filestore end mark %#x after the small compaction, want 0", end)
	}
}

func TestRegionValidation(t *testing.T) {
	fd := newTestFile(t)
	j, _ := mustOpen(t, fd, testOpts())
	initRoot(t, j)

	// The active region is region 0 after initRoot. A descriptor outside
	// the file is refused.
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:], headerSize)
	binary.LittleEndian.PutUint64(b[8:], 1<<30)
	if _, err := unix.Pwrite(fd, b[:], regionDescOff); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, _, err := open(t, fd, testOpts()); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("Open with a bad region descriptor: got %v, want an invalid region error", err)
	}
}

func TestFormatVersion(t *testing.T) {
	fd := newTestFile(t)
	mustOpen(t, fd, testOpts())
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
	if _, _, err := open(t, fd, testOpts()); err == nil || !strings.Contains(err.Error(), "format version is 2") {
		t.Fatalf("Open of a version 2 journal: got %v, want a format version error", err)
	}
	if _, ok := filestoreEnd(t, fd); ok {
		t.Errorf("version 2 journal has a filestore end mark")
	}
}

func TestDescribe(t *testing.T) {
	fd := newTestFile(t)
	f := dupFile(t, fd)
	defer f.Close()
	if _, _, err := Describe(f); err == nil {
		t.Errorf("Describe of an empty file succeeded")
	}
	j, _ := mustOpen(t, fd, testOpts())
	initRoot(t, j)
	imageID, gen, err := Describe(f)
	if err != nil || imageID != "image-1" || gen != 2 {
		t.Errorf("Describe: image %q, generation %d, error %v; want image-1, 2", imageID, gen, err)
	}
	if err := CreateIncomplete(f, testOpts()); err != nil {
		t.Fatalf("CreateIncomplete: %v", err)
	}
	if imageID, gen, err := Describe(f); err != nil || imageID != "image-1" || gen != 1 {
		t.Errorf("Describe of an incomplete journal: image %q, generation %d, error %v; want image-1, 1", imageID, gen, err)
	}
	if _, err := unix.Pwrite(fd, []byte("garbage!"), 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	if _, _, err := Describe(f); err == nil {
		t.Errorf("Describe of a garbage header succeeded")
	}
}
