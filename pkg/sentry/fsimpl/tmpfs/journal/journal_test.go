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
