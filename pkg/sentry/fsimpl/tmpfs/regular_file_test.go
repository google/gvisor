// Copyright 2019 The gVisor Authors.
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

package tmpfs

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/lock"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Test that we can write some data to a file and read it back.`
func TestSimpleWriteRead(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Write.
	data := []byte("foobarbaz")
	n, err := fd.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("fd.Write failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("fd.Write got short write length %d, want %d", n, len(data))
	}
	if got, want := fd.Impl().(*regularFileFD).off, int64(len(data)); got != want {
		t.Errorf("fd.Write left offset at %d, want %d", got, want)
	}

	// Seek back to beginning.
	if _, err := fd.Seek(ctx, 0, linux.SEEK_SET); err != nil {
		t.Fatalf("fd.Seek failed: %v", err)
	}
	if got, want := fd.Impl().(*regularFileFD).off, int64(0); got != want {
		t.Errorf("fd.Seek(0) left offset at %d, want %d", got, want)
	}

	// Read.
	buf := make([]byte, len(data))
	n, err = fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil && err != io.EOF {
		t.Fatalf("fd.Read failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("fd.Read got short read length %d, want %d", n, len(data))
	}
	if got, want := string(buf), string(data); got != want {
		t.Errorf("Read got %q want %s", got, want)
	}
	if got, want := fd.Impl().(*regularFileFD).off, int64(len(data)); got != want {
		t.Errorf("fd.Write left offset at %d, want %d", got, want)
	}
}

func TestPWrite(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Fill file with 1k 'a's.
	data := bytes.Repeat([]byte{'a'}, 1000)
	n, err := fd.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("fd.Write failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("fd.Write got short write length %d, want %d", n, len(data))
	}

	// Write "gVisor is awesome" at various offsets.
	buf := []byte("gVisor is awesome")
	offsets := []int{0, 1, 2, 10, 20, 50, 100, len(data) - 100, len(data) - 1, len(data), len(data) + 1}
	for _, offset := range offsets {
		name := fmt.Sprintf("PWrite offset=%d", offset)
		t.Run(name, func(t *testing.T) {
			n, err := fd.PWrite(ctx, usermem.BytesIOSequence(buf), int64(offset), vfs.WriteOptions{})
			if err != nil {
				t.Errorf("fd.PWrite got err %v want nil", err)
			}
			if n != int64(len(buf)) {
				t.Errorf("fd.PWrite got %d bytes want %d", n, len(buf))
			}

			// Update data to reflect expected file contents.
			if len(data) < offset+len(buf) {
				data = append(data, make([]byte, (offset+len(buf))-len(data))...)
			}
			copy(data[offset:], buf)

			// Read the whole file and compare with data.
			readBuf := make([]byte, len(data))
			n, err = fd.PRead(ctx, usermem.BytesIOSequence(readBuf), 0, vfs.ReadOptions{})
			if err != nil {
				t.Fatalf("fd.PRead failed: %v", err)
			}
			if n != int64(len(data)) {
				t.Errorf("fd.PRead got short read length %d, want %d", n, len(data))
			}
			if got, want := string(readBuf), string(data); got != want {
				t.Errorf("PRead got %q want %s", got, want)
			}

		})
	}
}

func TestLocks(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	uid1 := 123
	uid2 := 456
	if err := fd.Impl().LockBSD(ctx, uid1, 0 /* ownerPID */, lock.ReadLock, false /* block */); err != nil {
		t.Fatalf("fd.Impl().LockBSD failed: err = %v", err)
	}
	if err := fd.Impl().LockBSD(ctx, uid2, 0 /* ownerPID */, lock.ReadLock, false /* block */); err != nil {
		t.Fatalf("fd.Impl().LockBSD failed: err = %v", err)
	}
	if got, want := fd.Impl().LockBSD(ctx, uid2, 0 /* ownerPID */, lock.WriteLock, false /* block */), linuxerr.ErrWouldBlock; got != want {
		t.Fatalf("fd.Impl().LockBSD failed: got = %v, want = %v", got, want)
	}
	if err := fd.Impl().UnlockBSD(ctx, uid1); err != nil {
		t.Fatalf("fd.Impl().UnlockBSD failed: err = %v", err)
	}
	if err := fd.Impl().LockBSD(ctx, uid2, 0 /* ownerPID */, lock.WriteLock, false /* block */); err != nil {
		t.Fatalf("fd.Impl().LockBSD failed: err = %v", err)
	}

	if err := fd.Impl().LockPOSIX(ctx, uid1, 0 /* ownerPID */, lock.ReadLock, lock.LockRange{Start: 0, End: 1}, false /* block */); err != nil {
		t.Fatalf("fd.Impl().LockPOSIX failed: err = %v", err)
	}
	if err := fd.Impl().LockPOSIX(ctx, uid2, 0 /* ownerPID */, lock.ReadLock, lock.LockRange{Start: 1, End: 2}, false /* block */); err != nil {
		t.Fatalf("fd.Impl().LockPOSIX failed: err = %v", err)
	}
	if err := fd.Impl().LockPOSIX(ctx, uid1, 0 /* ownerPID */, lock.WriteLock, lock.LockRange{Start: 0, End: 1}, false /* block */); err != nil {
		t.Fatalf("fd.Impl().LockPOSIX failed: err = %v", err)
	}
	if got, want := fd.Impl().LockPOSIX(ctx, uid2, 0 /* ownerPID */, lock.ReadLock, lock.LockRange{Start: 0, End: 1}, false /* block */), linuxerr.ErrWouldBlock; got != want {
		t.Fatalf("fd.Impl().LockPOSIX failed: got = %v, want = %v", got, want)
	}
	if err := fd.Impl().UnlockPOSIX(ctx, uid1, lock.LockRange{Start: 0, End: 1}); err != nil {
		t.Fatalf("fd.Impl().UnlockPOSIX failed: err = %v", err)
	}
}

func TestPRead(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Write 100 sequences of 'gVisor is awesome'.
	data := bytes.Repeat([]byte("gVisor is awesome"), 100)
	n, err := fd.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("fd.Write failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("fd.Write got short write length %d, want %d", n, len(data))
	}

	// Read various sizes from various offsets.
	sizes := []int{0, 1, 2, 10, 20, 50, 100, 1000}
	offsets := []int{0, 1, 2, 10, 20, 50, 100, 1000, len(data) - 100, len(data) - 1, len(data), len(data) + 1}

	for _, size := range sizes {
		for _, offset := range offsets {
			name := fmt.Sprintf("PRead offset=%d size=%d", offset, size)
			t.Run(name, func(t *testing.T) {
				var (
					wantRead []byte
					wantErr  error
				)
				if offset < len(data) {
					wantRead = data[offset:]
				} else if size > 0 {
					wantErr = io.EOF
				}
				if offset+size < len(data) {
					wantRead = wantRead[:size]
				}
				buf := make([]byte, size)
				n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), int64(offset), vfs.ReadOptions{})
				if err != wantErr {
					t.Errorf("fd.PRead got err %v want %v", err, wantErr)
				}
				if n != int64(len(wantRead)) {
					t.Errorf("fd.PRead got %d bytes want %d", n, len(wantRead))
				}
				if got := string(buf[:n]); got != string(wantRead) {
					t.Errorf("fd.PRead got %q want %q", got, string(wantRead))
				}
			})
		}
	}
}

func TestTruncate(t *testing.T) {
	ctx := contexttest.Context(t)
	fd, cleanup, err := newFileFD(ctx, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Fill the file with some data.
	data := bytes.Repeat([]byte("gVisor is awesome"), 100)
	written, err := fd.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("fd.Write failed: %v", err)
	}

	// Size should be same as written.
	sizeStatOpts := vfs.StatOptions{Mask: linux.STATX_SIZE}
	stat, err := fd.Stat(ctx, sizeStatOpts)
	if err != nil {
		t.Fatalf("fd.Stat failed: %v", err)
	}
	if got, want := int64(stat.Size), written; got != want {
		t.Errorf("fd.Stat got size %d, want %d", got, want)
	}

	// Truncate down.
	newSize := uint64(10)
	if err := fd.SetStat(ctx, vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_SIZE,
			Size: newSize,
		},
	}); err != nil {
		t.Errorf("fd.Truncate failed: %v", err)
	}
	// Size should be updated.
	statAfterTruncateDown, err := fd.Stat(ctx, sizeStatOpts)
	if err != nil {
		t.Fatalf("fd.Stat failed: %v", err)
	}
	if got, want := statAfterTruncateDown.Size, newSize; got != want {
		t.Errorf("fd.Stat got size %d, want %d", got, want)
	}
	// We should only read newSize worth of data.
	buf := make([]byte, 1000)
	if n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{}); err != nil && err != io.EOF {
		t.Fatalf("fd.PRead failed: %v", err)
	} else if uint64(n) != newSize {
		t.Errorf("fd.PRead got size %d, want %d", n, newSize)
	}
	// Mtime and Ctime should be bumped.
	if got := statAfterTruncateDown.Mtime.ToNsec(); got <= stat.Mtime.ToNsec() {
		t.Errorf("fd.Stat got Mtime %v, want > %v", got, stat.Mtime)
	}
	if got := statAfterTruncateDown.Ctime.ToNsec(); got <= stat.Ctime.ToNsec() {
		t.Errorf("fd.Stat got Ctime %v, want > %v", got, stat.Ctime)
	}

	// Truncate up.
	newSize = 100
	if err := fd.SetStat(ctx, vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_SIZE,
			Size: newSize,
		},
	}); err != nil {
		t.Errorf("fd.Truncate failed: %v", err)
	}
	// Size should be updated.
	statAfterTruncateUp, err := fd.Stat(ctx, sizeStatOpts)
	if err != nil {
		t.Fatalf("fd.Stat failed: %v", err)
	}
	if got, want := statAfterTruncateUp.Size, newSize; got != want {
		t.Errorf("fd.Stat got size %d, want %d", got, want)
	}
	// We should read newSize worth of data.
	buf = make([]byte, 1000)
	if n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{}); err != nil && err != io.EOF {
		t.Fatalf("fd.PRead failed: %v", err)
	} else if uint64(n) != newSize {
		t.Errorf("fd.PRead got size %d, want %d", n, newSize)
	}
	// Bytes should be null after 10, since we previously truncated to 10.
	for i := uint64(10); i < newSize; i++ {
		if buf[i] != 0 {
			t.Errorf("fd.PRead got byte %d=%x, want 0", i, buf[i])
			break
		}
	}
	// Mtime and Ctime should be bumped.
	if got := statAfterTruncateUp.Mtime.ToNsec(); got <= statAfterTruncateDown.Mtime.ToNsec() {
		t.Errorf("fd.Stat got Mtime %v, want > %v", got, statAfterTruncateDown.Mtime)
	}
	if got := statAfterTruncateUp.Ctime.ToNsec(); got <= statAfterTruncateDown.Ctime.ToNsec() {
		t.Errorf("fd.Stat got Ctime %v, want > %v", got, stat.Ctime)
	}
}

func newSizedRegularFile(ctx context.Context, t *testing.T, size uint64) (*vfs.FileDescription, *regularFile, func()) {
	t.Helper()
	fd, cleanup, err := newFileFD(ctx, 0644)
	if err != nil {
		t.Fatal(err)
	}
	setSize(ctx, t, fd, size)
	return fd, fd.Impl().(*regularFileFD).inode().impl.(*regularFile), cleanup
}

func setSize(ctx context.Context, t *testing.T, fd *vfs.FileDescription, size uint64) {
	t.Helper()
	if err := fd.SetStat(ctx, vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_SIZE,
			Size: size,
		},
	}); err != nil {
		t.Fatalf("fd.SetStat failed: %v", err)
	}
}

// translateEnd returns the end of the translations that rf.Translate() returns
// for a one-page fault at off in a mapping of the whole file.
func translateEnd(ctx context.Context, t *testing.T, rf *regularFile, off, size uint64) uint64 {
	t.Helper()
	return translateEndIn(ctx, t, rf, off, memmap.MappableRange{0, size})
}

// translateEndIn is translateEnd for a fault in a mapping of optional.
func translateEndIn(ctx context.Context, t *testing.T, rf *regularFile, off uint64, optional memmap.MappableRange) uint64 {
	t.Helper()
	required := memmap.MappableRange{off, off + hostarch.PageSize}
	ts, err := rf.Translate(ctx, required, optional, hostarch.Write)
	if err != nil {
		t.Fatalf("Translate(%v) failed: %v", required, err)
	}
	return ts[len(ts)-1].Source.End
}

func TestTranslateFillsSequentialFaults(t *testing.T) {
	ctx := contexttest.Context(t)
	const size = 8 << 20
	_, rf, cleanup := newSizedRegularFile(ctx, t, size)
	defer cleanup()

	for _, test := range []struct {
		name    string
		off     uint64
		wantEnd uint64
	}{
		{"first fault", 64 << 10, 128 << 10},
		{"sequential fault", 128 << 10, 192 << 10},
		{"sequential fault", 192 << 10, 320 << 10},
		{"sequential fault", 320 << 10, 576 << 10},
		{"sequential fault", 576 << 10, 1088 << 10},
		{"sequential fault up to 2 MiB boundary", 1088 << 10, 2 << 20},
		{"sequential fault at 2 MiB", 2 << 20, 4032 << 10},
		{"sequential fault up to 4 MiB boundary", 4032 << 10, 4 << 20},
		{"sequential fault at 4 MiB", 4 << 20, 6 << 20},
		{"non-sequential fault", 7 << 20, 7<<20 + 64<<10},
	} {
		if got := translateEnd(ctx, t, rf, test.off, size); got != test.wantEnd {
			t.Errorf("%s at %#x: translated up to %#x, want %#x", test.name, test.off, got, test.wantEnd)
		}
	}
}

func TestTranslateAfterWriteDoesNotFillSequentially(t *testing.T) {
	ctx := contexttest.Context(t)
	const size = 4 << 20
	fd, rf, cleanup := newSizedRegularFile(ctx, t, size)
	defer cleanup()
	if _, err := fd.PWrite(ctx, usermem.BytesIOSequence([]byte{1}), 0, vfs.WriteOptions{}); err != nil {
		t.Fatalf("fd.PWrite failed: %v", err)
	}
	if got, want := translateEnd(ctx, t, rf, hostarch.PageSize, size), uint64(hostarch.PageSize+64<<10); got != want {
		t.Errorf("fault after write translated up to %#x, want %#x", got, want)
	}
}

func TestTranslateAfterTruncateDoesNotFillSequentially(t *testing.T) {
	ctx := contexttest.Context(t)
	const size = 8 << 20
	fd, rf, cleanup := newSizedRegularFile(ctx, t, size)
	defer cleanup()
	for off := uint64(0); off < 2<<20; {
		off = translateEnd(ctx, t, rf, off, size)
	}
	setSize(ctx, t, fd, 0)
	setSize(ctx, t, fd, size)
	if got, want := translateEnd(ctx, t, rf, 2<<20, size), uint64(2<<20+64<<10); got != want {
		t.Errorf("fault after truncate translated up to %#x, want %#x", got, want)
	}
}

func TestTranslateAfterPartialFillDoesNotFillSequentially(t *testing.T) {
	ctx := contexttest.Context(t)
	const size = 4 << 20
	fd, rf, cleanup := newSizedRegularFile(ctx, t, size)
	defer cleanup()
	if _, err := fd.PWrite(ctx, usermem.BytesIOSequence([]byte{1}), hostarch.PageSize, vfs.WriteOptions{}); err != nil {
		t.Fatalf("fd.PWrite failed: %v", err)
	}
	translateEnd(ctx, t, rf, 0, size)
	if got, want := translateEnd(ctx, t, rf, 64<<10, size), uint64(128<<10); got != want {
		t.Errorf("fault after partial fill translated up to %#x, want %#x", got, want)
	}
}

func TestTranslateAfterSeparateFaultsDoesNotFillSequentially(t *testing.T) {
	ctx := contexttest.Context(t)
	const size = 4 << 20
	_, rf, cleanup := newSizedRegularFile(ctx, t, size)
	defer cleanup()
	// Fault in consecutive pages through separate one-page mappings.
	const pages = 10
	for i := uint64(0); i < pages; i++ {
		off := i * hostarch.PageSize
		translateEndIn(ctx, t, rf, off, memmap.MappableRange{off, off + hostarch.PageSize})
	}
	// The next fill is the larger of the default and the run so far, not
	// something grown by each of the separate fills.
	run := uint64(pages * hostarch.PageSize)
	if got, want := translateEnd(ctx, t, rf, run, size), run+max(64<<10, run); got != want {
		t.Errorf("fault after separate faults translated up to %#x, want %#x", got, want)
	}
}
