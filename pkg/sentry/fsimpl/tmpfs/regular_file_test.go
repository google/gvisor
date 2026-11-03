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
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/lock"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
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

// newDiskBackedFileFD creates a new file in a new tmpfs mount that stores file
// data in a disk-backed MemoryFile. It returns the FD and the MemoryFile.
func newDiskBackedFileFD(ctx context.Context, tb testing.TB) (*vfs.FileDescription, *pgalloc.MemoryFile) {
	tb.Helper()
	file, err := os.CreateTemp(tb.TempDir(), "tmpfs-disk-backed")
	if err != nil {
		tb.Fatalf("os.CreateTemp failed: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(file, pgalloc.MemoryFileOpts{
		DelayedEviction:         pgalloc.DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		DiskBackedFile:          true,
	})
	if err != nil {
		file.Close()
		tb.Fatalf("pgalloc.NewMemoryFile failed: %v", err)
	}
	tb.Cleanup(mf.Destroy)

	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		tb.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOpts{MemoryFile: mf},
		},
	}, nil)
	if err != nil {
		tb.Fatalf("failed to create tmpfs root mount: %v", err)
	}
	tb.Cleanup(func() { mntns.DecRef(ctx) })
	root := mntns.Root(ctx)
	tb.Cleanup(func() { root.DecRef(ctx) })

	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("file"),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  linux.ModeRegular | 0644,
	})
	if err != nil {
		tb.Fatalf("failed to create file: %v", err)
	}
	tb.Cleanup(func() { fd.DecRef(ctx) })
	return fd, mf
}

// TestDiskBackedWriteHostFault tests a write to a file in a disk-backed
// MemoryFile, when the host raises SIGBUS for some of the pages that the
// write touches.
func TestDiskBackedWriteHostFault(t *testing.T) {
	// The write is smaller than hostWriteThreshold, so it is copied through
	// the internal mappings of the MemoryFile.
	const size = 2 * hostarch.PageSize
	for _, okPages := range []int{0, 1} {
		t.Run(fmt.Sprintf("SIGBUS after %d pages", okPages), func(t *testing.T) {
			ctx := contexttest.Context(t)
			fd, mf := newDiskBackedFileFD(ctx, t)

			// Allocate the file data.
			if n, err := fd.PWrite(ctx, usermem.BytesIOSequence(make([]byte, size)), 0, vfs.WriteOptions{}); err != nil || n != size {
				t.Fatalf("fd.PWrite: got (%d, %v), want (%d, nil)", n, err, size)
			}
			rf := fd.Impl().(*regularFileFD).inode().impl.(*regularFile)
			rf.dataMu.RLock()
			fr := rf.data.FirstSegment().FileRange()
			rf.dataMu.RUnlock()
			if fr.Length() != size {
				t.Fatalf("got file data in MemoryFile range %v, want one range of %d bytes", fr, size)
			}

			// The host raises SIGBUS when a page of a file mapping after the
			// end of the file is touched. Truncate the backing file so that
			// only the first okPages pages of the file data are before its
			// end.
			if err := mf.File().Truncate(int64(fr.Start) + int64(okPages*hostarch.PageSize)); err != nil {
				t.Fatalf("Truncate failed: %v", err)
			}

			// Overwrite the file data.
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i%255 + 1)
			}
			if n, err := fd.PWrite(ctx, usermem.BytesIOSequence(data), 0, vfs.WriteOptions{}); err != nil || n != size {
				t.Fatalf("fd.PWrite: got (%d, %v), want (%d, nil)", n, err, size)
			}

			// Read the file data.
			got := make([]byte, size)
			if n, err := fd.PRead(ctx, usermem.BytesIOSequence(got), 0, vfs.ReadOptions{}); err != nil || n != size {
				t.Fatalf("fd.PRead: got (%d, %v), want (%d, nil)", n, err, size)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("fd.PRead got data different from the written data")
			}
		})
	}
}

// BenchmarkDiskBackedWrite measures overwrites of populated pages of a file in
// a disk-backed MemoryFile. The writes are smaller than hostWriteThreshold, so
// they are copied through the internal mappings of the MemoryFile.
func BenchmarkDiskBackedWrite(b *testing.B) {
	for _, size := range []int{64, 4096, 32768} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			ctx := contexttest.Context(b)
			fd, _ := newDiskBackedFileFD(ctx, b)
			src := usermem.BytesIOSequence(make([]byte, size))
			if _, err := fd.PWrite(ctx, src, 0, vfs.WriteOptions{}); err != nil {
				b.Fatalf("fd.PWrite failed: %v", err)
			}
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := fd.PWrite(ctx, src, 0, vfs.WriteOptions{}); err != nil {
					b.Fatalf("fd.PWrite failed: %v", err)
				}
			}
		})
	}
}
