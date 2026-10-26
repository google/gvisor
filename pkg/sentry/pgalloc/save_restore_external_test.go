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

//go:build !pagesize_64k

package pgalloc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
)

// waitExternalRelease waits for decommit, not just DecRef's bookkeeping.
func waitExternalRelease(t *testing.T, f *MemoryFile) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		done := !f.haveWaste
		f.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for memory release")
		}
		runtime.Gosched()
	}
}

func TestFilestoreSnapshotSurvivesRelease(t *testing.T) {
	for _, huge := range []bool{false, true} {
		t.Run(map[bool]string{false: "small", true: "huge"}[huge], func(t *testing.T) {
			dir := t.TempDir()
			file := openSaveTestFile(t, dir)
			f, err := NewMemoryFile(file, MemoryFileOpts{DiskBackedFile: true, DisableMemoryAccounting: true, DecommitOnDestroy: true})
			if err != nil {
				t.Fatal(err)
			}
			defer f.Destroy()
			snapshot := openSaveTestFile(t, dir)
			defer snapshot.Close()
			// Probe before allocating to distinguish an unsupported test filesystem.
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, snapshot.Fd(), unix.FICLONE, file.Fd()); errno != 0 {
				if errno == unix.EOPNOTSUPP || errno == unix.ENOTTY || errno == unix.EINVAL {
					t.Skipf("reflink unsupported: %v", errno)
				}
				t.Fatal(errno)
			}
			size := uint64(hostarch.PageSize)
			if huge {
				size = hostarch.HugePageSize
			}
			fr, err := f.Allocate(size, AllocOpts{Mode: AllocateUncommitted, Huge: huge})
			if err != nil {
				t.Fatal(err)
			}
			writeMappedPage(f, fr, 0, 0x5a)
			var metadata bytes.Buffer
			if err := f.SaveTo(context.Background(), &metadata, &SaveOpts{FilestoreSnapshots: []*os.File{snapshot}}); err != nil {
				t.Fatal(err)
			}
			f.DecRef(fr)
			waitExternalRelease(t, f)
			data := make([]byte, hostarch.PageSize)
			if _, err := file.ReadAt(data, int64(fr.Start)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Fatal("source released range was not cleared")
			}
			if _, err := snapshot.ReadAt(data, int64(fr.Start)); err != nil {
				t.Fatal(err)
			}
			if data[17] != 0x5a {
				t.Fatal("source release modified snapshot")
			}
			clone := openSaveTestFile(t, dir)
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, clone.Fd(), unix.FICLONE, snapshot.Fd()); errno != 0 {
				clone.Close()
				t.Fatal(errno)
			}
			restored, err := NewMemoryFile(clone, MemoryFileOpts{DiskBackedFile: true, DisableMemoryAccounting: true, RestoreExternal: true})
			if err != nil {
				clone.Close()
				t.Fatal(err)
			}
			defer restored.Destroy()
			if err := restored.LoadFrom(context.Background(), &metadata, &LoadOpts{}); err != nil {
				t.Fatal(err)
			}
			restored.forEachMappingSlice(fr, func(data []byte) {
				if data[17] != 0x5a {
					t.Error("restored contents differ")
				}
			})
			restored.DecRef(fr)
			waitExternalRelease(t, restored)
			if _, err := snapshot.ReadAt(data, int64(fr.Start)); err != nil || data[17] != 0x5a {
				t.Fatalf("clone release modified template: %v", err)
			}
		})
	}
}

func TestOrdinaryCheckpointClearsRestoreClone(t *testing.T) {
	dir := t.TempDir()
	f := newSaveTestMemoryFile(t, dir, true)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 2, 0x6b)
	var checkpoint bytes.Buffer
	if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{}); err != nil {
		t.Fatal(err)
	}
	clone := openSaveTestFile(t, dir)
	// Old contents in an uncommitted page must not survive an ordinary load.
	if _, err := clone.WriteAt(bytes.Repeat([]byte{0xff}, hostarch.PageSize), int64(fr.Start)); err != nil {
		t.Fatal(err)
	}
	restored, err := NewMemoryFile(clone, MemoryFileOpts{DiskBackedFile: true, DisableMemoryAccounting: true, RestoreExternal: true})
	if err != nil {
		clone.Close()
		t.Fatal(err)
	}
	defer restored.Destroy()
	if err := restored.LoadFrom(context.Background(), &checkpoint, &LoadOpts{}); err != nil {
		t.Fatal(err)
	}
	want := make([]byte, fr.Length())
	want[2*hostarch.PageSize+17] = 0x6b
	restored.forEachMappingSlice(fr, func(got []byte) {
		if !bytes.Equal(got, want) {
			t.Error("old clone data survived ordinary restore")
		}
	})
	restored.DecRef(fr)
}

// TestDestroyAfterLoadFailsBeforeMmap verifies that partially loaded chunk
// metadata cannot cause destruction to unmap an unrelated address range.
func TestDestroyAfterLoadFailsBeforeMmap(t *testing.T) {
	const sentinel = uintptr(128 << 20)
	address, _, errno := unix.Syscall6(unix.SYS_MMAP, sentinel, hostarch.PageSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE, ^uintptr(0), 0)
	if errno != 0 {
		t.Skipf("cannot reserve low-address sentinel mapping: %v", errno)
	}
	defer unix.Syscall(unix.SYS_MUNMAP, address, hostarch.PageSize, 0)
	if address != sentinel {
		t.Skip("MAP_FIXED_NOREPLACE is not supported")
	}

	source := newSaveTestMemoryFile(t, "", false)
	allocateSaveTestPages(t, source)
	var checkpoint bytes.Buffer
	if err := source.SaveTo(context.Background(), &checkpoint, &SaveOpts{}); err != nil {
		t.Fatal(err)
	}
	fileFD, err := memutil.CreateMemFD("failed-load", unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fileFD), "failed-load")
	restored, err := NewMemoryFile(file, MemoryFileOpts{DisableMemoryAccounting: true, DecommitOnDestroy: true})
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	// Force file growth to fail after metadata import, before any mmap.
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_GROW); err != nil {
		restored.Destroy()
		t.Fatal(err)
	}
	if err := restored.LoadFrom(context.Background(), &checkpoint, &LoadOpts{}); !errors.Is(err, unix.EPERM) {
		restored.Destroy()
		t.Fatalf("LoadFrom: %v, want EPERM", err)
	}
	restored.Destroy()
	deadline := time.Now().Add(5 * time.Second)
	for {
		restored.mu.Lock()
		done := restored.file == nil
		restored.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for destruction")
		}
		runtime.Gosched()
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("backing FD not closed: %v", err)
	}
	var resident byte
	if _, _, errno := unix.Syscall(unix.SYS_MINCORE, address, hostarch.PageSize, uintptr(unsafe.Pointer(&resident))); errno != 0 {
		t.Fatalf("unrelated mapping was removed during destruction: %v", errno)
	}
}
