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
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

// openSaveTestFile returns a file in dir, or a memfd if dir is empty.
func openSaveTestFile(tb testing.TB, dir string) *os.File {
	tb.Helper()
	if dir == "" {
		fd, err := memutil.CreateMemFD("pgalloc-save-test", 0)
		if err != nil {
			tb.Fatalf("CreateMemFD: %v", err)
		}
		return os.NewFile(uintptr(fd), "pgalloc-save-test")
	}
	file, err := os.CreateTemp(dir, "pgalloc-save-test")
	if err != nil {
		tb.Fatalf("CreateTemp: %v", err)
	}
	return file
}

// newSaveTestMemoryFile returns a MemoryFile backed by a file in dir, or by a
// memfd if dir is empty.
func newSaveTestMemoryFile(t *testing.T, dir string, diskBacked bool) *MemoryFile {
	t.Helper()
	file := openSaveTestFile(t, dir)
	f, err := NewMemoryFile(file, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		DiskBackedFile:          diskBacked,
	})
	if err != nil {
		file.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)
	return f
}

func allocateSaveTestPages(t *testing.T, f *MemoryFile) memmap.FileRange {
	t.Helper()
	fr, err := f.Allocate(16*uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	t.Cleanup(func() { f.DecRef(fr) })
	return fr
}

// writeMappedPage writes b to byte 17 of the given page through f's mapping
// rather than with pwrite(2), so the page stays dirty in the page cache.
func writeMappedPage(f *MemoryFile, fr memmap.FileRange, page int, b byte) {
	start := fr.Start + uint64(page)*uint64(hostarch.PageSize)
	f.forEachMappingSlice(memmap.FileRange{Start: start, End: start + uint64(hostarch.PageSize)}, func(bs []byte) {
		bs[17] = b
	})
}

func pwritePage(t *testing.T, f *MemoryFile, fr memmap.FileRange, page int, b byte) {
	t.Helper()
	buf := make([]byte, hostarch.PageSize)
	buf[17] = b
	if _, err := unix.Pwrite(f.FD(), buf, int64(fr.Start)+int64(page*int(hostarch.PageSize))); err != nil {
		t.Fatalf("Pwrite page %d: %v", page, err)
	}
}

func TestHostFileDataSeeker(t *testing.T) {
	f := newSaveTestMemoryFile(t, "", true /* diskBacked */)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 2, 1)
	pwritePage(t, f, fr, 3, 1)
	pwritePage(t, f, fr, 9, 1)
	pwritePage(t, f, fr, 12, 0)
	page := func(n uint64) uint64 { return fr.Start + n*uint64(hostarch.PageSize) }
	d := f.newHostFileDataSeeker()
	if d == nil {
		t.Fatal("newHostFileDataSeeker returned nil for a disk-backed file on tmpfs")
	}
	for _, call := range []struct {
		off  uint64
		want memmap.FileRange
	}{
		{off: page(0), want: memmap.FileRange{page(2), page(4)}},
		{off: page(3), want: memmap.FileRange{page(3), page(4)}},
		{off: page(4), want: memmap.FileRange{page(9), page(10)}},
		{off: page(10), want: memmap.FileRange{page(12), page(13)}},
		{off: page(13), want: memmap.FileRange{f.TotalSize(), f.TotalSize()}},
		{off: page(15), want: memmap.FileRange{f.TotalSize(), f.TotalSize()}},
	} {
		got, err := d.dataAtOrAfter(call.off)
		if err != nil || got != call.want {
			t.Errorf("dataAtOrAfter(%#x): got (%v, %v), want (%v, nil)", call.off, got, err, call.want)
		}
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	w.Close()
	pipeMemFile := &MemoryFile{
		file: r,
		opts: MemoryFileOpts{DiskBackedFile: true},
	}
	if d := pipeMemFile.newHostFileDataSeeker(); d != nil {
		t.Errorf("newHostFileDataSeeker returned %v for a disk-backed file on pipefs, want nil", d)
	}
	r.Close()
	if d := pipeMemFile.newHostFileDataSeeker(); d != nil {
		t.Errorf("newHostFileDataSeeker returned %v for a closed file, want nil", d)
	}
}

func TestSaveToPreservesContents(t *testing.T) {
	for _, tc := range []struct {
		name          string
		diskBacked    bool
		exclude       bool
		wantCommitted uint64
	}{
		{name: "memfd", wantCommitted: 3 * uint64(hostarch.PageSize)},
		{name: "memfd excluding committed zero pages", exclude: true, wantCommitted: 2 * uint64(hostarch.PageSize)},
		{name: "disk-backed", diskBacked: true, wantCommitted: 3 * uint64(hostarch.PageSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dir string
			if tc.diskBacked {
				dir = t.TempDir()
			}
			f := newSaveTestMemoryFile(t, dir, tc.diskBacked)
			fr := allocateSaveTestPages(t, f)
			pwritePage(t, f, fr, 2, 1)
			pwritePage(t, f, fr, 13, 2)
			if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{}); err != nil {
				t.Fatalf("first SaveTo: %v", err)
			}
			pwritePage(t, f, fr, 9, 0)
			pwritePage(t, f, fr, 13, 0)
			writeMappedPage(f, fr, 5, 3)
			want := make([]byte, fr.Length())
			want[2*hostarch.PageSize+17] = 1
			want[5*hostarch.PageSize+17] = 3

			var checkpoint bytes.Buffer
			if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{ExcludeCommittedZeroPages: tc.exclude}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}
			if got := f.knownCommittedBytes; got != tc.wantCommitted {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, tc.wantCommitted)
			}

			restored := newSaveTestMemoryFile(t, dir, tc.diskBacked)
			if err := restored.LoadFrom(context.Background(), &checkpoint, &LoadOpts{}); err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			t.Cleanup(func() { restored.DecRef(fr) })
			restored.forEachMappingSlice(fr, func(bs []byte) {
				if !bytes.Equal(bs, want) {
					t.Error("restored contents differ from saved contents")
				}
			})
		})
	}
}

func TestAsyncSaveToPreservesContents(t *testing.T) {
	for _, tc := range []struct {
		name          string
		diskBacked    bool
		exclude       bool
		wantCommitted uint64
	}{
		{name: "memfd", wantCommitted: 2 * uint64(hostarch.PageSize)},
		{name: "memfd excluding committed zero pages", exclude: true, wantCommitted: uint64(hostarch.PageSize)},
		{name: "disk-backed", diskBacked: true, wantCommitted: 2 * uint64(hostarch.PageSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dir string
			if tc.diskBacked {
				dir = t.TempDir()
			}
			f := newSaveTestMemoryFile(t, dir, tc.diskBacked)
			fr := allocateSaveTestPages(t, f)
			pwritePage(t, f, fr, 2, 1)
			pwritePage(t, f, fr, 13, 2)

			save := func(exclude bool) ([]byte, []byte) {
				var metadata bytes.Buffer
				var pages bytes.Buffer
				saveDone := make(chan error, 1)
				apfs, err := StartAsyncPagesFileSave(
					stateio.NewIOWriter(&pages, uint64(hostarch.PageSize), 1 /* maxRanges */, 2 /* maxParallel */),
					func(err error) { saveDone <- err },
				)
				if err != nil {
					t.Fatalf("StartAsyncPagesFileSave: %v", err)
				}
				saveErr := f.SaveTo(context.Background(), &metadata, &SaveOpts{
					ExcludeCommittedZeroPages: exclude,
					PagesFile:                 apfs,
				})
				apfs.MemoryFilesDone()
				asyncErr := <-saveDone
				if saveErr != nil {
					t.Fatalf("SaveTo: %v", saveErr)
				}
				if asyncErr != nil {
					t.Fatalf("asynchronous page save: %v", asyncErr)
				}
				if got, want := uint64(pages.Len()), f.knownCommittedBytes; got != want {
					t.Fatalf("pages file length is %d, want %d", got, want)
				}
				return metadata.Bytes(), pages.Bytes()
			}

			save(false)
			pwritePage(t, f, fr, 9, 0)
			pwritePage(t, f, fr, 13, 0)
			want := make([]byte, fr.Length())
			want[2*hostarch.PageSize+17] = 1
			metadata, pages := save(tc.exclude)
			if got := f.knownCommittedBytes; got != tc.wantCommitted {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, tc.wantCommitted)
			}

			restored := newSaveTestMemoryFile(t, dir, tc.diskBacked)
			loadDone := make(chan error, 1)
			apfl, err := StartAsyncPagesFileLoad(
				stateio.NewIOReader(bytes.NewReader(pages), uint64(hostarch.PageSize), 1 /* maxRanges */, 2 /* maxParallel */),
				func(err error) { loadDone <- err },
				nil,
				AsyncPagesFileLoadOpts{},
			)
			if err != nil {
				t.Fatalf("StartAsyncPagesFileLoad: %v", err)
			}
			loadErr := restored.LoadFrom(context.Background(), bytes.NewReader(metadata), &LoadOpts{PagesFile: apfl})
			apfl.MemoryFilesDone()
			asyncErr := <-loadDone
			if loadErr != nil {
				t.Fatalf("LoadFrom: %v", loadErr)
			}
			if asyncErr != nil {
				t.Fatalf("asynchronous page load: %v", asyncErr)
			}
			t.Cleanup(func() { restored.DecRef(fr) })
			restored.forEachMappingSlice(fr, func(bs []byte) {
				if !bytes.Equal(bs, want) {
					t.Error("restored contents differ from saved contents")
				}
			})
		})
	}
}

// TestSaveToExitAfterSaving checks that SaveTo leaves zero pages that are
// committed on the host in place only if the sentry exits after saving.
func TestSaveToExitAfterSaving(t *testing.T) {
	for _, tc := range []struct {
		name            string
		exitAfterSaving bool
		wantDecommitted bool
	}{
		{name: "resume", wantDecommitted: true},
		{name: "exit after saving", exitAfterSaving: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSaveTestMemoryFile(t, "", false)
			fr := allocateSaveTestPages(t, f)
			pwritePage(t, f, fr, 2, 1)
			pwritePage(t, f, fr, 5, 0)
			if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{ExitAfterSaving: tc.exitAfterSaving}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}
			if got, want := f.knownCommittedBytes, uint64(hostarch.PageSize); got != want {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, want)
			}
			off := int64(fr.Start) + 5*int64(hostarch.PageSize)
			data, err := unix.Seek(f.FD(), off, unix.SEEK_DATA)
			if err != nil && err != unix.ENXIO {
				t.Fatalf("lseek(SEEK_DATA): %v", err)
			}
			if decommitted := err == unix.ENXIO || data != off; decommitted != tc.wantDecommitted {
				t.Errorf("zero page decommitted: got %t, want %t", decommitted, tc.wantDecommitted)
			}
		})
	}
}

// BenchmarkSaveToCommittedZeroPages measures SaveTo for a 256 MiB MemoryFile
// whose pages are all committed, with one of every 16 pages nonzero.
func BenchmarkSaveToCommittedZeroPages(b *testing.B) {
	const size = 256 << 20
	for _, bc := range []struct {
		name            string
		exitAfterSaving bool
	}{
		{name: "resume"},
		{name: "exit-after-saving", exitAfterSaving: true},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.SetBytes(size)
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				fd, err := memutil.CreateMemFD("pgalloc-save-bench", 0)
				if err != nil {
					b.Fatalf("CreateMemFD: %v", err)
				}
				f, err := NewMemoryFile(os.NewFile(uintptr(fd), "pgalloc-save-bench"), MemoryFileOpts{
					DelayedEviction:         DelayedEvictionDisabled,
					DisableMemoryAccounting: true,
				})
				if err != nil {
					b.Fatalf("NewMemoryFile: %v", err)
				}
				fr, err := f.Allocate(size, AllocOpts{Mode: AllocateUncommitted})
				if err != nil {
					b.Fatalf("Allocate: %v", err)
				}
				page := 0
				f.forEachMappingSlice(fr, func(bs []byte) {
					for off := 0; off < len(bs); off += hostarch.PageSize {
						if page%16 == 0 {
							bs[off] = 1
						} else {
							bs[off] = 0
						}
						page++
					}
				})
				b.StartTimer()
				if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{ExitAfterSaving: bc.exitAfterSaving}); err != nil {
					b.Fatalf("SaveTo: %v", err)
				}
				b.StopTimer()
				f.DecRef(fr)
				f.Destroy()
			}
		})
	}
}

// BenchmarkSaveToDiskBacked measures SaveTo for a 256 MiB disk-backed
// MemoryFile with 1% or all of its pages written through its mapping.
func BenchmarkSaveToDiskBacked(b *testing.B) {
	const size = 256 << 20
	pages := size / hostarch.PageSize
	dir := b.TempDir()
	for _, bc := range []struct {
		file    string
		dir     string
		percent int
	}{
		{file: "memfd", percent: 1},
		{file: "memfd", percent: 100},
		{file: "tempdir", dir: dir, percent: 1},
		{file: "tempdir", dir: dir, percent: 100},
	} {
		b.Run(fmt.Sprintf("file=%s/written=%dpct", bc.file, bc.percent), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				file := openSaveTestFile(b, bc.dir)
				f, err := NewMemoryFile(file, MemoryFileOpts{
					DelayedEviction:         DelayedEvictionDisabled,
					DisableMemoryAccounting: true,
					DiskBackedFile:          true,
					DecommitOnDestroy:       true,
				})
				if err != nil {
					b.Fatalf("NewMemoryFile: %v", err)
				}
				fr, err := f.Allocate(size, AllocOpts{Mode: AllocateUncommitted})
				if err != nil {
					b.Fatalf("Allocate: %v", err)
				}
				for page := 0; page < pages; page += 100 / bc.percent {
					writeMappedPage(f, fr, page, 1)
				}
				b.StartTimer()
				if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{}); err != nil {
					b.Fatalf("SaveTo: %v", err)
				}
				b.StopTimer()
				f.DecRef(fr)
				f.Destroy()
			}
		})
	}
}
