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
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

func newSaveTestMemoryFile(t *testing.T, diskBacked bool) *MemoryFile {
	t.Helper()
	var file *os.File
	if diskBacked {
		var err error
		if file, err = os.CreateTemp(t.TempDir(), "pgalloc-save-test"); err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
	} else {
		fd, err := memutil.CreateMemFD("pgalloc-save-test", 0)
		if err != nil {
			t.Fatalf("CreateMemFD: %v", err)
		}
		file = os.NewFile(uintptr(fd), "pgalloc-save-test")
	}
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

func pwritePage(t *testing.T, f *MemoryFile, fr memmap.FileRange, page int, b byte) {
	t.Helper()
	buf := make([]byte, hostarch.PageSize)
	buf[17] = b
	if _, err := unix.Pwrite(f.FD(), buf, int64(fr.Start)+int64(page*int(hostarch.PageSize))); err != nil {
		t.Fatalf("Pwrite page %d: %v", page, err)
	}
}

func TestHostFileDataSeeker(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 2, 1)
	pwritePage(t, f, fr, 3, 1)
	pwritePage(t, f, fr, 9, 1)
	pwritePage(t, f, fr, 12, 0)
	page := func(n uint64) uint64 { return fr.Start + n*uint64(hostarch.PageSize) }
	d := f.newHostFileDataSeeker()
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
}

func TestSaveToPreservesContents(t *testing.T) {
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
			f := newSaveTestMemoryFile(t, tc.diskBacked)
			fr := allocateSaveTestPages(t, f)
			pwritePage(t, f, fr, 2, 1)
			pwritePage(t, f, fr, 13, 2)
			if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{}); err != nil {
				t.Fatalf("first SaveTo: %v", err)
			}
			pwritePage(t, f, fr, 9, 0)
			pwritePage(t, f, fr, 13, 0)
			want := make([]byte, fr.Length())
			want[2*hostarch.PageSize+17] = 1

			var checkpoint bytes.Buffer
			if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{ExcludeCommittedZeroPages: tc.exclude}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}
			if got := f.knownCommittedBytes; got != tc.wantCommitted {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, tc.wantCommitted)
			}

			restored := newSaveTestMemoryFile(t, tc.diskBacked)
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
			f := newSaveTestMemoryFile(t, tc.diskBacked)
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

			restored := newSaveTestMemoryFile(t, tc.diskBacked)
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
			f := newSaveTestMemoryFile(t, false)
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

// countingAsyncReader counts reads started on an AsyncReader.
type countingAsyncReader struct {
	stateio.AsyncReader
	reads atomicbitops.Int32
}

func (r *countingAsyncReader) AddRead(id int, off int64, dstFile stateio.DestinationFile, dstFR memmap.FileRange, dstMap []byte) {
	r.reads.Add(1)
	r.AsyncReader.AddRead(id, off, dstFile, dstFR, dstMap)
}

func (r *countingAsyncReader) AddReadv(id int, off int64, total uint64, dstFile stateio.DestinationFile, dstFRs []memmap.FileRange, dstMaps []unix.Iovec) {
	r.reads.Add(1)
	r.AsyncReader.AddReadv(id, off, total, dstFile, dstFRs, dstMaps)
}

// TestAsyncPageLoadLazy checks that lazy loading reads only awaited pages, and
// that AwaitLoadAll loads the remaining pages.
func TestAsyncPageLoadLazy(t *testing.T) {
	const pages = 16
	pageSize := uint64(hostarch.PageSize)
	f := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, f)
	for i := range pages {
		pwritePage(t, f, fr, i, byte(i+1))
	}
	var data, meta bytes.Buffer
	saveDone := make(chan error, 1)
	apfs, err := StartAsyncPagesFileSave(stateio.NewIOWriter(&data, pageSize, 1, 1), func(err error) { saveDone <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	if err := f.SaveTo(context.Background(), &meta, &SaveOpts{PagesFile: apfs}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	apfs.MemoryFilesDone()
	if err := <-saveDone; err != nil {
		t.Fatalf("async page save: %v", err)
	}

	// Each read is one page, so the number of reads is the number of pages read.
	r := &countingAsyncReader{AsyncReader: stateio.NewIOReader(bytes.NewReader(data.Bytes()), pageSize, 1, 4)}
	loadDone := make(chan error, 1)
	apfl, err := StartAsyncPagesFileLoad(r, func(err error) { loadDone <- err }, nil, AsyncPagesFileLoadOpts{Lazy: true})
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad: %v", err)
	}
	rf := newSaveTestMemoryFile(t, false)
	if err := rf.LoadFrom(context.Background(), bytes.NewReader(meta.Bytes()), &LoadOpts{PagesFile: apfl}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	apfl.MemoryFilesDone()

	// Give the loader time to start reads that it should not start.
	time.Sleep(50 * time.Millisecond)
	if got := r.reads.Load(); got != 0 {
		t.Fatalf("got %d reads before any page is awaited, want 0", got)
	}
	amfl := rf.asyncPageLoad.Load()
	if amfl == nil {
		t.Fatal("async page load completed before any page was awaited")
	}
	if err := amfl.awaitLoad(memmap.FileRange{fr.Start + 3*pageSize, fr.Start + 4*pageSize}); err != nil {
		t.Fatalf("awaitLoad: %v", err)
	}
	if got := r.reads.Load(); got != 1 {
		t.Fatalf("got %d reads after one page is awaited, want 1", got)
	}
	select {
	case err := <-loadDone:
		t.Fatalf("async page load completed with unloaded pages: %v", err)
	default:
	}

	if err := rf.AwaitLoadAll(); err != nil {
		t.Fatalf("AwaitLoadAll: %v", err)
	}
	select {
	case err := <-loadDone:
		if err != nil {
			t.Fatalf("async page load: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for async page load to complete")
	}
	if got := r.reads.Load(); got != pages {
		t.Errorf("got %d reads in total, want %d", got, pages)
	}
	buf := make([]byte, pageSize)
	for i := range pages {
		if _, err := unix.Pread(rf.FD(), buf, int64(fr.Start+uint64(i)*pageSize)); err != nil {
			t.Fatalf("Pread page %d: %v", i, err)
		}
		if got, want := buf[17], byte(i+1); got != want {
			t.Errorf("page %d: got %d, want %d", i, got, want)
		}
	}
}
