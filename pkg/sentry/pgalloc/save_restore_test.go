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
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

func newSaveTestMemoryFile(t *testing.T, diskBacked bool) *MemoryFile {
	t.Helper()
	return newSaveTestMemoryFileOpts(t, diskBacked, false /* expectHugepages */)
}

func newSaveTestMemoryFileOpts(t *testing.T, diskBacked, expectHugepages bool) *MemoryFile {
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
		ExpectHugepages:         expectHugepages,
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
	return allocateSaveTestPagesN(t, f, 16)
}

func allocateSaveTestPagesN(t *testing.T, f *MemoryFile, pages uint64) memmap.FileRange {
	t.Helper()
	fr, err := f.Allocate(pages*uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted})
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

// hostDataIn returns true if any part of fr is allocated in the host file fd.
func hostDataIn(fd int, fr memmap.FileRange) (bool, error) {
	off, err := unix.Seek(fd, int64(fr.Start), unix.SEEK_DATA)
	if err == unix.ENXIO {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lseek(SEEK_DATA, %#x): %w", fr.Start, err)
	}
	return uint64(off) < fr.End, nil
}

// hasHostData returns true if any part of fr is allocated in f's file.
func hasHostData(t *testing.T, f *MemoryFile, fr memmap.FileRange) bool {
	t.Helper()
	ok, err := hostDataIn(f.FD(), fr)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// setReleaseBatchBytes sets apsReleaseBatchBytes to n for the duration of the
// test. Tests calling setReleaseBatchBytes must not run in parallel.
func setReleaseBatchBytes(t *testing.T, n uint64) {
	old := apsReleaseBatchBytes
	apsReleaseBatchBytes = n
	t.Cleanup(func() { apsReleaseBatchBytes = old })
}

// allocateSaveTestRange allocates length bytes from f with the given options.
func allocateSaveTestRange(t *testing.T, f *MemoryFile, length uint64, opts AllocOpts) memmap.FileRange {
	t.Helper()
	fr, err := f.Allocate(length, opts)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	t.Cleanup(func() { f.DecRef(fr) })
	return fr
}

// isSkippedSaveTestPage returns true if fillSaveTestPages leaves page i zero.
func isSkippedSaveTestPage(i uint64) bool {
	return i%5 == 3
}

// fillSaveTestPages writes distinct contents to the first pages pages of fr,
// except for pages for which isSkippedSaveTestPage returns true, so that
// saved ranges are not all contiguous. It returns the expected contents of
// fr.
func fillSaveTestPages(t *testing.T, f *MemoryFile, fr memmap.FileRange, pages uint64) []byte {
	t.Helper()
	want := make([]byte, fr.Length())
	for i := uint64(0); i < pages; i++ {
		if isSkippedSaveTestPage(i) {
			continue
		}
		pwritePage(t, f, fr, int(i), byte(i+1))
		want[i*hostarch.PageSize+17] = byte(i + 1)
	}
	return want
}

// checkSaveTestContents checks that the contents of fr in f are want.
func checkSaveTestContents(t *testing.T, f *MemoryFile, fr memmap.FileRange, want []byte, desc string) {
	t.Helper()
	off := 0
	f.forEachMappingSlice(fr, func(bs []byte) {
		if !bytes.Equal(bs, want[off:off+len(bs)]) {
			t.Errorf("%s: contents of %v differ from expected contents", desc, memmap.FileRange{Start: fr.Start + uint64(off), End: fr.Start + uint64(off+len(bs))})
		}
		off += len(bs)
	})
}

// writeObserver wraps a stateio.AsyncWriter, calling onWrite with the source
// mappings of each enqueued write before enqueueing it.
type writeObserver struct {
	stateio.AsyncWriter
	onWrite func(srcMaps []unix.Iovec)
}

// AddWrite implements stateio.AsyncWriter.AddWrite.
func (w *writeObserver) AddWrite(id int, srcFile stateio.SourceFile, srcFR memmap.FileRange, srcMap []byte) {
	w.onWrite([]unix.Iovec{{Base: &srcMap[0], Len: uint64(len(srcMap))}})
	w.AsyncWriter.AddWrite(id, srcFile, srcFR, srcMap)
}

// AddWritev implements stateio.AsyncWriter.AddWritev.
func (w *writeObserver) AddWritev(id int, total uint64, srcFile stateio.SourceFile, srcFRs []memmap.FileRange, srcMaps []unix.Iovec) {
	w.onWrite(srcMaps)
	w.AsyncWriter.AddWritev(id, total, srcFile, srcFRs, srcMaps)
}

func TestSaveToPagesFileReleaseAfterWrite(t *testing.T) {
	// Use a small release batch size so that saving releases pages in many
	// batches.
	setReleaseBatchBytes(t, 16*hostarch.PageSize)
	for _, tc := range []struct {
		name       string
		release    bool
		diskBacked bool
		huge       bool
		// If excludeZero is true, pages not written by fillSaveTestPages
		// are committed zero pages, and SaveOpts.ExcludeCommittedZeroPages
		// is set, such that they are not saved.
		excludeZero bool
	}{
		{name: "keep"},
		{name: "keep with huge pages", huge: true},
		{name: "release", release: true},
		{name: "release with huge pages", release: true, huge: true},
		{name: "release disk-backed", release: true, diskBacked: true},
		{name: "release excluding committed zero pages", release: true, excludeZero: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Write to a range that spans several huge pages and doesn't end
			// on a huge page boundary, so that releasing must handle partial
			// huge pages.
			pages := uint64(4*(hostarch.HugePageSize/hostarch.PageSize) + 64)
			length := pages * hostarch.PageSize
			if tc.huge {
				length = hostarch.MustHugePageRoundUp(length)
			}
			f := newSaveTestMemoryFileOpts(t, tc.diskBacked, tc.huge /* expectHugepages */)
			allocOpts := AllocOpts{Mode: AllocateUncommitted, Huge: tc.huge}
			if tc.excludeZero {
				allocOpts.Mode = AllocateAndCommit
			}
			fr := allocateSaveTestRange(t, f, length, allocOpts)
			want := fillSaveTestPages(t, f, fr, pages)
			if tc.excludeZero {
				// Write zeroes to skipped pages so that they have host data,
				// which releasing should free even though they aren't saved.
				for i := uint64(0); i < pages; i++ {
					if isSkippedSaveTestPage(i) {
						pwritePage(t, f, fr, int(i), 0)
					}
				}
			}

			// Save a second MemoryFile to the same pages file, as
			// Kernel.SaveTo() does for private MemoryFiles.
			f2 := newSaveTestMemoryFile(t, tc.diskBacked)
			fr2 := allocateSaveTestPages(t, f2)
			want2 := fillSaveTestPages(t, f2, fr2, fr2.Length()/hostarch.PageSize)

			// When the write containing the last written page of f is
			// enqueued, record whether the first huge page of f still has
			// host data. Since writes for f are enqueued in increasing order
			// of offset, and only a few writes can be inflight at a time, the
			// first huge page must have been released by then if releasing
			// happens during saving rather than at the end.
			lastPage := pages - 1
			for isSkippedSaveTestPage(lastPage) {
				lastPage--
			}
			var lastPageAddr uintptr
			f.forEachMappingSlice(memmap.FileRange{Start: fr.Start + lastPage*hostarch.PageSize, End: fr.Start + (lastPage+1)*hostarch.PageSize}, func(bs []byte) {
				lastPageAddr = uintptr(unsafe.Pointer(&bs[0]))
			})
			firstHugePage := memmap.FileRange{Start: fr.Start, End: fr.Start + hostarch.HugePageSize}
			fd := f.FD()
			var (
				// These are accessed by the async page saver goroutine, and
				// then by the test goroutine after saveDone is received from.
				sawLastPage      bool
				firstHasDataLate bool
				firstErr         error
			)
			onWrite := func(srcMaps []unix.Iovec) {
				for _, iov := range srcMaps {
					start := uintptr(unsafe.Pointer(iov.Base))
					if start <= lastPageAddr && lastPageAddr < start+uintptr(iov.Len) {
						sawLastPage = true
						firstHasDataLate, firstErr = hostDataIn(fd, firstHugePage)
					}
				}
			}

			// Use small writes and several parallel operations so that
			// saving involves many operations.
			var pagesFile bytes.Buffer
			aw := &writeObserver{
				AsyncWriter: stateio.NewIOWriter(&pagesFile, 16*uint64(hostarch.PageSize), 16 /* maxRanges */, 4 /* maxParallel */),
				onWrite:     onWrite,
			}
			saveDone := make(chan error, 1)
			apfs, err := StartAsyncPagesFileSave(aw, func(err error) { saveDone <- err })
			if err != nil {
				t.Fatalf("StartAsyncPagesFileSave: %v", err)
			}
			var metadata bytes.Buffer
			saveOpts := SaveOpts{
				PagesFile:                 apfs,
				ExcludeCommittedZeroPages: tc.excludeZero,
				ReleaseAfterWrite:         tc.release,
			}
			err = f.SaveTo(context.Background(), &metadata, &saveOpts)
			if err == nil {
				err = f2.SaveTo(context.Background(), &metadata, &saveOpts)
			}
			apfs.MemoryFilesDone()
			if saveErr := <-saveDone; saveErr != nil {
				t.Fatalf("async page saving: %v", saveErr)
			}
			if err != nil {
				t.Fatalf("SaveTo: %v", err)
			}

			if !sawLastPage {
				t.Fatalf("no write contained the last written page")
			}
			if firstErr != nil {
				t.Fatalf("checking host data during saving: %v", firstErr)
			}
			if firstHasDataLate == tc.release {
				t.Errorf("when the last page was enqueued for writing: first huge page has host data: %t, want %t", firstHasDataLate, !tc.release)
			}
			if got := hasHostData(t, f, fr); got == tc.release {
				t.Errorf("after saving: first MemoryFile has host data: %t, want %t", got, !tc.release)
			}
			if got := hasHostData(t, f2, fr2); got == tc.release {
				t.Errorf("after saving: second MemoryFile has host data: %t, want %t", got, !tc.release)
			}
			if !tc.release {
				checkSaveTestContents(t, f, fr, want, "first MemoryFile after saving")
				checkSaveTestContents(t, f2, fr2, want2, "second MemoryFile after saving")
			}

			restored := newSaveTestMemoryFileOpts(t, false /* diskBacked */, tc.huge /* expectHugepages */)
			restored2 := newSaveTestMemoryFile(t, false /* diskBacked */)
			ar := stateio.NewIOReader(bytes.NewReader(pagesFile.Bytes()), 16*uint64(hostarch.PageSize), 16 /* maxRanges */, 4 /* maxParallel */)
			loadDone := make(chan error, 1)
			apfl, err := StartAsyncPagesFileLoad(ar, func(err error) { loadDone <- err }, nil /* timeline */, AsyncPagesFileLoadOpts{})
			if err != nil {
				t.Fatalf("StartAsyncPagesFileLoad: %v", err)
			}
			loadOpts := LoadOpts{PagesFile: apfl}
			err = restored.LoadFrom(context.Background(), &metadata, &loadOpts)
			if err == nil {
				t.Cleanup(func() { restored.DecRef(fr) })
				err = restored2.LoadFrom(context.Background(), &metadata, &loadOpts)
				if err == nil {
					t.Cleanup(func() { restored2.DecRef(fr2) })
				}
			}
			apfl.MemoryFilesDone()
			if loadErr := <-loadDone; loadErr != nil {
				t.Fatalf("async page loading: %v", loadErr)
			}
			if err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			checkSaveTestContents(t, restored, fr, want, "first restored MemoryFile")
			checkSaveTestContents(t, restored2, fr2, want2, "second restored MemoryFile")
		})
	}
}

// writtenPages returns a FileRange spanning n pages starting at page pg of
// huge page hp of fr.
func writtenPages(fr memmap.FileRange, hp, pg, n uint64) memmap.FileRange {
	start := fr.Start + hp*hostarch.HugePageSize + pg*hostarch.PageSize
	return memmap.FileRange{Start: start, End: start + n*hostarch.PageSize}
}

// enqueueTestWrite simulates enqueueing a write of total bytes for amfs that
// ends at offset end, and returns its index in apfs.written.
func enqueueTestWrite(apfs *AsyncPagesFileSave, amfs *asyncMemoryFileSave, end, total uint64) int {
	apfs.written = append(apfs.written, apsWritten{amfs: amfs, end: end, total: total})
	return len(apfs.written) - 1
}

func TestReleaseAfterWriteWatermark(t *testing.T) {
	f := newSaveTestMemoryFile(t, false /* diskBacked */)
	fr := allocateSaveTestPages(t, f)
	for i := 0; i < 8; i++ {
		pwritePage(t, f, fr, i, 1)
	}
	apfs := &AsyncPagesFileSave{}
	amfs := &asyncMemoryFileSave{f: f, pf: apfs, releaseAfterWrite: true}
	// The first write saves pages [0, 2), and the second write saves pages
	// [3, 6). Page 2 represents a page that was not saved (e.g. a committed
	// zero page with SaveOpts.ExcludeCommittedZeroPages), which should be
	// released along with the saved pages around it.
	w0 := enqueueTestWrite(apfs, amfs, writtenPages(fr, 0, 2, 0).Start, 2*hostarch.PageSize)
	w1 := enqueueTestWrite(apfs, amfs, writtenPages(fr, 0, 6, 0).Start, 3*hostarch.PageSize)

	// The second write completing first must not release anything, since
	// the first write is still inflight.
	apfs.written[w1].done = true
	apfs.advanceWritten()
	if amfs.doneUpTo != 0 || apfs.releasableBytes != 0 {
		t.Errorf("after out-of-order completion: doneUpTo = %#x, releasableBytes = %d, want 0, 0", amfs.doneUpTo, apfs.releasableBytes)
	}
	apfs.releaseWritten(false /* final */)
	if apfs.releaseCalls != 0 || !hasHostData(t, f, writtenPages(fr, 0, 3, 3)) {
		t.Errorf("pages released before preceding write completed")
	}

	// Once the first write completes, all pages before the end of the second
	// write, including the unsaved page 2, are released in one syscall.
	apfs.written[w0].done = true
	apfs.advanceWritten()
	if len(apfs.written) != 0 || apfs.writtenHead != 2 {
		t.Errorf("after all completions: len(written) = %d, writtenHead = %d, want 0, 2", len(apfs.written), apfs.writtenHead)
	}
	if want := writtenPages(fr, 0, 6, 0).Start; amfs.doneUpTo != want {
		t.Errorf("doneUpTo = %#x, want %#x", amfs.doneUpTo, want)
	}
	if want := 5 * hostarch.PageSize; apfs.releasableBytes != uint64(want) {
		t.Errorf("releasableBytes = %d, want %d", apfs.releasableBytes, want)
	}
	apfs.releaseWritten(false /* final */)
	if hasHostData(t, f, writtenPages(fr, 0, 0, 6)) {
		t.Errorf("pages [0, 6) were not released")
	}
	if !hasHostData(t, f, writtenPages(fr, 0, 6, 2)) {
		t.Errorf("pages [6, 8) were released before being written")
	}
	if apfs.releaseCalls != 1 || len(apfs.releasing) != 0 || amfs.inReleasing {
		t.Errorf("releaseCalls = %d, len(releasing) = %d, inReleasing = %t, want 1, 0, false", apfs.releaseCalls, len(apfs.releasing), amfs.inReleasing)
	}

	// A subsequent write releases only pages after those already released.
	w2 := enqueueTestWrite(apfs, amfs, writtenPages(fr, 0, 8, 0).Start, 2*hostarch.PageSize)
	apfs.written[w2].done = true
	apfs.advanceWritten()
	apfs.releaseWritten(false /* final */)
	if hasHostData(t, f, writtenPages(fr, 0, 0, 8)) {
		t.Errorf("pages [0, 8) were not released")
	}
	if want := uint64(8 * hostarch.PageSize); apfs.releaseCalls != 2 || apfs.releasedBytes != fr.Start+want {
		t.Errorf("releaseCalls = %d, releasedBytes = %#x, want 2, %#x", apfs.releaseCalls, apfs.releasedBytes, fr.Start+want)
	}
}

func TestReleaseAfterWriteHugePages(t *testing.T) {
	f := newSaveTestMemoryFileOpts(t, false /* diskBacked */, true /* expectHugepages */)
	fr := allocateSaveTestRange(t, f, 3*hostarch.HugePageSize, AllocOpts{Mode: AllocateUncommitted, Huge: true})
	if !hostarch.IsHugePageAligned(fr.Start) {
		t.Fatalf("huge allocation %v is not huge page-aligned", fr)
	}
	hp0 := writtenPages(fr, 0, 0, 1)
	hp1a := writtenPages(fr, 1, 0, 1)
	hp1b := writtenPages(fr, 1, 5, 1)
	for _, r := range []memmap.FileRange{hp0, hp1a, hp1b} {
		pwritePage(t, f, r, 0, 1)
	}
	apfs := &AsyncPagesFileSave{}
	amfs := &asyncMemoryFileSave{f: f, pf: apfs, releaseAfterWrite: true}
	checkData := func(r memmap.FileRange, want bool) {
		t.Helper()
		if got := hasHostData(t, f, r); got != want {
			t.Errorf("range %v: has host data = %t, want %t", r, got, want)
		}
	}
	complete := func(end uint64) {
		t.Helper()
		apfs.written[enqueueTestWrite(apfs, amfs, end, hostarch.PageSize)].done = true
		apfs.advanceWritten()
	}

	// A write ending partway through huge page 1 releases huge page 0, but
	// not the written part of huge page 1, since further writes may complete
	// within it.
	complete(hp1a.End)
	apfs.releaseWritten(false /* final */)
	checkData(hp0, false)
	checkData(hp1a, true)
	if !amfs.inReleasing || len(apfs.releasing) != 1 {
		t.Errorf("inReleasing = %t, len(releasing) = %d, want true, 1", amfs.inReleasing, len(apfs.releasing))
	}

	// Another write within huge page 1 doesn't release anything, or make a
	// syscall.
	complete(hp1b.End)
	apfs.releaseWritten(false /* final */)
	checkData(hp1a, true)
	checkData(hp1b, true)
	if apfs.releaseCalls != 1 {
		t.Errorf("releaseCalls = %d, want 1", apfs.releaseCalls)
	}

	// The final release includes the partial huge page.
	apfs.releaseWritten(true /* final */)
	checkData(hp1a, false)
	checkData(hp1b, false)
	if apfs.releaseCalls != 2 || amfs.inReleasing || len(apfs.releasing) != 0 {
		t.Errorf("after final release: releaseCalls = %d, inReleasing = %t, len(releasing) = %d, want 2, false, 0", apfs.releaseCalls, amfs.inReleasing, len(apfs.releasing))
	}
}

func TestReleaseAfterWriteDecommitFailure(t *testing.T) {
	f := newSaveTestMemoryFile(t, false /* diskBacked */)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 0, 1)
	apfs := &AsyncPagesFileSave{}
	amfs := &asyncMemoryFileSave{f: f, pf: apfs, releaseAfterWrite: true}

	// fallocate(2) fails with EINVAL for negative lengths, which this
	// release has when converted to int64.
	apfs.written[enqueueTestWrite(apfs, amfs, 1<<63, hostarch.PageSize)].done = true
	apfs.advanceWritten()
	apfs.releaseWritten(false /* final */)
	if amfs.releaseAfterWrite {
		t.Fatalf("releaseAfterWrite is still set after decommit failure")
	}
	if amfs.inReleasing || len(apfs.releasing) != 0 {
		t.Errorf("inReleasing = %t, len(releasing) = %d, want false, 0", amfs.inReleasing, len(apfs.releasing))
	}

	// Releasing is disabled for the MemoryFile after the failure.
	apfs.written[enqueueTestWrite(apfs, amfs, writtenPages(fr, 0, 1, 0).Start, hostarch.PageSize)].done = true
	apfs.advanceWritten()
	apfs.releaseWritten(true /* final */)
	if good := writtenPages(fr, 0, 0, 1); !hasHostData(t, f, good) {
		t.Errorf("range %v released after decommit failure disabled releasing", good)
	}
}
