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
	"fmt"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
)

const decommitTestTimeout = 10 * time.Second

// decommitTestReader is an io.ReaderAt that records the offset of each read.
// If gated, it reports the start of each read on started and blocks reads
// until release is closed; otherwise, it delays each read by a random duration
// of up to maxDelay. Reads at failOff fail.
type decommitTestReader struct {
	r        *bytes.Reader
	failOff  int64
	gated    bool
	maxDelay time.Duration
	started  chan int64
	release  chan struct{}

	mu   sync.Mutex
	rng  *rand.Rand
	offs []int64
}

func (d *decommitTestReader) ReadAt(b []byte, off int64) (int, error) {
	d.mu.Lock()
	d.offs = append(d.offs, off)
	var delay time.Duration
	if !d.gated {
		delay = time.Duration(d.rng.Int63n(int64(d.maxDelay)))
	}
	d.mu.Unlock()
	if d.gated {
		d.started <- off
		<-d.release
	} else {
		time.Sleep(delay)
	}
	if off == d.failOff {
		return 0, errors.New("injected read failure")
	}
	return d.r.ReadAt(b, off)
}

func (d *decommitTestReader) readOffsets() []int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]int64(nil), d.offs...)
}

// decommitTestOpts configures startDecommitTestLoadOpts.
type decommitTestOpts struct {
	numFiles     int
	pages        int
	failOff      int64
	gated        bool
	maxDelay     time.Duration
	seed         int64
	maxReadPages int
	maxParallel  int
}

// decommitTestLoad is an async load of one or more MemoryFiles, each
// containing the same number of pages, from a single pages file. Every byte of
// page i of each MemoryFile is initially i+1, and page i of MemoryFile j is at
// offset (pages*j+i)*PageSize in the pages file.
type decommitTestLoad struct {
	r    *decommitTestReader
	fs   []*MemoryFile
	frs  []memmap.FileRange
	done chan error
}

// startDecommitTestLoad starts an async load of numFiles MemoryFiles of 16
// pages each, read one page at a time with one read in flight, by a gated
// reader.
func startDecommitTestLoad(t *testing.T, numFiles int, failOff int64) *decommitTestLoad {
	return startDecommitTestLoadOpts(t, decommitTestOpts{
		numFiles:     numFiles,
		pages:        16,
		failOff:      failOff,
		gated:        true,
		maxReadPages: 1,
		maxParallel:  1,
	})
}

func startDecommitTestLoadOpts(t *testing.T, opts decommitTestOpts) *decommitTestLoad {
	t.Helper()
	var pagesBuf bytes.Buffer
	saveDone := make(chan error, 1)
	apfs, err := StartAsyncPagesFileSave(stateio.NewIOWriter(&pagesBuf, 1<<20, 1, 1), func(err error) { saveDone <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	var metas [][]byte
	var frs []memmap.FileRange
	for range opts.numFiles {
		src := newSaveTestMemoryFile(t, false)
		fr, err := src.Allocate(uint64(opts.pages)*hostarch.PageSize, AllocOpts{Mode: AllocateUncommitted})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		t.Cleanup(func() { src.DecRef(fr) })
		for i := range opts.pages {
			src.forEachMappingSlice(decommitTestPage(fr, i), func(bs []byte) {
				for j := range bs {
					bs[j] = byte(i + 1)
				}
			})
		}
		var metaBuf bytes.Buffer
		if err := src.SaveTo(context.Background(), &metaBuf, &SaveOpts{PagesFile: apfs}); err != nil {
			t.Fatalf("SaveTo: %v", err)
		}
		metas = append(metas, metaBuf.Bytes())
		frs = append(frs, fr)
	}
	apfs.MemoryFilesDone()
	select {
	case err := <-saveDone:
		if err != nil {
			t.Fatalf("async pages file save: %v", err)
		}
	case <-time.After(decommitTestTimeout):
		t.Fatalf("async pages file save did not complete")
	}

	l := &decommitTestLoad{
		r: &decommitTestReader{
			r:        bytes.NewReader(pagesBuf.Bytes()),
			failOff:  opts.failOff,
			gated:    opts.gated,
			maxDelay: opts.maxDelay,
			started:  make(chan int64, opts.numFiles*opts.pages),
			release:  make(chan struct{}),
			rng:      rand.New(rand.NewSource(opts.seed)),
		},
		frs:  frs,
		done: make(chan error, 1),
	}
	ar := stateio.NewIOReader(l.r, uint64(opts.maxReadPages)*hostarch.PageSize, opts.maxReadPages, opts.maxParallel)
	apfl, err := StartAsyncPagesFileLoad(ar, func(err error) { l.done <- err }, nil, AsyncPagesFileLoadOpts{})
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad: %v", err)
	}
	lopts := LoadOpts{PagesFile: apfl}
	for i, meta := range metas {
		f := newSaveTestMemoryFile(t, false)
		if err := f.LoadFrom(context.Background(), bytes.NewReader(meta), &lopts); err != nil {
			t.Fatalf("LoadFrom: %v", err)
		}
		fr := frs[i]
		// Registered after newSaveTestMemoryFile's cleanup, so this runs
		// first. Unblock reads and let async page loading finish before
		// releasing pages.
		t.Cleanup(func() {
			l.releaseReads()
			l.wait(t)
			f.DecRef(fr)
		})
		l.fs = append(l.fs, f)
	}
	apfl.MemoryFilesDone()
	return l
}

func decommitTestPage(fr memmap.FileRange, i int) memmap.FileRange {
	start := fr.Start + uint64(i)*hostarch.PageSize
	return memmap.FileRange{start, start + hostarch.PageSize}
}

func decommitTestPages(fr memmap.FileRange, i, j int) memmap.FileRange {
	return memmap.FileRange{decommitTestPage(fr, i).Start, decommitTestPage(fr, j).Start}
}

func (l *decommitTestLoad) releaseReads() {
	select {
	case <-l.r.release:
	default:
		close(l.r.release)
	}
}

// awaitReadStart waits for a read at the given page index in the pages file
// to start.
func (l *decommitTestLoad) awaitReadStart(t *testing.T, page int) {
	t.Helper()
	select {
	case off := <-l.r.started:
		if want := int64(page) * hostarch.PageSize; off != want {
			t.Fatalf("read started at offset %#x, want %#x", off, want)
		}
	case <-time.After(decommitTestTimeout):
		t.Fatalf("read of page %d did not start", page)
	}
}

// wait waits for async page loading to finish, and returns its error.
func (l *decommitTestLoad) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-l.done:
		// Allow later calls to wait() to observe the same result.
		l.done <- err
		return err
	case <-time.After(decommitTestTimeout):
		t.Fatalf("async page loading did not finish")
		return nil
	}
}

// checkPages checks that page i of l.fs[file] contains either i+1 or 0
// (if decommitted[i]).
func (l *decommitTestLoad) checkPages(t *testing.T, file int, decommitted map[int]bool) {
	t.Helper()
	want := make([]byte, l.frs[file].Length()/hostarch.PageSize)
	for i := range want {
		if !decommitted[i] {
			want[i] = byte(i + 1)
		}
	}
	checkMemoryFilePages(t, l.fs[file], l.frs[file], want)
}

// checkMemoryFilePages checks that every byte of page i of fr in f is want[i].
func checkMemoryFilePages(t *testing.T, f *MemoryFile, fr memmap.FileRange, want []byte) {
	t.Helper()
	for i, w := range want {
		page := decommitTestPage(fr, i)
		if _, err := f.MapInternal(page, hostarch.Read); err != nil {
			t.Fatalf("MapInternal(page %d): %v", i, err)
		}
		f.forEachMappingSlice(page, func(bs []byte) {
			if !bytes.Equal(bs, bytes.Repeat([]byte{w}, len(bs))) {
				t.Errorf("page %d: got bytes %#x..., want %#x", i, bs[:4], w)
			}
		})
	}
}

// writeMemoryFilePage fills page i of fr in f with b, waiting for it to be
// loaded first.
func writeMemoryFilePage(t *testing.T, f *MemoryFile, fr memmap.FileRange, i int, b byte) {
	t.Helper()
	page := decommitTestPage(fr, i)
	if _, err := f.MapInternal(page, hostarch.Write); err != nil {
		t.Fatalf("MapInternal(page %d): %v", i, err)
	}
	f.forEachMappingSlice(page, func(bs []byte) {
		for j := range bs {
			bs[j] = b
		}
	})
}

// checkCommitted checks that f's backing file has the given number of
// committed (allocated) pages.
func checkCommitted(t *testing.T, f *MemoryFile, want int) {
	t.Helper()
	got, err := f.TotalUsage()
	if err != nil {
		t.Fatalf("TotalUsage: %v", err)
	}
	if got != uint64(want)*hostarch.PageSize {
		t.Errorf("TotalUsage: got %d pages, want %d", got/hostarch.PageSize, want)
	}
}

// saveAndRestore saves f synchronously and restores it to a new MemoryFile.
func saveAndRestore(t *testing.T, f *MemoryFile, fr memmap.FileRange) *MemoryFile {
	t.Helper()
	var buf bytes.Buffer
	if err := f.SaveTo(context.Background(), &buf, &SaveOpts{}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	restored := newSaveTestMemoryFile(t, false)
	if err := restored.LoadFrom(context.Background(), &buf, &LoadOpts{}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	t.Cleanup(func() { restored.DecRef(fr) })
	return restored
}

// startDecommit calls f.Decommit(fr) in a new goroutine and returns a channel
// that receives its result.
func startDecommit(f *MemoryFile, fr memmap.FileRange) <-chan error {
	done := make(chan error, 1)
	go func() { done <- f.Decommit(fr) }()
	return done
}

func awaitDecommit(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(decommitTestTimeout):
		t.Fatalf("Decommit did not return")
		return nil
	}
}

// startMapInternal calls f.MapInternal(fr, hostarch.Read) in a new goroutine
// and returns a channel that receives its error.
func startMapInternal(f *MemoryFile, fr memmap.FileRange) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := f.MapInternal(fr, hostarch.Read)
		done <- err
	}()
	return done
}

func expectBlocked(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s returned (%v) before the read of decommitted pages completed", what, err)
	case <-time.After(100 * time.Millisecond):
	}
}

func awaitMapInternal(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("MapInternal: %v", err)
		}
	case <-time.After(decommitTestTimeout):
		t.Fatalf("MapInternal did not return")
	}
}

// TestDecommitCancelsUnstartedLoads checks that Decommit doesn't wait for or
// load unloaded pages whose read hasn't started, and that those pages are
// zero afterwards.
func TestDecommitCancelsUnstartedLoads(t *testing.T) {
	l := startDecommitTestLoad(t, 1, -1)
	f, fr := l.fs[0], l.frs[0]
	l.awaitReadStart(t, 0)

	// Page 0 is being read; pages 4-7 are unstarted.
	if err := awaitDecommit(t, startDecommit(f, decommitTestPages(fr, 4, 8))); err != nil {
		t.Fatalf("Decommit: %v", err)
	}
	l.releaseReads()
	if err := l.wait(t); err != nil {
		t.Fatalf("async page loading failed: %v", err)
	}
	for _, off := range l.r.readOffsets() {
		if page := off / hostarch.PageSize; page >= 4 && page < 8 {
			t.Errorf("decommitted page %d was read", page)
		}
	}
	l.checkPages(t, 0, map[int]bool{4: true, 5: true, 6: true, 7: true})
}

// TestDecommitDuringInflightLoad checks that Decommit doesn't wait for an
// in-flight read of decommitted pages, that accesses to those pages wait for
// the read to complete and observe zeroed pages, and that unstarted reads of
// decommitted pages are still cancelled.
func TestDecommitDuringInflightLoad(t *testing.T) {
	l := startDecommitTestLoad(t, 1, -1)
	f, fr := l.fs[0], l.frs[0]
	l.awaitReadStart(t, 0)

	// Page 0 is being read; pages 1-2 are unstarted.
	if err := awaitDecommit(t, startDecommit(f, decommitTestPages(fr, 0, 3))); err != nil {
		t.Fatalf("Decommit: %v", err)
	}
	mapped := startMapInternal(f, decommitTestPage(fr, 0))
	expectBlocked(t, mapped, "MapInternal")
	l.releaseReads()
	awaitMapInternal(t, mapped)
	if err := l.wait(t); err != nil {
		t.Fatalf("async page loading failed: %v", err)
	}
	for _, off := range l.r.readOffsets() {
		if page := off / hostarch.PageSize; page == 1 || page == 2 {
			t.Errorf("decommitted page %d was read", page)
		}
	}
	l.checkPages(t, 0, map[int]bool{0: true, 1: true, 2: true})
}

// TestDecommitDuringAwaitedLoad checks that Decommit doesn't cancel awaited
// loads of decommitted pages, which would block their waiters forever, and
// that the decommitted pages are zeroed after they are loaded.
func TestDecommitDuringAwaitedLoad(t *testing.T) {
	l := startDecommitTestLoad(t, 1, -1)
	f, fr := l.fs[0], l.frs[0]
	l.awaitReadStart(t, 0)

	// Page 0 is being read. Wait for page 5 in another goroutine.
	page5 := decommitTestPage(fr, 5)
	mapped := startMapInternal(f, page5)
	apfl := f.asyncPageLoad.Load().pf
	for deadline := time.Now().Add(decommitTestTimeout); ; {
		apfl.mu.Lock()
		n := apfl.numWaiters
		apfl.mu.Unlock()
		if n != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("MapInternal did not wait for page 5")
		}
		time.Sleep(time.Millisecond)
	}

	if err := awaitDecommit(t, startDecommit(f, page5)); err != nil {
		t.Fatalf("Decommit: %v", err)
	}
	expectBlocked(t, mapped, "MapInternal")
	l.releaseReads()
	awaitMapInternal(t, mapped)
	if err := l.wait(t); err != nil {
		t.Fatalf("async page loading failed: %v", err)
	}
	l.checkPages(t, 0, map[int]bool{5: true})
}

// TestDecommitFinishesAsyncLoad checks that async page loading of a
// MemoryFile completes when Decommit cancels loading of its remaining
// unloaded pages, even if no read for that MemoryFile is in flight.
func TestDecommitFinishesAsyncLoad(t *testing.T) {
	l := startDecommitTestLoad(t, 2, -1)
	l.awaitReadStart(t, 0)

	// Page 0 of the first MemoryFile is being read; no page of the second
	// MemoryFile can be read before all pages of the first are.
	f, fr := l.fs[1], l.frs[1]
	if !f.IsAsyncLoading() {
		t.Fatalf("second MemoryFile is not async loading")
	}
	if err := awaitDecommit(t, startDecommit(f, fr)); err != nil {
		t.Fatalf("Decommit: %v", err)
	}
	if f.IsAsyncLoading() {
		t.Errorf("second MemoryFile is still async loading after all of its unloaded pages were decommitted")
	}
	l.releaseReads()
	if err := l.wait(t); err != nil {
		t.Fatalf("async page loading failed: %v", err)
	}
	for _, off := range l.r.readOffsets() {
		if page := off / hostarch.PageSize; page >= 16 {
			t.Errorf("decommitted page %d of the second MemoryFile was read", page-16)
		}
	}
	decommitted := make(map[int]bool)
	for i := range 16 {
		decommitted[i] = true
	}
	l.checkPages(t, 0, nil)
	l.checkPages(t, 1, decommitted)
}

// TestDecommitAfterAsyncLoadFailure checks that Decommit returns an error for
// pages that will never be loaded due to an async page loading failure.
func TestDecommitAfterAsyncLoadFailure(t *testing.T) {
	l := startDecommitTestLoad(t, 1, 0)
	f, fr := l.fs[0], l.frs[0]
	l.releaseReads()
	if err := l.wait(t); err == nil {
		t.Fatalf("async page loading succeeded, want failure")
	}
	if err := f.Decommit(decommitTestPage(fr, 5)); err == nil {
		t.Errorf("Decommit succeeded, want failure")
	}
}

// TestDecommitAfterAsyncLoad checks that Decommit behaves normally after async
// page loading completes.
func TestDecommitAfterAsyncLoad(t *testing.T) {
	l := startDecommitTestLoad(t, 1, -1)
	f, fr := l.fs[0], l.frs[0]
	l.releaseReads()
	if err := l.wait(t); err != nil {
		t.Fatalf("async page loading failed: %v", err)
	}
	if f.IsAsyncLoading() {
		t.Fatalf("MemoryFile is still async loading")
	}
	if err := f.Decommit(decommitTestPage(fr, 5)); err != nil {
		t.Fatalf("Decommit: %v", err)
	}
	l.checkPages(t, 0, map[int]bool{5: true})
}

// TestDecommitDuringInflightLoadThenWrite checks that data written to pages
// that were decommitted (twice) during their in-flight read is not discarded
// when the read completes, and that the pages aren't committed afterwards
// until written.
func TestDecommitDuringInflightLoadThenWrite(t *testing.T) {
	l := startDecommitTestLoad(t, 1, -1)
	f, fr := l.fs[0], l.frs[0]
	l.awaitReadStart(t, 0)

	// Page 0 is being read.
	for range 2 {
		if err := awaitDecommit(t, startDecommit(f, decommitTestPage(fr, 0))); err != nil {
			t.Fatalf("Decommit: %v", err)
		}
	}
	mapped := startMapInternal(f, decommitTestPage(fr, 0))
	expectBlocked(t, mapped, "MapInternal")
	l.releaseReads()
	awaitMapInternal(t, mapped)
	writeMemoryFilePage(t, f, fr, 0, 0xaa)
	if err := l.wait(t); err != nil {
		t.Fatalf("async page loading failed: %v", err)
	}
	want := make([]byte, 16)
	for i := range want {
		want[i] = byte(i + 1)
	}
	want[0] = 0xaa
	checkCommitted(t, f, 16)
	checkMemoryFilePages(t, f, fr, want)

	// A decommit after loading behaves normally.
	if err := f.Decommit(decommitTestPage(fr, 0)); err != nil {
		t.Fatalf("Decommit: %v", err)
	}
	want[0] = 0
	checkCommitted(t, f, 15)
	checkMemoryFilePages(t, f, fr, want)
}

// TestDecommitDuringLoadCommitted checks that pages decommitted during async
// page loading, whether being read or not, are not committed after loading
// completes.
func TestDecommitDuringLoadCommitted(t *testing.T) {
	l := startDecommitTestLoad(t, 1, -1)
	f, fr := l.fs[0], l.frs[0]
	l.awaitReadStart(t, 0)

	// Page 0 is being read; pages 4-7 are unstarted.
	for _, dfr := range []memmap.FileRange{decommitTestPage(fr, 0), decommitTestPages(fr, 4, 8)} {
		if err := awaitDecommit(t, startDecommit(f, dfr)); err != nil {
			t.Fatalf("Decommit: %v", err)
		}
	}
	l.releaseReads()
	if err := l.wait(t); err != nil {
		t.Fatalf("async page loading failed: %v", err)
	}
	checkCommitted(t, f, 11)
	f.mu.Lock()
	known := f.knownCommittedBytes
	f.mu.Unlock()
	if want := 11 * uint64(hostarch.PageSize); known != want {
		t.Errorf("knownCommittedBytes: got %d, want %d", known, want)
	}
	l.checkPages(t, 0, map[int]bool{0: true, 4: true, 5: true, 6: true, 7: true})
}

// TestDecommitThenSaveDuringLoad checks that saving a MemoryFile while pages
// decommitted during async page loading are still being loaded saves them as
// zeroed.
func TestDecommitThenSaveDuringLoad(t *testing.T) {
	l := startDecommitTestLoad(t, 1, -1)
	f, fr := l.fs[0], l.frs[0]
	l.awaitReadStart(t, 0)

	// Page 0 is being read; pages 4-7 are unstarted.
	for _, dfr := range []memmap.FileRange{decommitTestPage(fr, 0), decommitTestPages(fr, 4, 8)} {
		if err := awaitDecommit(t, startDecommit(f, dfr)); err != nil {
			t.Fatalf("Decommit: %v", err)
		}
	}
	var buf bytes.Buffer
	saved := make(chan error, 1)
	go func() { saved <- f.SaveTo(context.Background(), &buf, &SaveOpts{}) }()
	expectBlocked(t, saved, "SaveTo")
	l.releaseReads()
	select {
	case err := <-saved:
		if err != nil {
			t.Fatalf("SaveTo: %v", err)
		}
	case <-time.After(decommitTestTimeout):
		t.Fatalf("SaveTo did not complete")
	}
	restored := newSaveTestMemoryFile(t, false)
	if err := restored.LoadFrom(context.Background(), &buf, &LoadOpts{}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	t.Cleanup(func() { restored.DecRef(fr) })
	want := make([]byte, 16)
	for i := range want {
		if i != 0 && (i < 4 || i >= 8) {
			want[i] = byte(i + 1)
		}
	}
	checkMemoryFilePages(t, restored, fr, want)
	checkMemoryFilePages(t, f, fr, want)
}

// TestDecommitStress races random decommits, writes and reads of a MemoryFile
// against its async page loading (with multi-page reads, several in flight,
// and random read latencies), then checks the MemoryFile's contents and
// committed pages, and those of a copy saved before loading completes.
func TestDecommitStress(t *testing.T) {
	const pages = 128
	for seed := range int64(20) {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			l := startDecommitTestLoadOpts(t, decommitTestOpts{
				numFiles:     1,
				pages:        pages,
				failOff:      -1,
				maxDelay:     5 * time.Millisecond,
				seed:         seed,
				maxReadPages: 4,
				maxParallel:  4,
			})
			l.releaseReads()
			f, fr := l.fs[0], l.frs[0]
			want := make([]byte, pages)
			for i := range want {
				want[i] = byte(i + 1)
			}
			readZero := make([]bool, pages)
			rng := rand.New(rand.NewSource(seed))
			for range 200 {
				i := rng.Intn(pages)
				switch rng.Intn(3) {
				case 0:
					j := min(i+1+rng.Intn(5), pages)
					if err := f.Decommit(decommitTestPages(fr, i, j)); err != nil {
						t.Fatalf("Decommit: %v", err)
					}
					for k := i; k < j; k++ {
						want[k] = 0
						readZero[k] = false
					}
				case 1:
					b := byte(0x80 + rng.Intn(0x80))
					writeMemoryFilePage(t, f, fr, i, b)
					want[i] = b
				case 2:
					checkMemoryFilePages(t, f, decommitTestPage(fr, i), want[i:i+1])
					if want[i] == 0 {
						// Reading a decommitted page may commit it.
						readZero[i] = true
					}
				}
				if rng.Intn(16) == 0 {
					time.Sleep(time.Duration(rng.Int63n(int64(time.Millisecond))))
				}
			}
			restored := saveAndRestore(t, f, fr)
			if err := l.wait(t); err != nil {
				t.Fatalf("async page loading failed: %v", err)
			}
			// Decommitted pages must not be committed, unless they were read
			// after being decommitted.
			minCommitted, maxCommitted := 0, 0
			for i, b := range want {
				if b != 0 {
					minCommitted++
					maxCommitted++
				} else if readZero[i] {
					maxCommitted++
				}
			}
			usage, err := f.TotalUsage()
			if err != nil {
				t.Fatalf("TotalUsage: %v", err)
			}
			if got := int(usage / hostarch.PageSize); got < minCommitted || got > maxCommitted {
				t.Errorf("TotalUsage: got %d pages, want %d-%d", got, minCommitted, maxCommitted)
			}
			checkMemoryFilePages(t, f, fr, want)
			checkMemoryFilePages(t, restored, fr, want)
		})
	}
}
