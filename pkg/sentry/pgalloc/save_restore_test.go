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

package pgalloc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

const asyncLoadTestTimeout = 10 * time.Second

// countingReaderAt records the pages read from the checkpoint and serves
// their contents to stateio.NewIOReader.
type countingReaderAt struct {
	mu       sync.Mutex
	data     []byte
	reads    []memmap.FileRange
	readChan chan struct{}
}

func (r *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if off < 0 || off+int64(len(p)) > int64(len(r.data)) {
		return 0, io.EOF
	}
	copy(p, r.data[off:off+int64(len(p))])
	r.reads = append(r.reads, memmap.FileRange{Start: uint64(off), End: uint64(off) + uint64(len(p))})
	select {
	case r.readChan <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (r *countingReaderAt) snapshotReads() []memmap.FileRange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]memmap.FileRange(nil), r.reads...)
}

func waitForNoAsyncReads(t *testing.T, r *countingReaderAt) {
	t.Helper()
	select {
	case <-r.readChan:
		t.Fatalf("unexpected background page read: %v", r.snapshotReads())
	case <-time.After(100 * time.Millisecond):
	}
}

func drainReadNotifications(r *countingReaderAt) {
	for {
		select {
		case <-r.readChan:
		default:
			return
		}
	}
}

func waitForAsyncDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("async page load failed: %v", err)
		}
	case <-time.After(asyncLoadTestTimeout):
		t.Fatal("timed out waiting for async page loader")
	}
}

func requireReadRanges(t *testing.T, got, want []memmap.FileRange) {
	t.Helper()
	readSet := make(map[memmap.FileRange]int, len(got))
	for _, fr := range got {
		readSet[fr]++
	}
	wantSet := make(map[memmap.FileRange]int, len(want))
	for _, fr := range want {
		wantSet[fr]++
	}
	if len(readSet) != len(wantSet) {
		t.Fatalf("read ranges = %v, want %v", got, want)
	}
	for fr, n := range wantSet {
		if readSet[fr] != n {
			t.Fatalf("read ranges = %v, want %v", got, want)
		}
	}
}

func newTestMemoryFile(t *testing.T) *MemoryFile {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "pgalloc-memory-file")
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewMemoryFile(file, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionManual,
		DisableIMAWorkAround:    true,
		DisableMemoryAccounting: true,
	})
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	return f
}

// newAsyncLoadFixture saves three distinct committed pages to an async pages
// file, then restores their metadata with opts.
func newAsyncLoadFixture(t *testing.T, opts AsyncPagesFileLoadOpts) (*MemoryFile, *countingReaderAt, chan error, memmap.FileRange, [][]byte) {
	t.Helper()
	page := uint64(hostarch.PageSize)
	allPages := memmap.FileRange{Start: 0, End: 3 * page}
	want := make([][]byte, 3)
	for i := range want {
		want[i] = bytes.Repeat([]byte{byte(0x31 + i)}, int(page))
	}

	source := newTestMemoryFile(t)
	allocated, err := source.Allocate(allPages.Length(), AllocOpts{Mode: AllocateAndCommit})
	if err != nil {
		t.Fatal(err)
	}
	for i, data := range want {
		bs, err := source.MapInternal(memmap.FileRange{Start: uint64(i) * page, End: uint64(i+1) * page}, hostarch.Write)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(data))); err != nil || n != page {
			t.Fatalf("CopySeq() = (%d, %v), want (%d, nil)", n, err, page)
		}
	}

	var checkpoint bytes.Buffer
	var pages bytes.Buffer
	saverDone := make(chan error, 1)
	writer := stateio.NewIOWriter(&pages, page, 1, 2)
	saver, err := StartAsyncPagesFileSave(writer, func(err error) { saverDone <- err })
	if err != nil {
		t.Fatal(err)
	}
	if err := source.SaveTo(context.Background(), &checkpoint, &SaveOpts{PagesFile: saver}); err != nil {
		t.Fatal(err)
	}
	saver.MemoryFilesDone()
	select {
	case err := <-saverDone:
		if err != nil {
			t.Fatalf("async page save failed: %v", err)
		}
	case <-time.After(asyncLoadTestTimeout):
		t.Fatal("timed out waiting for async page saver")
	}
	source.DecRef(allocated)
	source.Destroy()

	reader := &countingReaderAt{data: append([]byte(nil), pages.Bytes()...), readChan: make(chan struct{}, 8)}
	asyncDone := make(chan error, 1)
	loader, err := StartAsyncPagesFileLoad(
		stateio.NewIOReader(reader, page, 1, 2),
		func(err error) { asyncDone <- err },
		nil,
		opts,
	)
	if err != nil {
		t.Fatal(err)
	}
	restored := newTestMemoryFile(t)
	if err := restored.LoadFrom(context.Background(), bytes.NewReader(checkpoint.Bytes()), &LoadOpts{PagesFile: loader}); err != nil {
		t.Fatal(err)
	}
	loader.MemoryFilesDone()
	return restored, reader, asyncDone, allPages, want
}

func readMemoryFileRange(t *testing.T, f *MemoryFile, fr memmap.FileRange) []byte {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		bs, err := f.MapInternal(fr, hostarch.Read)
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		got := make([]byte, fr.Length())
		n, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(got)), bs)
		if err == nil && n != fr.Length() {
			err = fmt.Errorf("CopySeq() copied %d bytes, want %d", n, fr.Length())
		}
		resultCh <- result{data: got, err: err}
	}()
	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("reading MemoryFile range %v failed: %v", fr, res.err)
		}
		return res.data
	case <-time.After(asyncLoadTestTimeout):
		t.Fatalf("timed out reading MemoryFile range %v", fr)
	}
	return nil
}

func TestAsyncPagesFileLoadThrottledColdPages(t *testing.T) {
	f, reader, asyncDone, allPages, want := newAsyncLoadFixture(t, AsyncPagesFileLoadOpts{BackgroundBytesPerSecond: 1})
	defer func() {
		f.DecRef(allPages)
		f.Destroy()
	}()
	waitForNoAsyncReads(t, reader)

	page := uint64(hostarch.PageSize)
	requested := memmap.FileRange{Start: 2 * page, End: 3 * page}
	if got := readMemoryFileRange(t, f, requested); !bytes.Equal(got, want[2]) {
		t.Fatalf("read requested page = %x, want %x", got[:8], want[2][:8])
	}
	requireReadRanges(t, reader.snapshotReads(), []memmap.FileRange{{Start: 2 * page, End: 3 * page}})
	drainReadNotifications(reader)
	waitForNoAsyncReads(t, reader)

	awaitAll := make(chan error, 1)
	go func() { awaitAll <- f.AwaitLoadAll() }()
	select {
	case err := <-awaitAll:
		if err != nil {
			t.Fatalf("AwaitLoadAll() failed: %v", err)
		}
	case <-time.After(asyncLoadTestTimeout):
		t.Fatal("timed out waiting for AwaitLoadAll()")
	}
	waitForAsyncDone(t, asyncDone)
	requireReadRanges(t, reader.snapshotReads(), []memmap.FileRange{
		{Start: 0, End: page},
		{Start: page, End: 2 * page},
		{Start: 2 * page, End: 3 * page},
	})
	for i := range want {
		fr := memmap.FileRange{Start: uint64(i) * page, End: uint64(i+1) * page}
		if got := readMemoryFileRange(t, f, fr); !bytes.Equal(got, want[i]) {
			t.Fatalf("page %d = %x, want %x", i, got[:8], want[i][:8])
		}
	}
}

func TestAsyncPagesFileLoadThrottledFreedColdPages(t *testing.T) {
	f, reader, asyncDone, allPages, _ := newAsyncLoadFixture(t, AsyncPagesFileLoadOpts{BackgroundBytesPerSecond: 1})
	released := false
	defer func() {
		if !released {
			f.DecRef(allPages)
		}
		f.Destroy()
	}()
	waitForNoAsyncReads(t, reader)
	f.DecRef(allPages)
	released = true
	waitForAsyncDone(t, asyncDone)
	if got := reader.snapshotReads(); len(got) != 0 {
		t.Fatalf("freed cold pages were read: %v", got)
	}
}

func TestAsyncPagesFileLoadBackgroundThrottlePrioritizesWaiters(t *testing.T) {
	page := uint64(hostarch.PageSize)
	f, reader, asyncDone, allPages, want := newAsyncLoadFixture(t, AsyncPagesFileLoadOpts{
		BackgroundBytesPerSecond: page,
	})
	defer func() {
		f.DecRef(allPages)
		f.Destroy()
	}()

	// The first speculative read should be limited to one page. At this rate,
	// the next background page cannot start for about one second.
	select {
	case <-reader.readChan:
	case <-time.After(asyncLoadTestTimeout):
		t.Fatal("timed out waiting for first background read")
	}
	reads := reader.snapshotReads()
	if len(reads) != 1 || reads[0].Length() > page {
		t.Fatalf("first background read ranges = %v, want one range of at most %d bytes", reads, page)
	}
	waitForNoAsyncReads(t, reader)

	// An application page fault must wake the throttled loader and bypass its
	// background rate limit.
	requested := memmap.FileRange{Start: 2 * page, End: 3 * page}
	requestStart := time.Now()
	if got := readMemoryFileRange(t, f, requested); !bytes.Equal(got, want[2]) {
		t.Fatalf("foreground read = %x, want %x", got[:8], want[2][:8])
	}
	if elapsed := time.Since(requestStart); elapsed >= 500*time.Millisecond {
		t.Fatalf("foreground page fault took %s while background throttle had budget for one page per second", elapsed)
	}

	waitForAsyncDone(t, asyncDone)
	requireReadRanges(t, reader.snapshotReads(), []memmap.FileRange{
		{Start: 0, End: page},
		{Start: page, End: 2 * page},
		{Start: 2 * page, End: 3 * page},
	})
}
