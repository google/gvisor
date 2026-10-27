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
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

const decommitRestoreTestTimeout = 10 * time.Second

// decommitRestoreReader holds checkpoint reads until the test releases them.
type decommitRestoreReader struct {
	data    []byte
	started chan struct{}
	release chan struct{}
	readErr error
}

func (r *decommitRestoreReader) ReadAt(p []byte, off int64) (int, error) {
	r.started <- struct{}{}
	<-r.release
	if r.readErr != nil {
		return 0, r.readErr
	}
	if off < 0 || off+int64(len(p)) > int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:off+int64(len(p))]), nil
}

func waitForDecommitRestoreDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("async page load failed: %v", err)
		}
	case <-time.After(decommitRestoreTestTimeout):
		t.Fatal("timed out waiting for async page loader")
	}
}

func newDecommitRestoreMemoryFile(t *testing.T) *MemoryFile {
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

// newDecommitRestoreFixture saves three distinct pages and restores them
// with a reader whose checkpoint reads are initially blocked.
func newDecommitRestoreFixture(t *testing.T, readErr error) (*MemoryFile, *decommitRestoreReader, chan error, memmap.FileRange, [][]byte) {
	t.Helper()
	page := uint64(hostarch.PageSize)
	allPages := memmap.FileRange{Start: 0, End: 3 * page}
	want := make([][]byte, 3)
	for i := range want {
		want[i] = bytes.Repeat([]byte{byte(0x31 + i)}, int(page))
	}

	source := newDecommitRestoreMemoryFile(t)
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
	case <-time.After(decommitRestoreTestTimeout):
		t.Fatal("timed out waiting for async page saver")
	}
	source.DecRef(allocated)
	source.Destroy()

	reader := &decommitRestoreReader{data: append([]byte(nil), pages.Bytes()...), started: make(chan struct{}, 8), release: make(chan struct{}), readErr: readErr}
	asyncDone := make(chan error, 1)
	loader, err := StartAsyncPagesFileLoad(
		stateio.NewIOReader(reader, page, 1, 1),
		func(err error) { asyncDone <- err },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	restored := newDecommitRestoreMemoryFile(t)
	if err := restored.LoadFrom(context.Background(), bytes.NewReader(checkpoint.Bytes()), &LoadOpts{PagesFile: loader}); err != nil {
		t.Fatal(err)
	}
	loader.MemoryFilesDone()
	return restored, reader, asyncDone, allPages, want
}

func readDecommitRestoreRange(t *testing.T, f *MemoryFile, fr memmap.FileRange) []byte {
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
	case <-time.After(decommitRestoreTestTimeout):
		t.Fatalf("timed out reading MemoryFile range %v", fr)
	}
	return nil
}

func TestDecommitDuringAsyncRestore(t *testing.T) {
	for _, index := range []uint64{0, 2} {
		t.Run(fmt.Sprintf("page%d", index), func(t *testing.T) {
			f, reader, asyncDone, allPages, want := newDecommitRestoreFixture(t, nil)
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(reader.release) }) }
			defer func() { release(); f.DecRef(allPages); f.Destroy() }()
			select {
			case <-reader.started:
			case <-time.After(decommitRestoreTestTimeout):
				t.Fatal("checkpoint reader did not start")
			}
			page := uint64(hostarch.PageSize)
			target := memmap.FileRange{Start: index * page, End: (index + 1) * page}
			// Decommit must not wait for the blocked checkpoint read, but pages must
			// still read as zero once the read completes.
			done := make(chan error, 1)
			go func() { done <- f.Decommit(target) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Decommit failed: %v", err)
				}
			case <-time.After(decommitRestoreTestTimeout):
				t.Fatal("Decommit blocked on checkpoint reads")
			}
			release()
			waitForDecommitRestoreDone(t, asyncDone)
			for i := range want {
				expected := want[i]
				if uint64(i) == index {
					expected = make([]byte, page)
				}
				fr := memmap.FileRange{Start: uint64(i) * page, End: uint64(i+1) * page}
				if got := readDecommitRestoreRange(t, f, fr); !bytes.Equal(got, expected) {
					t.Errorf("page %d begins with %x, want %x", i, got[:8], expected[:8])
				}
			}
		})
	}
}

func TestDecommitAfterAsyncRestore(t *testing.T) {
	f, reader, asyncDone, allPages, _ := newDecommitRestoreFixture(t, nil)
	defer func() { f.DecRef(allPages); f.Destroy() }()
	close(reader.release)
	waitForDecommitRestoreDone(t, asyncDone)
	page := uint64(hostarch.PageSize)
	target := memmap.FileRange{Start: page, End: 2 * page}
	if err := f.Decommit(target); err != nil {
		t.Fatal(err)
	}
	if got := readDecommitRestoreRange(t, f, target); !bytes.Equal(got, make([]byte, page)) {
		t.Fatalf("page begins with %x, want zeroes", got[:8])
	}
}

func TestDecommitAsyncRestoreReadError(t *testing.T) {
	f, reader, asyncDone, allPages, _ := newDecommitRestoreFixture(t, linuxerr.EIO)
	defer func() { f.DecRef(allPages); f.Destroy() }()
	close(reader.release)
	select {
	case err := <-asyncDone:
		if !errors.Is(err, linuxerr.EIO) {
			t.Fatalf("restore error = %v, want EIO", err)
		}
	case <-time.After(decommitRestoreTestTimeout):
		t.Fatal("restore did not finish")
	}
	if err := f.Decommit(allPages); !errors.Is(err, linuxerr.EIO) {
		t.Fatalf("Decommit error = %v, want EIO", err)
	}
}

func TestWriteAfterDecommitDuringAsyncRestore(t *testing.T) {
	f, reader, asyncDone, allPages, want := newDecommitRestoreFixture(t, nil)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(reader.release) }) }
	defer func() { release(); f.DecRef(allPages); f.Destroy() }()
	select {
	case <-reader.started:
	case <-time.After(decommitRestoreTestTimeout):
		t.Fatal("checkpoint reader did not start")
	}
	page := uint64(hostarch.PageSize)
	target := memmap.FileRange{Start: 0, End: page}
	if err := f.Decommit(target); err != nil {
		t.Fatalf("Decommit failed: %v", err)
	}
	// The write waits for the page to load, so it must land after the load
	// completes and the page is decommitted again.
	written := bytes.Repeat([]byte{0x7a}, int(page))
	writeDone := make(chan error, 1)
	go func() {
		bs, err := f.MapInternal(target, hostarch.Write)
		if err != nil {
			writeDone <- err
			return
		}
		_, err = safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(written)))
		writeDone <- err
	}()
	release()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}
	case <-time.After(decommitRestoreTestTimeout):
		t.Fatal("write did not finish")
	}
	waitForDecommitRestoreDone(t, asyncDone)
	if got := readDecommitRestoreRange(t, f, target); !bytes.Equal(got, written) {
		t.Errorf("page 0 begins with %x, want %x", got[:8], written[:8])
	}
	for i := 1; i < len(want); i++ {
		fr := memmap.FileRange{Start: uint64(i) * page, End: uint64(i+1) * page}
		if got := readDecommitRestoreRange(t, f, fr); !bytes.Equal(got, want[i]) {
			t.Errorf("page %d begins with %x, want %x", i, got[:8], want[i][:8])
		}
	}
}
