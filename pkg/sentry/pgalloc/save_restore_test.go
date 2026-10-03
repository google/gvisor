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
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

type seekStep struct {
	offset int64
	whence int
	result int64
	err    error
}

func scriptedSeek(t *testing.T, steps []seekStep) func(int64, int) (int64, error) {
	t.Helper()
	next := 0
	t.Cleanup(func() {
		if next != len(steps) {
			t.Errorf("seek called %d times, want %d", next, len(steps))
		}
	})
	return func(offset int64, whence int) (int64, error) {
		if next == len(steps) {
			t.Fatalf("unexpected seek(%#x, %d)", offset, whence)
		}
		step := steps[next]
		next++
		if offset != step.offset || whence != step.whence {
			t.Errorf("seek %d: got (%#x, %d), want (%#x, %d)", next, offset, whence, step.offset, step.whence)
		}
		return step.result, step.err
	}
}

func newSaveTestMemoryFile(t testing.TB, diskBacked bool) *MemoryFile {
	t.Helper()
	fd, err := memutil.CreateMemFD("pgalloc-save-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	f, err := NewMemoryFile(os.NewFile(uintptr(fd), "pgalloc-save-test"), MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		DiskBackedFile:          diskBacked,
	})
	if err != nil {
		unix.Close(fd)
		t.Fatalf("NewMemoryFile: %v", err)
	}
	return f
}

func destroySaveTestMemoryFile(f *MemoryFile, fr memmap.FileRange) {
	f.DecRef(fr)
	f.Destroy()
}

func restoreAndCheckSaveTestContents(t *testing.T, diskBacked bool, fr memmap.FileRange, checkpoint io.Reader, want []byte) {
	t.Helper()
	restored := newSaveTestMemoryFile(t, diskBacked)
	if err := restored.LoadFrom(context.Background(), checkpoint, &LoadOpts{}); err != nil {
		restored.Destroy()
		t.Fatalf("LoadFrom: %v", err)
	}
	defer destroySaveTestMemoryFile(restored, fr)
	restored.forEachMappingSlice(fr, func(bs []byte) {
		if !bytes.Equal(bs, want) {
			t.Error("restored contents differ from saved contents")
		}
	})
}

func TestHostFileUsageShowsEnoughHoles(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		backingFileUsageBytes uint64
		accountedBytes        uint64
		want                  bool
	}{
		{name: "no accounted memory", backingFileUsageBytes: 0, accountedBytes: 0, want: false},
		{name: "sparse", backingFileUsageBytes: 1, accountedBytes: 8, want: true},
		{name: "below dense boundary", backingFileUsageBytes: 6, accountedBytes: 8, want: true},
		{name: "at dense boundary", backingFileUsageBytes: 7, accountedBytes: 8, want: false},
		{name: "data exceeds accounted memory", backingFileUsageBytes: 9, accountedBytes: 8, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostFileUsageShowsEnoughHoles(tc.backingFileUsageBytes, tc.accountedBytes); got != tc.want {
				t.Errorf("hostFileUsageShowsEnoughHoles(%d, %d): got %t, want %t", tc.backingFileUsageBytes, tc.accountedBytes, got, tc.want)
			}
		})
	}
}

func TestHostFileDataIterator(t *testing.T) {
	const page = hostarch.PageSize
	testErr := errors.New("seek failed")
	type call struct {
		off         uint64
		want        memmap.FileRange
		wantOK      bool
		wantFailure bool
		wantErr     error
	}
	for _, tc := range []struct {
		name  string
		size  uint64
		steps []seekStep
		calls []call
	}{
		{
			name: "unaligned data with leading, middle, and trailing holes",
			size: 8 * page,
			steps: []seekStep{
				{offset: 0, whence: unix.SEEK_DATA, result: page + 1},
				{offset: page + 1, whence: unix.SEEK_HOLE, result: 3*page - 1},
				{offset: 3 * page, whence: unix.SEEK_DATA, result: 5*page + 1},
				{offset: 5*page + 1, whence: unix.SEEK_HOLE, result: 7*page - 1},
				{offset: 7 * page, whence: unix.SEEK_DATA, err: unix.ENXIO},
			},
			calls: []call{
				{off: 0, want: memmap.FileRange{Start: page, End: 3 * page}, wantOK: true},
				{off: 3 * page, want: memmap.FileRange{Start: 5 * page, End: 7 * page}, wantOK: true},
				{off: 7 * page},
			},
		},
		{
			name: "retains current range before propagating error",
			size: 4 * page,
			steps: []seekStep{
				{offset: 0, whence: unix.SEEK_DATA, result: page},
				{offset: page, whence: unix.SEEK_HOLE, result: 3 * page},
				{offset: 3 * page, whence: unix.SEEK_DATA, err: testErr},
			},
			calls: []call{
				{off: 0, want: memmap.FileRange{Start: page, End: 3 * page}, wantOK: true},
				{off: 2 * page, want: memmap.FileRange{Start: page, End: 3 * page}, wantOK: true},
				{off: 3 * page, wantFailure: true, wantErr: testErr},
			},
		},
		{
			name: "starts at requested offset and rejects backward data",
			size: 4 * page,
			steps: []seekStep{
				{offset: 2 * page, whence: unix.SEEK_DATA, result: 2 * page},
				{offset: 2 * page, whence: unix.SEEK_HOLE, result: 3 * page},
				{offset: 3 * page, whence: unix.SEEK_DATA, result: 2 * page},
			},
			calls: []call{
				{off: 2 * page, want: memmap.FileRange{Start: 2 * page, End: 3 * page}, wantOK: true},
				{off: 3 * page, wantFailure: true},
			},
		},
		{
			name: "seek hole does not advance",
			size: 4 * page,
			steps: []seekStep{
				{offset: 0, whence: unix.SEEK_DATA, result: page},
				{offset: page, whence: unix.SEEK_HOLE, result: page},
			},
			calls: []call{{wantFailure: true}},
		},
		{
			name: "seek hole exceeds file",
			size: 4 * page,
			steps: []seekStep{
				{offset: 0, whence: unix.SEEK_DATA, result: page},
				{offset: page, whence: unix.SEEK_HOLE, result: 4*page + 1},
			},
			calls: []call{{wantFailure: true}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			it := hostFileDataIterator{size: tc.size, seek: scriptedSeek(t, tc.steps)}
			for i, call := range tc.calls {
				got, ok, err := it.rangeAtOrAfter(call.off)
				if call.wantFailure {
					if err == nil {
						t.Errorf("call %d rangeAtOrAfter(%#x) succeeded, want error", i, call.off)
					} else if call.wantErr != nil && !errors.Is(err, call.wantErr) {
						t.Errorf("call %d rangeAtOrAfter(%#x) error: got %v, want %v", i, call.off, err, call.wantErr)
					}
					continue
				}
				if err != nil || ok != call.wantOK || got != call.want {
					t.Errorf("call %d rangeAtOrAfter(%#x): got (%v, %t, %v), want (%v, %t, nil)", i, call.off, got, ok, err, call.want, call.wantOK)
				}
			}
		})
	}
}

func TestHostFileDataIteratorOnMemFD(t *testing.T) {
	fd, err := memutil.CreateMemFD("pgalloc-data-pages-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	defer unix.Close(fd)

	const size = 16 * hostarch.PageSize
	if err := unix.Ftruncate(fd, size); err != nil {
		t.Fatalf("Ftruncate: %v", err)
	}
	for _, offset := range []int64{2 * hostarch.PageSize, 9 * hostarch.PageSize} {
		if _, err := unix.Pwrite(fd, []byte{1}, offset); err != nil {
			t.Fatalf("Pwrite(%#x): %v", offset, err)
		}
	}
	it := hostFileDataIterator{
		size: size,
		seek: func(offset int64, whence int) (int64, error) {
			return unix.Seek(fd, offset, whence)
		},
	}
	got := make(map[uint64]struct{})
	for off := uint64(0); off < it.size; {
		fr, ok, err := it.rangeAtOrAfter(off)
		if err != nil {
			t.Fatalf("rangeAtOrAfter(%#x): %v", off, err)
		}
		if !ok {
			break
		}
		for page := max(off, fr.Start) / hostarch.PageSize; page < fr.End/hostarch.PageSize; page++ {
			got[page] = struct{}{}
		}
		off = fr.End
	}
	for _, page := range []uint64{2, 9} {
		if _, ok := got[page]; !ok {
			t.Errorf("written page %d was not reported as data", page)
		}
	}
}

func TestSaveToPreservesSparseContents(t *testing.T) {
	for _, tc := range []struct {
		name       string
		diskBacked bool
	}{
		{name: "host data pages"},
		{name: "disk-backed scan", diskBacked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSaveTestMemoryFile(t, tc.diskBacked)
			fr, err := f.Allocate(16*hostarch.PageSize, AllocOpts{Mode: AllocateUncommitted})
			if err != nil {
				t.Fatalf("Allocate: %v", err)
			}
			defer destroySaveTestMemoryFile(f, fr)
			want := make([]byte, int(fr.Length()))
			want[2*hostarch.PageSize] = 1
			want[13*hostarch.PageSize+17] = 2
			f.forEachMappingSlice(fr, func(bs []byte) {
				bs[2*hostarch.PageSize] = want[2*hostarch.PageSize]
				bs[13*hostarch.PageSize+17] = want[13*hostarch.PageSize+17]
			})
			if _, err := unix.Pwrite(f.FD(), []byte{0}, int64(9*hostarch.PageSize)); err != nil {
				t.Fatalf("Pwrite explicit zero: %v", err)
			}
			if !tc.diskBacked {
				backingFileUsageBytes, err := f.TotalUsage()
				if err != nil {
					t.Fatalf("TotalUsage: %v", err)
				}
				if wantMin := uint64(3 * hostarch.PageSize); backingFileUsageBytes < wantMin {
					t.Fatalf("backing file usage %d, want at least %d for nonzero and explicitly zero pages", backingFileUsageBytes, wantMin)
				}
				accountedBytes := uint64(f.memAcct.Span())
				if !hostFileUsageShowsEnoughHoles(backingFileUsageBytes, accountedBytes) {
					t.Fatalf("sparse MemoryFile did not pass extent scan gate: backing file usage %d, accounted bytes %d", backingFileUsageBytes, accountedBytes)
				}
			}
			const originalOffset = 7 * hostarch.PageSize
			if _, err := unix.Seek(int(f.file.Fd()), originalOffset, unix.SEEK_SET); err != nil {
				t.Fatalf("Seek: %v", err)
			}

			var checkpoint bytes.Buffer
			if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}
			if got, want := f.knownCommittedBytes, uint64(2*hostarch.PageSize); got != want {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, want)
			}
			if off, err := unix.Seek(int(f.file.Fd()), 0, unix.SEEK_CUR); err != nil {
				t.Fatalf("Seek(SEEK_CUR): %v", err)
			} else if off != originalOffset {
				t.Errorf("file offset: got %#x, want %#x", off, originalOffset)
			}

			restoreAndCheckSaveTestContents(t, tc.diskBacked, fr, &checkpoint, want)
		})
	}
}

func TestSaveToExcludeCommittedZeroPages(t *testing.T) {
	for _, tc := range []struct {
		name          string
		exclude       bool
		wantCommitted uint64
	}{
		{name: "disabled", wantCommitted: 16 * hostarch.PageSize},
		{name: "enabled", exclude: true, wantCommitted: 3 * hostarch.PageSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSaveTestMemoryFile(t, false)
			fr, err := f.Allocate(16*hostarch.PageSize, AllocOpts{Mode: AllocateUncommitted})
			if err != nil {
				t.Fatalf("Allocate: %v", err)
			}
			defer destroySaveTestMemoryFile(f, fr)
			initial := make([]byte, int(fr.Length()))
			for page := 0; page < 16; page++ {
				initial[page*hostarch.PageSize] = byte(page + 1)
			}
			if _, err := unix.Pwrite(f.FD(), initial, int64(fr.Start)); err != nil {
				t.Fatalf("Pwrite initial contents: %v", err)
			}
			if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{}); err != nil {
				t.Fatalf("initial SaveTo: %v", err)
			}
			decommitted := memmap.FileRange{
				Start: fr.Start + 2*hostarch.PageSize,
				End:   fr.End - hostarch.PageSize,
			}
			if err := f.decommitFile(decommitted); err != nil {
				t.Fatalf("decommitFile: %v", err)
			}
			if _, err := unix.Pwrite(f.FD(), make([]byte, hostarch.PageSize), int64(fr.Start+9*hostarch.PageSize)); err != nil {
				t.Fatalf("Pwrite explicit zero: %v", err)
			}
			wantContents := make([]byte, int(fr.Length()))
			wantContents[0] = 1
			wantContents[hostarch.PageSize] = 2
			wantContents[15*hostarch.PageSize] = 16

			var checkpoint bytes.Buffer
			if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{ExcludeCommittedZeroPages: tc.exclude}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}
			if got := f.knownCommittedBytes; got != tc.wantCommitted {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, tc.wantCommitted)
			}

			restoreAndCheckSaveTestContents(t, false, fr, &checkpoint, wantContents)
		})
	}
}
