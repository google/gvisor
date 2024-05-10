// Copyright 2018 The gVisor Authors.
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
	"runtime"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/sync"
)

// SaveOpts provides options to MemoryFile.SaveTo().
type SaveOpts struct {
	// If ExcludeCommittedZeroPages is true, SaveTo() will scan both committed
	// and possibly-committed pages to find zero pages, whose contents are
	// saved implicitly rather than explicitly to reduce checkpoint size. If
	// ExcludeCommittedZeroPages is false, SaveTo() will scan only
	// possibly-committed pages to find zero pages.
	//
	// Enabling ExcludeCommittedZeroPages will usually increase the time taken
	// by SaveTo() (due to the larger number of pages that must be scanned),
	// but may instead improve SaveTo() and LoadFrom() time, and checkpoint
	// size, if the application has many committed zero pages.
	ExcludeCommittedZeroPages bool
}

// SaveTo writes f's state to the given stream.
func (f *MemoryFile) SaveTo(ctx context.Context, w io.Writer, pw io.Writer, opts SaveOpts) error {
	// Wait for reclaim.
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.reclaimable {
		f.reclaimCond.Signal()
		f.mu.Unlock()
		runtime.Gosched()
		f.mu.Lock()
	}

	// Ensure that there are no pending evictions.
	if len(f.evictable) != 0 {
		panic(fmt.Sprintf("evictions still pending for %d users; call StartEvictions and WaitForEvictions before SaveTo", len(f.evictable)))
	}

	// Ensure that all pages that contain non-zero bytes have knownCommitted
	// set, since we only store knownCommitted pages below.
	zeroPage := make([]byte, hostarch.PageSize)
	var (
		decommitWarnOnce  sync.Once
		decommitPendingFR memmap.FileRange
		scanTotal         uint64
		decommitTotal     uint64
		decommitCount     uint64
	)
	decommitNow := func(fr memmap.FileRange) {
		decommitTotal += fr.Length()
		decommitCount++
		if err := f.decommitFile(fr); err != nil {
			// This doesn't impact the correctness of saved memory, it just
			// means that we're incrementally more likely to OOM. Complain, but
			// don't abort saving.
			decommitWarnOnce.Do(func() {
				log.Warningf("Decommitting MemoryFile offsets %v while saving failed: %v", fr, err)
			})
		}
	}
	decommitAddPage := func(off uint64) {
		// Invariants:
		// (1) All of decommitPendingFR lies within a single huge page.
		// (2) decommitPendingFR.End is hugepage-aligned iff
		// decommitPendingFR.Length() == 0.
		end := off + hostarch.PageSize
		if decommitPendingFR.End == off {
			// Merge with the existing range. By invariants, the page {off,
			// end} must be within the same huge page as the rest of
			// decommitPendingFR.
			decommitPendingFR.End = end
		} else {
			// Decommit the existing range and start a new one.
			if decommitPendingFR.Length() != 0 {
				decommitNow(decommitPendingFR)
			}
			decommitPendingFR = memmap.FileRange{off, end}
		}
		// Maintain invariants by decommitting if we've reached the end of the
		// containing huge page.
		if hostarch.IsHugePageAligned(end) {
			decommitNow(decommitPendingFR)
			decommitPendingFR = memmap.FileRange{}
		}
	}
	err := f.updateUsageLocked(0, nil, opts.ExcludeCommittedZeroPages, func(bs []byte, committed []byte, off uint64, wasCommitted bool) error {
		scanTotal += uint64(len(bs))
		for pgoff := 0; pgoff < len(bs); pgoff += hostarch.PageSize {
			i := pgoff / hostarch.PageSize
			pg := bs[pgoff : pgoff+hostarch.PageSize]
			if !bytes.Equal(pg, zeroPage) {
				committed[i] = 1
				continue
			}
			committed[i] = 0
			if !wasCommitted {
				// Reading the page may have caused it to be committed;
				// decommit it to reduce memory usage.
				decommitAddPage(off + uint64(pgoff))
			}
		}
		return nil
	})
	if decommitPendingFR.Length() != 0 {
		decommitNow(decommitPendingFR)
		decommitPendingFR = memmap.FileRange{}
	}
	if err != nil {
		return err
	}
	log.Debugf("MemoryFile.SaveTo: scanned %d bytes, decommitted %d bytes in %d syscalls", scanTotal, decommitTotal, decommitCount)

	// Save metadata.
	if _, err := state.Save(ctx, w, &f.fileSize); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.usage); err != nil {
		return err
	}

	// Dump out committed pages.
	for seg := f.usage.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		if !seg.Value().knownCommitted {
			continue
		}
		// Write a header to distinguish from objects.
		if err := state.WriteHeader(w, uint64(seg.Range().Length()), false); err != nil {
			return err
		}
		// Write out data.
		var ioErr error
		err := f.forEachMappingSlice(seg.Range(), func(s []byte) {
			if ioErr != nil {
				return
			}
			_, ioErr = pw.Write(s)
		})
		if ioErr != nil {
			return ioErr
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// MarkSavable marks f as savable.
func (f *MemoryFile) MarkSavable() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.savable = true
}

// IsSavable returns true if f is savable.
func (f *MemoryFile) IsSavable() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.savable
}

// RestoreID returns the restore ID for f.
func (f *MemoryFile) RestoreID() string {
	return f.opts.RestoreID
}

// LoadFrom loads MemoryFile state from the given stream.
func (f *MemoryFile) LoadFrom(ctx context.Context, r io.Reader, pr *statefile.AsyncReader) error {
	// Load metadata.
	if _, err := state.Load(ctx, r, &f.fileSize); err != nil {
		return err
	}
	if err := f.file.Truncate(f.fileSize); err != nil {
		return err
	}
	newMappings := make([]uintptr, f.fileSize>>chunkShift)
	f.mappings.Store(&newMappings)
	if _, err := state.Load(ctx, r, &f.usage); err != nil {
		return err
	}

	// Try to map committed chunks concurrently: For any given chunk, either
	// this loop or the following one will mmap the chunk first and cache it in
	// f.mappings for the other, but this loop is likely to run ahead of the
	// other since it doesn't do any work between mmaps. The rest of this
	// function doesn't mutate f.usage, so it's safe to iterate concurrently.
	mapperDone := make(chan struct{})
	mapperCanceled := atomicbitops.FromInt32(0)
	go func() { // S/R-SAFE: see comment
		defer func() { close(mapperDone) }()
		for seg := f.usage.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			if mapperCanceled.Load() != 0 {
				return
			}
			if seg.Value().knownCommitted {
				f.forEachMappingSlice(seg.Range(), func(s []byte) {})
			}
		}
	}()
	defer func() {
		mapperCanceled.Store(1)
		<-mapperDone
	}()

	// Load committed pages.
	for seg := f.usage.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		if !seg.Value().knownCommitted {
			continue
		}
		// Verify header.
		length, object, err := state.ReadHeader(r)
		if err != nil {
			return err
		}
		if object {
			// Not expected.
			return fmt.Errorf("unexpected object")
		}
		if expected := uint64(seg.Range().Length()); length != expected {
			// Size mismatch.
			return fmt.Errorf("mismatched segment: expected %d, got %d", expected, length)
		}
		// Read data.
		var ioErr error
		err = f.forEachMappingSlice(seg.Range(), func(s []byte) {
			if ioErr != nil {
				return
			}
			if pr != nil {
				pr.ReadAsync(s)
			} else {
				_, ioErr = io.ReadFull(r, s)
			}
		})
		if ioErr != nil {
			return ioErr
		}
		if err != nil {
			return err
		}

		// Update accounting for restored pages. We need to do this here since
		// these segments are marked as "known committed", and will be skipped
		// over on accounting scans.
		amount := seg.Range().Length()
		usage.MemoryAccounting.Inc(amount, seg.Value().kind, seg.Value().memCgID)
		f.usageExpected += amount
	}

	return nil
}
