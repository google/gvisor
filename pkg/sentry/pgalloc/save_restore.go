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
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/state"
)

// SaveTo writes f's state to the given stream.
func (f *MemoryFile) SaveTo(ctx context.Context, w io.Writer) error {
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

	// Ensure that all pages that contain data have knownCommitted set, since
	// we only store knownCommitted pages below.
	zeroPage := make([]byte, usermem.PageSize)
	err := f.updateUsageLocked(0, func(bs []byte, committed []byte) error {
		for pgoff := 0; pgoff < len(bs); pgoff += usermem.PageSize {
			i := pgoff / usermem.PageSize
			pg := bs[pgoff : pgoff+usermem.PageSize]
			if !bytes.Equal(pg, zeroPage) {
				committed[i] = 1
				continue
			}
			committed[i] = 0
			// Reading the page caused it to be committed; decommit it to
			// reduce memory usage.
			//
			// "MADV_REMOVE [...] Free up a given range of pages and its
			// associated backing store. This is equivalent to punching a hole
			// in the corresponding byte range of the backing store (see
			// fallocate(2))." - madvise(2)
			if err := syscall.Madvise(pg, syscall.MADV_REMOVE); err != nil {
				// This doesn't impact the correctness of saved memory, it
				// just means that we're incrementally more likely to OOM.
				// Complain, but don't abort saving.
				log.Warningf("Decommitting page %p while saving failed: %v", pg, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Save metadata.
	if err := state.Save(ctx, w, &f.fileSize, nil); err != nil {
		return err
	}
	if err := state.Save(ctx, w, &f.usage, nil); err != nil {
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
			_, ioErr = w.Write(s)
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

// LoadFrom loads MemoryFile state from the given stream.
func (f *MemoryFile) LoadFrom(ctx context.Context, r io.Reader) error {
	// Load metadata.
	if err := state.Load(ctx, r, &f.fileSize, nil); err != nil {
		return err
	}
	if err := f.file.Truncate(f.fileSize); err != nil {
		return err
	}
	newMappings := make([]uintptr, f.fileSize>>chunkShift)
	f.mappings.Store(newMappings)
	if err := state.Load(ctx, r, &f.usage, nil); err != nil {
		return err
	}

	// Try to map committed chunks concurrently: For any given chunk, either
	// this loop or the following one will mmap the chunk first and cache it in
	// f.mappings for the other, but this loop is likely to run ahead of the
	// other since it doesn't do any work between mmaps. The rest of this
	// function doesn't mutate f.usage, so it's safe to iterate concurrently.
	mapperDone := make(chan struct{})
	mapperCanceled := int32(0)
	go func() { // S/R-SAFE: see comment
		defer func() { close(mapperDone) }()
		for seg := f.usage.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			if atomic.LoadInt32(&mapperCanceled) != 0 {
				return
			}
			if seg.Value().knownCommitted {
				f.forEachMappingSlice(seg.Range(), func(s []byte) {})
			}
		}
	}()
	defer func() {
		atomic.StoreInt32(&mapperCanceled, 1)
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
			_, ioErr = io.ReadFull(r, s)
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
		usage.MemoryAccounting.Inc(seg.End()-seg.Start(), seg.Value().kind)
	}

	return nil
}

// MemoryFileProvider provides the MemoryFile method.
//
// This type exists to work around a save/restore defect. The only object in a
// saved object graph that S/R allows to be replaced at time of restore is the
// starting point of the restore, kernel.Kernel. However, the MemoryFile
// changes between save and restore as well, so objects that need persistent
// access to the MemoryFile must instead store a pointer to the Kernel and call
// Kernel.MemoryFile() as required. In most cases, depending on the kernel
// package directly would create a package dependency loop, so the stored
// pointer must instead be a MemoryProvider interface object. Correspondingly,
// kernel.Kernel is the only implementation of this interface.
type MemoryFileProvider interface {
	// MemoryFile returns the Kernel MemoryFile.
	MemoryFile() *MemoryFile
}
