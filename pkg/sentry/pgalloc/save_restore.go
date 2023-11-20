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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
)

// SaveTo writes f's state to the given stream.
func (f *MemoryFile) SaveTo(ctx context.Context, w wire.Writer) error {
	// Wait for memory release.
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.haveWaste {
		f.mu.Unlock()
		runtime.Gosched()
		f.mu.Lock()
	}

	// Ensure that there are no pending evictions.
	if len(f.evictable) != 0 {
		panic(fmt.Sprintf("evictions still pending for %d users; call StartEvictions and WaitForEvictions before SaveTo", len(f.evictable)))
	}

	// Ensure that all pages that contain data are marked known-committed,
	// since we only store known-committed pages below.
	zeroPage := make([]byte, hostarch.PageSize)
	err := f.updateUsageLocked(nil, func(bs []byte, committed []byte) error {
		for pgoff := 0; pgoff < len(bs); pgoff += hostarch.PageSize {
			i := pgoff / hostarch.PageSize
			pg := bs[pgoff : pgoff+hostarch.PageSize]
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
			if err := unix.Madvise(pg, unix.MADV_REMOVE); err != nil {
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
	if _, err := state.Save(ctx, w, &f.unwasteSmall); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.unwasteHuge); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.unfreeSmall); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.unfreeHuge); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.subreleased); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.memAcct); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.knownCommittedBytes); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.commitSeq); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, f.chunks.Load()); err != nil {
		return err
	}

	// Dump out committed pages.
	for maseg := f.memAcct.FirstSegment(); maseg.Ok(); maseg = maseg.NextSegment() {
		if maseg.ValuePtr().committed != committedTrue {
			continue
		}
		// Write a header to distinguish from objects.
		if err := state.WriteHeader(w, uint64(maseg.Range().Length()), false); err != nil {
			return err
		}
		// Write out data.
		var ioErr error
		f.forEachMappingSlice(maseg.Range(), func(s []byte) {
			if ioErr != nil {
				return
			}
			_, ioErr = w.Write(s)
		})
		if ioErr != nil {
			return ioErr
		}
	}

	return nil
}

// LoadFrom loads MemoryFile state from the given stream.
func (f *MemoryFile) LoadFrom(ctx context.Context, r wire.Reader) error {
	// Clear sets since non-empty sets will panic if loaded into.
	f.unwasteSmall.RemoveAll()
	f.unwasteHuge.RemoveAll()
	f.unfreeSmall.RemoveAll()
	f.unfreeHuge.RemoveAll()
	f.memAcct.RemoveAll()

	// Load metadata.
	if _, err := state.Load(ctx, r, &f.unwasteSmall); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.unwasteHuge); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.unfreeSmall); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.unfreeHuge); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.subreleased); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.memAcct); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.knownCommittedBytes); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.commitSeq); err != nil {
		return err
	}
	var chunks []chunkInfo
	if _, err := state.Load(ctx, r, &chunks); err != nil {
		return err
	}
	f.chunks.Store(&chunks)
	if err := f.file.Truncate(int64(len(chunks)) * chunkSize); err != nil {
		return err
	}
	for i := range chunks {
		chunk := &chunks[i]
		var mapStart uintptr
		if chunk.huge {
			m, err := memutil.MapAlignedPrivateAnon(chunkSize, hostarch.HugePageSize, unix.PROT_NONE, 0)
			if err != nil {
				return err
			}
			_, _, errno := unix.Syscall6(
				unix.SYS_MMAP,
				m,
				chunkSize,
				unix.PROT_READ|unix.PROT_WRITE,
				unix.MAP_SHARED|unix.MAP_FIXED,
				f.file.Fd(),
				uintptr(i)*chunkSize)
			if errno != 0 {
				unix.RawSyscall(unix.SYS_MUNMAP, m, chunkSize, 0)
				return errno
			}
			mapStart = m
		} else {
			m, _, errno := unix.Syscall6(
				unix.SYS_MMAP,
				0,
				chunkSize,
				unix.PROT_READ|unix.PROT_WRITE,
				unix.MAP_SHARED,
				f.file.Fd(),
				uintptr(i)*chunkSize)
			if errno != 0 {
				return errno
			}
			mapStart = m
		}
		f.adviseChunkMapping(mapStart, chunkSize, chunk.huge)
		chunk.mapping = mapStart
	}

	// Load committed pages.
	for maseg := f.memAcct.FirstSegment(); maseg.Ok(); maseg = maseg.NextSegment() {
		if maseg.ValuePtr().committed != committedTrue {
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
		if expected := uint64(maseg.Range().Length()); length != expected {
			// Size mismatch.
			return fmt.Errorf("mismatched segment: expected %d, got %d", expected, length)
		}
		// Read data.
		var ioErr error
		f.forEachMappingSlice(maseg.Range(), func(s []byte) {
			if ioErr != nil {
				return
			}
			_, ioErr = io.ReadFull(r, s)
		})
		if ioErr != nil {
			return ioErr
		}

		// Update accounting for restored pages. We need to do this here since
		// these segments are marked as "known committed", and will be skipped
		// over on accounting scans.
		usage.MemoryAccounting.Inc(maseg.Range().Length(), maseg.ValuePtr().kind, maseg.ValuePtr().memCgID)
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
