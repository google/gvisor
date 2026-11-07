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
	"fmt"
	"math"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// AdoptExisting makes f take ownership of the existing contents of its
// backing file. After AdoptExisting returns, each page in used is allocated
// with one reference and the given memory accounting kind, and all other
// pages in the file are free. AdoptExisting punches holes over the pages that
// are not in used, since free pages must be zeroed.
//
// used must be sorted, non-overlapping, page-aligned, and within the current
// size of the backing file.
//
// Preconditions:
//   - f was created with MemoryFileOpts.KeepFileContents.
//   - No pages have been allocated from f.
func (f *MemoryFile) AdoptExisting(used []memmap.FileRange, kind usage.MemoryKind) error {
	if !f.opts.KeepFileContents {
		return fmt.Errorf("AdoptExisting requires MemoryFileOpts.KeepFileContents")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.file.Fd()), &stat); err != nil {
		return fmt.Errorf("failed to stat backing file: %w", err)
	}
	if stat.Size < 0 {
		return fmt.Errorf("invalid backing file size %d", stat.Size)
	}
	curSize := uint64(stat.Size)
	if err := validateAdoptedRanges(used, curSize); err != nil {
		return err
	}
	fileSize := curSize
	if fileSize&chunkMask != 0 {
		fileSize = (fileSize + chunkMask) &^ chunkMask
	}
	nrChunks := fileSize / chunkSize
	if nrChunks > maxChunks {
		return fmt.Errorf("backing file size %d is too large", curSize)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.chunksLoad()) != 0 {
		return fmt.Errorf("AdoptExisting called after allocation")
	}
	if fileSize == 0 {
		return nil
	}
	if fileSize != curSize {
		if err := f.file.Truncate(int64(fileSize)); err != nil {
			return fmt.Errorf("failed to extend backing file to %d bytes: %w", fileSize, err)
		}
	}

	// Free pages must be zeroed, so punch holes in every page range that is
	// not in used.
	var off uint64
	for _, fr := range used {
		if off < fr.Start {
			if err := f.decommitFile(memmap.FileRange{Start: off, End: fr.Start}); err != nil {
				return fmt.Errorf("failed to punch hole in [%#x, %#x): %w", off, fr.Start, err)
			}
		}
		off = fr.End
	}
	if off < fileSize {
		if err := f.decommitFile(memmap.FileRange{Start: off, End: fileSize}); err != nil {
			return fmt.Errorf("failed to punch hole in [%#x, %#x): %w", off, fileSize, err)
		}
	}

	m, _, errno := unix.Syscall6(
		unix.SYS_MMAP,
		0,
		uintptr(fileSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
		f.file.Fd(),
		0)
	if errno != 0 {
		return fmt.Errorf("failed to mmap backing file: %w", errno)
	}
	chunks := make([]chunkInfo, nrChunks)
	for i := range chunks {
		chunks[i].mapping = m
		f.madviseChunkMapping(m, chunkSize, false /* huge */)
		m += chunkSize
	}
	f.chunks.Store(&chunks)

	// All chunks are small-page-backed. unfreeHuge already covers the whole
	// file, as for chunks that are backed by a different page size.
	// unwasteSmall and unwasteHuge already cover the whole file, since no
	// page is waste.
	f.unfreeSmall.RemoveAll()
	for _, fr := range used {
		f.unfreeSmall.InsertRange(fr, unfreeInfo{refs: 1})
	}
	f.unfreeSmall.InsertRange(memmap.FileRange{Start: fileSize, End: math.MaxUint64}, unfreeInfo{})
	for _, fr := range used {
		f.memAcct.InsertRange(fr, memAcctInfo{
			kind:           kind,
			knownCommitted: false,
			commitSeq:      f.commitSeq,
		})
	}
	return nil
}

// validateAdoptedRanges returns an error if used is not sorted,
// non-overlapping, page-aligned, and within [0, size).
func validateAdoptedRanges(used []memmap.FileRange, size uint64) error {
	var prevEnd uint64
	for i, fr := range used {
		if !fr.WellFormed() || fr.Length() == 0 {
			return fmt.Errorf("adopted range %d %v is empty or malformed", i, fr)
		}
		if !hostarch.IsPageAligned(fr.Start) || !hostarch.IsPageAligned(fr.End) {
			return fmt.Errorf("adopted range %d %v is not page-aligned", i, fr)
		}
		if fr.Start < prevEnd {
			return fmt.Errorf("adopted range %d %v is not sorted or overlaps the previous range", i, fr)
		}
		if fr.End > size {
			return fmt.Errorf("adopted range %d %v exceeds the backing file size %#x", i, fr, size)
		}
		prevEnd = fr.End
	}
	return nil
}
