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
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// AdoptExisting makes f take ownership of the existing contents of its
// backing file. After AdoptExisting returns, each page in used is allocated
// with one reference and the given memory accounting kind, each page in
// unsaved is reserved outside usage.MemoryAccounting and checkpointing (though
// committed blocks in unsaved still count toward TotalUsage), and all other
// pages in the file are free. AdoptExisting decommits (or zeroes) the pages
// that are in neither used nor unsaved, since free pages must be zeroed.
//
// used and unsaved must each be sorted, non-overlapping, mutually disjoint,
// page-aligned, and within the current size of the backing file.
//
// Preconditions:
//   - f was created with MemoryFileOpts.KeepFileContents.
//   - AdoptExisting has not yet been called on f, and no pages have been
//     allocated from f.
func (f *MemoryFile) AdoptExisting(used, unsaved []memmap.FileRange, kind usage.MemoryKind) error {
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
	if err := validateAdoptedRanges("adopted", used, curSize); err != nil {
		return err
	}
	if err := validateAdoptedRanges("unsaved", unsaved, curSize); err != nil {
		return err
	}
	for i, j := 0, 0; i < len(used) && j < len(unsaved); {
		if used[i].Overlaps(unsaved[j]) {
			return fmt.Errorf("adopted range %v overlaps unsaved range %v", used[i], unsaved[j])
		}
		if used[i].End <= unsaved[j].Start {
			i++
		} else {
			j++
		}
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
	if !f.unadopted || len(f.chunksLoad()) != 0 {
		return fmt.Errorf("AdoptExisting called more than once or after allocation")
	}
	if fileSize == 0 {
		f.unadopted = false
		return nil
	}
	if fileSize != curSize {
		if err := f.file.Truncate(int64(fileSize)); err != nil {
			return fmt.Errorf("failed to extend backing file to %d bytes: %w", fileSize, err)
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
		if fileSize != curSize {
			_ = f.file.Truncate(int64(curSize))
		}
		return fmt.Errorf("failed to mmap backing file: %w", errno)
	}
	chunks := make([]chunkInfo, nrChunks)
	for i := range chunks {
		chunks[i].mapping = m
		f.madviseChunkMapping(m, chunkSize, false /* huge */)
		m += chunkSize
	}
	f.chunks.Store(&chunks)
	f.unadopted = false

	// Free pages must be zeroed, so decommit (or manually zero) every page
	// range up to clearEnd that is in neither used nor unsaved. Pages in
	// [clearEnd, fileSize) were newly created by Truncate above and are already
	// uncommitted zeros.
	clearEnd := hostarch.MustPageRoundUp(curSize)
	var off uint64
	for i, j := 0, 0; i < len(used) || j < len(unsaved); {
		var fr memmap.FileRange
		if j >= len(unsaved) || (i < len(used) && used[i].Start < unsaved[j].Start) {
			fr = used[i]
			i++
		} else {
			fr = unsaved[j]
			j++
		}
		if off < fr.Start {
			f.decommitOrManuallyZero(memmap.FileRange{Start: off, End: fr.Start})
		}
		off = fr.End
	}
	if off < clearEnd {
		f.decommitOrManuallyZero(memmap.FileRange{Start: off, End: clearEnd})
	}

	// All chunks are small-page-backed. unfreeHuge already covers the whole
	// file, as for chunks that are backed by a different page size.
	// unwasteSmall and unwasteHuge already cover the whole file, since no
	// page is waste.
	f.unfreeSmall.RemoveAll()
	for _, fr := range used {
		f.unfreeSmall.InsertRange(fr, unfreeInfo{refs: 1})
	}
	for _, fr := range unsaved {
		f.unfreeSmall.InsertRange(fr, unfreeInfo{refs: 1, unsaved: true})
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

// ClaimFirstPageUnsaved reserves the first page [0, PageSize) of f as an
// unsaved range. It returns an error if the first page is already allocated.
func (f *MemoryFile) ClaimFirstPageUnsaved() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.chunksLoad()) == 0 {
		if err := f.extendChunksLocked(&allocState{length: hostarch.PageSize}); err != nil {
			return err
		}
	}
	ufgap := f.unfreeSmall.FindGap(0)
	if (!ufgap.Ok() || ufgap.Start() != 0 || ufgap.End() < hostarch.PageSize) && f.haveWaste {
		for f.haveWaste {
			f.mu.Unlock()
			runtime.Gosched()
			f.mu.Lock()
		}
		ufgap = f.unfreeSmall.FindGap(0)
	}
	if !ufgap.Ok() || ufgap.Start() != 0 || ufgap.End() < hostarch.PageSize {
		return fmt.Errorf("first page of MemoryFile is already allocated")
	}
	first := memmap.FileRange{Start: 0, End: hostarch.PageSize}
	f.unfreeSmall.Insert(ufgap, first, unfreeInfo{refs: 1, unsaved: true})
	return nil
}

// AllocateUnsaved allocates a contiguous page-aligned range of length bytes in
// f that is omitted from usage.MemoryAccounting and checkpoints (though
// committed blocks still count toward TotalUsage). The returned range must be
// released with FreeUnsaved (not DecRef).
func (f *MemoryFile) AllocateUnsaved(length uint64) (memmap.FileRange, error) {
	if length == 0 || !hostarch.IsPageAligned(length) {
		return memmap.FileRange{}, linuxerr.EINVAL
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ufgap := f.unfreeSmall.FirstLargeEnoughGap(length)
	if !ufgap.Ok() && f.haveWaste {
		for f.haveWaste {
			f.mu.Unlock()
			runtime.Gosched()
			f.mu.Lock()
		}
		ufgap = f.unfreeSmall.FirstLargeEnoughGap(length)
	}
	if !ufgap.Ok() {
		if err := f.extendChunksLocked(&allocState{length: length}); err != nil {
			return memmap.FileRange{}, err
		}
		ufgap = f.unfreeSmall.FirstLargeEnoughGap(length)
		if !ufgap.Ok() {
			return memmap.FileRange{}, linuxerr.ENOMEM
		}
	}
	fr := memmap.FileRange{Start: ufgap.Start(), End: ufgap.Start() + length}
	f.unfreeSmall.Insert(ufgap, fr, unfreeInfo{refs: 1, unsaved: true})
	return fr, nil
}

// FreeUnsaved decommits and frees an unsaved range previously reserved with
// AdoptExisting, ClaimFirstPageUnsaved, or AllocateUnsaved.
func (f *MemoryFile) FreeUnsaved(fr memmap.FileRange) {
	if !fr.WellFormed() || fr.Length() == 0 || !hostarch.IsPageAligned(fr.Start) || !hostarch.IsPageAligned(fr.End) {
		panic(fmt.Sprintf("invalid unsaved range: %v", fr))
	}
	f.mu.Lock()
	seg := f.unfreeSmall.LowerBoundSegment(fr.Start)
	for end := fr.Start; end < fr.End; {
		if !seg.Ok() || seg.Start() > end || seg.Value() != (unfreeInfo{refs: 1, unsaved: true}) {
			state := f.stringLocked()
			f.mu.Unlock()
			panic(fmt.Sprintf("FreeUnsaved(%v): unexpected state at %#x\n%s", fr, end, state))
		}
		if seg.Start() < fr.Start {
			seg = f.unfreeSmall.SplitBefore(seg, fr.Start)
		}
		seg = f.unfreeSmall.SplitAfter(seg, fr.End)
		*seg.ValuePtr() = unfreeInfo{refs: 0, unsaved: true}
		end = seg.End()
		seg = f.unfreeSmall.MergePrev(seg).NextSegment()
	}
	f.mu.Unlock()
	f.decommitOrManuallyZero(fr)
	f.mu.Lock()
	f.unfreeSmall.RemoveFullRange(fr)
	f.mu.Unlock()
}

// validateAdoptedRanges returns an error if ranges is not sorted,
// non-overlapping, page-aligned, and within [0, size).
func validateAdoptedRanges(kind string, ranges []memmap.FileRange, size uint64) error {
	var prevEnd uint64
	for i, fr := range ranges {
		if !fr.WellFormed() || fr.Length() == 0 {
			return fmt.Errorf("%s range %d %v is empty or malformed", kind, i, fr)
		}
		if !hostarch.IsPageAligned(fr.Start) || !hostarch.IsPageAligned(fr.End) {
			return fmt.Errorf("%s range %d %v is not page-aligned", kind, i, fr)
		}
		if fr.Start < prevEnd {
			return fmt.Errorf("%s range %d %v is not sorted or overlaps the previous range", kind, i, fr)
		}
		if fr.End > size {
			return fmt.Errorf("%s range %d %v exceeds the backing file size %#x", kind, i, fr, size)
		}
		prevEnd = fr.End
	}
	return nil
}
