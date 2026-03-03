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

package fsutil

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// MmapCachedFile implements MmapFile. It differs from MmapPreciseFile in the
// following notable ways:
//   - MmapCachedFile tracks referenced pages as host page cache usage in
//     sentry memory accounting. (This is the "cache" referred to by the name of
//     MmapCachedFile.) The AddMapping and RemoveMapping methods manipulate
//     reference counts without memory accounting.
//   - MmapCachedFile creates sentry mappings of referenced pages at aligned
//     units called "chunks", to expedite mapping reference counting and lookup.
//
// SetFD must be called on zero-value MmapCachedFiles before first use.
//
// +stateify savable
type MmapCachedFile struct {
	memmap.DefaultMemoryType
	memmap.NoBufferedIOFallback

	// fd is the file descriptor.
	fd atomicbitops.Int32

	refsMu refsMutex `state:"nosave"`

	// +checklocks:refsMu
	mappableReleased bool

	// refs maps chunk start offsets to the sum of reference counts for all
	// pages in that chunk.
	// +checklocks:refsMu
	refs map[uint64]int64

	// +checklocks:refsMu
	memAcct FrameRefSet

	mapsMu mapsMutex `state:"nosave"`

	// mappings maps chunk start offsets to mappings of those chunks.
	// +checklocks:mapsMu
	mappings map[uint64]mapping `state:"nosave"`
}

const (
	// TODO: In addition to compounding the repeated remapping problem
	// described in MmapCachedFile.DecRef, this small chunk size may contribute
	// to host VMA exhaustion. Consider increasing chunkShift. (But note that
	// larger values of chunkShift increase the speed with which applications
	// can consume sentry's address space, since only one byte per chunk needs
	// to be touched to cause the whole chunk to be mapped.)
	chunkShift = hostarch.HugePageShift
	chunkSize  = 1 << chunkShift
	chunkMask  = chunkSize - 1
)

func pagesInChunk(fr memmap.FileRange, chunkStart uint64) int64 {
	return int64(fr.Intersect(memmap.FileRange{chunkStart, chunkStart + chunkSize}).Length() / hostarch.PageSize)
}

// +stateify savable
type mapping struct {
	addr     uintptr
	writable bool
}

// SetFD implements MmapFile.SetFD.
//
// It is legal to call SetFD on a MmapCachedFile more than once; however,
// after the first call to SetFD that passes a non-negative fd, all calls to
// SetFD must pass the same fd.
func (f *MmapCachedFile) SetFD(fd int) {
	f.fd.Store(int32(fd))
}

func (f *MmapCachedFile) close() {
	if fd := f.fd.RacyLoad(); fd >= 0 {
		unix.Close(int(fd))
		f.fd.RacyStore(-1)
	}
}

// MappableRelease implements MmapFile.MappableRelease.
func (f *MmapCachedFile) MappableRelease() {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	if f.mappableReleased {
		return
	}
	f.mappableReleased = true
	if len(f.refs) == 0 {
		f.close()
	}
}

// IncRef implements memmap.File.IncRef.
func (f *MmapCachedFile) IncRef(fr memmap.FileRange, memCgID uint32) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	f.incRefUnaccounted(fr)
	f.memAcct.IncRefAndAccount(fr, memCgID)
}

// AddMapping is called by implementations of memmap.Mappable.AddMapping to
// increment the reference count on the pages mapped by ar, starting at the
// given file offset, without affecting memory accounting. This is not needed
// for correctness, but ensures that mappings of those pages will be maintained
// if all references obtained using IncRef are dropped. The reference must be
// released using RemoveMapping when no longer needed.
//
// AddMapping may be called on pages without an existing reference as long as
// f.MappableRelease() has not been called.
//
// Preconditions: As for memmap.Mappable.AddMapping.
func (f *MmapCachedFile) AddMapping(ar hostarch.AddrRange, offset uint64) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	f.incRefUnaccounted(memmap.FileRange{offset, offset + uint64(ar.Length())})
}

// Preconditions:
//   - fr.Length() != 0.
//   - fr.Start and fr.End must be page-aligned.
//
// +checklocks:f.refsMu
func (f *MmapCachedFile) incRefUnaccounted(fr memmap.FileRange) {
	if f.refs == nil {
		f.refs = make(map[uint64]int64)
	}
	chunkStart := fr.Start &^ chunkMask
	for {
		refs := f.refs[chunkStart]
		pgs := pagesInChunk(fr, chunkStart)
		if refs+pgs < refs {
			// Would overflow.
			panic(fmt.Sprintf("fsutil.MmapCachedFile.IncRef(%v): adding %d page references to chunk %#x, which has %d page references", fr, pgs, chunkStart, refs))
		}
		f.refs[chunkStart] = refs + pgs
		chunkStart += chunkSize
		if chunkStart >= fr.End || chunkStart == 0 {
			break
		}
	}
}

// DecRef implements memmap.File.DecRef.
func (f *MmapCachedFile) DecRef(fr memmap.FileRange) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	f.decRefUnaccounted(fr)
	f.memAcct.DecRefAndAccount(fr)
}

// RemoveMapping is called by implementations of memmap.Mappable.RemoveMapping
// to release page references acquired by AddMapping.
//
// Preconditions: As for memmap.Mappable.RemoveMapping.
func (f *MmapCachedFile) RemoveMapping(ar hostarch.AddrRange, offset uint64) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	f.decRefUnaccounted(memmap.FileRange{offset, offset + uint64(ar.Length())})
}

// Preconditions:
//   - fr.Length() != 0.
//   - fr.Start and fr.End must be page-aligned.
//
// +checklocks:f.refsMu
func (f *MmapCachedFile) decRefUnaccounted(fr memmap.FileRange) {
	chunkStart := fr.Start &^ chunkMask
	for {
		refs := f.refs[chunkStart]
		pgs := pagesInChunk(fr, chunkStart)
		switch {
		case refs > pgs:
			f.refs[chunkStart] = refs - pgs
		case refs == pgs:
			delete(f.refs, chunkStart)
			// TODO: Unmapping here generally means that mappings of host FDs
			// will be unmapped when there are no application VMAs mapping f,
			// e.g. between process executions, which may be expensive for some
			// workloads. Consider retaining mappings until f.close() instead.
			// This would also let us drop Add/RemoveMapping.
			f.mapsMu.Lock()
			if m, ok := f.mappings[chunkStart]; ok {
				f.unmapAndRemove(chunkStart, m)
			}
			f.mapsMu.Unlock()
		case refs < pgs:
			panic(fmt.Sprintf("fsutil.MmapCachedFile.DecRef(%v): removing %d page references from chunk %#x, which has %d page references", fr, pgs, chunkStart, refs))
		}
		chunkStart += chunkSize
		if chunkStart >= fr.End || chunkStart == 0 {
			break
		}
	}
	if f.mappableReleased && len(f.refs) == 0 {
		f.close()
	}
}

// Preconditions:
//   - f.mappings[chunkStart] == m.
//
// +checklocks:f.mapsMu
func (f *MmapCachedFile) unmapAndRemove(chunkStart uint64, m mapping) {
	if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, m.addr, chunkSize, 0); errno != 0 {
		// This leaks address space and is unexpected, but is otherwise
		// harmless, so complain but don't panic.
		log.Warningf("fsutil.MmapCachedFile: failed to unmap mapping %#x for chunk %#x: %v", m.addr, chunkStart, errno)
	}
	delete(f.mappings, chunkStart)
}

// MapInternal implements memmap.File.MapInternal.
func (f *MmapCachedFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	chunks := ((fr.End + chunkMask) >> chunkShift) - (fr.Start >> chunkShift)
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()
	if chunks == 1 {
		// Avoid an unnecessary slice allocation.
		var seq safemem.BlockSeq
		err := f.forEachMappingBlockLocked(fr, at.Write, func(b safemem.Block) {
			seq = safemem.BlockSeqOf(b)
		})
		return seq, err
	}
	blocks := make([]safemem.Block, 0, chunks)
	err := f.forEachMappingBlockLocked(fr, at.Write, func(b safemem.Block) {
		blocks = append(blocks, b)
	})
	return safemem.BlockSeqFromSlice(blocks), err
}

// +checklocks:f.mapsMu
func (f *MmapCachedFile) forEachMappingBlockLocked(fr memmap.FileRange, write bool, fn func(safemem.Block)) error {
	fd := f.fd.Load()
	if fd < 0 {
		return unix.EBADF
	}
	prot := unix.PROT_READ
	if write {
		prot |= unix.PROT_WRITE
	}
	chunkStart := fr.Start &^ chunkMask
	if f.mappings == nil {
		f.mappings = make(map[uint64]mapping)
	}
	for {
		m, ok := f.mappings[chunkStart]
		if !ok {
			addr, _, errno := unix.Syscall6(
				unix.SYS_MMAP,
				0,
				chunkSize,
				uintptr(prot),
				unix.MAP_SHARED,
				uintptr(fd),
				uintptr(chunkStart))
			if errno != 0 {
				return errno
			}
			m = mapping{addr, write}
			f.mappings[chunkStart] = m
		} else if write && !m.writable {
			addr, _, errno := unix.Syscall6(
				unix.SYS_MMAP,
				m.addr,
				chunkSize,
				uintptr(prot),
				unix.MAP_SHARED|unix.MAP_FIXED,
				uintptr(fd),
				uintptr(chunkStart))
			if errno != 0 {
				return errno
			}
			m = mapping{addr, write}
			f.mappings[chunkStart] = m
		}
		var startOff uint64
		if chunkStart < fr.Start {
			startOff = fr.Start - chunkStart
		}
		endOff := uint64(chunkSize)
		if chunkStart+chunkSize > fr.End {
			endOff = fr.End - chunkStart
		}
		fn(unsafeBlockFromMapping(m.addr, chunkSize).TakeFirst64(endOff).DropFirst64(startOff))
		chunkStart += chunkSize
		if chunkStart >= fr.End || chunkStart == 0 {
			break
		}
	}
	return nil
}

// RegenerateMappings must be called when the file description mapped by f
// changes, to replace existing mappings of the previous file description.
//
// Preconditions:
//   - f.MappableRelease() is not called concurrently with, or before,
//     f.RegenerateMappings().
func (f *MmapCachedFile) RegenerateMappings() error {
	fd := f.fd.Load()
	if fd < 0 {
		// No previous call to f.MapInternal() can have succeeded.
		return nil
	}

	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()

	for chunkStart, m := range f.mappings {
		prot := unix.PROT_READ
		if m.writable {
			prot |= unix.PROT_WRITE
		}
		_, _, errno := unix.Syscall6(
			unix.SYS_MMAP,
			m.addr,
			chunkSize,
			uintptr(prot),
			unix.MAP_SHARED|unix.MAP_FIXED,
			uintptr(fd),
			uintptr(chunkStart))
		if errno != 0 {
			return errno
		}
	}
	return nil
}

// DataFD implements memmap.File.DataFD.
func (f *MmapCachedFile) DataFD(fr memmap.FileRange) (int, error) {
	fd := f.FD()
	if fd < 0 {
		return -1, unix.EBADF
	}
	return fd, nil
}

// FD implements memmap.File.FD.
func (f *MmapCachedFile) FD() int {
	return int(f.fd.Load())
}
