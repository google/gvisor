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
	"syscall"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// HostFileMapper caches mappings of an arbitrary host file descriptor. It is
// used by implementations of memmap.Mappable that represent a host file
// descriptor.
//
// +stateify savable
type HostFileMapper struct {
	// HostFile conceptually breaks the file into pieces called chunks, of
	// size and alignment chunkSize, and caches mappings of the file on a chunk
	// granularity.

	refsMu sync.Mutex `state:"nosave"`

	// refs maps chunk start offsets to the sum of reference counts for all
	// pages in that chunk. refs is protected by refsMu.
	refs map[uint64]int32

	mapsMu sync.Mutex `state:"nosave"`

	// mappings maps chunk start offsets to mappings of those chunks,
	// obtained by calling syscall.Mmap. mappings is protected by
	// mapsMu.
	mappings map[uint64]mapping `state:"nosave"`
}

const (
	chunkShift = usermem.HugePageShift
	chunkSize  = 1 << chunkShift
	chunkMask  = chunkSize - 1
)

func pagesInChunk(mr memmap.MappableRange, chunkStart uint64) int32 {
	return int32(mr.Intersect(memmap.MappableRange{chunkStart, chunkStart + chunkSize}).Length() / usermem.PageSize)
}

type mapping struct {
	addr     uintptr
	writable bool
}

// Init must be called on zero-value HostFileMappers before first use.
func (f *HostFileMapper) Init() {
	f.refs = make(map[uint64]int32)
	f.mappings = make(map[uint64]mapping)
}

// IsInited returns true if f.Init() has been called. This is used when
// restoring a checkpoint that contains a HostFileMapper that may or may not
// have been initialized.
func (f *HostFileMapper) IsInited() bool {
	return f.refs != nil
}

// NewHostFileMapper returns an initialized HostFileMapper allocated on the
// heap with no references or cached mappings.
func NewHostFileMapper() *HostFileMapper {
	f := &HostFileMapper{}
	f.Init()
	return f
}

// IncRefOn increments the reference count on all offsets in mr.
//
// Preconditions:
// * mr.Length() != 0.
// * mr.Start and mr.End must be page-aligned.
func (f *HostFileMapper) IncRefOn(mr memmap.MappableRange) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	for chunkStart := mr.Start &^ chunkMask; chunkStart < mr.End; chunkStart += chunkSize {
		refs := f.refs[chunkStart]
		pgs := pagesInChunk(mr, chunkStart)
		if refs+pgs < refs {
			// Would overflow.
			panic(fmt.Sprintf("HostFileMapper.IncRefOn(%v): adding %d page references to chunk %#x, which has %d page references", mr, pgs, chunkStart, refs))
		}
		f.refs[chunkStart] = refs + pgs
	}
}

// DecRefOn decrements the reference count on all offsets in mr.
//
// Preconditions:
// * mr.Length() != 0.
// * mr.Start and mr.End must be page-aligned.
func (f *HostFileMapper) DecRefOn(mr memmap.MappableRange) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	for chunkStart := mr.Start &^ chunkMask; chunkStart < mr.End; chunkStart += chunkSize {
		refs := f.refs[chunkStart]
		pgs := pagesInChunk(mr, chunkStart)
		switch {
		case refs > pgs:
			f.refs[chunkStart] = refs - pgs
		case refs == pgs:
			f.mapsMu.Lock()
			delete(f.refs, chunkStart)
			if m, ok := f.mappings[chunkStart]; ok {
				f.unmapAndRemoveLocked(chunkStart, m)
			}
			f.mapsMu.Unlock()
		case refs < pgs:
			panic(fmt.Sprintf("HostFileMapper.DecRefOn(%v): removing %d page references from chunk %#x, which has %d page references", mr, pgs, chunkStart, refs))
		}
	}
}

// MapInternal returns a mapping of offsets in fr from fd. The returned
// safemem.BlockSeq is valid as long as at least one reference is held on all
// offsets in fr or until the next call to UnmapAll.
//
// Preconditions: The caller must hold a reference on all offsets in fr.
func (f *HostFileMapper) MapInternal(fr memmap.FileRange, fd int, write bool) (safemem.BlockSeq, error) {
	chunks := ((fr.End + chunkMask) >> chunkShift) - (fr.Start >> chunkShift)
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()
	if chunks == 1 {
		// Avoid an unnecessary slice allocation.
		var seq safemem.BlockSeq
		err := f.forEachMappingBlockLocked(fr, fd, write, func(b safemem.Block) {
			seq = safemem.BlockSeqOf(b)
		})
		return seq, err
	}
	blocks := make([]safemem.Block, 0, chunks)
	err := f.forEachMappingBlockLocked(fr, fd, write, func(b safemem.Block) {
		blocks = append(blocks, b)
	})
	return safemem.BlockSeqFromSlice(blocks), err
}

// Preconditions: f.mapsMu must be locked.
func (f *HostFileMapper) forEachMappingBlockLocked(fr memmap.FileRange, fd int, write bool, fn func(safemem.Block)) error {
	prot := syscall.PROT_READ
	if write {
		prot |= syscall.PROT_WRITE
	}
	for chunkStart := fr.Start &^ chunkMask; chunkStart < fr.End; chunkStart += chunkSize {
		m, ok := f.mappings[chunkStart]
		if !ok {
			addr, _, errno := syscall.Syscall6(
				syscall.SYS_MMAP,
				0,
				chunkSize,
				uintptr(prot),
				syscall.MAP_SHARED,
				uintptr(fd),
				uintptr(chunkStart))
			if errno != 0 {
				return errno
			}
			m = mapping{addr, write}
			f.mappings[chunkStart] = m
		} else if write && !m.writable {
			addr, _, errno := syscall.Syscall6(
				syscall.SYS_MMAP,
				m.addr,
				chunkSize,
				uintptr(prot),
				syscall.MAP_SHARED|syscall.MAP_FIXED,
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
		fn(f.unsafeBlockFromChunkMapping(m.addr).TakeFirst64(endOff).DropFirst64(startOff))
	}
	return nil
}

// UnmapAll unmaps all cached mappings. Callers are responsible for
// synchronization with mappings returned by previous calls to MapInternal.
func (f *HostFileMapper) UnmapAll() {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()
	for chunkStart, m := range f.mappings {
		f.unmapAndRemoveLocked(chunkStart, m)
	}
}

// Preconditions:
// * f.mapsMu must be locked.
// * f.mappings[chunkStart] == m.
func (f *HostFileMapper) unmapAndRemoveLocked(chunkStart uint64, m mapping) {
	if _, _, errno := syscall.Syscall(syscall.SYS_MUNMAP, m.addr, chunkSize, 0); errno != 0 {
		// This leaks address space and is unexpected, but is otherwise
		// harmless, so complain but don't panic.
		log.Warningf("HostFileMapper: failed to unmap mapping %#x for chunk %#x: %v", m.addr, chunkStart, errno)
	}
	delete(f.mappings, chunkStart)
}

// RegenerateMappings must be called when the file description mapped by f
// changes, to replace existing mappings of the previous file description.
func (f *HostFileMapper) RegenerateMappings(fd int) error {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()

	for chunkStart, m := range f.mappings {
		prot := syscall.PROT_READ
		if m.writable {
			prot |= syscall.PROT_WRITE
		}
		_, _, errno := syscall.Syscall6(
			syscall.SYS_MMAP,
			m.addr,
			chunkSize,
			uintptr(prot),
			syscall.MAP_SHARED|syscall.MAP_FIXED,
			uintptr(fd),
			uintptr(chunkStart))
		if errno != 0 {
			return errno
		}
	}
	return nil
}
