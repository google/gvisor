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

	// cached maps start offsets of chunks in mappings with no referenced pages
	// to their entries in chunkCache.
	// +checklocks:mapsMu
	cached map[uint64]*cachedChunk `state:"nosave"`
}

// chunkCache holds chunk mappings with no referenced pages, across all
// MmapCachedFiles, so that mapping the same pages again reuses them. On the
// KVM platform, a new mapping must also be faulted into the guest one page at
// a time.
var chunkCache struct {
	mu chunkCacheMutex

	// chunks is ordered from most to least recently unreferenced.
	chunks chunkList

	len int
}

var (
	// maxCachedChunks is the maximum length of chunkCache.chunks.
	maxCachedChunks = 4096

	// chunkCacheEvictBatch is how far below maxCachedChunks an overflow
	// evicts chunkCache.chunks.
	chunkCacheEvictBatch = 1024
)

// cachedChunk is an entry in chunkCache.chunks.
type cachedChunk struct {
	chunkEntry

	file       *MmapCachedFile
	chunkStart uint64

	// inList is true while the chunk is in chunkCache.chunks. inList is
	// protected by chunkCache.mu.
	inList bool
}

// chunkShift returns the binary log of the chunk size, which is the huge page
// size. It is not a constant since the huge page size is only known at runtime
// on some architectures.
//
// TODO: This small chunk size may contribute to host VMA exhaustion.
// Consider increasing chunkShift. (But note that larger values of chunkShift
// increase the speed with which applications can consume sentry's address
// space, since only one byte per chunk needs to be touched to cause the whole
// chunk to be mapped.)
func chunkShift() uint {
	return hostarch.HugePageShift
}

// chunkSize returns the size of a chunk.
func chunkSize() uint64 {
	return 1 << chunkShift()
}

// chunkMask returns chunkSize() - 1.
func chunkMask() uint64 {
	return chunkSize() - 1
}

func pagesInChunk(fr memmap.FileRange, chunkStart uint64) int64 {
	return int64(fr.Intersect(memmap.FileRange{Start: chunkStart, End: chunkStart + chunkSize()}).Length() >> hostarch.PageShift)
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
	f.mapsMu.Lock()
	for chunkStart, m := range f.mappings {
		f.unmapAndRemove(chunkStart, m)
	}
	f.mapsMu.Unlock()
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
	chunkStart := fr.Start &^ chunkMask()
	for {
		refs := f.refs[chunkStart]
		pgs := pagesInChunk(fr, chunkStart)
		if refs+pgs < refs {
			// Would overflow.
			panic(fmt.Sprintf("fsutil.MmapCachedFile.IncRef(%v): adding %d page references to chunk %#x, which has %d page references", fr, pgs, chunkStart, refs))
		}
		if refs == 0 {
			f.mapsMu.Lock()
			f.uncacheChunkLocked(chunkStart)
			f.mapsMu.Unlock()
		}
		f.refs[chunkStart] = refs + pgs
		chunkStart += chunkSize()
		if chunkStart >= fr.End || chunkStart == 0 {
			break
		}
	}
}

// DecRef implements memmap.File.DecRef.
func (f *MmapCachedFile) DecRef(fr memmap.FileRange) {
	f.refsMu.Lock()
	evict := f.decRefUnaccounted(fr)
	f.memAcct.DecRefAndAccount(fr)
	f.refsMu.Unlock()
	if evict {
		evictCachedChunks()
	}
}

// RemoveMapping is called by implementations of memmap.Mappable.RemoveMapping
// to release page references acquired by AddMapping.
//
// Preconditions: As for memmap.Mappable.RemoveMapping.
func (f *MmapCachedFile) RemoveMapping(ar hostarch.AddrRange, offset uint64) {
	f.refsMu.Lock()
	evict := f.decRefUnaccounted(memmap.FileRange{offset, offset + uint64(ar.Length())})
	f.refsMu.Unlock()
	if evict {
		evictCachedChunks()
	}
}

// decRefUnaccounted returns true if chunkCache needs eviction.
//
// Preconditions:
//   - fr.Length() != 0.
//   - fr.Start and fr.End must be page-aligned.
//
// +checklocks:f.refsMu
func (f *MmapCachedFile) decRefUnaccounted(fr memmap.FileRange) bool {
	evict := false
	chunkStart := fr.Start &^ chunkMask()
	for {
		refs := f.refs[chunkStart]
		pgs := pagesInChunk(fr, chunkStart)
		switch {
		case refs > pgs:
			f.refs[chunkStart] = refs - pgs
		case refs == pgs:
			delete(f.refs, chunkStart)
			f.mapsMu.Lock()
			if m, ok := f.mappings[chunkStart]; ok {
				if f.mappableReleased {
					f.unmapAndRemove(chunkStart, m)
				} else if f.cacheChunkLocked(chunkStart) {
					evict = true
				}
			}
			f.mapsMu.Unlock()
		case refs < pgs:
			panic(fmt.Sprintf("fsutil.MmapCachedFile.DecRef(%v): removing %d page references from chunk %#x, which has %d page references", fr, pgs, chunkStart, refs))
		}
		chunkStart += chunkSize()
		if chunkStart >= fr.End || chunkStart == 0 {
			break
		}
	}
	if f.mappableReleased && len(f.refs) == 0 {
		f.close()
	}
	return evict
}

// cacheChunkLocked adds the mapping of the chunk at chunkStart to chunkCache,
// and returns true if chunkCache needs eviction.
//
// +checklocks:f.mapsMu
func (f *MmapCachedFile) cacheChunkLocked(chunkStart uint64) bool {
	c := &cachedChunk{file: f, chunkStart: chunkStart, inList: true}
	if f.cached == nil {
		f.cached = make(map[uint64]*cachedChunk)
	}
	f.cached[chunkStart] = c
	chunkCache.mu.Lock()
	defer chunkCache.mu.Unlock()
	chunkCache.chunks.PushFront(c)
	chunkCache.len++
	return chunkCache.len > maxCachedChunks
}

// uncacheChunkLocked removes the chunk at chunkStart from chunkCache, if it is
// there.
//
// +checklocks:f.mapsMu
func (f *MmapCachedFile) uncacheChunkLocked(chunkStart uint64) {
	c, ok := f.cached[chunkStart]
	if !ok {
		return
	}
	delete(f.cached, chunkStart)
	chunkCache.mu.Lock()
	defer chunkCache.mu.Unlock()
	if c.inList {
		chunkCache.chunks.Remove(c)
		chunkCache.len--
		c.inList = false
	}
}

// evictCachedChunks unmaps the least recently unreferenced chunks in
// chunkCache until chunkCache.len is at most maxCachedChunks -
// chunkCacheEvictBatch.
func evictCachedChunks() {
	for {
		chunkCache.mu.Lock()
		if chunkCache.len <= maxCachedChunks-chunkCacheEvictBatch {
			chunkCache.mu.Unlock()
			return
		}
		c := chunkCache.chunks.Back()
		chunkCache.chunks.Remove(c)
		chunkCache.len--
		c.inList = false
		chunkCache.mu.Unlock()

		// c's pages may have been referenced again after c was removed from
		// chunkCache.chunks, in which case c is no longer in f.cached.
		f := c.file
		f.mapsMu.Lock()
		if f.cached[c.chunkStart] == c {
			f.unmapAndRemove(c.chunkStart, f.mappings[c.chunkStart])
		}
		f.mapsMu.Unlock()
	}
}

// Preconditions:
//   - f.mappings[chunkStart] == m.
//
// +checklocks:f.mapsMu
func (f *MmapCachedFile) unmapAndRemove(chunkStart uint64, m mapping) {
	if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, m.addr, uintptr(chunkSize()), 0); errno != 0 {
		// This leaks address space and is unexpected, but is otherwise
		// harmless, so complain but don't panic.
		log.Warningf("fsutil.MmapCachedFile: failed to unmap mapping %#x for chunk %#x: %v", m.addr, chunkStart, errno)
	}
	delete(f.mappings, chunkStart)
	f.uncacheChunkLocked(chunkStart)
}

// MapInternal implements memmap.File.MapInternal.
func (f *MmapCachedFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	chunks := ((fr.End + chunkMask()) >> chunkShift()) - (fr.Start >> chunkShift())
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
	chunkStart := fr.Start &^ chunkMask()
	if f.mappings == nil {
		f.mappings = make(map[uint64]mapping)
	}
	for {
		m, ok := f.mappings[chunkStart]
		if !ok {
			addr, _, errno := unix.Syscall6(
				unix.SYS_MMAP,
				0,
				uintptr(chunkSize()),
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
				uintptr(chunkSize()),
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
		endOff := chunkSize()
		if chunkStart+chunkSize() > fr.End {
			endOff = fr.End - chunkStart
		}
		fn(unsafeBlockFromMapping(m.addr, int(chunkSize())).TakeFirst64(endOff).DropFirst64(startOff))
		chunkStart += chunkSize()
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
			uintptr(chunkSize()),
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
