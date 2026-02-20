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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// PreciseHostFileMapper caches mappings of an arbitrary host file descriptor.
// It is used by implementations of memmap.Mappable that represent a host file
// descriptor. It differs from HostFileMapper in that it maps at exact page
// boundaries specified in a file range, not in chunks.
//
// +stateify savable
type PreciseHostFileMapper struct {
	addrMustEqualFileOffset bool

	refsMu refsMutex `state:"nosave"`

	// +checklocks:refsMu
	refs refsSet

	mapsMu mapsMutex `state:"nosave"`

	// mappings is a set of internal mappings of the device. The value is a
	// mapping object.
	//
	// +checklocks:mapsMu
	mappings mappingSet
}

// NewPreciseHostFileMapper returns an initialized PreciseHostFileMapper
// allocated on the heap with no references or cached mappings.
func NewPreciseHostFileMapper() *PreciseHostFileMapper {
	f := &PreciseHostFileMapper{}
	return f
}

// RequireAddrEqualsFileOffset causes the PreciseHostFileMapper to map the host
// file descriptor at addresses equal to the corresponding file offsets.
func (f *PreciseHostFileMapper) RequireAddrEqualsFileOffset() {
	f.addrMustEqualFileOffset = true
}

// IncRefOn increments the reference count on all pages in mr.
//
// Preconditions:
//   - mr.Length() != 0.
//   - mr.Start and mr.End must be page-aligned.
func (f *PreciseHostFileMapper) IncRefOn(mr memmap.MappableRange) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	fr := memmap.FileRange(mr)
	seg, gap := f.refs.Find(fr.Start)
	for seg.Ok() || gap.Ok() {
		if seg.Ok() {
			seg = f.refs.Isolate(seg, fr)
			refs := seg.ValuePtr()
			*refs++
		} else if gap.Ok() {
			seg = f.refs.Insert(gap, fr.Intersect(gap.Range()), 1)
		}
		if seg.End() >= fr.End {
			break
		}
		fr.Start = seg.End()
		seg, gap = seg.NextNonEmpty()
	}
}

// DecRefOn decrements the reference count on all offsets in mr.
//
// Preconditions:
//   - mr.Length() != 0.
//   - mr.Start and mr.End must be page-aligned.
func (f *PreciseHostFileMapper) DecRefOn(mr memmap.MappableRange) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	rseg := f.refs.FindSegment(mr.Start)
	if !rseg.Ok() {
		panic(fmt.Sprintf("could not find segment for range %v", mr))
	}
	fr := memmap.FileRange(mr)
	for fr.Length() > 0 && rseg.Ok() {
		rseg = f.refs.Isolate(rseg, fr)
		refs := rseg.ValuePtr()
		*refs--
		gap := refsGapIterator{}
		fr.Start = rseg.End()
		if *refs == 0 {
			f.mapsMu.Lock()
			f.mappings.RemoveRangeWith(rseg.Range(), f.unmapSegmentLocked)
			f.mapsMu.Unlock()
			gap = f.refs.RemoveRange(rseg.Range())
		}
		if gap.Ok() {
			rseg = gap.NextSegment()
		} else {
			rseg = rseg.NextSegment()
		}
	}
}

// MapInternal returns a mapping of offsets in fr from fd. The returned
// safemem.BlockSeq is valid as long as at least one reference is held on all
// offsets in fr or until the next call to UnmapAll.
//
// Preconditions: The caller must hold a reference on all offsets in fr.
func (f *PreciseHostFileMapper) MapInternal(fr memmap.FileRange, fd int, write bool) (safemem.BlockSeq, error) {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()
	prot := unix.PROT_READ
	if write {
		prot |= unix.PROT_WRITE
	}

	origFR := fr
	var blocks []safemem.Block
	seg, gap := f.mappings.Find(fr.Start)
	for seg.Ok() || gap.Ok() {
		if seg.Ok() {
			block, newSeg, errno := f.mapInternalSegment(&fr, seg, fd, prot, write)
			if errno != 0 {
				return safemem.BlockSeq{}, errno
			}
			blocks = append(blocks, block)
			seg, gap = newSeg.NextNonEmpty()

			if fr.Length() == 0 {
				break
			}
		}
		if gap.Ok() {
			block, newSeg, errno := f.mapInternalGap(&fr, gap, fd, prot, write)
			if errno != 0 {
				return safemem.BlockSeq{}, errno
			}
			blocks = append(blocks, block)
			seg, gap = newSeg.NextSegment(), mappingGapIterator{}

			if fr.Length() == 0 {
				break
			}
		}
	}
	if fr.Length() > 0 {
		return safemem.BlockSeq{}, fmt.Errorf("failed to map range %v", origFR)
	}

	return safemem.BlockSeqFromSlice(blocks), nil
}

// +checklocks:f.mapsMu
func (f *PreciseHostFileMapper) mapInternalSegment(fr *memmap.FileRange, seg mappingIterator, fd int, prot int, write bool) (safemem.Block, mappingIterator, syscall.Errno) {
	addr := seg.Value().addr + uintptr(fr.Start-seg.Start())
	if !seg.Value().writable && write {
		seg = f.mappings.Isolate(seg, *fr)
		_, _, errno := unix.Syscall6(
			unix.SYS_MMAP,
			addr,
			uintptr(seg.Range().Length()),
			uintptr(prot),
			unix.MAP_SHARED|unix.MAP_FIXED,
			uintptr(fd),
			uintptr(seg.Start()))
		if errno != 0 {
			return safemem.Block{}, seg, errno
		}
		seg.ValuePtr().writable = write
	}
	mapRange := seg.Range().Intersect(*fr)
	fr.Start = mapRange.End
	return unsafeBlockFromMapping(addr, int(mapRange.Length())), seg, 0
}

// +checklocks:f.mapsMu
func (f *PreciseHostFileMapper) mapInternalGap(fr *memmap.FileRange, gap mappingGapIterator, fd int, prot int, write bool) (safemem.Block, mappingIterator, syscall.Errno) {
	newRange := fr.Intersect(gap.Range())
	var (
		addr  uintptr
		errno unix.Errno
	)
	if f.addrMustEqualFileOffset {
		addr, _, errno = unix.Syscall6(
			unix.SYS_MMAP,
			uintptr(newRange.Start),
			uintptr(newRange.Length()),
			uintptr(prot),
			unix.MAP_SHARED|unix.MAP_FIXED_NOREPLACE,
			uintptr(fd),
			uintptr(newRange.Start))
		if errno == 0 && uint64(addr) != newRange.Start {
			// The host kernel predates MAP_FIXED_NOREPLACE and the requested
			// address would conflict with an existing mapping. Return EEXIST
			// for consistency with MAP_FIXED_NOREPLACE.
			errno = unix.EEXIST
			unix.RawSyscall(unix.SYS_MUNMAP, addr, uintptr(newRange.Length()), 0)
		}
	} else {
		addr, _, errno = unix.Syscall6(
			unix.SYS_MMAP,
			0,
			uintptr(newRange.Length()),
			uintptr(prot),
			unix.MAP_SHARED,
			uintptr(fd),
			uintptr(newRange.Start))
	}
	if errno != 0 {
		return safemem.Block{}, mappingIterator{}, errno
	}
	fr.Start = newRange.End
	seg := f.mappings.Insert(gap, newRange, mapping{addr: addr, writable: write})
	return unsafeBlockFromMapping(addr, int(newRange.Length())), seg, 0
}

// UnmapAll unmaps all cached mappings. Callers are responsible for
// synchronization with mappings returned by previous calls to MapInternal.
func (f *PreciseHostFileMapper) UnmapAll() {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()
	for seg := f.mappings.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		f.unmapSegmentLocked(seg)
	}
	f.mappings.RemoveAll()
}

// +checklocks:f.mapsMu
func (f *PreciseHostFileMapper) unmapSegmentLocked(mseg mappingIterator) {
	if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, uintptr(mseg.Value().addr), uintptr(mseg.Range().Length()), 0); errno != 0 {
		// This leaks address space and is unexpected, but is otherwise
		// harmless, so complain but don't panic.
		log.Warningf("HostFileMapper: failed to unmap mapping %#x: %v", mseg.Range().Start, errno)
	}
}

type refsSetFuncs struct{}

func (refsSetFuncs) MinKey() uint64 {
	return 0
}

func (refsSetFuncs) MaxKey() uint64 {
	return ^uint64(0)
}

func (refsSetFuncs) ClearValue(val *uint64) {
	*val = 0
}

func (refsSetFuncs) Merge(r1 memmap.FileRange, v1 uint64, r2 memmap.FileRange, v2 uint64) (uint64, bool) {
	return v1, v1 == v2
}

func (refsSetFuncs) Split(r memmap.FileRange, val uint64, split uint64) (uint64, uint64) {
	return val, val
}

type mappingSetFuncs struct{}

func (mappingSetFuncs) MinKey() uint64 {
	return 0
}

func (mappingSetFuncs) MaxKey() uint64 {
	return ^uint64(0)
}

func (mappingSetFuncs) ClearValue(val *mapping) {
	*val = mapping{}
}

func (mappingSetFuncs) Merge(r1 memmap.FileRange, v1 mapping, r2 memmap.FileRange, v2 mapping) (mapping, bool) {
	// Are we the same writability?
	if v1.writable != v2.writable {
		return mapping{}, false
	}

	// Do we have contiguous offsets in the backing file?
	if v1.addr+uintptr(r1.Length()) != v2.addr {
		return mapping{}, false
	}

	return v1, true
}

func (mappingSetFuncs) Split(r memmap.FileRange, val mapping, split uint64) (mapping, mapping) {
	n := split - r.Start

	left := val

	right := val
	right.addr += uintptr(n)

	return left, right
}
