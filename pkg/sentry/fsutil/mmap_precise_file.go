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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// MmapPreciseFile implements MmapFile. It differs from MmapCachedFile in the
// following notable ways:
//   - MmapPreciseFile does not track referenced pages in sentry memory
//     accounting.
//   - MmapPreciseFile creates sentry mappings of referenced pages at exact
//     page boundaries specified in a file range.
//
// SetFD must be called on zero-value MmapPreciseFiles before first use.
//
// +stateify savable
type MmapPreciseFile struct {
	memmap.NoBufferedIOFallback

	// immutable after initialization
	fd                      int
	memType                 hostarch.MemoryType
	addrMustEqualFileOffset bool

	refsMu refsMutex `state:"nosave"`

	// +checklocks:refsMu
	mappableReleased bool

	// +checklocks:refsMu
	refs refsSet

	mapsMu mapsMutex `state:"nosave"`

	// mappings is a set of internal mappings of the device. The value is a
	// mapping object.
	//
	// +checklocks:mapsMu
	mappings mappingSet
}

// SetFD implements MmapFile.SetFD.
func (f *MmapPreciseFile) SetFD(fd int) {
	f.fd = fd
}

// SetMemType sets the value returned by MemoryType. If used, it must be called
// before first use of the MmapPreciseFile.
func (f *MmapPreciseFile) SetMemType(mt hostarch.MemoryType) {
	f.memType = mt
}

// RequireAddrEqualsFileOffset causes the MmapPreciseFile to map the host file
// descriptor at addresses equal to the corresponding file offsets. If used, it
// must be called before first use of the MmapPreciseFile.
func (f *MmapPreciseFile) RequireAddrEqualsFileOffset() {
	f.addrMustEqualFileOffset = true
}

func (f *MmapPreciseFile) close() {
	if f.fd >= 0 {
		unix.Close(f.fd)
		f.fd = -1
	}
}

// MappableRelease implements MmapFile.MappableRelease.
func (f *MmapPreciseFile) MappableRelease() {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	if f.mappableReleased {
		return
	}
	f.mappableReleased = true
	if f.refs.IsEmpty() {
		f.close()
	}
}

// IncRef implements memmap.File.IncRef.
func (f *MmapPreciseFile) IncRef(fr memmap.FileRange, memCgID uint32) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	seg, gap := f.refs.Find(fr.Start)
	for seg.Ok() || gap.Ok() {
		if seg.Ok() {
			seg = f.refs.Isolate(seg, fr)
			refs := seg.ValuePtr()
			newRefs := *refs + 1
			if newRefs < *refs {
				panic(fmt.Sprintf("fsutil.MmapPreciseFile.IncRef(%v): adding page reference to %v would overflow", fr, seg.Range()))
			}
			*refs = newRefs
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

// DecRef implements memmap.File.DecRef.
func (f *MmapPreciseFile) DecRef(fr memmap.FileRange) {
	f.refsMu.Lock()
	defer f.refsMu.Unlock()
	rseg := f.refs.FindSegment(fr.Start)
	if !rseg.Ok() {
		panic(fmt.Sprintf("could not find segment for range %v", fr))
	}
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
	if f.mappableReleased && f.refs.IsEmpty() {
		f.close()
	}
}

// MapInternal implements memmap.File.MapInternal.
func (f *MmapPreciseFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	f.mapsMu.Lock()
	defer f.mapsMu.Unlock()
	prot := unix.PROT_READ
	if at.Write {
		prot |= unix.PROT_WRITE
	}

	origFR := fr
	var blocks []safemem.Block
	seg, gap := f.mappings.Find(fr.Start)
	for seg.Ok() || gap.Ok() {
		if seg.Ok() {
			block, newSeg, errno := f.mapInternalSegment(&fr, seg, prot, at.Write)
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
			block, newSeg, errno := f.mapInternalGap(&fr, gap, prot, at.Write)
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
func (f *MmapPreciseFile) mapInternalSegment(fr *memmap.FileRange, seg mappingIterator, prot int, write bool) (safemem.Block, mappingIterator, syscall.Errno) {
	addr := seg.Value().addr + uintptr(fr.Start-seg.Start())
	if !seg.Value().writable && write {
		seg = f.mappings.Isolate(seg, *fr)
		_, _, errno := unix.Syscall6(
			unix.SYS_MMAP,
			addr,
			uintptr(seg.Range().Length()),
			uintptr(prot),
			unix.MAP_SHARED|unix.MAP_FIXED,
			uintptr(f.fd),
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
func (f *MmapPreciseFile) mapInternalGap(fr *memmap.FileRange, gap mappingGapIterator, prot int, write bool) (safemem.Block, mappingIterator, syscall.Errno) {
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
			uintptr(f.fd),
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
			uintptr(f.fd),
			uintptr(newRange.Start))
	}
	if errno != 0 {
		return safemem.Block{}, mappingIterator{}, errno
	}
	fr.Start = newRange.End
	seg := f.mappings.Insert(gap, newRange, mapping{addr: addr, writable: write})
	return unsafeBlockFromMapping(addr, int(newRange.Length())), seg, 0
}

// +checklocks:f.mapsMu
func (f *MmapPreciseFile) unmapSegmentLocked(mseg mappingIterator) {
	if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, uintptr(mseg.Value().addr), uintptr(mseg.Range().Length()), 0); errno != 0 {
		// This leaks address space and is unexpected, but is otherwise
		// harmless, so complain but don't panic.
		log.Warningf("fsutil.MmapPreciseFile: failed to unmap mapping %#x: %v", mseg.Range().Start, errno)
	}
}

// MemoryType implements memmap.File.MemoryType.
func (f *MmapPreciseFile) MemoryType() hostarch.MemoryType {
	return f.memType
}

// DataFD implements memmap.File.DataFD.
func (f *MmapPreciseFile) DataFD(fr memmap.FileRange) (int, error) {
	return f.fd, nil
}

// FD implements memmap.File.FD.
func (f *MmapPreciseFile) FD() int {
	return f.fd
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
