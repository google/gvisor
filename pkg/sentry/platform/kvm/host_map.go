// Copyright 2018 Google Inc.
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

package kvm

import (
	"fmt"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type hostMap struct {
	// mu protects below.
	mu sync.RWMutex

	// set contains host mappings.
	set hostMapSet
}

type hostMapEntry struct {
	addr   uintptr
	length uintptr
}

// forEach iterates over all mappings in the given range.
//
// Precondition: segFn and gapFn must be non-nil.
func (hm *hostMap) forEach(
	r usermem.AddrRange,
	segFn func(offset uint64, m hostMapEntry),
	gapFn func(offset uint64, length uintptr) (uintptr, bool)) {

	seg, gap := hm.set.Find(r.Start)
	for {
		if seg.Ok() && seg.Start() < r.End {
			// A valid segment: pass information.
			overlap := seg.Range().Intersect(r)
			segOffset := uintptr(overlap.Start - seg.Start())
			mapOffset := uint64(overlap.Start - r.Start)
			segFn(mapOffset, hostMapEntry{
				addr:   seg.Value() + segOffset,
				length: uintptr(overlap.Length()),
			})
			seg, gap = seg.NextNonEmpty()
		} else if gap.Ok() && gap.Start() < r.End {
			// A gap: pass gap information.
			overlap := gap.Range().Intersect(r)
			mapOffset := uint64(overlap.Start - r.Start)
			addr, ok := gapFn(mapOffset, uintptr(overlap.Length()))
			if ok {
				seg = hm.set.Insert(gap, overlap, addr)
				seg, gap = seg.NextNonEmpty()
			} else {
				seg = gap.NextSegment()
				gap = hostMapGapIterator{} // Invalid.
			}
		} else {
			// Terminal.
			break
		}
	}
}

func (hm *hostMap) createMappings(r usermem.AddrRange, at usermem.AccessType, fd int, offset uint64) (ms []hostMapEntry, err error) {
	hm.forEach(r, func(mapOffset uint64, m hostMapEntry) {
		// Replace any existing mappings.
		_, _, errno := syscall.RawSyscall6(
			syscall.SYS_MMAP,
			m.addr,
			m.length,
			uintptr(at.Prot()),
			syscall.MAP_FIXED|syscall.MAP_SHARED,
			uintptr(fd),
			uintptr(offset+mapOffset))
		if errno != 0 && err == nil {
			err = errno
		}
	}, func(mapOffset uint64, length uintptr) (uintptr, bool) {
		// Create a new mapping.
		addr, _, errno := syscall.RawSyscall6(
			syscall.SYS_MMAP,
			0,
			length,
			uintptr(at.Prot()),
			syscall.MAP_SHARED,
			uintptr(fd),
			uintptr(offset+mapOffset))
		if errno != 0 {
			err = errno
			return 0, false
		}
		return addr, true
	})
	if err != nil {
		return nil, err
	}

	// Collect all entries.
	//
	// We do this after the first iteration because some segments may have
	// been merged in the above, and we'll return the simplest form. This
	// also provides a basic sanity check in the form of no gaps.
	hm.forEach(r, func(_ uint64, m hostMapEntry) {
		ms = append(ms, m)
	}, func(uint64, uintptr) (uintptr, bool) {
		// Should not happen: we just mapped this above.
		panic("unexpected gap")
	})

	return ms, nil
}

// CreateMappings creates a new set of host mapping entries.
func (hm *hostMap) CreateMappings(r usermem.AddrRange, at usermem.AccessType, fd int, offset uint64) (ms []hostMapEntry, err error) {
	hm.mu.Lock()
	ms, err = hm.createMappings(r, at, fd, offset)
	hm.mu.Unlock()
	return
}

func (hm *hostMap) deleteMapping(r usermem.AddrRange) {
	// Remove all the existing mappings.
	hm.forEach(r, func(_ uint64, m hostMapEntry) {
		_, _, errno := syscall.RawSyscall(
			syscall.SYS_MUNMAP,
			m.addr,
			m.length,
			0)
		if errno != 0 {
			// Should never happen.
			panic(fmt.Sprintf("unmap error: %v", errno))
		}
	}, func(uint64, uintptr) (uintptr, bool) {
		// Sometimes deleteMapping will be called on a larger range
		// than physical mappings are defined. That's okay.
		return 0, false
	})

	// Knock the entire range out.
	hm.set.RemoveRange(r)
}

// DeleteMapping deletes the given range.
func (hm *hostMap) DeleteMapping(r usermem.AddrRange) {
	hm.mu.Lock()
	hm.deleteMapping(r)
	hm.mu.Unlock()
}

// hostMapSetFunctions is used in the implementation of mapSet.
type hostMapSetFunctions struct{}

func (hostMapSetFunctions) MinKey() usermem.Addr    { return 0 }
func (hostMapSetFunctions) MaxKey() usermem.Addr    { return ^usermem.Addr(0) }
func (hostMapSetFunctions) ClearValue(val *uintptr) { *val = 0 }

func (hostMapSetFunctions) Merge(r1 usermem.AddrRange, addr1 uintptr, r2 usermem.AddrRange, addr2 uintptr) (uintptr, bool) {
	if addr1+uintptr(r1.Length()) != addr2 {
		return 0, false
	}

	// Since the two regions are contiguous in both the key space and the
	// value space, we can just store a single segment with the first host
	// virtual address; the logic above operates based on the size of the
	// segments.
	return addr1, true
}

func (hostMapSetFunctions) Split(r usermem.AddrRange, hostAddr uintptr, split usermem.Addr) (uintptr, uintptr) {
	return hostAddr, hostAddr + uintptr(split-r.Start)
}
