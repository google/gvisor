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

func (hm *hostMap) forEachEntry(r usermem.AddrRange, fn func(offset uint64, m hostMapEntry)) {
	for seg := hm.set.FindSegment(r.Start); seg.Ok() && seg.Start() < r.End; seg = seg.NextSegment() {
		length := uintptr(seg.Range().Length())
		segOffset := uint64(0) // Adjusted below.
		if seg.End() > r.End {
			length -= uintptr(seg.End() - r.End)
		}
		if seg.Start() < r.Start {
			length -= uintptr(r.Start - seg.Start())
		} else {
			segOffset = uint64(seg.Start() - r.Start)
		}
		fn(segOffset, hostMapEntry{
			addr:   seg.Value(),
			length: length,
		})
	}
}

func (hm *hostMap) createMappings(r usermem.AddrRange, at usermem.AccessType, fd int, offset uint64) (ms []hostMapEntry, err error) {
	// Replace any existing mappings.
	hm.forEachEntry(r, func(segOffset uint64, m hostMapEntry) {
		_, _, errno := syscall.RawSyscall6(
			syscall.SYS_MMAP,
			m.addr,
			m.length,
			uintptr(at.Prot()),
			syscall.MAP_FIXED|syscall.MAP_SHARED,
			uintptr(fd),
			uintptr(offset+segOffset))
		if errno != 0 && err == nil {
			err = errno
		}
	})
	if err != nil {
		return nil, err
	}

	// Add in necessary new mappings.
	for gap := hm.set.FindGap(r.Start); gap.Ok() && gap.Start() < r.End; {
		length := uintptr(gap.Range().Length())
		gapOffset := uint64(0) // Adjusted below.
		if gap.End() > r.End {
			length -= uintptr(gap.End() - r.End)
		}
		if gap.Start() < r.Start {
			length -= uintptr(r.Start - gap.Start())
		} else {
			gapOffset = uint64(gap.Start() - r.Start)
		}

		// Map the host file memory.
		hostAddr, _, errno := syscall.RawSyscall6(
			syscall.SYS_MMAP,
			0,
			length,
			uintptr(at.Prot()),
			syscall.MAP_SHARED,
			uintptr(fd),
			uintptr(offset+gapOffset))
		if errno != 0 {
			return nil, errno
		}

		// Insert into the host set and move to the next gap.
		gap = hm.set.Insert(gap, gap.Range().Intersect(r), hostAddr).NextGap()
	}

	// Collect all slices.
	hm.forEachEntry(r, func(_ uint64, m hostMapEntry) {
		ms = append(ms, m)
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
	hm.forEachEntry(r, func(_ uint64, m hostMapEntry) {
		_, _, errno := syscall.RawSyscall(
			syscall.SYS_MUNMAP,
			m.addr,
			m.length,
			0)
		if errno != 0 {
			// Should never happen.
			panic(fmt.Sprintf("unmap error: %v", errno))
		}
	})

	// Knock the range out.
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
