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
	"sort"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

const (
	// reservedMemory is a chunk of physical memory reserved starting at
	// physical address zero. There are some special pages in this region,
	// so we just call the whole thing off.
	//
	// Other architectures may define this to be zero.
	reservedMemory = 0x100000000
)

type region struct {
	virtual uintptr
	length  uintptr
}

type physicalRegion struct {
	region
	physical uintptr
}

// physicalRegions contains a list of available physical regions.
//
// The physical value used in physicalRegions is a number indicating the
// physical offset, aligned appropriately and starting above reservedMemory.
var physicalRegions []physicalRegion

// fillAddressSpace fills the host address space with PROT_NONE mappings until
// the number of available bits until we have a host address space size that is
// equal to the physical address space.
//
// The excluded regions are returned.
func fillAddressSpace() (excludedRegions []region) {
	// We can cut vSize in half, because the kernel will be using the top
	// half and we ignore it while constructing mappings. It's as if we've
	// already excluded half the possible addresses.
	vSize := uintptr(1) << ring0.VirtualAddressBits()
	vSize = vSize >> 1

	// We exclude reservedMemory below from our physical memory size, so it
	// needs to be dropped here as well. Otherwise, we could end up with
	// physical addresses that are beyond what is mapped.
	pSize := uintptr(1) << ring0.PhysicalAddressBits()
	pSize -= reservedMemory

	// Sanity check.
	if vSize < pSize {
		panic(fmt.Sprintf("vSize (%x) < pSize (%x)", vSize, pSize))
	}

	// Add specifically excluded regions; see excludeVirtualRegion.
	applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) {
			excludedRegions = append(excludedRegions, vr.region)
			vSize -= vr.length
			log.Infof("excluded: virtual [%x,%x)", vr.virtual, vr.virtual+vr.length)
		}
	})

	// Calculate the required space and fill it.
	//
	// Note carefully that we add faultBlockSize to required up front, and
	// on each iteration of the loop below (i.e. each new physical region
	// we define), we add faultBlockSize again. This is done because the
	// computation of physical regions will ensure proper alignments with
	// faultBlockSize, potentially causing up to faultBlockSize bytes in
	// internal fragmentation for each physical region. So we need to
	// account for this properly during allocation.
	requiredAddr, ok := usermem.Addr(vSize - pSize + faultBlockSize).RoundUp()
	if !ok {
		panic(fmt.Sprintf(
			"overflow for vSize (%x) - pSize (%x) + faultBlockSize (%x)",
			vSize, pSize, faultBlockSize))
	}
	required := uintptr(requiredAddr)
	current := required // Attempted mmap size.
	for filled := uintptr(0); filled < required && current > 0; {
		addr, _, errno := syscall.RawSyscall6(
			syscall.SYS_MMAP,
			0, // Suggested address.
			current,
			syscall.PROT_NONE,
			syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE|syscall.MAP_NORESERVE,
			0, 0)
		if errno != 0 {
			// Attempt half the size; overflow not possible.
			currentAddr, _ := usermem.Addr(current >> 1).RoundUp()
			current = uintptr(currentAddr)
			continue
		}
		// We filled a block.
		filled += current
		excludedRegions = append(excludedRegions, region{
			virtual: addr,
			length:  current,
		})
		// See comment above.
		if filled != required {
			required += faultBlockSize
		}
	}
	if current == 0 {
		panic("filling address space failed")
	}
	sort.Slice(excludedRegions, func(i, j int) bool {
		return excludedRegions[i].virtual < excludedRegions[j].virtual
	})
	for _, r := range excludedRegions {
		log.Infof("region: virtual [%x,%x)", r.virtual, r.virtual+r.length)
	}
	return excludedRegions
}

// computePhysicalRegions computes physical regions.
func computePhysicalRegions(excludedRegions []region) (physicalRegions []physicalRegion) {
	physical := uintptr(reservedMemory)
	addValidRegion := func(virtual, length uintptr) {
		if length == 0 {
			return
		}
		if virtual == 0 {
			virtual += usermem.PageSize
			length -= usermem.PageSize
		}
		if end := virtual + length; end > ring0.MaximumUserAddress {
			length -= (end - ring0.MaximumUserAddress)
		}
		if length == 0 {
			return
		}
		// Round physical up to the same alignment as the virtual
		// address (with respect to faultBlockSize).
		if offset := virtual &^ faultBlockMask; physical&^faultBlockMask != offset {
			if newPhysical := (physical & faultBlockMask) + offset; newPhysical > physical {
				physical = newPhysical // Round up by only a little bit.
			} else {
				physical = ((physical + faultBlockSize) & faultBlockMask) + offset
			}
		}
		physicalRegions = append(physicalRegions, physicalRegion{
			region: region{
				virtual: virtual,
				length:  length,
			},
			physical: physical,
		})
		physical += length
	}
	lastExcludedEnd := uintptr(0)
	for _, r := range excludedRegions {
		addValidRegion(lastExcludedEnd, r.virtual-lastExcludedEnd)
		lastExcludedEnd = r.virtual + r.length
	}
	addValidRegion(lastExcludedEnd, ring0.MaximumUserAddress-lastExcludedEnd)

	// Dump our all physical regions.
	for _, r := range physicalRegions {
		log.Infof("physicalRegion: virtual [%x,%x) => physical [%x,%x)",
			r.virtual, r.virtual+r.length, r.physical, r.physical+r.length)
	}
	return physicalRegions
}

// physicalInit initializes physical address mappings.
func physicalInit() {
	physicalRegions = computePhysicalRegions(fillAddressSpace())
}

// applyPhysicalRegions applies the given function on physical regions.
//
// Iteration continues as long as true is returned. The return value is the
// return from the last call to fn, or true if there are no entries.
//
// Precondition: physicalInit must have been called.
func applyPhysicalRegions(fn func(pr physicalRegion) bool) bool {
	for _, pr := range physicalRegions {
		if !fn(pr) {
			return false
		}
	}
	return true
}

// TranslateToPhysical translates the given virtual address.
//
// Precondition: physicalInit must have been called.
func TranslateToPhysical(virtual uintptr) (physical uintptr, length uintptr, ok bool) {
	ok = !applyPhysicalRegions(func(pr physicalRegion) bool {
		if pr.virtual <= virtual && virtual < pr.virtual+pr.length {
			physical = pr.physical + (virtual - pr.virtual)
			length = pr.length - (virtual - pr.virtual)
			return false
		}
		return true
	})
	return
}
