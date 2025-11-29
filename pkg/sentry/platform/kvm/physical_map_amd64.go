// Copyright 2019 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/ring0"
)

const (
	// reservedMemory is a chunk of physical memory reserved starting at
	// physical address zero. There are some special pages in this region,
	// so we just call the whole thing off.
	reservedMemory = 0x100000000
)

const (
	// defaultAddressSpaceSize is the default limit for the user virtual
	// address space, which is 47-bits (2^47 bytes). The mmap syscall
	// respects this limit by default, even with 5-level page tables
	// enabled.
	defaultAddressSpaceSize = uintptr(1) << 47

	// exendedAddressSpaceAllowed controls address space usage beyond
	// the default 47-bit limit. It is set to 'false' for several reasons:
	// * There are no known use cases requiring the extended address space.
	// * By restricting the size, we avoid the overhead of:
	//    a) Aligning the virtual address space size to the physical
	//       address space size.
	//    b) Creating unnecessary page table entries for the unused
	//       extended range.
	// * The memory slot size is currently configured only to cover
	//   the default 47-bit address space.
	// * 5-level page table support was primarily introduced to workaround
	//    a specific kernel bug where VDSO could be mapped above the 47-bit
	//    boundary (v6.9-rc1~186^2~7).
	exendedAddressSpaceAllowed = false
)

// archSpecialRegions returns special regions that are excluded from the virtual
// address space. Linux doesn't map vma-s above 47-bit by default.
func archSpecialRegions(vSize uintptr, maxUserAddr uintptr) (uintptr, []specialVirtualRegion) {
	var specialRegions []specialVirtualRegion
	if exendedAddressSpaceAllowed || vSize <= defaultAddressSpaceSize {
		return vSize, nil
	}
	// This is a workaround for the kernel bug when vdso can be
	// mapped above the 47-bit address space boundary.
	if defaultAddressSpaceSize > maxUserAddr {
		maxUserAddr = defaultAddressSpaceSize
	}
	r := region{
		virtual: maxUserAddr,
		length:  ring0.MaximumUserAddress - defaultAddressSpaceSize,
	}
	specialRegions = append(specialRegions, specialVirtualRegion{
		region: r,
	})
	vSize -= r.length
	log.Infof("excluded: virtual [%x,%x)", r.virtual, r.virtual+r.length)

	return vSize, specialRegions
}
