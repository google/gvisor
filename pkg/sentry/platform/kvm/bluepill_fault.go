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

package kvm

import (
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
)

var (
	// faultBlockSize is the size used for servicing memory faults.
	//
	// Its value has to be a power of 2.
	faultBlockSize uintptr

	// faultBlockMask is the mask for the fault blocks.
	faultBlockMask uintptr
)

// yield yields the CPU.
//
//go:nosplit
func yield() {
	unix.RawSyscall(unix.SYS_SCHED_YIELD, 0, 0, 0)
}

// calculateBluepillFault calculates the fault address range.
//
//go:nosplit
func calculateBluepillFault(physical uintptr, phyRegions []physicalRegion) (virtualStart, physicalStart, length uintptr, ok bool) {
	alignedPhysical := physical &^ uintptr(hostarch.PageSize-1)
	for _, pr := range phyRegions {
		end := pr.physical + pr.length
		if physical < pr.physical || physical >= end {
			continue
		}

		// Adjust the block to match our size.
		physicalStart = pr.physical + (alignedPhysical-pr.physical)&faultBlockMask
		virtualStart = pr.virtual + (physicalStart - pr.physical)
		physicalEnd := physicalStart + faultBlockSize
		if physicalEnd > end {
			physicalEnd = end
		}
		length = physicalEnd - physicalStart
		return virtualStart, physicalStart, length, true
	}

	return 0, 0, 0, false
}

// mapPhysicalSlot maps one physical slot.
//
// The slot physical address and its length is returned. This may throw on error.
func (m *machine) mapPhysicalSlot(physical uintptr, phyRegions []physicalRegion, flags uint32) (uintptr, uintptr, bool) {
	// Paging fault: we need to map the underlying physical pages for this
	// fault. This all has to be done in this function because we're in a
	// signal handler context. (We can't call any functions that might
	// split the stack.)
	virtualStart, physicalStart, length, ok := calculateBluepillFault(physical, phyRegions)
	if !ok {
		return 0, 0, false
	}

	slot := m.nextSlot
	errno := m.setMemoryRegion(int(slot), physicalStart, length, virtualStart, flags)
	if errno == 0 {
		// Store the physical address in the slot. This is used to
		// avoid calls to handleBluepillFault in the future (see
		// machine.mapPhysical).
		atomic.StoreUintptr(&m.usedSlots[slot], physicalStart)
		// Successfully added region; we can increment nextSlot and
		// allow another set to proceed here.
		m.nextSlot = slot + 1
		return physicalStart, length, true
	}

	switch errno {
	case unix.EEXIST:
		throw("set memory region failed; slot already exists")
	case unix.EINVAL:
		throw("set memory region failed; out of slots")
	case unix.ENOMEM:
		throw("set memory region failed: out of memory")
	case unix.EFAULT:
		throw("set memory region failed: invalid physical range")
	default:
		throw("set memory region failed: unknown reason")
	}

	panic("unreachable")
}
