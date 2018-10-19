// Copyright 2018 Google LLC
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
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

const (
	// faultBlockSize is the size used for servicing memory faults.
	//
	// This should be large enough to avoid frequent faults and avoid using
	// all available KVM slots (~512), but small enough that KVM does not
	// complain about slot sizes (~4GB). See handleBluepillFault for how
	// this block is used.
	faultBlockSize = 2 << 30

	// faultBlockMask is the mask for the fault blocks.
	//
	// This must be typed to avoid overflow complaints (ugh).
	faultBlockMask = ^uintptr(faultBlockSize - 1)
)

// yield yields the CPU.
//
//go:nosplit
func yield() {
	syscall.RawSyscall(syscall.SYS_SCHED_YIELD, 0, 0, 0)
}

// calculateBluepillFault calculates the fault address range.
//
//go:nosplit
func calculateBluepillFault(physical uintptr) (virtualStart, physicalStart, length uintptr, ok bool) {
	alignedPhysical := physical &^ uintptr(usermem.PageSize-1)
	for _, pr := range physicalRegions {
		end := pr.physical + pr.length
		if physical < pr.physical || physical >= end {
			continue
		}

		// Adjust the block to match our size.
		physicalStart = alignedPhysical & faultBlockMask
		if physicalStart < pr.physical {
			// Bound the starting point to the start of the region.
			physicalStart = pr.physical
		}
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

// handleBluepillFault handles a physical fault.
//
// The corresponding virtual address is returned. This may throw on error.
//
//go:nosplit
func handleBluepillFault(m *machine, physical uintptr) (uintptr, bool) {
	// Paging fault: we need to map the underlying physical pages for this
	// fault. This all has to be done in this function because we're in a
	// signal handler context. (We can't call any functions that might
	// split the stack.)
	virtualStart, physicalStart, length, ok := calculateBluepillFault(physical)
	if !ok {
		return 0, false
	}

	// Set the KVM slot.
	//
	// First, we need to acquire the exclusive right to set a slot.  See
	// machine.nextSlot for information about the protocol.
	slot := atomic.SwapUint32(&m.nextSlot, ^uint32(0))
	for slot == ^uint32(0) {
		yield() // Race with another call.
		slot = atomic.SwapUint32(&m.nextSlot, ^uint32(0))
	}
	errno := m.setMemoryRegion(int(slot), physicalStart, length, virtualStart)
	if errno == 0 {
		// Successfully added region; we can increment nextSlot and
		// allow another set to proceed here.
		atomic.StoreUint32(&m.nextSlot, slot+1)
		return virtualStart + (physical - physicalStart), true
	}

	// Release our slot (still available).
	atomic.StoreUint32(&m.nextSlot, slot)

	switch errno {
	case syscall.EEXIST:
		// The region already exists. It's possible that we raced with
		// another vCPU here. We just revert nextSlot and return true,
		// because this must have been satisfied by some other vCPU.
		return virtualStart + (physical - physicalStart), true
	case syscall.EINVAL:
		throw("set memory region failed; out of slots")
	case syscall.ENOMEM:
		throw("set memory region failed: out of memory")
	case syscall.EFAULT:
		throw("set memory region failed: invalid physical range")
	default:
		throw("set memory region failed: unknown reason")
	}

	panic("unreachable")
}
