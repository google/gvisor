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
	"gvisor.dev/gvisor/pkg/hostsyscall"
)

var (
	// faultBlockSize is the size used for servicing memory faults.
	//
	// This should be large enough to avoid frequent faults and avoid using
	// all available KVM slots (~512), but small enough that KVM does not
	// complain about slot sizes (~4GB). See handleBluepillFault for how
	// this block is used.
	faultBlockSize = uintptr(2 << 30)

	// faultBlockMask is the mask for the fault blocks.
	//
	// This must be typed to avoid overflow complaints (ugh).
	faultBlockMask = ^uintptr(faultBlockSize - 1)
)

// yield yields the CPU.
//
//go:nosplit
func yield() {
	hostsyscall.RawSyscallErrno(unix.SYS_SCHED_YIELD, 0, 0, 0)
}

// calculateBluepillFault calculates the fault address range.
//
//go:nosplit
func calculateBluepillFault(physical uintptr) (virtualStart, physicalStart, length uintptr, pr *physicalRegion) {
	alignedPhysical := physical &^ uintptr(hostarch.PageSize-1)
	for i, pr := range physicalRegions {
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
		return virtualStart, physicalStart, length, &physicalRegions[i]
	}

	return 0, 0, 0, nil
}

//go:nosplit
func (m *machine) mapMemorySlot(virtualStart, physicalStart, length uintptr, readOnly bool) {
	// Set the KVM slot.
	//
	// First, we need to acquire the exclusive right to set a slot.  See
	// machine.nextSlot for information about the protocol.
	slot := m.nextSlot.Swap(^uint32(0))
	for slot == ^uint32(0) {
		yield() // Race with another call.
		slot = m.nextSlot.Swap(^uint32(0))
	}
	flags := _KVM_MEM_FLAGS_NONE
	if readOnly {
		flags |= _KVM_MEM_READONLY
	}
	errno := m.setMemoryRegion(int(slot), physicalStart, length, virtualStart, flags)
	if errno == 0 {
		// Store the physical address in the slot. This is used to
		// avoid calls to handleBluepillFault in the future (see
		// machine.mapPhysical).
		atomic.StoreUintptr(&m.usedSlots[slot], physicalStart)
		// Successfully added region; we can increment nextSlot and
		// allow another set to proceed here.
		m.nextSlot.Store(slot + 1)
		return
	}

	// Release our slot (still available).
	m.nextSlot.Store(slot)

	switch errno {
	case unix.EEXIST:
		// The region already exists. It's possible that we raced with
		// another vCPU here. We just revert nextSlot and return true,
		// because this must have been satisfied by some other vCPU.
		return
	case unix.EINVAL:
		throw("set memory region failed; out of slots")
	case unix.ENOMEM:
		throw("set memory region failed: out of memory")
	case unix.EFAULT:
		throw("set memory region failed: invalid physical range")
	default:
		printHex([]byte("set memory region failed:"), uint64(errno))
		throw("set memory region failed: unknown reason")
	}

	throw("unreachable")
}
