// Copyright 2026 The gVisor Authors.
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

package slimvm

import (
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
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
func calculateBluepillFault(physical uintptr) (virtualStart, physicalStart, length uintptr, ok bool) {
	alignedPhysical := physical &^ uintptr(hostarch.PageSize-1)
	for _, pr := range physicalRegions {
		end := pr.physical + pr.length
		if physical < pr.physical || physical >= end {
			continue
		}

		// Adjust the block to match our size.
		physicalStart = alignedPhysical
		if physicalStart < pr.physical {
			// Bound the starting point to the start of the region.
			physicalStart = pr.physical
		}
		virtualStart = pr.virtual + (physicalStart - pr.physical)
		physicalEnd := physicalStart + pr.length
		if physicalEnd > end {
			physicalEnd = end
		}
		length = physicalEnd - physicalStart
		return virtualStart, physicalStart, length, true
	}

	return 0, 0, 0, false
}
