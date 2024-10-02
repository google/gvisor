// Copyright 2024 The gVisor Authors.
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

//go:build linux
// +build linux

package kvm

import (
	"unsafe"
)

// seccompMmapHandler is a signal handler for runtime mmap system calls
// that are trapped by seccomp.
//
// It executes the mmap syscall with specified arguments and maps a new region
// to the guest.
//
//go:nosplit
func seccompMmapHandler(context unsafe.Pointer) {
	mmapCallCounter.Increment()

	addr, length, errno := seccompMmapSyscall(context)
	if errno != 0 {
		return
	}

	seccompMmapHandlerCnt.Add(1)
	for i := uint32(0); i < machinePoolLen.Load(); i++ {
		m := machinePool[i].Load()
		if m == nil {
			continue
		}

		// Map the new region to the guest.
		vr := region{
			virtual: addr,
			length:  length,
		}
		for virtual := vr.virtual; virtual < vr.virtual+vr.length; {
			physical, length, ok := translateToPhysical(virtual)
			if !ok {
				// This must be an invalid region that was
				// knocked out by creation of the physical map.
				return
			}
			if virtual+length > vr.virtual+vr.length {
				// Cap the length to the end of the area.
				length = vr.virtual + vr.length - virtual
			}

			// Ensure the physical range is mapped.
			m.mapPhysical(physical, length)
			virtual += length
		}
	}
	seccompMmapHandlerCnt.Add(-1)
}
