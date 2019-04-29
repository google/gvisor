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

// +build amd64

package kvm

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	runDataSize    int
	hasGuestPCID   bool
	cpuidSupported = cpuidEntries{nr: _KVM_NR_CPUID_ENTRIES}
)

func updateSystemValues(fd int) error {
	// Extract the mmap size.
	sz, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, uintptr(fd), _KVM_GET_VCPU_MMAP_SIZE, 0)
	if errno != 0 {
		return fmt.Errorf("getting VCPU mmap size: %v", errno)
	}

	// Save the data.
	runDataSize = int(sz)

	// Must do the dance to figure out the number of entries.
	_, _, errno = syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		_KVM_GET_SUPPORTED_CPUID,
		uintptr(unsafe.Pointer(&cpuidSupported)))
	if errno != 0 && errno != syscall.ENOMEM {
		// Some other error occurred.
		return fmt.Errorf("getting supported CPUID: %v", errno)
	}

	// The number should now be correct.
	_, _, errno = syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		_KVM_GET_SUPPORTED_CPUID,
		uintptr(unsafe.Pointer(&cpuidSupported)))
	if errno != 0 {
		// Didn't work with the right number.
		return fmt.Errorf("getting supported CPUID (2nd attempt): %v", errno)
	}

	// Calculate whether guestPCID is supported.
	//
	// FIXME(ascannell): These should go through the much more pleasant
	// cpuid package interfaces, once a way to accept raw kvm CPUID entries
	// is plumbed (or some rough equivalent).
	for i := 0; i < int(cpuidSupported.nr); i++ {
		entry := cpuidSupported.entries[i]
		if entry.function == 1 && entry.index == 0 && entry.ecx&(1<<17) != 0 {
			hasGuestPCID = true // Found matching PCID in guest feature set.
		}
	}

	// Success.
	return nil
}
