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

package ptrace

import (
	"reflect"
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/safecopy"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// stub is defined in arch-specific assembly.
func stub()

// stubCall calls the stub at the given address with the given pid.
func stubCall(addr, pid uintptr)

// unsafeSlice returns a slice for the given address and length.
func unsafeSlice(addr uintptr, length int) (slice []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	sh.Data = addr
	sh.Len = length
	sh.Cap = length
	return
}

// stubInit initializes the stub.
func stubInit() {
	// Grab the existing stub.
	stubBegin := reflect.ValueOf(stub).Pointer()
	stubLen := int(safecopy.FindEndAddress(stubBegin) - stubBegin)
	stubSlice := unsafeSlice(stubBegin, stubLen)
	mapLen := uintptr(stubLen)
	if offset := mapLen % usermem.PageSize; offset != 0 {
		mapLen += usermem.PageSize - offset
	}

	for stubStart > 0 {
		// Map the target address for the stub.
		//
		// We don't use FIXED here because we don't want to unmap
		// something that may have been there already. We just walk
		// down the address space until we find a place where the stub
		// can be placed.
		addr, _, errno := syscall.RawSyscall6(
			syscall.SYS_MMAP,
			stubStart,
			mapLen,
			syscall.PROT_WRITE|syscall.PROT_READ,
			syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,
			0 /* fd */, 0 /* offset */)
		if addr != stubStart || errno != 0 {
			if addr != 0 {
				// Unmap the region we've mapped accidentally.
				syscall.RawSyscall(syscall.SYS_MUNMAP, addr, mapLen, 0)
			}

			// Attempt to begin at a lower address.
			stubStart -= uintptr(usermem.PageSize)
			continue
		}

		// Copy the stub to the address.
		targetSlice := unsafeSlice(addr, stubLen)
		copy(targetSlice, stubSlice)

		// Make the stub executable.
		if _, _, errno := syscall.RawSyscall(
			syscall.SYS_MPROTECT,
			stubStart,
			mapLen,
			syscall.PROT_EXEC|syscall.PROT_READ); errno != 0 {
			panic("mprotect failed: " + errno.Error())
		}

		// Set the end.
		stubEnd = stubStart + mapLen
		return
	}

	// This will happen only if we exhaust the entire address
	// space, and it will take a long, long time.
	panic("failed to map stub")
}
