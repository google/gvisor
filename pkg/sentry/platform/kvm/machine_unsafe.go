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

// +build go1.12
// +build !go1.16

// Check go:linkname function signatures when updating Go version.

package kvm

import (
	"fmt"
	"math"
	"sync/atomic"
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

//go:linkname entersyscall runtime.entersyscall
func entersyscall()

//go:linkname exitsyscall runtime.exitsyscall
func exitsyscall()

// setMemoryRegion initializes a region.
//
// This may be called from bluepillHandler, and therefore returns an errno
// directly (instead of wrapping in an error) to avoid allocations.
//
//go:nosplit
func (m *machine) setMemoryRegion(slot int, physical, length, virtual uintptr, flags uint32) syscall.Errno {
	userRegion := userMemoryRegion{
		slot:          uint32(slot),
		flags:         uint32(flags),
		guestPhysAddr: uint64(physical),
		memorySize:    uint64(length),
		userspaceAddr: uint64(virtual),
	}

	// Set the region.
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(m.fd),
		_KVM_SET_USER_MEMORY_REGION,
		uintptr(unsafe.Pointer(&userRegion)))
	return errno
}

// mapRunData maps the vCPU run data.
func mapRunData(fd int) (*runData, error) {
	r, _, errno := syscall.RawSyscall6(
		syscall.SYS_MMAP,
		0,
		uintptr(runDataSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED,
		uintptr(fd),
		0)
	if errno != 0 {
		return nil, fmt.Errorf("error mapping runData: %v", errno)
	}
	return (*runData)(unsafe.Pointer(r)), nil
}

// unmapRunData unmaps the vCPU run data.
func unmapRunData(r *runData) error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_MUNMAP,
		uintptr(unsafe.Pointer(r)),
		uintptr(runDataSize),
		0); errno != 0 {
		return fmt.Errorf("error unmapping runData: %v", errno)
	}
	return nil
}

// atomicAddressSpace is an atomic address space pointer.
type atomicAddressSpace struct {
	pointer unsafe.Pointer
}

// set sets the address space value.
//
//go:nosplit
func (a *atomicAddressSpace) set(as *addressSpace) {
	atomic.StorePointer(&a.pointer, unsafe.Pointer(as))
}

// get gets the address space value.
//
// Note that this should be considered best-effort, and may have changed by the
// time this function returns.
//
//go:nosplit
func (a *atomicAddressSpace) get() *addressSpace {
	return (*addressSpace)(atomic.LoadPointer(&a.pointer))
}

// notify notifies that the vCPU has transitioned modes.
//
// This may be called by a signal handler and therefore throws on error.
//
//go:nosplit
func (c *vCPU) notify() {
	_, _, errno := syscall.RawSyscall6( // escapes: no.
		syscall.SYS_FUTEX,
		uintptr(unsafe.Pointer(&c.state)),
		linux.FUTEX_WAKE|linux.FUTEX_PRIVATE_FLAG,
		math.MaxInt32, // Number of waiters.
		0, 0, 0)
	if errno != 0 {
		throw("futex wake error")
	}
}

// waitUntilNot waits for the vCPU to transition modes.
//
// The state should have been previously set to vCPUWaiter after performing an
// appropriate action to cause a transition (e.g. interrupt injection).
//
// This panics on error.
func (c *vCPU) waitUntilNot(state uint32) {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FUTEX,
		uintptr(unsafe.Pointer(&c.state)),
		linux.FUTEX_WAIT|linux.FUTEX_PRIVATE_FLAG,
		uintptr(state),
		0, 0, 0)
	if errno != 0 && errno != syscall.EINTR && errno != syscall.EAGAIN {
		panic("futex wait error")
	}
}
