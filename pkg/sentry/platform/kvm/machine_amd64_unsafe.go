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
	"sync/atomic"
	"syscall"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/time"
)

// setMemoryRegion initializes a region.
//
// This may be called from bluepillHandler, and therefore returns an errno
// directly (instead of wrapping in an error) to avoid allocations.
//
//go:nosplit
func (m *machine) setMemoryRegion(slot int, physical, length, virtual uintptr) syscall.Errno {
	userRegion := userMemoryRegion{
		slot:          uint32(slot),
		flags:         0,
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

// loadSegments copies the current segments.
//
// This may be called from within the signal context and throws on error.
//
//go:nosplit
func (c *vCPU) loadSegments(tid uint64) {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_ARCH_PRCTL,
		linux.ARCH_GET_FS,
		uintptr(unsafe.Pointer(&c.CPU.Registers().Fs_base)),
		0); errno != 0 {
		throw("getting FS segment")
	}
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_ARCH_PRCTL,
		linux.ARCH_GET_GS,
		uintptr(unsafe.Pointer(&c.CPU.Registers().Gs_base)),
		0); errno != 0 {
		throw("getting GS segment")
	}
	atomic.StoreUint64(&c.tid, tid)
}

// setCPUID sets the CPUID to be used by the guest.
func (c *vCPU) setCPUID() error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_CPUID2,
		uintptr(unsafe.Pointer(&cpuidSupported))); errno != 0 {
		return fmt.Errorf("error setting CPUID: %v", errno)
	}
	return nil
}

// setSystemTime sets the TSC for the vCPU.
//
// FIXME: This introduces a slight TSC offset between host and
// guest, which may vary per vCPU.
func (c *vCPU) setSystemTime() error {
	const _MSR_IA32_TSC = 0x00000010
	registers := modelControlRegisters{
		nmsrs: 1,
	}
	registers.entries[0] = modelControlRegister{
		index: _MSR_IA32_TSC,
		data:  uint64(time.Rdtsc()),
	}
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_MSRS,
		uintptr(unsafe.Pointer(&registers))); errno != 0 {
		return fmt.Errorf("error setting system time: %v", errno)
	}
	return nil
}

// setSignalMask sets the vCPU signal mask.
//
// This must be called prior to running the vCPU.
func (c *vCPU) setSignalMask() error {
	// The layout of this structure implies that it will not necessarily be
	// the same layout chosen by the Go compiler. It gets fudged here.
	var data struct {
		length uint32
		mask1  uint32
		mask2  uint32
		_      uint32
	}
	data.length = 8 // Fixed sigset size.
	data.mask1 = ^uint32(bounceSignalMask & 0xffffffff)
	data.mask2 = ^uint32(bounceSignalMask >> 32)
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_SET_SIGNAL_MASK,
		uintptr(unsafe.Pointer(&data))); errno != 0 {
		return fmt.Errorf("error setting signal mask: %v", errno)
	}
	return nil
}
