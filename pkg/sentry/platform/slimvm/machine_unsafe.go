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
	"math"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostsyscall"
)

//go:linkname entersyscall runtime.entersyscall
func entersyscall()

//go:linkname exitsyscall runtime.exitsyscall
func exitsyscall()

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
	errno := hostsyscall.RawSyscallErrno6(
		unix.SYS_FUTEX,
		uintptr(unsafe.Pointer(&c.state)),
		linux.FUTEX_WAKE,
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
func (c *vCPU) waitUntilNot(state uint32) bool {
	// Check transition mode before to issue a SYS_FUTEX.
	if c.state.Load() != state {
		return false
	}
	ts := linux.Timespec{Sec: 1}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FUTEX,
		uintptr(unsafe.Pointer(&c.state)),
		linux.FUTEX_WAIT,
		uintptr(state),
		uintptr(unsafe.Pointer(&ts)),
		0, 0)
	if errno != 0 && errno != syscall.EINTR && errno != syscall.EAGAIN && errno != syscall.ETIMEDOUT {
		panic("futex wait error")
	}
	return errno == syscall.ETIMEDOUT
}

// createVCPU create VCPU in slimvm.
func (c *vCPU) createVCPU(memoryRegions []userMemoryRegion) (uintptr, unix.Errno) {
	c.vmxConfig.memoryRegionNum = uint64(len(memoryRegions))
	c.vmxConfig.memoryRegionAddr = uintptr(unsafe.Pointer(&memoryRegions[0]))

	return hostsyscall.RawSyscall(unix.SYS_IOCTL, slimvmFD, _SLIMVM_CREATE_VCPU, uintptr(unsafe.Pointer(&c.vmxConfig)))
}
