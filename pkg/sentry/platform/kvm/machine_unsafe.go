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

//go:build go1.18
// +build go1.18

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

package kvm

import (
	"fmt"
	"math"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostsyscall"
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
func (m *machine) setMemoryRegion(slot int, physical, length, virtual uintptr, flags uint32) unix.Errno {
	userRegion := userMemoryRegion{
		slot:          uint32(slot),
		flags:         uint32(flags),
		guestPhysAddr: uint64(physical),
		memorySize:    uint64(length),
		userspaceAddr: uint64(virtual),
	}

	// Set the region.
	errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(m.fd),
		KVM_SET_USER_MEMORY_REGION,
		uintptr(unsafe.Pointer(&userRegion)))
	return errno
}

// mapRunData maps the vCPU run data.
func mapRunData(fd int) (*runData, error) {
	r, errno := hostsyscall.RawSyscall6(
		unix.SYS_MMAP,
		0,
		uintptr(runDataSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
		uintptr(fd),
		0)
	if errno != 0 {
		return nil, fmt.Errorf("error mapping runData: %v", errno)
	}
	return (*runData)(unsafe.Pointer(r)), nil
}

// unmapRunData unmaps the vCPU run data.
func unmapRunData(r *runData) error {
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_MUNMAP,
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

// availableNotify is called when a vCPU's state transitions to vCPUReady.
//
//go:nosplit
func (m *machine) availableNotify() {
	m.availableSeq.Add(1)
	if m.availableWaiters.Load() == 0 {
		return
	}
	errno := hostsyscall.RawSyscallErrno( // escapes: no.
		unix.SYS_FUTEX,
		uintptr(unsafe.Pointer(&m.availableSeq)),
		linux.FUTEX_WAKE|linux.FUTEX_PRIVATE_FLAG,
		1)
	if errno != 0 {
		throw("futex wake error")
	}
}

// availableWait blocks until availableNotify is called.
//
// Preconditions:
// - epoch was the value of m.availableSeq before the caller last checked that
// no vCPUs were in state vCPUReady.
// - m.availableWaiters must be non-zero.
//
//go:nosplit
func (m *machine) availableWait(epoch uint32) {
	_, _, errno := unix.Syscall6(
		unix.SYS_FUTEX,
		uintptr(unsafe.Pointer(&m.availableSeq)),
		linux.FUTEX_WAIT|linux.FUTEX_PRIVATE_FLAG,
		uintptr(epoch),
		0, 0, 0)
	if errno != 0 && errno != unix.EINTR && errno != unix.EAGAIN {
		panic("futex wait error")
	}
}

// notify notifies that the vCPU has transitioned modes.
//
// This may be called by a signal handler and therefore throws on error.
//
//go:nosplit
func (c *vCPU) notify() {
	errno := hostsyscall.RawSyscallErrno( // escapes: no.
		unix.SYS_FUTEX,
		uintptr(unsafe.Pointer(&c.state)),
		linux.FUTEX_WAKE|linux.FUTEX_PRIVATE_FLAG,
		// Number of waiters.
		math.MaxInt32)
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
	_, _, errno := unix.Syscall6(
		unix.SYS_FUTEX,
		uintptr(unsafe.Pointer(&c.state)),
		linux.FUTEX_WAIT|linux.FUTEX_PRIVATE_FLAG,
		uintptr(state),
		0, 0, 0)
	if errno != 0 && errno != unix.EINTR && errno != unix.EAGAIN {
		panic("futex wait error")
	}
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
	if errno := hostsyscall.RawSyscallErrno(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_SET_SIGNAL_MASK,
		uintptr(unsafe.Pointer(&data))); errno != 0 {
		return fmt.Errorf("error setting signal mask: %v", errno)
	}

	return nil
}

// seccompMmapHandlerCnt is a number of currently running seccompMmapHandler
// instances.
var seccompMmapHandlerCnt atomicbitops.Int64

// seccompMmapSync waits for all currently running seccompMmapHandler
// instances.
//
// The standard locking primitives can't be used in this case since
// seccompMmapHandler is executed in a signal handler context.
//
// It can be implemented by using FUTEX calls, but it will require to call
// FUTEX_WAKE from seccompMmapHandler. Consider machine.Destroy is called only
// once, and the probability is racing with seccompMmapHandler is very low the
// spinlock-like way looks more reasonable.
func seccompMmapSync() {
	for seccompMmapHandlerCnt.Load() != 0 {
		runtime.Gosched()
	}
}

// disableAsyncPreemption disables asynchronous preemption of go-routines.
func disableAsyncPreemption() {
	set := linux.MakeSignalSet(linux.SIGURG)
	errno := hostsyscall.RawSyscallErrno6(unix.SYS_RT_SIGPROCMASK, linux.SIG_BLOCK,
		uintptr(unsafe.Pointer(&set)), 0, linux.SignalSetSize, 0, 0)
	if errno != 0 {
		panic(fmt.Sprintf("sigprocmask failed: %d", errno))
	}
}

// enableAsyncPreemption enables asynchronous preemption of go-routines.
func enableAsyncPreemption() {
	set := linux.MakeSignalSet(linux.SIGURG)
	errno := hostsyscall.RawSyscallErrno6(unix.SYS_RT_SIGPROCMASK, linux.SIG_UNBLOCK,
		uintptr(unsafe.Pointer(&set)), 0, linux.SignalSetSize, 0, 0)
	if errno != 0 {
		panic(fmt.Sprintf("sigprocmask failed: %d", errno))
	}
}
