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
// +build !go1.18

// Check go:linkname function signatures when updating Go version.

package kvm

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

//go:linkname throw runtime.throw
func throw(string)

// vCPUPtr returns a CPU for the given address.
//
//go:nosplit
func vCPUPtr(addr uintptr) *vCPU {
	return (*vCPU)(unsafe.Pointer(addr))
}

// bytePtr returns a bytePtr for the given address.
//
//go:nosplit
func bytePtr(addr uintptr) *byte {
	return (*byte)(unsafe.Pointer(addr))
}

// uintptrValue returns a uintptr for the given address.
//
//go:nosplit
func uintptrValue(addr *byte) uintptr {
	return (uintptr)(unsafe.Pointer(addr))
}

// bluepillArchContext returns the UContext64.
//
//go:nosplit
func bluepillArchContext(context unsafe.Pointer) *arch.SignalContext64 {
	return &((*arch.UContext64)(context).MContext)
}

// bluepillHandleHlt is reponsible for handling VM-Exit.
//
//go:nosplit
func bluepillGuestExit(c *vCPU, context unsafe.Pointer) {
	// Increment our counter.
	atomic.AddUint64(&c.guestExits, 1)

	// Copy out registers.
	bluepillArchExit(c, bluepillArchContext(context))

	// Return to the vCPUReady state; notify any waiters.
	user := atomic.LoadUint32(&c.state) & vCPUUser
	switch atomic.SwapUint32(&c.state, user) {
	case user | vCPUGuest: // Expected case.
	case user | vCPUGuest | vCPUWaiter:
		c.notify()
	default:
		throw("invalid state")
	}
}

// bluepillHandler is called from the signal stub.
//
// The world may be stopped while this is executing, and it executes on the
// signal stack. It should only execute raw system calls and functions that are
// explicitly marked go:nosplit.
//
// +checkescape:all
//
//go:nosplit
func bluepillHandler(context unsafe.Pointer) {
	// Sanitize the registers; interrupts must always be disabled.
	c := bluepillArchEnter(bluepillArchContext(context))

	// Mark this as guest mode.
	switch atomic.SwapUint32(&c.state, vCPUGuest|vCPUUser) {
	case vCPUUser: // Expected case.
	case vCPUUser | vCPUWaiter:
		c.notify()
	default:
		throw("invalid state")
	}

	for {
		_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(c.fd), _KVM_RUN, 0) // escapes: no.
		switch errno {
		case 0: // Expected case.
		case unix.EINTR:
			// First, we process whatever pending signal
			// interrupted KVM. Since we're in a signal handler
			// currently, all signals are masked and the signal
			// must have been delivered directly to this thread.
			timeout := unix.Timespec{}
			sig, _, errno := unix.RawSyscall6( // escapes: no.
				unix.SYS_RT_SIGTIMEDWAIT,
				uintptr(unsafe.Pointer(&bounceSignalMask)),
				0,                                 // siginfo.
				uintptr(unsafe.Pointer(&timeout)), // timeout.
				8,                                 // sigset size.
				0, 0)
			if errno == unix.EAGAIN {
				continue
			}
			if errno != 0 {
				throw("error waiting for pending signal")
			}
			if sig != uintptr(bounceSignal) {
				throw("unexpected signal")
			}

			// Check whether the current state of the vCPU is ready
			// for interrupt injection. Because we don't have a
			// PIC, we can't inject an interrupt while they are
			// masked. We need to request a window if it's not
			// ready.
			if bluepillReadyStopGuest(c) {
				// Force injection below; the vCPU is ready.
				c.runData.exitReason = _KVM_EXIT_IRQ_WINDOW_OPEN
			} else {
				c.runData.requestInterruptWindow = 1
				continue // Rerun vCPU.
			}
		case unix.EFAULT:
			// If a fault is not serviceable due to the host
			// backing pages having page permissions, instead of an
			// MMIO exit we receive EFAULT from the run ioctl. We
			// always inject an NMI here since we may be in kernel
			// mode and have interrupts disabled.
			bluepillSigBus(c)
			continue // Rerun vCPU.
		case unix.ENOSYS:
			bluepillHandleEnosys(c)
			continue
		default:
			throw("run failed")
		}

		switch c.runData.exitReason {
		case _KVM_EXIT_EXCEPTION:
			c.die(bluepillArchContext(context), "exception")
			return
		case _KVM_EXIT_IO:
			c.die(bluepillArchContext(context), "I/O")
			return
		case _KVM_EXIT_INTERNAL_ERROR:
			// An internal error is typically thrown when emulation
			// fails. This can occur via the MMIO path below (and
			// it might fail because we have multiple regions that
			// are not mapped). We would actually prefer that no
			// emulation occur, and don't mind at all if it fails.
		case _KVM_EXIT_HYPERCALL:
			c.die(bluepillArchContext(context), "hypercall")
			return
		case _KVM_EXIT_DEBUG:
			c.die(bluepillArchContext(context), "debug")
			return
		case _KVM_EXIT_HLT:
			bluepillGuestExit(c, context)
			return
		case _KVM_EXIT_MMIO:
			physical := uintptr(c.runData.data[0])
			if getHypercallID(physical) == _KVM_HYPERCALL_VMEXIT {
				bluepillGuestExit(c, context)
				return
			}

			// Increment the fault count.
			atomic.AddUint32(&c.faults, 1)

			// For MMIO, the physical address is the first data item.
			physical = uintptr(c.runData.data[0])
			virtual, ok := handleBluepillFault(c.machine, physical, physicalRegions, _KVM_MEM_FLAGS_NONE)
			if !ok {
				c.die(bluepillArchContext(context), "invalid physical address")
				return
			}

			// We now need to fill in the data appropriately. KVM
			// expects us to provide the result of the given MMIO
			// operation in the runData struct. This is safe
			// because, if a fault occurs here, the same fault
			// would have occurred in guest mode. The kernel should
			// not create invalid page table mappings.
			data := (*[8]byte)(unsafe.Pointer(&c.runData.data[1]))
			length := (uintptr)((uint32)(c.runData.data[2]))
			write := (uint8)(((c.runData.data[2] >> 32) & 0xff)) != 0
			for i := uintptr(0); i < length; i++ {
				b := bytePtr(uintptr(virtual) + i)
				if write {
					// Write to the given address.
					*b = data[i]
				} else {
					// Read from the given address.
					data[i] = *b
				}
			}
		case _KVM_EXIT_IRQ_WINDOW_OPEN:
			bluepillStopGuest(c)
		case _KVM_EXIT_SHUTDOWN:
			c.die(bluepillArchContext(context), "shutdown")
			return
		case _KVM_EXIT_FAIL_ENTRY:
			c.die(bluepillArchContext(context), "entry failed")
			return
		default:
			bluepillArchHandleExit(c, context)
			return
		}
	}
}
