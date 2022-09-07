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

//go:build go1.12
// +build go1.12

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

package kvm

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

//go:linkname throw runtime.throw
func throw(s string)

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
	c.guestExits.Add(1)

	// Copy out registers.
	bluepillArchExit(c, bluepillArchContext(context))

	// Return to the vCPUReady state; notify any waiters.
	user := c.state.Load() & vCPUUser
	switch c.state.Swap(user) {
	case user | vCPUGuest: // Expected case.
	case user | vCPUGuest | vCPUWaiter:
		c.notify()
	default:
		throw("invalid state")
	}
}

var hexSyms = []byte("0123456789abcdef")

//go:nosplit
func printHex(title []byte, val uint64) {
	var str [18]byte
	for i := 0; i < 16; i++ {
		str[16-i] = hexSyms[val&0xf]
		val = val >> 4
	}
	str[0] = ' '
	str[17] = '\n'
	unix.RawSyscall(unix.SYS_WRITE, uintptr(unix.Stderr), uintptr(unsafe.Pointer(&title[0])), uintptr(len(title)))
	unix.RawSyscall(unix.SYS_WRITE, uintptr(unix.Stderr), uintptr(unsafe.Pointer(&str)), 18)
}

// bluepillHandler is called from the signal stub.
//
// The world may be stopped while this is executing, and it executes on the
// signal stack. It should only execute raw system calls and functions that are
// explicitly marked go:nosplit.
//
// Ideally, this function should switch to gsignal, as runtime.sigtramp does,
// but that is tedious given all the runtime internals. That said, using
// gsignal inside a signal handler is not _required_, provided we avoid stack
// splits and allocations. Note that calling any splittable function here will
// be flaky; if the signal stack is below the G stack then we will trigger a
// split and crash. If above, we won't trigger a split.
//
// +checkescape:all
//
//go:nosplit
func bluepillHandler(context unsafe.Pointer) {
	// Sanitize the registers; interrupts must always be disabled.
	c := bluepillArchEnter(bluepillArchContext(context))

	// Mark this as guest mode.
	switch c.state.Swap(vCPUGuest | vCPUUser) {
	case vCPUUser: // Expected case.
	case vCPUUser | vCPUWaiter:
		c.notify()
	default:
		throw("invalid state")
	}

	for {
		hostExitCounter.Increment()
		_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(c.fd), _KVM_RUN, 0) // escapes: no.
		switch errno {
		case 0: // Expected case.
		case unix.EINTR:
			interruptCounter.Increment()
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
			c.hltSanityCheck()
			bluepillGuestExit(c, context)
			return
		case _KVM_EXIT_MMIO:
			physical := uintptr(c.runData.data[0])
			if getHypercallID(physical) == _KVM_HYPERCALL_VMEXIT {
				bluepillGuestExit(c, context)
				return
			}

			c.die(bluepillArchContext(context), "exit_mmio")
			return
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
