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
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/safecopy"
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
	if c.safecopySiginfo.Signo != 0 {
		// This exit was triggered by one of safecopy calls that triggered a signal.
		_, _, errno := unix.RawSyscall6(unix.SYS_RT_TGSIGQUEUEINFO,
			uintptr(pid), uintptr(c.tid), uintptr(c.safecopySiginfo.Signo),
			uintptr(unsafe.Pointer(&c.safecopySiginfo)), 0, 0)
		if errno != 0 {
			throw("failed to send a signal")
		}
		c.safecopySiginfo.Signo = 0
	}

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
			mmio := (*mmioData)(unsafe.Pointer(&c.runData.data[0]))
			if getHypercallID(uintptr(mmio.physical)) == _KVM_HYPERCALL_VMEXIT {
				bluepillGuestExit(c, context)
				return
			}

			// Increment the fault count.
			atomic.AddUint32(&c.faults, 1)

			// For MMIO, the physical address is the first data item.
			virtual, ok := handleBluepillFault(c.machine, uintptr(mmio.physical), physicalRegions, _KVM_MEM_FLAGS_NONE)
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
			// Here is one exception when the Sentry reads a user
			// mapping with safecopy. In this case, the SIGBUS
			// signal can be triggered, and we need to catch it and
			// trigger the signal after returning back to the guest.
			set := linux.SignalSet(1 << linux.SIGBUS.Index())
			oldset := linux.SignalSet(0)
			if _, _, errno := unix.RawSyscall6(
				unix.SYS_RT_SIGPROCMASK, linux.SIG_UNBLOCK,
				uintptr(unsafe.Pointer(&set)), uintptr(unsafe.Pointer(&oldset)),
				linux.SignalSetSize, 0, 0); errno != 0 {
				throw("failed to unblock SIGBUS")
			}

			sig := int32(0)
			fault := uintptr(0)
			if mmio.isWrite != 0 {
				// Write to the given address.
				fault, sig = safecopy.Memcpy(virtual, uintptr(unsafe.Pointer(&mmio.data[0])), uintptr(mmio.length))
			} else {
				fault, sig = safecopy.Memcpy(uintptr(unsafe.Pointer(&mmio.data[0])), virtual, uintptr(mmio.length))
			}
			if _, _, errno := unix.RawSyscall6(
				unix.SYS_RT_SIGPROCMASK, linux.SIG_SETMASK,
				uintptr(unsafe.Pointer(&oldset)), 0,
				linux.SignalSetSize, 0, 0); errno != 0 {
				throw("failed to restore the signal mask")
			}
			if linux.Signal(sig) == linux.SIGBUS {
				c.safecopySiginfo.Signo = sig
				c.safecopySiginfo.Code = linux.SI_KERNEL
				c.safecopySiginfo.SetAddr(uint64(fault))
				bluepillSigBus(c)
			} else if sig != 0 {
				throw("unexpected signal")
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
