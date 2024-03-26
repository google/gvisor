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

//go:build amd64
// +build amd64

package kvm

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// dieArchSetup initializes the state for dieTrampoline.
//
// The amd64 dieTrampoline requires the vCPU to be set in BX, and the last RIP
// to be in AX. The trampoline then simulates a call to dieHandler from the
// provided RIP.
//
//go:nosplit
func dieArchSetup(c *vCPU, context *arch.SignalContext64, guestRegs *userRegs) {
	// Reload all registers to have an accurate stack trace when we return
	// to host mode. This means that the stack should be unwound correctly.
	if errno := c.getUserRegisters(&c.dieState.guestRegs); errno != 0 {
		throw(c.dieState.message)
	}

	// If the vCPU is in user mode, we set the stack to the stored stack
	// value in the vCPU itself. We don't want to unwind the user stack.
	if guestRegs.RFLAGS&ring0.UserFlagsSet == ring0.UserFlagsSet {
		regs := c.CPU.Registers()
		context.Rax = regs.Rax
		context.Rsp = regs.Rsp
		context.Rbp = regs.Rbp
	} else {
		context.Rax = guestRegs.RIP
		context.Rsp = guestRegs.RSP
		context.Rbp = guestRegs.RBP
		context.Eflags = guestRegs.RFLAGS
	}
	context.Rbx = uint64(uintptr(unsafe.Pointer(c)))
	context.Rip = uint64(dieTrampolineAddr)
}

// getHypercallID returns hypercall ID.
//
//go:nosplit
func getHypercallID(addr uintptr) int {
	return _KVM_HYPERCALL_MAX
}

// bluepillStopGuest is responsible for injecting interrupt.
//
//go:nosplit
func bluepillStopGuest(c *vCPU) {
	// Interrupt: we must have requested an interrupt
	// window; set the interrupt line.
	if _, _, errno := unix.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_INTERRUPT,
		uintptr(unsafe.Pointer(&bounce))); errno != 0 {
		throw("interrupt injection failed")
	}
	// Clear previous injection request.
	c.runData.requestInterruptWindow = 0
}

// bluepillSigBus is responsible for injecting NMI to trigger sigbus.
//
//go:nosplit
func bluepillSigBus(c *vCPU) {
	if _, _, errno := unix.RawSyscall( // escapes: no.
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_NMI, 0); errno != 0 {
		throw("NMI injection failed")
	}
}

// bluepillHandleEnosys is responsible for handling enosys error.
//
//go:nosplit
func bluepillHandleEnosys(c *vCPU) {
	throw("run failed: ENOSYS")
}

// bluepillReadyStopGuest checks whether the current vCPU is ready for interrupt injection.
//
//go:nosplit
func bluepillReadyStopGuest(c *vCPU) bool {
	if c.runData.readyForInterruptInjection == 0 {
		return false
	}

	if c.runData.ifFlag == 0 {
		// This is impossible if readyForInterruptInjection is 1.
		throw("interrupts are disabled")
	}

	// Disable interrupts if we are in the kernel space.
	//
	// When the Sentry switches into the kernel mode, it disables
	// interrupts. But when goruntime switches on a goroutine which has
	// been saved in the host mode, it restores flags and this enables
	// interrupts.  See the comment of UserFlagsSet for more details.
	uregs := userRegs{}
	err := c.getUserRegisters(&uregs)
	if err != 0 {
		throw("failed to get user registers")
	}

	if ring0.IsKernelFlags(uregs.RFLAGS) {
		uregs.RFLAGS &^= ring0.KernelFlagsClear
		err = c.setUserRegisters(&uregs)
		if err != 0 {
			throw("failed to set user registers")
		}
		return false
	}
	return true
}

// bluepillArchHandleExit checks architecture specific exitcode.
//
//go:nosplit
func bluepillArchHandleExit(c *vCPU, context unsafe.Pointer) {
	c.die(bluepillArchContext(context), "unknown")
}

func (c *vCPU) switchToUser(switchOpts ring0.SwitchOpts) (vector ring0.Vector) {
	{
		regs := c.CPU.Registers()
		regs.Eflags &^= uint64(ring0.KernelFlagsClear)
		regs.Eflags |= ring0.KernelFlagsSet
		regs.Cs = uint64(ring0.Kcode)
		regs.Ds = uint64(ring0.Udata)
		regs.Es = uint64(ring0.Udata)
		regs.Ss = uint64(ring0.Kdata)
		regs.Rsp = c.SwitchOptsStackTop()
		regs.Rip = uint64(ring0.AddrOfDoSwitchToUserLoop())
		regs.Rsi = uint64(uintptr(unsafe.Pointer(&c.CPU)))
	}

	userCR3 := switchOpts.PageTables.CR3(!switchOpts.Flush, switchOpts.UserPCID)
	c.KernelCR3(switchOpts.KernelPCID)

	// Sanitize registers.
	regs := switchOpts.Registers
	regs.Eflags &= ^uint64(ring0.UserFlagsClear)
	regs.Eflags |= ring0.UserFlagsSet
	regs.Cs = uint64(ring0.Ucode64) // Required for iret.
	regs.Ss = uint64(ring0.Udata)   // Ditto.

	// Perform the switch.
	needIRET := uint64(0)
	if switchOpts.FullRestore {
		needIRET = 1
	}

	c.SwitchOptsRegs = regs
	c.SwitchOptsFPU = switchOpts.FloatingPointState.BytePointer()
	c.SwitchOptsNeedIRET = needIRET
	c.SwitchOptsUserCR3 = userCR3

	// Mark this as guest mode.
	switch c.state.Swap(vCPUGuest | vCPUUser) {
	case vCPUUser: // Expected case.
	case vCPUUser | vCPUWaiter:
		c.notify()
	default:
		throw("invalid state")
	}

	for {
		entersyscall()
		_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(c.fd), KVM_RUN, 0) // escapes: no.
		exitsyscall()
		switch errno {
		case 0: // Expected case.
		default:
			throw("run failed")
		}

		switch c.runData.exitReason {
		case _KVM_EXIT_HLT:
			c.hltSanityCheck()
			goto done
		case _KVM_EXIT_EXCEPTION:
			c.die(nil, "exception")
			return
		case _KVM_EXIT_IO:
			c.die(nil, "I/O")
			return
		case _KVM_EXIT_INTERNAL_ERROR:
			// An internal error is typically thrown when emulation
			// fails. This can occur via the MMIO path below (and
			// it might fail because we have multiple regions that
			// are not mapped). We would actually prefer that no
			// emulation occur, and don't mind at all if it fails.
		case _KVM_EXIT_HYPERCALL:
			c.die(nil, "hypercall")
			return
		case _KVM_EXIT_DEBUG:
			c.die(nil, "debug")
			return
		case _KVM_EXIT_MMIO:
			c.die(nil, "exit_mmio")
			return
		case _KVM_EXIT_IRQ_WINDOW_OPEN:
			//bluepillStopGuest(c)
		case _KVM_EXIT_SHUTDOWN:
			c.die(nil, "shutdown")
			return
		case _KVM_EXIT_FAIL_ENTRY:
			c.die(nil, "entry failed")
			return
		default:
			bluepillArchHandleExit(c, nil)
			return
		}
	}
done:
	// Return to the vCPUReady state; notify any waiters.
	user := c.state.Load() & vCPUUser
	switch c.state.Swap(user) {
	case user | vCPUGuest: // Expected case.
	case user | vCPUGuest | vCPUWaiter:
		c.notify()
	default:
		throw("invalid state")
	}
	vector = c.SwitchOptsVector
	return
}

