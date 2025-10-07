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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sigframe"
)

// Instruction pointers used to trigger panics.
const (
	_PANIC_RIP_CPU_DIE   = 0xabc
	_PANIC_RIP_EXC_CHECK = 0xabd
)

// dieArchSetup initializes the state for dieTrampoline.
//
// The amd64 dieTrampoline requires the vCPU to be set in BX, and the last RIP
// to be in AX. The trampoline then simulates a call to dieHandler from the
// provided RIP.
//
//go:nosplit
func (c *vCPU) dieArchSetup(context *arch.SignalContext64, guestRegs *userRegs, dumpExitReason bool) {
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
	if dumpExitReason {
		// Store the original instruction pointer in R9 and populates
		// registers R10-R14 with the vCPU's exit reason and associated
		// data from c.runData. To ensure this information is preserved
		// in a crash report, RIP is set to an invalid address (0xabc).
		// This forces a memory fault immediately after a sigreturn,
		// triggering a crash report that includes the altered register
		// state, providing diagnostic details about why the vCPU
		// exited.
		context.R9 = context.Rip
		context.Rip = _PANIC_RIP_CPU_DIE
		context.R10 = uint64(c.runData.exitReason)
		context.R11 = c.runData.data[0]
		context.R12 = c.runData.data[1]
		context.R13 = c.runData.data[2]
		context.R14 = c.runData.data[3]
	} else {
		context.Rbx = uint64(uintptr(unsafe.Pointer(c)))
		context.Rip = uint64(dieTrampolineAddr)
	}
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
	if errno := hostsyscall.RawSyscallErrno(
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
	if errno := hostsyscall.RawSyscallErrno(
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
	c.dieAndDumpExitReason(bluepillArchContext(context))
}

func addrOfBluepillUserHandler() uintptr

func getcs() uint16

func currentCPU() *vCPU

// bluepill enters guest mode.
//
//go:nosplit
func bluepill(c *vCPU) {
	// The sentry is running in the VM ring 0.
	if getcs()&3 == 0 {
		if currentCPU() == c {
			// Already in the vm.
			return
		}
		// Wrong vCPU, switch to the right one.
		redpill()
	}

	// Block all signals.
	sigmask := linux.SignalSet(^uint64(0))
	if err := sigframe.CallWithSignalFrame(
		&c.signalStack, addrOfBluepillUserHandler(),
		&sigmask, uint64(uintptr(unsafe.Pointer(c)))); err != nil {
		throw("failed to swallow the bluepill")
	}
}

// +checkescape:all
//
//go:nosplit
func bluepillUserHandler(frame uintptr) {
	bluepillHandler(unsafe.Pointer(frame))
	sigframe.Sigreturn((*arch.UContext64)(unsafe.Pointer(frame)))
}
