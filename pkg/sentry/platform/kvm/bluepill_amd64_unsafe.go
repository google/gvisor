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

// +build amd64

package kvm

import (
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0"
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

// bluepillStopGuest is reponsible for injecting interrupt.
//
//go:nosplit
func bluepillStopGuest(c *vCPU) {
	// Interrupt: we must have requested an interrupt
	// window; set the interrupt line.
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(c.fd),
		_KVM_INTERRUPT,
		uintptr(unsafe.Pointer(&bounce))); errno != 0 {
		throw("interrupt injection failed")
	}
	// Clear previous injection request.
	c.runData.requestInterruptWindow = 0
}

// bluepillReadyStopGuest checks whether the current vCPU is ready for interrupt injection.
//
//go:nosplit
func bluepillReadyStopGuest(c *vCPU) bool {
	return c.runData.readyForInterruptInjection != 0
}
