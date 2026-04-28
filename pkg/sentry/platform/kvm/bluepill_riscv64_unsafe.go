// Copyright 2019 The gVisor Authors.
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

//go:build riscv64
// +build riscv64

package kvm

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// fpRegsPtr returns a fpState for the given address.
//
//go:nosplit
func fpRegsPtr(addr *byte) *arch.FpState {
	return (*arch.FpState)(unsafe.Pointer(addr))
}

// dieArchSetup initializes the state for dieTrampoline.
//
// The riscv64 dieTrampoline requires the vCPU to be set in A1, and the last PC
// to be in A0. The trampoline then simulates a call to dieHandler from the
// provided PC.
//
//go:nosplit
func (c *vCPU) dieArchSetup(context *arch.SignalContext64, guestRegs *userRegs, dumpExitReason bool) {
	// If the vCPU is in user mode, we set the stack to the stored stack
	// value in the vCPU itself. We don't want to unwind the user stack.
	if guestRegs.Sstatus&ring0.SPPMask == 0 {
		regs := c.CPU.Registers()
		context.Regs[10] = regs.Regs[0]
		context.Regs[2] = regs.Regs[2]
	} else {
		context.Regs[10] = guestRegs.Regs.Regs[0]
		context.Regs[2] = guestRegs.Regs.Regs[2]
	}
	context.Regs[11] = uint64(uintptr(unsafe.Pointer(c)))
	context.Regs[0] = uint64(dieTrampolineAddr)
}

// bluepillArchFpContext returns the arch-specific fpsimd context.
//
//go:nosplit
func bluepillArchFpContext(context unsafe.Pointer) *arch.FpState {
	return &((*arch.SignalContext64)(context).FpRegs)
}

// getHypercallID returns hypercall ID.
//
//go:nosplit
func getHypercallID(addr uintptr) int {
	if addr < riscv64HypercallMMIOBase || addr >= (riscv64HypercallMMIOBase+_RISCV64_HYPERCALL_MMIO_SIZE) {
		return _KVM_HYPERCALL_MAX
	} else {
		return int(((addr) - riscv64HypercallMMIOBase) >> 2)
	}
}

// bluepillStopGuest is responsible for injecting sError.
//
//go:nosplit
func bluepillStopGuest(c *vCPU) {
	interrupt := uint32(ring0.Bounce)
	// Interrupt: we must have requested an interrupt
	// window; set the interrupt line.
	if _, _, errno := unix.RawSyscall( // escapes: no
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_INTERRUPT,
		uintptr(unsafe.Pointer(&interrupt))); errno != 0 {
		throw("interrupt injection failed")
	}
	// Clear previous injection request.
	c.runData.requestInterruptWindow = 0
}

// bluepillSigBus is responsible for injecting sError to trigger sigbus.
//
//go:nosplit
func bluepillSigBus(c *vCPU) {
	interrupt := uint32(ring0.Sigbus)
	// Interrupt: we must have requested an interrupt
	// window; set the interrupt line.
	if _, _, errno := unix.RawSyscall( // escapes: no
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_INTERRUPT,
		uintptr(unsafe.Pointer(&interrupt))); errno != 0 {
		throw("interrupt injection failed")
	}
	// Clear previous injection request.
	c.runData.requestInterruptWindow = 0
}

// bluepillExtDabt is responsible for injecting external data abort.
//
//go:nosplit
func bluepillExtDabt(c *vCPU) {
	interrupt := uint32(ring0.ExtDabt)
	// Interrupt: we must have requested an interrupt
	// window; set the interrupt line.
	if _, _, errno := unix.RawSyscall( // escapes: no
		unix.SYS_IOCTL,
		uintptr(c.fd),
		KVM_INTERRUPT,
		uintptr(unsafe.Pointer(&interrupt))); errno != 0 {
		throw("interrupt injection failed")
	}
	// Clear previous injection request.
	c.runData.requestInterruptWindow = 0
}

// bluepillHandleEnosys is responsible for handling enosys error.
//
//go:nosplit
func bluepillHandleEnosys(c *vCPU) {
	bluepillExtDabt(c)
}

// bluepillReadyStopGuest checks whether the current vCPU is ready for sError injection.
//
//go:nosplit
func bluepillReadyStopGuest(c *vCPU) bool {
	return true
}

// bluepillArchHandleExit checks architecture specific exitcode.
//
//go:nosplit
func bluepillArchHandleExit(c *vCPU, context unsafe.Pointer) {
	c.die(bluepillArchContext(context), "unknown")
}
