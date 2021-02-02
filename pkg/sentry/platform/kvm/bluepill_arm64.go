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

// +build arm64

package kvm

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0"
)

var (
	// The action for bluepillSignal is changed by sigaction().
	bluepillSignal = syscall.SIGILL

	// vcpuSErrBounce is the event of system error for bouncing KVM.
	vcpuSErrBounce = kvmVcpuEvents{
		exception: exception{
			sErrPending: 1,
		},
	}

	// vcpuSErrNMI is the event of system error to trigger sigbus.
	vcpuSErrNMI = kvmVcpuEvents{
		exception: exception{
			sErrPending: 1,
			sErrHasEsr:  1,
			sErrEsr:     _ESR_ELx_SERR_NMI,
		},
	}

	// vcpuExtDabt is the event of ext_dabt.
	vcpuExtDabt = kvmVcpuEvents{
		exception: exception{
			extDabtPending: 1,
		},
	}
)

// getTLS returns the value of TPIDR_EL0 register.
//
//go:nosplit
func getTLS() (value uint64)

// setTLS writes the TPIDR_EL0 value.
//
//go:nosplit
func setTLS(value uint64)

// bluepillArchEnter is called during bluepillEnter.
//
//go:nosplit
func bluepillArchEnter(context *arch.SignalContext64) (c *vCPU) {
	c = vCPUPtr(uintptr(context.Regs[8]))
	regs := c.CPU.Registers()
	regs.Regs = context.Regs
	regs.Sp = context.Sp
	regs.Pc = context.Pc
	regs.Pstate = context.Pstate
	regs.Pstate &^= uint64(ring0.PsrFlagsClear)
	regs.Pstate |= ring0.KernelFlagsSet
	regs.TPIDR_EL0 = getTLS()

	return
}

// bluepillArchExit is called during bluepillEnter.
//
//go:nosplit
func bluepillArchExit(c *vCPU, context *arch.SignalContext64) {
	regs := c.CPU.Registers()
	context.Regs = regs.Regs
	context.Sp = regs.Sp
	context.Pc = regs.Pc
	context.Pstate = regs.Pstate
	context.Pstate &^= uint64(ring0.PsrFlagsClear)
	context.Pstate |= ring0.UserFlagsSet
	setTLS(regs.TPIDR_EL0)

	lazyVfp := c.GetLazyVFP()
	if lazyVfp != 0 {
		fpsimd := fpsimdPtr((*byte)(c.floatingPointState))
		context.Fpsimd64.Fpsr = fpsimd.Fpsr
		context.Fpsimd64.Fpcr = fpsimd.Fpcr
		context.Fpsimd64.Vregs = fpsimd.Vregs
	}
}

// KernelSyscall handles kernel syscalls.
//
// +checkescape:all
//
//go:nosplit
func (c *vCPU) KernelSyscall() {
	regs := c.Registers()

	// Is this a fast-path call?
	if regs.Rax == linux.SYS_FUTEX && regs.Rdi == linux.FUTEX_WAKE|linux.FUTEX_PRIVATE_FLAG {
		ring0.Hypercall()
		return
	}

	// Need to rewind to redo.
	if regs.Regs[8] != ^uint64(0) {
		regs.Pc -= 4 // Rewind.
	}

	vfpEnable := ring0.CPACREL1()
	if vfpEnable != 0 {
		fpsimd := fpsimdPtr((*byte)(c.floatingPointState))
		fpcr := ring0.GetFPCR()
		fpsr := ring0.GetFPSR()
		fpsimd.Fpcr = uint32(fpcr)
		fpsimd.Fpsr = uint32(fpsr)
		ring0.SaveVRegs((*byte)(c.floatingPointState))
	}

	ring0.Halt()
}

// KernelException handles kernel exceptions.
//
// +checkescape:all
//
//go:nosplit
func (c *vCPU) KernelException(vector ring0.Vector) {
	regs := c.Registers()
	if vector == ring0.Vector(bounce) {
		regs.Pc = 0
	}

	vfpEnable := ring0.CPACREL1()
	if vfpEnable != 0 {
		fpsimd := fpsimdPtr((*byte)(c.floatingPointState))
		fpcr := ring0.GetFPCR()
		fpsr := ring0.GetFPSR()
		fpsimd.Fpcr = uint32(fpcr)
		fpsimd.Fpsr = uint32(fpsr)
		ring0.SaveVRegs((*byte)(c.floatingPointState))
	}

	ring0.Halt()
}

// bluepillArchSyscall handles an inline system call.
//
//go:nosplit
func bluepillArchSyscall(c *vCPU) {
	regs := c.CPU.Registers()
	r, _, errno := syscall.RawSyscall(regs.Regs[0], regs.Regs[1], regs.Regs[2], regs.Regs[3], regs.Regs[4], regs.Regs[5])
	if errno != 0 {
		regs.Regs[0] = -errno
	} else {
		regs.Regs[0] = r
	}
}
