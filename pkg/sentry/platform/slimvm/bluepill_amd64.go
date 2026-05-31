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

//go:build amd64
// +build amd64

package slimvm

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

var (
	// The action for bluepillSignal is changed by sigaction().
	bluepillSignal = syscall.SIGSEGV
)

// bluepillArchEnter is called during bluepillEnter.
//
//go:nosplit
func bluepillArchEnter(context *arch.SignalContext64) *vCPU {
	c := vCPUPtr(uintptr(context.Rax))
	regs := c.CPU.Registers()
	regs.R8 = context.R8
	regs.R9 = context.R9
	regs.R10 = context.R10
	regs.R11 = context.R11
	regs.R12 = context.R12
	regs.R13 = context.R13
	regs.R14 = context.R14
	regs.R15 = context.R15
	regs.Rdi = context.Rdi
	regs.Rsi = context.Rsi
	regs.Rbp = context.Rbp
	regs.Rbx = context.Rbx
	regs.Rdx = context.Rdx
	regs.Rax = context.Rax
	regs.Rcx = context.Rcx
	regs.Rsp = context.Rsp
	regs.Rip = context.Rip
	regs.Eflags = context.Eflags
	regs.Eflags &^= uint64(ring0.KernelFlagsClear)
	regs.Eflags |= ring0.KernelFlagsSet
	regs.Cs = uint64(ring0.Kcode)
	regs.Ds = uint64(ring0.Udata)
	regs.Es = uint64(ring0.Udata)
	regs.Ss = uint64(ring0.Kdata)

	return c
}

// KernelSyscall handles kernel syscalls.
//
//go:nosplit
func (c *vCPU) KernelSyscall() {
	regs := c.Registers()
	if regs.Rax != ^uint64(0) {
		regs.Rip -= 2 // Rewind.
	}
	// Syscall/exception handling in SlimVM:
	//
	// When enableVMCALL is set (normal SlimVM operation), most syscalls
	// from GR0 (guest ring 0, i.e. the sentry) are forwarded to the host
	// kernel directly via VMCALL/VMMCALL in entry_amd64.s, without exiting
	// to HR3. Only special syscalls (exit, exit_group, and
	// RedPill/0xFFFFFFFF) fall through to the HLT path below.
	//
	// When enableVMCALL is not set, all syscalls go through the HLT path
	// (same as KVM, see kvm/bluepill_amd64.go for details). This happens
	// in two cases:
	// - KVM platform: enableVMCALL is never set.
	// - SlimVM platform upgrade: DisableVMCALL() is called temporarily to
	//   return the M (machine thread) back to HR3.
	ring0.HaltAndWriteFSBase(regs) // escapes: no, reload host segment.
}

// KernelException handles kernel exceptions.
//
//go:nosplit
func (c *vCPU) KernelException(vector ring0.Vector) {
	regs := c.Registers()
	if vector == ring0.Vector(bounce) {
		// This go-routine was saved in hr3 and resumed in gr0 with the
		// userspace flags. Let's adjust flags and skip the interrupt.
		regs.Eflags &^= uint64(ring0.KernelFlagsClear)
		regs.Eflags |= ring0.KernelFlagsSet
		return
	}
	// See above.
	ring0.HaltAndWriteFSBase(regs) // escapes: no, reload host segment.
}

// bluepillArchExit is called during bluepillEnter.
//
//go:nosplit
func bluepillArchExit(c *vCPU, context *arch.SignalContext64) {
	regs := c.CPU.Registers()
	context.R8 = regs.R8
	context.R9 = regs.R9
	context.R10 = regs.R10
	context.R11 = regs.R11
	context.R12 = regs.R12
	context.R13 = regs.R13
	context.R14 = regs.R14
	context.R15 = regs.R15
	context.Rdi = regs.Rdi
	context.Rsi = regs.Rsi
	context.Rbp = regs.Rbp
	context.Rbx = regs.Rbx
	context.Rdx = regs.Rdx
	context.Rax = regs.Rax
	context.Rcx = regs.Rcx
	context.Rsp = regs.Rsp
	context.Rip = regs.Rip
	context.Eflags = regs.Eflags

	// Set the context pointer to the saved floating point state. This is
	// where the guest data has been serialized, the kernel will restore
	// from this new pointer value.
	context.Fpstate = uint64(uintptrValue(c.FloatingPointState().BytePointer())) // escapes: no.
}
