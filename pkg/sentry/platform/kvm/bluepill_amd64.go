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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

var (
	// The action for bluepillSignal is changed by sigaction().
	bluepillSignal = unix.SIGSEGV
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

// hltSanityCheck verifies the current state to detect obvious corruption.
//
//go:nosplit
func (c *vCPU) hltSanityCheck() {
	vector := c.CPU.Vector()
	switch ring0.Vector(vector) {
	case ring0.PageFault:
		if c.CPU.FaultAddr() < ring0.KernelStartAddress {
			return
		}
	case ring0.DoubleFault:
	case ring0.GeneralProtectionFault:
	case ring0.InvalidOpcode:
	case ring0.MachineCheck:
	case ring0.VirtualizationException:
	default:
		return
	}

	printHex([]byte("Vector    = "), uint64(c.CPU.Vector()))
	printHex([]byte("FaultAddr = "), uint64(c.CPU.FaultAddr()))
	printHex([]byte("rip       = "), uint64(c.CPU.Registers().Rip))
	printHex([]byte("rsp       = "), uint64(c.CPU.Registers().Rsp))
	throw("fault")
}

// KernelSyscall handles kernel syscalls.
//
// +checkescape:all
//
//go:nosplit
func (c *vCPU) KernelSyscall() {
	regs := c.Registers()
	if regs.Rax != ^uint64(0) {
		regs.Rip -= 2 // Rewind.
	}
	// N.B. Since KernelSyscall is called when the kernel makes a syscall,
	// FS_BASE is already set for correct execution of this function.
	//
	// Refresher on syscall/exception handling:
	// 1. When the sentry is in guest mode and makes a syscall, it goes to
	// sysenter(), which saves the register state (including RIP of SYSCALL
	// instruction) to vCPU.registers.
	// 2. It then calls KernelSyscall, which rewinds the IP and executes
	// HLT.
	// 3. HLT does a VM-exit to bluepillHandler, which returns from the
	// signal handler using vCPU.registers, directly to the SYSCALL
	// instruction.
	// 4. Later, when we want to re-use the vCPU (perhaps on a different
	// host thread), we set the new thread's registers in vCPU.registers
	// (as opposed to setting the KVM registers with KVM_SET_REGS).
	// 5. KVM_RUN thus enters the guest with the old register state,
	// immediately following the HLT instruction, returning here.
	// 6. We then restore FS_BASE and the full registers from vCPU.register
	// to return from sysenter() back to the desired bluepill point from
	// the host.
	ring0.HaltAndWriteFSBase(regs) // escapes: no, reload host segment.
}

// KernelException handles kernel exceptions.
//
// +checkescape:all
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
