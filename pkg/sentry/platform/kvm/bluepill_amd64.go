// Copyright 2018 Google Inc.
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

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0"
)

var (
	// bounceSignal is the signal used for bouncing KVM.
	//
	// We use SIGCHLD because it is not masked by the runtime, and
	// it will be ignored properly by other parts of the kernel.
	bounceSignal = syscall.SIGCHLD

	// bounceSignalMask has only bounceSignal set.
	bounceSignalMask = uint64(1 << (uint64(bounceSignal) - 1))

	// bounce is the interrupt vector used to return to the kernel.
	bounce = uint32(ring0.VirtualizationException)
)

// redpill on amd64 invokes a syscall with -1.
//
//go:nosplit
func redpill() {
	syscall.RawSyscall(^uintptr(0), 0, 0, 0)
}

// bluepillArchEnter is called during bluepillEnter.
//
//go:nosplit
func bluepillArchEnter(context *arch.SignalContext64) (c *vCPU) {
	c = vCPUPtr(uintptr(context.Rax))
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
	regs.Fs = uint64(ring0.Udata)
	regs.Ss = uint64(ring0.Kdata)

	// ring0 uses GS exclusively, so we use GS_base to store the location
	// of the floating point address.
	//
	// The address will be restored directly after running the VCPU, and
	// will be saved again prior to halting. We rely on the fact that the
	// SaveFloatingPointer/LoadFloatingPoint functions use the most
	// efficient mechanism available (including compression) so the state
	// size is guaranteed to be less than what's pointed to here.
	regs.Gs_base = uint64(context.Fpstate)
	return
}

// bluepillSyscall handles kernel syscalls.
//
//go:nosplit
func bluepillSyscall() {
	regs := ring0.Current().Registers()
	if regs.Rax != ^uint64(0) {
		regs.Rip -= 2 // Rewind.
	}
	ring0.SaveFloatingPoint(bytePtr(uintptr(regs.Gs_base)))
	ring0.Halt()
	ring0.WriteFS(uintptr(regs.Fs_base)) // Reload host segment.
	ring0.LoadFloatingPoint(bytePtr(uintptr(regs.Gs_base)))
}

// bluepillException handles kernel exceptions.
//
//go:nosplit
func bluepillException(vector ring0.Vector) {
	regs := ring0.Current().Registers()
	if vector == ring0.Vector(bounce) {
		// These should not interrupt kernel execution; point the Rip
		// to zero to ensure that we get a reasonable panic when we
		// attempt to return.
		regs.Rip = 0
	}
	ring0.SaveFloatingPoint(bytePtr(uintptr(regs.Gs_base)))
	ring0.Halt()
	ring0.WriteFS(uintptr(regs.Fs_base)) // Reload host segment.
	ring0.LoadFloatingPoint(bytePtr(uintptr(regs.Gs_base)))
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
}
