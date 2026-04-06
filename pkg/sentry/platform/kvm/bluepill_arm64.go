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

//go:build arm64
// +build arm64

package kvm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sighandling"
)

var (
	// The action for bluepillSignal is changed by sigaction().
	bluepillSignal = unix.SIGILL
)

// bluepill enters guest mode.
//
//go:nosplit
func bluepill(c *vCPU)

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
		fpsimd := fpsimdPtr(c.FloatingPointState().BytePointer()) // escapes: no
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
	if regs.Regs[8] != ^uint64(0) {
		regs.Pc -= 4 // Rewind.
	}

	fpDisableTrap := ring0.CPACREL1()
	if fpDisableTrap != 0 {
		fpsimd := fpsimdPtr(c.FloatingPointState().BytePointer()) // escapes: no
		fpcr := ring0.GetFPCR()
		fpsr := ring0.GetFPSR()
		fpsimd.Fpcr = uint32(fpcr)
		fpsimd.Fpsr = uint32(fpsr)
		ring0.SaveVRegs(c.FloatingPointState().BytePointer()) // escapes: no
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

	fpDisableTrap := ring0.CPACREL1()
	if fpDisableTrap != 0 {
		fpsimd := fpsimdPtr(c.FloatingPointState().BytePointer()) // escapes: no
		fpcr := ring0.GetFPCR()
		fpsr := ring0.GetFPSR()
		fpsimd.Fpcr = uint32(fpcr)
		fpsimd.Fpsr = uint32(fpsr)
		ring0.SaveVRegs(c.FloatingPointState().BytePointer()) // escapes: no
	}

	ring0.Halt()
}

func currentEL() uint64

func inKernelMode() bool {
	return currentEL() == 1
}

// addrOfSigillInstruction returns the address of the MRS TPIDR_EL1
// instruction in bluepill() that deliberately triggers SIGILL.
func addrOfSigillInstruction() uintptr

// bluepillExpectedPC is the PC value that the sighandler checks against
// to distinguish expected SIGILLs (from bluepill entry) from spurious
// SIGILLs delivered to non-KVM threads. Without this check, a spurious
// SIGILL on a thread whose R8 doesn't contain a vCPU pointer causes a
// SIGSEGV in bluepillArchEnter when it dereferences the garbage R8 value.
//
// This is set during init() to the address of the MRS TPIDR_EL1
// instruction inside bluepill() that deliberately triggers SIGILL.
var bluepillExpectedPC uintptr

// sigillMRSInstruction is the raw encoding of "MRS TPIDR_EL1, X10"
// (0xd538d08a). We scan for it in the bluepill function to find its PC.
const sigillMRSInstruction = 0xd538d08a

func init() {
	// Find the address of the MRS TPIDR_EL1 instruction in bluepill()
	// by scanning the function body for the known instruction encoding.
	// This is more robust than hardcoding an offset, which can change
	// if the compiler or assembler inserts additional instructions.
	bluepillExpectedPC = addrOfSigillInstruction()

	// Verify the instruction at the computed address is actually
	// MRS TPIDR_EL1 (0xd538d08a). This catches offset miscalculations.
	insn := *(*uint32)(unsafe.Pointer(bluepillExpectedPC))
	if insn != sigillMRSInstruction {
		panic(fmt.Sprintf(
			"bluepill sigill instruction mismatch at %#x: got %#x, want %#x",
			bluepillExpectedPC, insn, sigillMRSInstruction))
	}

	// Install the handler.
	if err := sighandling.ReplaceSignalHandler(bluepillSignal, addrOfSighandler(), &savedHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for signal %d: %v", bluepillSignal, err))
	}
}
