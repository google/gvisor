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

package ring0

// HaltAndResume halts execution and point the pointer to the resume function.
//go:nosplit
func HaltAndResume()

// HaltEl1SvcAndResume calls Hooks.KernelSyscall and resume.
//go:nosplit
func HaltEl1SvcAndResume()

// HaltEl1ExceptionAndResume calls Hooks.KernelException and resume.
//go:nosplit
func HaltEl1ExceptionAndResume()

// init initializes architecture-specific state.
func (k *Kernel) init(maxCPUs int) {
}

// init initializes architecture-specific state.
func (c *CPU) init(cpuID int) {
	// Set the kernel stack pointer(virtual address).
	c.registers.Sp = uint64(c.StackTop())

}

// StackTop returns the kernel's stack address.
//
//go:nosplit
func (c *CPU) StackTop() uint64 {
	return uint64(kernelAddr(&c.stack[0])) + uint64(len(c.stack))
}

// IsCanonical indicates whether addr is canonical per the arm64 spec.
//
//go:nosplit
func IsCanonical(addr uint64) bool {
	return addr <= 0x0000ffffffffffff || addr > 0xffff000000000000
}

// SwitchToUser performs an eret.
//
// The return value is the exception vector.
//
// +checkescape:all
//
//go:nosplit
func (c *CPU) SwitchToUser(switchOpts SwitchOpts) (vector Vector) {
	storeAppASID(uintptr(switchOpts.UserASID))
	storeEl0Fpstate(switchOpts.FloatingPointState.BytePointer())

	if switchOpts.Flush {
		LocalFlushTlbByASID(uintptr(switchOpts.UserASID))
	}

	regs := switchOpts.Registers

	regs.Pstate &= ^uint64(PsrFlagsClear)
	regs.Pstate |= UserFlagsSet

	fpDisableTrap := CPACREL1()
	if fpDisableTrap != 0 {
		FPSIMDEnableTrap()
	}

	kernelExitToEl0()

	fpDisableTrap = CPACREL1()
	if fpDisableTrap != 0 {
		SaveFloatingPoint(switchOpts.FloatingPointState.BytePointer())
	}

	vector = c.vecCode

	return
}
