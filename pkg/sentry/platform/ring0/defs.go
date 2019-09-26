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

package ring0

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// Kernel is a global kernel object.
//
// This contains global state, shared by multiple CPUs.
type Kernel struct {
	KernelArchState
}

// Hooks are hooks for kernel functions.
type Hooks interface {
	// KernelSyscall is called for kernel system calls.
	//
	// Return from this call will restore registers and return to the kernel: the
	// registers must be modified directly.
	//
	// If this function is not provided, a kernel exception results in halt.
	//
	// This must be go:nosplit, as this will be on the interrupt stack.
	// Closures are permitted, as the pointer to the closure frame is not
	// passed on the stack.
	KernelSyscall()

	// KernelException handles an exception during kernel execution.
	//
	// Return from this call will restore registers and return to the kernel: the
	// registers must be modified directly.
	//
	// If this function is not provided, a kernel exception results in halt.
	//
	// This must be go:nosplit, as this will be on the interrupt stack.
	// Closures are permitted, as the pointer to the closure frame is not
	// passed on the stack.
	KernelException(Vector)
}

// CPU is the per-CPU struct.
type CPU struct {
	// self is a self reference.
	//
	// This is always guaranteed to be at offset zero.
	self *CPU

	// kernel is reference to the kernel that this CPU was initialized
	// with. This reference is kept for garbage collection purposes: CPU
	// registers may refer to objects within the Kernel object that cannot
	// be safely freed.
	kernel *Kernel

	// CPUArchState is architecture-specific state.
	CPUArchState

	// registers is a set of registers; these may be used on kernel system
	// calls and exceptions via the Registers function.
	registers syscall.PtraceRegs

	// hooks are kernel hooks.
	hooks Hooks
}

// Registers returns a modifiable-copy of the kernel registers.
//
// This is explicitly safe to call during KernelException and KernelSyscall.
//
//go:nosplit
func (c *CPU) Registers() *syscall.PtraceRegs {
	return &c.registers
}

// SwitchOpts are passed to the Switch function.
type SwitchOpts struct {
	// Registers are the user register state.
	Registers *syscall.PtraceRegs

	// FloatingPointState is a byte pointer where floating point state is
	// saved and restored.
	FloatingPointState *byte

	// PageTables are the application page tables.
	PageTables *pagetables.PageTables

	// Flush indicates that a TLB flush should be forced on switch.
	Flush bool

	// FullRestore indicates that an iret-based restore should be used.
	FullRestore bool

	// SwitchArchOpts are architecture-specific options.
	SwitchArchOpts
}
