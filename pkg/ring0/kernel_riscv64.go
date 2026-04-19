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

package ring0

// HaltAndResume halts execution and point the pointer to the resume function.
//
//go:nosplit
func HaltAndResume()

// HaltExceptionAndResume calls Hooks.KernelException and resume.
//
//go:nosplit
func HaltExceptionAndResume()

//go:nosplit
func HaltEcallAndResume()	

// init initializes architecture-specific state.
func (k *Kernel) init(maxCPUs int) {
}

// init initializes architecture-specific state.
func (c *CPU) init(cpuID int) {
	// Set the kernel stack pointer(virtual address).
	c.registers.Regs[2] = uint64(c.StackTop())

}

// StackTop returns the kernel's stack address.
//
//go:nosplit
func (c *CPU) StackTop() uint64 {
	return uint64(kernelAddr(&c.stack[0])) + uint64(len(c.stack))
}

// IsCanonical indicates whether addr is canonical per the riscv64 spec.
//
//go:nosplit
func IsCanonical(addr uint64) bool {
	return addr <= 0x00007fffffffffff || addr >= 0xffff800000000000
}

// SwitchToUser performs an sret.
//
// The return value is the exception vector.
//
// +checkescape:all
//
//go:nosplit
func (c *CPU) SwitchToUser(switchOpts SwitchOpts) (vector Vector) {
	storeAppASID(uintptr(switchOpts.UserASID))
	storeFpState(switchOpts.FloatingPointState.BytePointer())

	if switchOpts.Flush {
		LocalFlushTlbByASID(uintptr(switchOpts.UserASID))
	}

	// Perform the switch
	kernelExitToUser()

	vector = c.vecCode
	return
}
