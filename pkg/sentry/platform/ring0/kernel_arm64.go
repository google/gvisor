// Copyright 2019 Google Inc.
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

// init initializes architecture-specific state.
func (k *Kernel) init(opts KernelOpts) {
	// Save the root page tables.
	k.PageTables = opts.PageTables
}

// init initializes architecture-specific state.
func (c *CPU) init() {
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

//go:nosplit
func (c *CPU) SwitchToUser(switchOpts SwitchOpts) (vector Vector) {
	// Sanitize registers.
	regs := switchOpts.Registers

	regs.Pstate &= ^uint64(UserFlagsClear)
	regs.Pstate |= UserFlagsSet
	kernelExitToEl0()
	vector = c.vecCode

	// Perform the switch.
	return
}
