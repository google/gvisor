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

// Init initializes a new kernel.
//
// N.B. that constraints on KernelOpts must be satisfied.
//
//go:nosplit
func (k *Kernel) Init(opts KernelOpts, maxCPUs int) {
	k.init(opts, maxCPUs)
}

// Halt halts execution.
func Halt()

// defaultHooks implements hooks.
type defaultHooks struct{}

// KernelSyscall implements Hooks.KernelSyscall.
//
// +checkescape:all
//
//go:nosplit
func (defaultHooks) KernelSyscall() {
	Halt()
}

// KernelException implements Hooks.KernelException.
//
// +checkescape:all
//
//go:nosplit
func (defaultHooks) KernelException(Vector) {
	Halt()
}

// kernelSyscall is a trampoline.
//
// When in amd64, it is called with %rip on the upper half, so it can
// NOT access to any global data which is not mapped on upper and must
// call to function pointers or interfaces to switch to the lower half
// so that callee can access to global data.
//
// +checkescape:hard,stack
//
//go:nosplit
func kernelSyscall(c *CPU) {
	c.hooks.KernelSyscall()
}

// kernelException is a trampoline.
//
// When in amd64, it is called with %rip on the upper half, so it can
// NOT access to any global data which is not mapped on upper and must
// call to function pointers or interfaces to switch to the lower half
// so that callee can access to global data.
//
// +checkescape:hard,stack
//
//go:nosplit
func kernelException(c *CPU, vector Vector) {
	c.hooks.KernelException(vector)
}

// Init initializes a new CPU.
//
// Init allows embedding in other objects.
func (c *CPU) Init(k *Kernel, cpuID int, hooks Hooks) {
	c.self = c    // Set self reference.
	c.kernel = k  // Set kernel reference.
	c.init(cpuID) // Perform architectural init.

	// Require hooks.
	if hooks != nil {
		c.hooks = hooks
	} else {
		c.hooks = defaultHooks{}
	}
}
