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
func (k *Kernel) Init(opts KernelOpts) {
	k.init(opts)
}

// Halt halts execution.
func Halt()

// defaultHooks implements hooks.
type defaultHooks struct{}

// KernelSyscall implements Hooks.KernelSyscall.
//
//go:nosplit
func (defaultHooks) KernelSyscall() { Halt() }

// KernelException implements Hooks.KernelException.
//
//go:nosplit
func (defaultHooks) KernelException(Vector) { Halt() }

// kernelSyscall is a trampoline.
//
//go:nosplit
func kernelSyscall(c *CPU) { c.hooks.KernelSyscall() }

// kernelException is a trampoline.
//
//go:nosplit
func kernelException(c *CPU, vector Vector) { c.hooks.KernelException(vector) }

// Init initializes a new CPU.
//
// Init allows embedding in other objects.
func (c *CPU) Init(k *Kernel, hooks Hooks) {
	c.self = c   // Set self reference.
	c.kernel = k // Set kernel reference.
	c.init()     // Perform architectural init.

	// Require hooks.
	if hooks != nil {
		c.hooks = hooks
	} else {
		c.hooks = defaultHooks{}
	}
}
