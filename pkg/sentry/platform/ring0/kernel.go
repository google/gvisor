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

package ring0

// New creates a new kernel.
//
// N.B. that constraints on KernelOpts must be satisfied.
//
// Init must have been called.
func New(opts KernelOpts) *Kernel {
	k := new(Kernel)
	k.init(opts)
	return k
}

// NewCPU creates a new CPU associated with this Kernel.
//
// Note that execution of the new CPU must begin at Start, with constraints as
// documented. Initialization is not completed by this method alone.
//
// See also Init.
func (k *Kernel) NewCPU() *CPU {
	c := new(CPU)
	c.Init(k)
	return c
}

// Halt halts execution.
func Halt()

// Current returns the current CPU.
//
// Its use is only legal in the KernelSyscall and KernelException contexts,
// which must all be guarded go:nosplit.
func Current() *CPU

// defaultSyscall is the default syscall hook.
//
//go:nosplit
func defaultSyscall() { Halt() }

// defaultException is the default exception hook.
//
//go:nosplit
func defaultException(Vector) { Halt() }

// Init allows the initialization of a CPU from a kernel without allocation.
// The same constraints as NewCPU apply.
//
// Init allows embedding in other objects.
func (c *CPU) Init(k *Kernel) {
	c.self = c   // Set self reference.
	c.kernel = k // Set kernel reference.
	c.init()     // Perform architectural init.

	// Defaults.
	c.KernelSyscall = defaultSyscall
	c.KernelException = defaultException
}
