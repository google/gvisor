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

// Init initializes a new CPU.
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
