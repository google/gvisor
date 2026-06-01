// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

// Package ring0: the LoongArch port targets only the ptrace platform,
// which does NOT use ring0. This file provides the minimum set of types
// and method stubs needed so the package compiles. Anything ever called
// at runtime here would indicate a configuration bug.

package ring0

// KernelArchState is empty on LoongArch64.
//
// +stateify savable
type KernelArchState struct{}

// CPUArchState is empty on LoongArch64.
//
// +stateify savable
type CPUArchState struct{}

// SwitchArchOpts is empty on LoongArch64.
type SwitchArchOpts struct{}

// Vector identifies an exception or syscall vector.
type Vector int

const ring0NotImpl = "ring0 is not implemented on LoongArch64 (gVisor uses the ptrace platform here)"

// init is the per-Kernel architectural init hook called by Kernel.Init.
func (k *Kernel) init(maxCPUs int) {}

// init is the per-CPU architectural init hook called by CPU.Init.
func (c *CPU) init(cpuID int) {}

// StackTop returns the kernel stack top; ring0 is unused on LoongArch.
//
//go:nosplit
func (c *CPU) StackTop() uint64 { return 0 }

// SwitchToUser would transition CPU into user mode. Never invoked on
// LoongArch because the ptrace platform schedules user code via a
// tracee thread, not by an in-process mode switch.
//
//go:nosplit
func (c *CPU) SwitchToUser(switchOpts SwitchOpts) (vector Vector) {
	panic(ring0NotImpl)
}

// KernelStartAddress placeholder so ring0/kernel_unsafe.go compiles. The
// ptrace platform never reads this value on LoongArch.
const KernelStartAddress uintptr = 0

// InitDefault is a no-op on LoongArch64; ring0 is not used.
func InitDefault() {}
