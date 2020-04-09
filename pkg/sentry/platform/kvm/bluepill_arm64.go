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

package kvm

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0"
)

var (
	// The action for bluepillSignal is changed by sigaction().
	bluepillSignal = syscall.SIGILL
)

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
	regs.Pstate &^= uint64(ring0.KernelFlagsClear)
	regs.Pstate |= ring0.KernelFlagsSet
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
	context.Pstate &^= uint64(ring0.UserFlagsClear)
	context.Pstate |= ring0.UserFlagsSet
}

// KernelSyscall handles kernel syscalls.
//
//go:nosplit
func (c *vCPU) KernelSyscall() {
	regs := c.Registers()
	if regs.Regs[8] != ^uint64(0) {
		regs.Pc -= 4 // Rewind.
	}
	ring0.Halt()
}

// KernelException handles kernel exceptions.
//
//go:nosplit
func (c *vCPU) KernelException(vector ring0.Vector) {
	regs := c.Registers()
	if vector == ring0.Vector(bounce) {
		regs.Pc = 0
	}
	ring0.Halt()
}
