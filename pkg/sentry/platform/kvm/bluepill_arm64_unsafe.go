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
	"unsafe"

	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/ring0"
)

// dieArchSetup initialies the state for dieTrampoline.
//
// The arm64 dieTrampoline requires the vCPU to be set in R1, and the last PC
// to be in R0. The trampoline then simulates a call to dieHandler from the
// provided PC.
//
//go:nosplit
func dieArchSetup(c *vCPU, context *arch.SignalContext64, guestRegs *userRegs) {
	// If the vCPU is in user mode, we set the stack to the stored stack
	// value in the vCPU itself. We don't want to unwind the user stack.
	if guestRegs.Regs.Pstate&ring0.PSR_MODE_MASK == ring0.PSR_MODE_EL0t {
		regs := c.CPU.Registers()
		context.Regs[0] = regs.Regs[0]
		context.Sp = regs.Sp
		context.Regs[29] = regs.Regs[29] // stack base address
	} else {
		context.Regs[0] = guestRegs.Regs.Pc
		context.Sp = guestRegs.Regs.Sp
		context.Regs[29] = guestRegs.Regs.Regs[29]
		context.Pstate = guestRegs.Regs.Pstate
	}
	context.Regs[1] = uint64(uintptr(unsafe.Pointer(c)))
	context.Pc = uint64(dieTrampolineAddr)
}
