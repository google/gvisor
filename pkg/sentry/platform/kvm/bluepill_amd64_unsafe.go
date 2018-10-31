// Copyright 2018 Google LLC
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

// +build amd64

package kvm

import (
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0"
)

// bluepillArchContext returns the arch-specific context.
//
//go:nosplit
func bluepillArchContext(context unsafe.Pointer) *arch.SignalContext64 {
	return &((*arch.UContext64)(context).MContext)
}

// dieArchSetup initialies the state for dieTrampoline.
//
// The amd64 dieTrampoline requires the vCPU to be set in BX, and the last RIP
// to be in AX. The trampoline then simulates a call to dieHandler from the
// provided RIP.
//
//go:nosplit
func dieArchSetup(c *vCPU, context *arch.SignalContext64, guestRegs *userRegs) {
	// If the vCPU is in user mode, we set the stack to the stored stack
	// value in the vCPU itself. We don't want to unwind the user stack.
	if guestRegs.RFLAGS&ring0.UserFlagsSet == ring0.UserFlagsSet {
		regs := c.CPU.Registers()
		context.Rax = regs.Rax
		context.Rsp = regs.Rsp
		context.Rbp = regs.Rbp
	} else {
		context.Rax = guestRegs.RIP
		context.Rsp = guestRegs.RSP
		context.Rbp = guestRegs.RBP
		context.Eflags = guestRegs.RFLAGS
	}
	context.Rbx = uint64(uintptr(unsafe.Pointer(c)))
	context.Rip = uint64(dieTrampolineAddr)
}
