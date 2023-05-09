// Copyright 2020 The gVisor Authors.
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

//go:build arm64
// +build arm64

package arch

const restartSyscallNr = uintptr(128)

// SyscallSaveOrig save the value of the register R0 which is clobbered in
// syscall handler(doSyscall()).
//
// In linux, at the entry of the syscall handler(el0_svc_common()), value of R0
// is saved to the pt_regs.orig_x0 in kernel code. But currently, the orig_x0
// was not accessible to the userspace application, so we have to do the same
// operation in the sentry code to save the R0 value into the App context.
func (c *Context64) SyscallSaveOrig() {
	c.OrigR0 = c.Regs.Regs[0]
}

// SyscallNo returns the syscall number according to the 64-bit convention.
func (c *Context64) SyscallNo() uintptr {
	return uintptr(c.Regs.Regs[8])
}

// SyscallArgs provides syscall arguments according to the 64-bit convention.
//
// Due to the way addresses are mapped for the sentry this binary *must* be
// built in 64-bit mode. So we can just assume the syscall numbers that come
// back match the expected host system call numbers.
// General purpose registers usage on Arm64:
// R0...R7: parameter/result registers.
// R8: indirect result location register.
// R9...R15: temporary registers.
// R16: the first intra-procedure-call scratch register.
// R17: the second intra-procedure-call scratch register.
// R18: the platform register.
// R19...R28: callee-saved registers.
// R29: the frame pointer.
// R30: the link register.
func (c *Context64) SyscallArgs() SyscallArguments {
	return SyscallArguments{
		SyscallArgument{Value: uintptr(c.OrigR0)},
		SyscallArgument{Value: uintptr(c.Regs.Regs[1])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[2])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[3])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[4])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[5])},
	}
}

// RestartSyscall implements Context.RestartSyscall.
// Prepare for system call restart, OrigR0 will be restored to R0.
// Please see the linux code as reference:
// arch/arm64/kernel/signal.c:do_signal()
func (c *Context64) RestartSyscall() {
	c.Regs.Pc -= SyscallWidth
	// R0 will be backed up into OrigR0 when entering doSyscall().
	// Please see the linux code as reference:
	// arch/arm64/kernel/syscall.c:el0_svc_common().
	// Here we restore it back.
	c.Regs.Regs[0] = uint64(c.OrigR0)
}

// RestartSyscallWithRestartBlock implements Context.RestartSyscallWithRestartBlock.
func (c *Context64) RestartSyscallWithRestartBlock() {
	c.Regs.Pc -= SyscallWidth
	c.Regs.Regs[0] = uint64(c.OrigR0)
	c.Regs.Regs[8] = uint64(restartSyscallNr)
}
