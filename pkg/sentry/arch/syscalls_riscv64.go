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

//go:build riscv64
// +build riscv64

package arch

const restartSyscallNr = uintptr(128)

// SyscallSaveOrig save the value of the register which is clobbered in
// syscall handler(doSyscall()).
//
func (c *Context64) SyscallSaveOrig() {
	c.OrigA0 = c.Regs.Regs[32]
}

// SyscallNo returns the syscall number according to the 64-bit convention.
func (c *Context64) SyscallNo() uintptr {
	return uintptr(c.Regs.Regs[17])
}

// SyscallArgs provides syscall arguments according to the 64-bit convention.
//
// Due to the way addresses are mapped for the sentry this binary *must* be
// built in 64-bit mode. So we can just assume the syscall numbers that come
// back match the expected host system call numbers.
func (c *Context64) SyscallArgs() SyscallArguments {
	return SyscallArguments{
		SyscallArgument{Value: uintptr(c.OrigA0)},
		SyscallArgument{Value: uintptr(c.Regs.Regs[11])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[12])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[13])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[14])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[15])},
	}
}

// RestartSyscall implements Context.RestartSyscall.
// Please see the linux code as reference:
// arch/riscv64/kernel/signal.c:do_signal()
func (c *Context64) RestartSyscall() {
	c.Regs.Regs[0] -= SyscallWidth
	// PtraceRegs.OrigA0 = c.origA0
	c.Regs.Regs[10] = uint64(c.OrigA0)
}

// RestartSyscallWithRestartBlock implements Context.RestartSyscallWithRestartBlock.
func (c *Context64) RestartSyscallWithRestartBlock() {
	c.Regs.Regs[0] -= SyscallWidth
	c.Regs.Regs[10] = uint64(c.OrigA0)
	c.Regs.Regs[17] = uint64(restartSyscallNr)
}
