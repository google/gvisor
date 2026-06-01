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

package arch

// LoongArch uses the asm-generic syscall table; __NR_restart_syscall = 128.
const restartSyscallNr = uintptr(128)

// SyscallSaveOrig is a no-op on LoongArch64.
//
// The kernel's syscall entry path (arch/loongarch/kernel/syscall.c) saves the
// original $a0 into pt_regs.orig_a0 *before* overwriting $a0 ($r4) with
// -ENOSYS as the default return value. Therefore the original arg0 is always
// available in OrigA0 (read directly from the ptrace register set); there is
// no sentry-side value to snapshot here.
func (c *Context64) SyscallSaveOrig() {}

// SyscallNo returns the syscall number, held in $a7 ($r11).
func (c *Context64) SyscallNo() uintptr {
	return uintptr(c.Regs.Regs[regA7])
}

// SyscallArgs returns syscall arguments $a0..$a5. arg0 comes from OrigA0
// (pt_regs.orig_a0) because the live $a0 register has already been clobbered
// with -ENOSYS by the kernel at syscall entry. args 1..5 are read from
// $a1..$a5 directly.
func (c *Context64) SyscallArgs() SyscallArguments {
	return SyscallArguments{
		SyscallArgument{Value: uintptr(c.Regs.OrigA0)},
		SyscallArgument{Value: uintptr(c.Regs.Regs[regA1])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[regA2])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[regA3])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[regA4])},
		SyscallArgument{Value: uintptr(c.Regs.Regs[regA5])},
	}
}

// RestartSyscall rewinds the PC past the `syscall 0` instruction and restores
// $a0 from OrigA0 so the syscall re-runs with its original argument.
func (c *Context64) RestartSyscall() {
	c.Regs.Era -= SyscallWidth
	c.Regs.Regs[regA0] = uint64(c.Regs.OrigA0)
}

// RestartSyscallWithRestartBlock additionally switches the syscall number to
// __NR_restart_syscall.
func (c *Context64) RestartSyscallWithRestartBlock() {
	c.Regs.Era -= SyscallWidth
	c.Regs.Regs[regA0] = uint64(c.Regs.OrigA0)
	c.Regs.Regs[regA7] = uint64(restartSyscallNr)
}
