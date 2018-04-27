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

// +build amd64

package ptrace

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
)

const (
	// maximumUserAddress is the largest possible user address.
	maximumUserAddress = 0x7ffffffff000

	// initRegsRipAdjustment is the size of the syscall instruction.
	initRegsRipAdjustment = 2
)

// Linux kernel errnos which "should never be seen by user programs", but will
// be revealed to ptrace syscall exit tracing.
//
// These constants are used in subprocess.go.
const (
	ERESTARTSYS    = syscall.Errno(512)
	ERESTARTNOINTR = syscall.Errno(513)
	ERESTARTNOHAND = syscall.Errno(514)
)

// resetSysemuRegs sets up emulation registers.
//
// This should be called prior to calling sysemu.
func (s *subprocess) resetSysemuRegs(regs *syscall.PtraceRegs) {
	regs.Cs = s.initRegs.Cs
	regs.Ss = s.initRegs.Ss
	regs.Ds = s.initRegs.Ds
	regs.Es = s.initRegs.Es
	regs.Fs = s.initRegs.Fs
	regs.Gs = s.initRegs.Gs
}

// createSyscallRegs sets up syscall registers.
//
// This should be called to generate registers for a system call.
func createSyscallRegs(initRegs *syscall.PtraceRegs, sysno uintptr, args ...arch.SyscallArgument) syscall.PtraceRegs {
	// Copy initial registers (RIP, segments, etc.).
	regs := *initRegs

	// Set our syscall number.
	regs.Rax = uint64(sysno)
	if len(args) >= 1 {
		regs.Rdi = args[0].Uint64()
	}
	if len(args) >= 2 {
		regs.Rsi = args[1].Uint64()
	}
	if len(args) >= 3 {
		regs.Rdx = args[2].Uint64()
	}
	if len(args) >= 4 {
		regs.R10 = args[3].Uint64()
	}
	if len(args) >= 5 {
		regs.R8 = args[4].Uint64()
	}
	if len(args) >= 6 {
		regs.R9 = args[5].Uint64()
	}

	return regs
}

// isSingleStepping determines if the registers indicate single-stepping.
func isSingleStepping(regs *syscall.PtraceRegs) bool {
	return (regs.Eflags & arch.X86TrapFlag) != 0
}

// updateSyscallRegs updates registers after finishing sysemu.
func updateSyscallRegs(regs *syscall.PtraceRegs) {
	// Ptrace puts -ENOSYS in rax on syscall-enter-stop.
	regs.Rax = regs.Orig_rax
}

// syscallReturnValue extracts a sensible return from registers.
func syscallReturnValue(regs *syscall.PtraceRegs) (uintptr, error) {
	rval := int64(regs.Rax)
	if rval < 0 {
		return 0, syscall.Errno(-rval)
	}
	return uintptr(rval), nil
}
