// Copyright 2018 The gVisor Authors.
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
	"fmt"
	"strings"
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
func (t *thread) resetSysemuRegs(regs *syscall.PtraceRegs) {
	regs.Cs = t.initRegs.Cs
	regs.Ss = t.initRegs.Ss
	regs.Ds = t.initRegs.Ds
	regs.Es = t.initRegs.Es
	regs.Fs = t.initRegs.Fs
	regs.Gs = t.initRegs.Gs
}

// createSyscallRegs sets up syscall registers.
//
// This should be called to generate registers for a system call.
func createSyscallRegs(initRegs *syscall.PtraceRegs, sysno uintptr, args ...arch.SyscallArgument) syscall.PtraceRegs {
	// Copy initial registers.
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

func dumpRegs(regs *syscall.PtraceRegs) string {
	var m strings.Builder

	fmt.Fprintf(&m, "Registers:\n")
	fmt.Fprintf(&m, "\tR15\t = %016x\n", regs.R15)
	fmt.Fprintf(&m, "\tR14\t = %016x\n", regs.R14)
	fmt.Fprintf(&m, "\tR13\t = %016x\n", regs.R13)
	fmt.Fprintf(&m, "\tR12\t = %016x\n", regs.R12)
	fmt.Fprintf(&m, "\tRbp\t = %016x\n", regs.Rbp)
	fmt.Fprintf(&m, "\tRbx\t = %016x\n", regs.Rbx)
	fmt.Fprintf(&m, "\tR11\t = %016x\n", regs.R11)
	fmt.Fprintf(&m, "\tR10\t = %016x\n", regs.R10)
	fmt.Fprintf(&m, "\tR9\t = %016x\n", regs.R9)
	fmt.Fprintf(&m, "\tR8\t = %016x\n", regs.R8)
	fmt.Fprintf(&m, "\tRax\t = %016x\n", regs.Rax)
	fmt.Fprintf(&m, "\tRcx\t = %016x\n", regs.Rcx)
	fmt.Fprintf(&m, "\tRdx\t = %016x\n", regs.Rdx)
	fmt.Fprintf(&m, "\tRsi\t = %016x\n", regs.Rsi)
	fmt.Fprintf(&m, "\tRdi\t = %016x\n", regs.Rdi)
	fmt.Fprintf(&m, "\tOrig_rax = %016x\n", regs.Orig_rax)
	fmt.Fprintf(&m, "\tRip\t = %016x\n", regs.Rip)
	fmt.Fprintf(&m, "\tCs\t = %016x\n", regs.Cs)
	fmt.Fprintf(&m, "\tEflags\t = %016x\n", regs.Eflags)
	fmt.Fprintf(&m, "\tRsp\t = %016x\n", regs.Rsp)
	fmt.Fprintf(&m, "\tSs\t = %016x\n", regs.Ss)
	fmt.Fprintf(&m, "\tFs_base\t = %016x\n", regs.Fs_base)
	fmt.Fprintf(&m, "\tGs_base\t = %016x\n", regs.Gs_base)
	fmt.Fprintf(&m, "\tDs\t = %016x\n", regs.Ds)
	fmt.Fprintf(&m, "\tEs\t = %016x\n", regs.Es)
	fmt.Fprintf(&m, "\tFs\t = %016x\n", regs.Fs)
	fmt.Fprintf(&m, "\tGs\t = %016x\n", regs.Gs)

	return m.String()
}
