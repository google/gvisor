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

package ptrace

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/sentry/arch"
)

const (
	// maximumUserAddress is the largest possible user address.
	maximumUserAddress = 0xfffffffff000

	// stubInitAddress is the initial attempt link address for the stub.
	// Only support 48bits VA currently.
	stubInitAddress = 0xffffffff0000

	// initRegsRipAdjustment is the size of the svc instruction.
	initRegsRipAdjustment = 4
)

// resetSysemuRegs sets up emulation registers.
//
// This should be called prior to calling sysemu.
func (s *subprocess) resetSysemuRegs(regs *syscall.PtraceRegs) {
}

// createSyscallRegs sets up syscall registers.
//
// This should be called to generate registers for a system call.
func createSyscallRegs(initRegs *syscall.PtraceRegs, sysno uintptr, args ...arch.SyscallArgument) syscall.PtraceRegs {
	// Copy initial registers (Pc, Sp, etc.).
	regs := *initRegs

	// Set our syscall number.
	// r8 for the syscall number.
	// r0-r6 is used to store the parameters.
	regs.Regs[8] = uint64(sysno)
	if len(args) >= 1 {
		regs.Regs[0] = args[0].Uint64()
	}
	if len(args) >= 2 {
		regs.Regs[1] = args[1].Uint64()
	}
	if len(args) >= 3 {
		regs.Regs[2] = args[2].Uint64()
	}
	if len(args) >= 4 {
		regs.Regs[3] = args[3].Uint64()
	}
	if len(args) >= 5 {
		regs.Regs[4] = args[4].Uint64()
	}
	if len(args) >= 6 {
		regs.Regs[5] = args[5].Uint64()
	}

	return regs
}

// isSingleStepping determines if the registers indicate single-stepping.
func isSingleStepping(regs *syscall.PtraceRegs) bool {
	// Refer to the ARM SDM D2.12.3: software step state machine
	// return (regs.Pstate.SS == 1) && (MDSCR_EL1.SS == 1).
	//
	// Since the host Linux kernel will set MDSCR_EL1.SS on our behalf
	// when we call a single-step ptrace command, we only need to check
	// the Pstate.SS bit here.
	return (regs.Pstate & arch.ARMTrapFlag) != 0
}

// updateSyscallRegs updates registers after finishing sysemu.
func updateSyscallRegs(regs *syscall.PtraceRegs) {
	// No special work is necessary.
	return
}

// syscallReturnValue extracts a sensible return from registers.
func syscallReturnValue(regs *syscall.PtraceRegs) (uintptr, error) {
	rval := int64(regs.Regs[0])
	if rval < 0 {
		return 0, syscall.Errno(-rval)
	}
	return uintptr(rval), nil
}

func dumpRegs(regs *syscall.PtraceRegs) string {
	var m strings.Builder

	fmt.Fprintf(&m, "Registers:\n")

	for i := 0; i < 31; i++ {
		fmt.Fprintf(&m, "\tRegs[%d]\t = %016x\n", i, regs.Regs[i])
	}
	fmt.Fprintf(&m, "\tSp\t = %016x\n", regs.Sp)
	fmt.Fprintf(&m, "\tPc\t = %016x\n", regs.Pc)
	fmt.Fprintf(&m, "\tPstate\t = %016x\n", regs.Pstate)

	return m.String()
}

// adjustInitregsRip adjust the current register RIP value to
// be just before the system call instruction excution
func (t *thread) adjustInitRegsRip() {
	t.initRegs.Pc -= initRegsRipAdjustment
}

// Pass the expected PPID to the child via X7 when creating stub process
func initChildProcessPPID(initregs *syscall.PtraceRegs, ppid int32) {
	initregs.Regs[7] = uint64(ppid)
}
