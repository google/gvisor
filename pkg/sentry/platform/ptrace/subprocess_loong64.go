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

package ptrace

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

const (
	// initRegsRipAdjustment is the size of the `syscall 0` instruction on
	// LoongArch. Used to rewind Era so the syscall is re-executed after
	// sentry has rewritten the syscall number / arguments.
	initRegsRipAdjustment = 4
)

// resetSysemuRegs sets up emulation registers. No-op on LoongArch: no
// CPU-flag clearing is required between sysemu iterations.
func (t *thread) resetSysemuRegs(regs *arch.Registers) {
}

// createSyscallRegs prepares a register set for issuing a syscall. The
// LoongArch Linux ABI puts the syscall number in $a7 ($r11) and arguments
// in $a0..$a5 ($r4..$r9); $a0 also receives the return value.
func createSyscallRegs(initRegs *arch.Registers, sysno uintptr, args ...arch.SyscallArgument) arch.Registers {
	// Inherit Era / SP / callee-saved regs from initRegs.
	regs := *initRegs

	regs.Regs[11] = uint64(sysno) // $a7 = syscall number
	if len(args) >= 1 {
		regs.Regs[4] = args[0].Uint64()
	}
	if len(args) >= 2 {
		regs.Regs[5] = args[1].Uint64()
	}
	if len(args) >= 3 {
		regs.Regs[6] = args[2].Uint64()
	}
	if len(args) >= 4 {
		regs.Regs[7] = args[3].Uint64()
	}
	if len(args) >= 5 {
		regs.Regs[8] = args[4].Uint64()
	}
	if len(args) >= 6 {
		regs.Regs[9] = args[5].Uint64()
	}
	return regs
}

// isSingleStepping returns true if the registers indicate single-stepping.
// LoongArch ptrace single-step is currently not exposed in gVisor and the
// helper is left returning false.
func isSingleStepping(regs *arch.Registers) bool {
	return false
}

// updateSyscallRegs is called after a sysemu round. Nothing to fix up on
// LoongArch — Era / args / OrigA0 are already in the right shape.
func updateSyscallRegs(regs *arch.Registers) {
}

// syscallReturnValue extracts the syscall return from $a0 ($r4). Negative
// values are interpreted as -errno per the Linux convention.
func syscallReturnValue(regs *arch.Registers) (uintptr, error) {
	rval := int64(regs.Regs[4])
	if rval < 0 {
		return 0, unix.Errno(-rval)
	}
	return uintptr(rval), nil
}

func dumpRegs(regs *arch.Registers) string {
	var m strings.Builder
	fmt.Fprintf(&m, "Registers:\n")
	for i := 0; i < 32; i++ {
		fmt.Fprintf(&m, "\tRegs[%d]\t = %016x\n", i, regs.Regs[i])
	}
	fmt.Fprintf(&m, "\tOrigA0\t = %016x\n", regs.OrigA0)
	fmt.Fprintf(&m, "\tEra\t    = %016x\n", regs.Era)
	fmt.Fprintf(&m, "\tBadv\t   = %016x\n", regs.Badv)
	return m.String()
}

// adjustInitRegsRip rewinds Era by 4 bytes so we are positioned at the
// start of the `syscall 0` instruction in the stub. The next ptrace resume
// will re-execute it with the rewritten arguments.
func (t *thread) adjustInitRegsRip() {
	t.initRegs.Era -= initRegsRipAdjustment
}

// initChildProcessPPID passes the expected parent PID and the
// initial-stub flag to a freshly spawned stub child. We use the
// callee-saved registers $s0 ($r23) and $s1 ($r24) because they survive
// every syscall the kernel runs on the child's behalf — unlike $a7 / $a0
// which are clobbered by syscall entry/exit.
func initChildProcessPPID(initregs *arch.Registers, ppid int32) {
	initregs.Regs[23] = uint64(ppid) // $s0 = expected PPID
	initregs.Regs[24] = 1             // $s1 = 1 marks the initial bootstrap
}

// patchSignalInfo turns a SIGSYS (raised by seccomp on a denied vsyscall
// emulation, etc.) into a SIGSEGV that fault-handling code paths
// elsewhere in gVisor expect. The Era is repointed at the faulting
// instruction and the stack push performed by the kernel for SIGSYS is
// undone (`Regs[3] -= 8`).
func patchSignalInfo(regs *arch.Registers, signalInfo *linux.SignalInfo) {
	if linux.Signal(signalInfo.Signo) == linux.SIGSYS {
		signalInfo.Signo = int32(linux.SIGSEGV)
		regs.Era = signalInfo.Addr()
		regs.Regs[3] -= 8 // $sp (= $r3)
	}
}

// enableCpuidFault is a no-op on LoongArch (no CPUID-equivalent fault).
//
//go:nosplit
func enableCpuidFault() {
}

// appendArchSeccompRules returns the input rules unchanged. LoongArch has
// no special vsyscall / vDSO trampoline that the BPF filter must cover.
func appendArchSeccompRules(rules []seccomp.RuleSet, defaultAction seccomp.Action) []seccomp.RuleSet {
	return rules
}

// probeSeccomp returns true: PTRACE_SYSEMU + PTRACE_O_TRACESECCOMP work
// together on LoongArch since the architecture's mainline support landed
// in Linux 5.19.
func probeSeccomp() bool {
	return true
}

// arm64SyscallWorkaround is named after its arm64 sibling but the ptrace
// quirk it addresses (kernel exposing x7 to indicate syscall enter/exit)
// does not exist on LoongArch. We provide the method only so the generic
// subprocess.go path that calls it compiles.
func (s *subprocess) arm64SyscallWorkaround(t *thread, regs *arch.Registers) {
}
