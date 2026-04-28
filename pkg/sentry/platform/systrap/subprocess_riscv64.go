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

//go:build riscv64
// +build riscv64

package systrap

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

const (
	// initRegsRipAdjustment is the size of the svc instruction.
	initRegsRipAdjustment = 4
	// syscall num of riscv_flush_icache
	RISCV_FLUSH_ICACHE = 259
)

// resetSysemuRegs sets up emulation registers.
//
// This should be called prior to calling sysemu.
func (s *subprocess) resetSysemuRegs(regs *arch.Registers) {
}

// createSyscallRegs sets up syscall registers.
//
// This should be called to generate registers for a system call.
func createSyscallRegs(initRegs *arch.Registers, sysno uintptr, args ...arch.SyscallArgument) arch.Registers {
	// Copy initial registers (Pc, Sp, etc.).
	regs := *initRegs

	// Set our syscall number.
	// a7 for the syscall number.
	// a0-a5 is used to store the parameters.
	regs.Regs[17] = uint64(sysno)
	if len(args) >= 1 {
		regs.Regs[10] = args[0].Uint64()
	}
	if len(args) >= 2 {
		regs.Regs[11] = args[1].Uint64()
	}
	if len(args) >= 3 {
		regs.Regs[12] = args[2].Uint64()
	}
	if len(args) >= 4 {
		regs.Regs[13] = args[3].Uint64()
	}
	if len(args) >= 5 {
		regs.Regs[14] = args[4].Uint64()
	}
	if len(args) >= 6 {
		regs.Regs[15] = args[5].Uint64()
	}

	return regs
}

// updateSyscallRegs updates registers after finishing sysemu.
func updateSyscallRegs(regs *arch.Registers) {
	// No special work is necessary.
	return
}

// syscallReturnValue extracts a sensible return from registers.
func syscallReturnValue(regs *arch.Registers) (uintptr, error) {
	rval := int64(regs.Regs[10])
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
	fmt.Fprintf(&m, "\tSp\t = %016x\n", regs.Regs[2])
	fmt.Fprintf(&m, "\tPc\t = %016x\n", regs.Regs[0])
	//fmt.Fprintf(&m, "\tPstate\t = %016x\n", regs.Pstate)

	return m.String()
}

// adjustInitregsRip adjust the current register RIP value to
// be just before the system call instruction execution.
func (t *thread) adjustInitRegsRip() {
	t.initRegs.Regs[0] -= initRegsRipAdjustment
}

// Pass the expected PPID to the child via S7 when creating stub process
func initChildProcessPPID(initregs *arch.Registers, ppid int32) {
	// S8 has to be set to 1 when creating stub process.
	initregs.Regs[24] = _NEW_STUB
}

// sigErrorToAccessType determines the access type for a signal error.
//
// On RISC-V, the scause register values for page faults are:
//
//	12 = instruction page fault (Execute)
//	13 = load page fault (Read)
//	15 = store/AMO page fault (Write)
func sigErrorToAccessType(sigError uint64) hostarch.AccessType {
	switch sigError {
	case 15: // Store/AMO page fault
		return hostarch.Write
	case 12: // Instruction page fault
		return hostarch.Execute
	case 13: // Load page fault
		return hostarch.Read
	default:
		return hostarch.NoAccess
	}
}

func maybePatchSignalInfo(regs *arch.Registers, signalInfo *linux.SignalInfo) (patched bool) {
	// vsyscall emulation is not supported on ARM64. No need to patch anything.
	return false
}

// Noop on riscv64.
//
//go:nosplit
func enableCpuidFault() {
}

// appendArchSeccompRules append architecture specific seccomp rules when creating BPF program.
// Ref attachedThread() for more detail.
func appendArchSeccompRules(rules []seccomp.RuleSet) []seccomp.RuleSet {
	return append(rules, []seccomp.RuleSet{
		{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				RISCV_FLUSH_ICACHE: seccomp.MatchAll{},
			}),
			Action: seccomp.Allow,
		},
	}...)
}

// probeSeccomp returns true if seccomp is run after ptrace notifications,
// which is generally the case for kernel version >= 4.8.
//
// On riscv64, the support of PTRACE_SYSEMU was added in the 5.3 kernel, so
// probeSeccomp can always return true.
func probeSeccomp() bool {
	return true
}

func restoreArchSpecificState(ctx *sysmsg.ThreadContext, ac *arch.Context64) {
}

func setArchSpecificRegs(sysThread *sysmsgThread, regs *arch.Registers) {
}

func retrieveArchSpecificState(ctx *sysmsg.ThreadContext, ac *arch.Context64) {
}

func archSpecificSysmsgThreadInit(sysThread *sysmsgThread) {
	// Send a fake event to stop the BPF process so that it enters the sighandler.
	if _, _, e := unix.RawSyscall(unix.SYS_TGKILL, uintptr(sysThread.thread.tgid), uintptr(sysThread.thread.tid), uintptr(unix.SIGSEGV)); e != 0 {
		panic(fmt.Sprintf("tkill failed: %v", e))
	}
}

func (s *subprocess) doFlushIcache(ac *arch.Context64) error {
	if (!ac.FlushIcache) {
		return nil
	}
	ac.FlushIcache = false
	// force a global flush since it's called from syscallThread
	_, err := s.syscall(uintptr(RISCV_FLUSH_ICACHE))
	return err
}
