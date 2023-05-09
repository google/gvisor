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

//go:build arm64
// +build arm64

package systrap

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

const (
	// initRegsRipAdjustment is the size of the svc instruction.
	initRegsRipAdjustment = 4
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

// updateSyscallRegs updates registers after finishing sysemu.
func updateSyscallRegs(regs *arch.Registers) {
	// No special work is necessary.
	return
}

// syscallReturnValue extracts a sensible return from registers.
func syscallReturnValue(regs *arch.Registers) (uintptr, error) {
	rval := int64(regs.Regs[0])
	if rval < 0 {
		return 0, unix.Errno(-rval)
	}
	return uintptr(rval), nil
}

func dumpRegs(regs *arch.Registers) string {
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
// be just before the system call instruction execution.
func (t *thread) adjustInitRegsRip() {
	t.initRegs.Pc -= initRegsRipAdjustment
}

// Pass the expected PPID to the child via X7 when creating stub process
func initChildProcessPPID(initregs *arch.Registers, ppid int32) {
	initregs.Regs[7] = uint64(ppid)
	// R9 has to be set to 1 when creating stub process.
	initregs.Regs[9] = _NEW_STUB
}

func maybePatchSignalInfo(regs *arch.Registers, signalInfo *linux.SignalInfo) (patched bool) {
	// vsyscall emulation is not supported on ARM64. No need to patch anything.
	return false
}

// Noop on arm64.
//
//go:nosplit
func enableCpuidFault() {
}

// appendArchSeccompRules append architecture specific seccomp rules when creating BPF program.
// Ref attachedThread() for more detail.
func appendArchSeccompRules(rules []seccomp.RuleSet) []seccomp.RuleSet {
	return rules
}

// probeSeccomp returns true if seccomp is run after ptrace notifications,
// which is generally the case for kernel version >= 4.8.
//
// On arm64, the support of PTRACE_SYSEMU was added in the 5.3 kernel, so
// probeSeccomp can always return true.
func probeSeccomp() bool {
	return true
}

func (s *subprocess) arm64SyscallWorkaround(t *thread, regs *arch.Registers) {
	// On ARM64, when ptrace stops on a system call, it uses the x7
	// register to indicate whether the stop has been signalled from
	// syscall entry or syscall exit. This means that we can't get a value
	// of this register and we can't change it. More details are in the
	// comment for tracehook_report_syscall in arch/arm64/kernel/ptrace.c.
	//
	// This happens only if we stop on a system call, so let's queue a
	// signal, resume a stub thread and catch it on a signal handling.
	t.NotifyInterrupt()
	for {
		if _, _, errno := unix.RawSyscall6(
			unix.SYS_PTRACE,
			unix.PTRACE_SYSEMU,
			uintptr(t.tid), 0, 0, 0, 0); errno != 0 {
			panic(fmt.Sprintf("ptrace sysemu failed: %v", errno))
		}

		// Wait for the syscall-enter stop.
		sig := t.wait(stopped)
		if sig == unix.SIGSTOP {
			// SIGSTOP was delivered to another thread in the same thread
			// group, which initiated another group stop. Just ignore it.
			continue
		}
		if sig == (syscallEvent | unix.SIGTRAP) {
			t.dumpAndPanic(fmt.Sprintf("unexpected syscall event"))
		}
		break
	}
	if err := t.getRegs(regs); err != nil {
		panic(fmt.Sprintf("ptrace get regs failed: %v", err))
	}
}

func restoreArchSpecificState(ctx *sysmsg.ThreadContext, ac *arch.Context64) {
	ctx.TLS = uint64(ac.TLS())
}

func setArchSpecificRegs(sysThread *sysmsgThread, regs *arch.Registers) {
}

func retrieveArchSpecificState(ctx *sysmsg.ThreadContext, ac *arch.Context64) {
	if !ac.SetTLS(uintptr(ctx.TLS)) {
		panic(fmt.Sprintf("ac.SetTLS(%+v) failed", ctx.TLS))
	}
}

func archSpecificSysmsgThreadInit(sysThread *sysmsgThread) {
	// Send a fake event to stop the BPF process so that it enters the sighandler.
	if _, _, e := unix.RawSyscall(unix.SYS_TGKILL, uintptr(sysThread.thread.tgid), uintptr(sysThread.thread.tid), uintptr(unix.SIGSEGV)); e != 0 {
		panic(fmt.Sprintf("tkill failed: %v", e))
	}
}
