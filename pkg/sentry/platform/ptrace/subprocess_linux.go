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

// +build linux

package ptrace

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/seccomp"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/procid"
)

const (
	syscallEvent           syscall.Signal = 0x80
	seccompEvent           syscall.Signal = 0x700 // 0x7 (PTRACE_SECCOMP_EVENT) << 8
	_PTRACE_O_TRACESECCOMP                = 0x80  // 1 << 0x7 (PTRACE_SECCOMP_EVENT)
)

// probeSeccomp returns true iff seccomp is run after ptrace notifications,
// which is generally the case for kernel version >= 4.8. This check is dynamic
// because kernels have be backported behavior.
//
// See createStub for more information.
//
// Precondition: the runtime OS thread must be locked.
func probeSeccomp() bool {
	// Create a completely new, destroyable process.
	t, err := attachedThread(0, uint32(linux.SECCOMP_RET_ERRNO))
	if err != nil {
		panic(fmt.Sprintf("seccomp probe failed: %v", err))
	}
	defer t.destroy()

	// Set registers to the yield system call. This call is not allowed
	// by the filters specified in the attachThread function.
	regs := createSyscallRegs(&t.initRegs, syscall.SYS_SCHED_YIELD)
	if err := t.setRegs(&regs); err != nil {
		panic(fmt.Sprintf("ptrace set regs failed: %v", err))
	}

	for {
		// Attempt an emulation.
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PTRACE, syscall.PTRACE_SYSEMU, uintptr(t.tid), 0); errno != 0 {
			panic(fmt.Sprintf("ptrace syscall-enter failed: %v", errno))
		}

		sig := t.wait(stopped)
		if sig == (syscallEvent | syscall.SIGTRAP) {
			// Did the seccomp errno hook already run? This would
			// indicate that seccomp is first in line and we're
			// less than 4.8.
			if err := t.getRegs(&regs); err != nil {
				panic(fmt.Sprintf("ptrace get-regs failed: %v", err))
			}
			if _, err := syscallReturnValue(&regs); err == nil {
				// The seccomp errno mode ran first, and reset
				// the error in the registers.
				return false
			}
			// The seccomp hook did not run yet, and therefore it
			// is safe to use RET_KILL mode for dispatched calls.
			return true
		}
	}
}

// createStub creates a fresh stub processes.
//
// Precondition: the runtime OS thread must be locked.
func createStub() (*thread, error) {
	// The exact interactions of ptrace and seccomp are complex, and
	// changed in recent kernel versions. Before commit 93e35efb8de45, the
	// seccomp check is done before the ptrace emulation check. This means
	// that any calls not matching this list will trigger the seccomp
	// default action instead of notifying ptrace.
	//
	// After commit 93e35efb8de45, the seccomp check is done after the
	// ptrace emulation check. This simplifies using SYSEMU, since seccomp
	// will never run for emulation. Seccomp will only run for injected
	// system calls, and thus we can use RET_KILL as our violation action.
	var defaultAction uint32
	if probeSeccomp() {
		log.Infof("Latest seccomp behavior found (kernel >= 4.8 likely)")
		defaultAction = uint32(linux.SECCOMP_RET_KILL)
	} else {
		// We must rely on SYSEMU behavior; tracing with SYSEMU is broken.
		log.Infof("Legacy seccomp behavior found (kernel < 4.8 likely)")
		defaultAction = uint32(linux.SECCOMP_RET_ALLOW)
	}

	// When creating the new child process, we specify SIGKILL as the
	// signal to deliver when the child exits. We never expect a subprocess
	// to exit; they are pooled and reused. This is done to ensure that if
	// a subprocess is OOM-killed, this process (and all other stubs,
	// transitively) will be killed as well. It's simply not possible to
	// safely handle a single stub getting killed: the exact state of
	// execution is unknown and not recoverable.
	return attachedThread(uintptr(syscall.SIGKILL)|syscall.CLONE_FILES, defaultAction)
}

// attachedThread returns a new attached thread.
//
// Precondition: the runtime OS thread must be locked.
func attachedThread(flags uintptr, defaultAction uint32) (*thread, error) {
	// Create a BPF program that allows only the system calls needed by the
	// stub and all its children. This is used to create child stubs
	// (below), so we must include the ability to fork, but otherwise lock
	// down available calls only to what is needed.
	rules := []seccomp.RuleSet{
		// Rules for trapping vsyscall access.
		seccomp.RuleSet{
			Rules: seccomp.SyscallRules{
				syscall.SYS_GETTIMEOFDAY: {},
				syscall.SYS_TIME:         {},
				309:                      {}, // SYS_GETCPU.
			},
			Action:   uint32(linux.SECCOMP_RET_TRACE),
			Vsyscall: true,
		},
	}
	if defaultAction != uint32(linux.SECCOMP_RET_ALLOW) {
		rules = append(rules, seccomp.RuleSet{
			Rules: seccomp.SyscallRules{
				syscall.SYS_CLONE: []seccomp.Rule{
					// Allow creation of new subprocesses (used by the master).
					{seccomp.AllowValue(syscall.CLONE_FILES | syscall.SIGKILL)},
					// Allow creation of new threads within a single address space (used by addresss spaces).
					{seccomp.AllowValue(
						syscall.CLONE_FILES |
							syscall.CLONE_FS |
							syscall.CLONE_SIGHAND |
							syscall.CLONE_THREAD |
							syscall.CLONE_PTRACE |
							syscall.CLONE_VM)},
				},

				// For the initial process creation.
				syscall.SYS_WAIT4: {},
				syscall.SYS_ARCH_PRCTL: []seccomp.Rule{
					{seccomp.AllowValue(linux.ARCH_SET_CPUID), seccomp.AllowValue(0)},
				},
				syscall.SYS_EXIT: {},

				// For the stub prctl dance (all).
				syscall.SYS_PRCTL: []seccomp.Rule{
					{seccomp.AllowValue(syscall.PR_SET_PDEATHSIG), seccomp.AllowValue(syscall.SIGKILL)},
				},
				syscall.SYS_GETPPID: {},

				// For the stub to stop itself (all).
				syscall.SYS_GETPID: {},
				syscall.SYS_KILL: []seccomp.Rule{
					{seccomp.AllowAny{}, seccomp.AllowValue(syscall.SIGSTOP)},
				},

				// Injected to support the address space operations.
				syscall.SYS_MMAP:   {},
				syscall.SYS_MUNMAP: {},
			},
			Action: uint32(linux.SECCOMP_RET_ALLOW),
		})
	}
	instrs, err := seccomp.BuildProgram(rules, defaultAction)
	if err != nil {
		return nil, err
	}

	// Declare all variables up front in order to ensure that there's no
	// need for allocations between beforeFork & afterFork.
	var (
		pid   uintptr
		ppid  uintptr
		errno syscall.Errno
	)

	// Remember the current ppid for the pdeathsig race.
	ppid, _, _ = syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)

	// Among other things, beforeFork masks all signals.
	beforeFork()

	// Do the clone.
	pid, _, errno = syscall.RawSyscall6(syscall.SYS_CLONE, flags, 0, 0, 0, 0, 0)
	if errno != 0 {
		afterFork()
		return nil, errno
	}

	// Is this the parent?
	if pid != 0 {
		// Among other things, restore signal mask.
		afterFork()

		// Initialize the first thread.
		t := &thread{
			tgid: int32(pid),
			tid:  int32(pid),
			cpu:  ^uint32(0),
		}
		if sig := t.wait(stopped); sig != syscall.SIGSTOP {
			return nil, fmt.Errorf("wait failed: expected SIGSTOP, got %v", sig)
		}
		t.attach()

		return t, nil
	}

	// Move the stub to a new session (and thus a new process group). This
	// prevents the stub from getting PTY job control signals intended only
	// for the sentry process. We must call this before restoring signal
	// mask.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETSID, 0, 0, 0); errno != 0 {
		syscall.RawSyscall(syscall.SYS_EXIT, uintptr(errno), 0, 0)
	}

	// afterForkInChild resets all signals to their default dispositions
	// and restores the signal mask to its pre-fork state.
	afterForkInChild()

	// Explicitly unmask all signals to ensure that the tracer can see
	// them.
	if errno := unmaskAllSignals(); errno != 0 {
		syscall.RawSyscall(syscall.SYS_EXIT, uintptr(errno), 0, 0)
	}

	// Set an aggressive BPF filter for the stub and all it's children. See
	// the description of the BPF program built above.
	if errno := seccomp.SetFilter(instrs); errno != 0 {
		syscall.RawSyscall(syscall.SYS_EXIT, uintptr(errno), 0, 0)
	}

	// Enable cpuid-faulting; this may fail on older kernels or hardware,
	// so we just disregard the result. Host CPUID will be enabled.
	syscall.RawSyscall(syscall.SYS_ARCH_PRCTL, linux.ARCH_SET_CPUID, 0, 0)

	// Call the stub; should not return.
	stubCall(stubStart, ppid)
	panic("unreachable")
}

// createStub creates a stub processes as a child of an existing subprocesses.
//
// Precondition: the runtime OS thread must be locked.
func (s *subprocess) createStub() (*thread, error) {
	// There's no need to lock the runtime thread here, as this can only be
	// called from a context that is already locked.
	currentTID := int32(procid.Current())
	t := s.syscallThreads.lookupOrCreate(currentTID, s.newThread)

	// Pass the expected PPID to the child via R15.
	regs := t.initRegs
	regs.R15 = uint64(t.tgid)

	// Call fork in a subprocess.
	//
	// The new child must set up PDEATHSIG to ensure it dies if this
	// process dies. Since this process could die at any time, this cannot
	// be done via instrumentation from here.
	//
	// Instead, we create the child untraced, which will do the PDEATHSIG
	// setup and then SIGSTOP itself for our attach below.
	//
	// See above re: SIGKILL.
	pid, err := t.syscallIgnoreInterrupt(
		&regs,
		syscall.SYS_CLONE,
		arch.SyscallArgument{Value: uintptr(syscall.SIGKILL | syscall.CLONE_FILES)},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0})
	if err != nil {
		return nil, err
	}

	// Wait for child to enter group-stop, so we don't stop its
	// bootstrapping work with t.attach below.
	//
	// We unfortunately don't have a handy part of memory to write the wait
	// status. If the wait succeeds, we'll assume that it was the SIGSTOP.
	// If the child actually exited, the attach below will fail.
	_, err = t.syscallIgnoreInterrupt(
		&t.initRegs,
		syscall.SYS_WAIT4,
		arch.SyscallArgument{Value: uintptr(pid)},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: syscall.WALL | syscall.WUNTRACED},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0})
	if err != nil {
		return nil, err
	}

	childT := &thread{
		tgid: int32(pid),
		tid:  int32(pid),
		cpu:  ^uint32(0),
	}
	childT.attach()

	return childT, nil
}
