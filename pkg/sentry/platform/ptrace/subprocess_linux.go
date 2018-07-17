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

// +build linux

package ptrace

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/procid"
)

// createStub creates a fresh stub processes.
//
// Precondition: the runtime OS thread must be locked.
func createStub() (*thread, error) {
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

	// When creating the new child process, we specify SIGKILL as the
	// signal to deliver when the child exits. We never expect a subprocess
	// to exit; they are pooled and reused. This is done to ensure that if
	// a subprocess is OOM-killed, this process (and all other stubs,
	// transitively) will be killed as well. It's simply not possible to
	// safely handle a single stub getting killed: the exact state of
	// execution is unknown and not recoverable.
	pid, _, errno = syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGKILL)|syscall.CLONE_FILES, 0, 0, 0, 0, 0)
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
		if sig := t.wait(); sig != syscall.SIGSTOP {
			return nil, fmt.Errorf("wait failed: expected SIGSTOP, got %v", sig)
		}
		t.attach()

		return t, nil
	}

	// afterForkInChild resets all signals to their default dispositions
	// and restores the signal mask to its pre-fork state.
	afterForkInChild()

	// Explicitly unmask all signals to ensure that the tracer can see
	// them.
	errno = unmaskAllSignals()
	if errno != 0 {
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
	regs := s.initRegs
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
		&s.initRegs,
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
