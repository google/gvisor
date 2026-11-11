// Copyright 2026 The gVisor Authors.
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

package kernel

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// syscallUserDispatch is a task's syscall user dispatch configuration, set
// with prctl(PR_SET_SYSCALL_USER_DISPATCH). It follows Linux's
// kernel/entry/syscall_user_dispatch.c. The configuration belongs to one
// thread. Clone starts a task without it and execve clears it, as in Linux.
//
// +stateify savable
type syscallUserDispatch struct {
	// enabled is true while the task's syscalls are subject to dispatch.
	enabled bool

	// offset and length give the range of return addresses whose syscalls
	// are never dispatched. A syscall is exempt when its return address minus
	// offset, wrapping around, is less than length. An inclusive range is
	// stored as its complement.
	offset uint64
	length uint64

	// selector is the address of the byte that allows or blocks syscalls
	// from outside the exempt range, or 0 to block them all.
	selector hostarch.Addr
}

// syscallDispatchVerdict is what syscall user dispatch does with a syscall.
type syscallDispatchVerdict int

const (
	// syscallDispatchAllow runs the syscall.
	syscallDispatchAllow syscallDispatchVerdict = iota

	// syscallDispatchSignal skips the syscall and sends SIGSYS with si_code
	// SYS_USER_DISPATCH.
	syscallDispatchSignal

	// syscallDispatchKillSegv kills the task's thread group with SIGSEGV,
	// because the selector cannot be read.
	syscallDispatchKillSegv

	// syscallDispatchKillSys kills the task's thread group with SIGSYS,
	// because the selector holds neither allow nor block.
	syscallDispatchKillSys
)

// newSyscallUserDispatch validates the arguments of
// prctl(PR_SET_SYSCALL_USER_DISPATCH, mode, offset, length, selector) and
// returns the configuration they set, as task_set_syscall_user_dispatch()
// does. It does not check that the selector is a user address.
func newSyscallUserDispatch(mode, offset, length uint64, selector hostarch.Addr) (syscallUserDispatch, error) {
	switch mode {
	case linux.PR_SYS_DISPATCH_OFF:
		if offset != 0 || length != 0 || selector != 0 {
			return syscallUserDispatch{}, linuxerr.EINVAL
		}
		return syscallUserDispatch{}, nil
	case linux.PR_SYS_DISPATCH_EXCLUSIVE_ON:
		// A zero offset admits any length, so the range may cover every
		// address.
		if offset != 0 && offset+length <= offset {
			return syscallUserDispatch{}, linuxerr.EINVAL
		}
	case linux.PR_SYS_DISPATCH_INCLUSIVE_ON:
		if length == 0 || offset+length <= offset {
			return syscallUserDispatch{}, linuxerr.EINVAL
		}
		// The exempt range is everything outside [offset, offset+length).
		offset, length = offset+length, -length
	default:
		return syscallUserDispatch{}, linuxerr.EINVAL
	}
	return syscallUserDispatch{
		enabled:  true,
		offset:   offset,
		length:   length,
		selector: selector,
	}, nil
}

// verdict returns what dispatch does with a syscall whose return address is
// ip, reading the selector through cc. It follows syscall_user_dispatch().
func (sud *syscallUserDispatch) verdict(ip uint64, cc marshal.CopyContext) syscallDispatchVerdict {
	if ip-sud.offset < sud.length {
		return syscallDispatchAllow
	}
	if sud.selector == 0 {
		return syscallDispatchSignal
	}
	var state uint8
	if _, err := primitive.CopyUint8In(cc, sud.selector, &state); err != nil {
		return syscallDispatchKillSegv
	}
	switch state {
	case linux.SYSCALL_DISPATCH_FILTER_ALLOW:
		return syscallDispatchAllow
	case linux.SYSCALL_DISPATCH_FILTER_BLOCK:
		return syscallDispatchSignal
	default:
		return syscallDispatchKillSys
	}
}

// SetSyscallUserDispatch implements prctl(PR_SET_SYSCALL_USER_DISPATCH) for
// the calling task. The caller must be running on the task goroutine.
func (t *Task) SetSyscallUserDispatch(mode, offset, length uint64, selector hostarch.Addr) error {
	sud, err := newSyscallUserDispatch(mode, offset, length, selector)
	if err != nil {
		return err
	}
	// Linux checks once here that the selector is a user address.
	if sud.selector != 0 {
		if _, ok := t.MemoryManager().CheckIORange(sud.selector, 1); !ok {
			return linuxerr.EFAULT
		}
	}
	t.sud = sud
	return nil
}

// dispatchSyscall applies syscall user dispatch to the syscall sysno with
// arguments args that the task is entering. It returns nil if the syscall
// runs. Otherwise, it returns the task's next run state, after it skips the
// syscall and queues SIGSYS or kills the thread group. The caller must be
// running on the task goroutine, with t.sud.enabled set.
func (t *Task) dispatchSyscall(sysno uintptr, args arch.SyscallArguments) taskRunState {
	switch t.sud.verdict(uint64(t.Arch().IP()), t) {
	case syscallDispatchAllow:
		return nil
	case syscallDispatchKillSegv:
		// Linux kills the process with force_exit_sig(), which a handler or
		// a concurrent sigaction(2) cannot change.
		t.PrepareGroupExit(linux.WaitStatusTerminationSignal(linux.SIGSEGV))
		return (*runExit)(nil)
	case syscallDispatchKillSys:
		t.PrepareGroupExit(linux.WaitStatusTerminationSignal(linux.SIGSYS))
		return (*runExit)(nil)
	}
	// Match Linux's syscall_rollback(), as seccomp's SECCOMP_RET_TRAP does.
	// The return register holds the syscall number on x86_64 and the first
	// argument on arm64, so the handler can emulate or retry the syscall.
	switch t.Arch().Arch() {
	case arch.ARM64:
		t.Arch().SetReturn(args[0].Value)
	default:
		t.Arch().SetReturn(sysno)
	}
	info := &linux.SignalInfo{
		Signo: int32(linux.SIGSYS),
		Code:  linux.SYS_USER_DISPATCH,
	}
	info.SetCallAddr(uint64(t.Arch().IP()))
	info.SetSyscall(int32(sysno))
	info.SetArch(t.SyscallTable().AuditNumber)
	t.forceSignal(linux.SIGSYS, false /* unconditional */)
	t.SendSignal(info)
	return (*runApp)(nil)
}
