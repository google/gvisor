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

package kernel

import (
	"fmt"
	"os"
	"runtime/trace"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

var vsyscallCount = metric.MustCreateNewUint64Metric("/kernel/vsyscall_count", false /* sync */, "Number of times vsyscalls were invoked by the application")

// SyscallRestartBlock represents the restart block for a syscall restartable
// with a custom function. It encapsulates the state required to restart a
// syscall across a S/R.
type SyscallRestartBlock interface {
	Restart(t *Task) (uintptr, error)
}

// SyscallControl is returned by syscalls to control the behavior of
// Task.doSyscallInvoke.
type SyscallControl struct {
	// next is the state that the task goroutine should switch to. If next is
	// nil, the task goroutine should continue to syscall exit as usual.
	next taskRunState

	// If ignoreReturn is true, Task.doSyscallInvoke should not store any value
	// in the task's syscall return value register.
	ignoreReturn bool
}

var (
	// CtrlDoExit is returned by the implementations of the exit and exit_group
	// syscalls to enter the task exit path directly, skipping syscall exit
	// tracing.
	CtrlDoExit = &SyscallControl{next: (*runExit)(nil), ignoreReturn: true}

	// ctrlStopAndReinvokeSyscall is returned by syscalls using the external
	// feature before syscall execution. This causes Task.doSyscallInvoke
	// to return runSyscallReinvoke, allowing Task.run to check for stops
	// before immediately re-invoking the syscall (skipping the re-checking
	// of seccomp filters and ptrace which would confuse userspace
	// tracing).
	ctrlStopAndReinvokeSyscall = &SyscallControl{next: (*runSyscallReinvoke)(nil), ignoreReturn: true}

	// ctrlStopBeforeSyscallExit is returned by syscalls that initiate a stop at
	// their end. This causes Task.doSyscallInvoke to return runSyscallExit, rather
	// than tail-calling it, allowing stops to be checked before syscall exit.
	ctrlStopBeforeSyscallExit = &SyscallControl{next: (*runSyscallExit)(nil)}
)

func (t *Task) invokeExternal() {
	t.BeginExternalStop()
	go func() { // S/R-SAFE: External control flow.
		defer t.EndExternalStop()
		t.SyscallTable().External(t.Kernel())
	}()
}

func (t *Task) executeSyscall(sysno uintptr, args arch.SyscallArguments) (rval uintptr, ctrl *SyscallControl, err error) {
	s := t.SyscallTable()

	fe := s.FeatureEnable.Word(sysno)

	var straceContext interface{}
	if bits.IsAnyOn32(fe, StraceEnableBits) {
		straceContext = s.Stracer.SyscallEnter(t, sysno, args, fe)
	}

	if bits.IsOn32(fe, ExternalBeforeEnable) && (s.ExternalFilterBefore == nil || s.ExternalFilterBefore(t, sysno, args)) {
		t.invokeExternal()
		// Ensure we check for stops, then invoke the syscall again.
		ctrl = ctrlStopAndReinvokeSyscall
	} else {
		fn := s.Lookup(sysno)
		var region *trace.Region // Only non-nil if tracing == true.
		if trace.IsEnabled() {
			region = trace.StartRegion(t.traceContext, s.LookupName(sysno))
		}
		if fn != nil {
			// Call our syscall implementation.
			rval, ctrl, err = fn(t, args)
		} else {
			// Use the missing function if not found.
			rval, err = t.SyscallTable().Missing(t, sysno, args)
		}
		if region != nil {
			region.End()
		}
	}

	if bits.IsOn32(fe, ExternalAfterEnable) && (s.ExternalFilterAfter == nil || s.ExternalFilterAfter(t, sysno, args)) {
		t.invokeExternal()
		// Don't reinvoke the syscall.
	}

	if bits.IsAnyOn32(fe, StraceEnableBits) {
		s.Stracer.SyscallExit(straceContext, t, sysno, rval, err)
	}

	return
}

// doSyscall is the entry point for an invocation of a system call specified by
// the current state of t's registers.
//
// The syscall path is very hot; avoid defer.
func (t *Task) doSyscall() taskRunState {
	// Save value of the register which is clobbered in the following
	// t.Arch().SetReturn(-ENOSYS) operation. This is dedicated to arm64.
	//
	// On x86, register rax was shared by syscall number and return
	// value, and at the entry of the syscall handler, the rax was
	// saved to regs.orig_rax which was exposed to userspace.
	// But on arm64, syscall number was passed through X8, and the X0
	// was shared by the first syscall argument and return value. The
	// X0 was saved to regs.orig_x0 which was not exposed to userspace.
	// So we have to do the same operation here to save the X0 value
	// into the task context.
	t.Arch().SyscallSaveOrig()

	sysno := t.Arch().SyscallNo()
	args := t.Arch().SyscallArgs()

	// Tracers expect to see this between when the task traps into the kernel
	// to perform a syscall and when the syscall is actually invoked.
	// This useless-looking temporary is needed because Go.
	tmp := uintptr(syscall.ENOSYS)
	t.Arch().SetReturn(-tmp)

	// Check seccomp filters. The nil check is for performance (as seccomp use
	// is rare), not needed for correctness.
	if t.syscallFilters.Load() != nil {
		switch r := t.checkSeccompSyscall(int32(sysno), args, usermem.Addr(t.Arch().IP())); r {
		case linux.SECCOMP_RET_ERRNO, linux.SECCOMP_RET_TRAP:
			t.Debugf("Syscall %d: denied by seccomp", sysno)
			return (*runSyscallExit)(nil)
		case linux.SECCOMP_RET_ALLOW:
			// ok
		case linux.SECCOMP_RET_KILL_THREAD:
			t.Debugf("Syscall %d: killed by seccomp", sysno)
			t.PrepareExit(ExitStatus{Signo: int(linux.SIGSYS)})
			return (*runExit)(nil)
		case linux.SECCOMP_RET_TRACE:
			t.Debugf("Syscall %d: stopping for PTRACE_EVENT_SECCOMP", sysno)
			return (*runSyscallAfterPtraceEventSeccomp)(nil)
		default:
			panic(fmt.Sprintf("Unknown seccomp result %d", r))
		}
	}

	return t.doSyscallEnter(sysno, args)
}

type runSyscallAfterPtraceEventSeccomp struct{}

func (*runSyscallAfterPtraceEventSeccomp) execute(t *Task) taskRunState {
	if t.killed() {
		// "[S]yscall-exit-stop is not generated prior to death by SIGKILL." -
		// ptrace(2)
		return (*runInterrupt)(nil)
	}
	sysno := t.Arch().SyscallNo()
	// "The tracer can skip the system call by changing the syscall number to
	// -1." - Documentation/prctl/seccomp_filter.txt
	if sysno == ^uintptr(0) {
		return (*runSyscallExit)(nil).execute(t)
	}
	args := t.Arch().SyscallArgs()
	return t.doSyscallEnter(sysno, args)
}

func (t *Task) doSyscallEnter(sysno uintptr, args arch.SyscallArguments) taskRunState {
	if next, ok := t.ptraceSyscallEnter(); ok {
		return next
	}
	return t.doSyscallInvoke(sysno, args)
}

// +stateify savable
type runSyscallAfterSyscallEnterStop struct{}

func (*runSyscallAfterSyscallEnterStop) execute(t *Task) taskRunState {
	if sig := linux.Signal(t.ptraceCode); sig.IsValid() {
		t.tg.signalHandlers.mu.Lock()
		t.sendSignalLocked(SignalInfoPriv(sig), false /* group */)
		t.tg.signalHandlers.mu.Unlock()
	}
	if t.killed() {
		return (*runInterrupt)(nil)
	}
	sysno := t.Arch().SyscallNo()
	if sysno == ^uintptr(0) {
		return (*runSyscallExit)(nil)
	}
	args := t.Arch().SyscallArgs()

	return t.doSyscallInvoke(sysno, args)
}

// +stateify savable
type runSyscallAfterSysemuStop struct{}

func (*runSyscallAfterSysemuStop) execute(t *Task) taskRunState {
	if sig := linux.Signal(t.ptraceCode); sig.IsValid() {
		t.tg.signalHandlers.mu.Lock()
		t.sendSignalLocked(SignalInfoPriv(sig), false /* group */)
		t.tg.signalHandlers.mu.Unlock()
	}
	if t.killed() {
		return (*runInterrupt)(nil)
	}
	return (*runSyscallExit)(nil).execute(t)
}

func (t *Task) doSyscallInvoke(sysno uintptr, args arch.SyscallArguments) taskRunState {
	rval, ctrl, err := t.executeSyscall(sysno, args)

	if ctrl != nil {
		if !ctrl.ignoreReturn {
			t.Arch().SetReturn(rval)
		}
		if ctrl.next != nil {
			return ctrl.next
		}
	} else if err != nil {
		t.Arch().SetReturn(uintptr(-ExtractErrno(err, int(sysno))))
		t.haveSyscallReturn = true
	} else {
		t.Arch().SetReturn(rval)
	}

	return (*runSyscallExit)(nil).execute(t)
}

// +stateify savable
type runSyscallReinvoke struct{}

func (*runSyscallReinvoke) execute(t *Task) taskRunState {
	if t.killed() {
		// It's possible that since the last execution, the task has
		// been forcible killed. Invoking the system call here could
		// result in an infinite loop if it is again preempted by an
		// external stop and reinvoked.
		return (*runInterrupt)(nil)
	}

	sysno := t.Arch().SyscallNo()
	args := t.Arch().SyscallArgs()
	return t.doSyscallInvoke(sysno, args)
}

// +stateify savable
type runSyscallExit struct{}

func (*runSyscallExit) execute(t *Task) taskRunState {
	t.ptraceSyscallExit()
	return (*runApp)(nil)
}

// doVsyscall is the entry point for a vsyscall invocation of syscall sysno, as
// indicated by an execution fault at address addr. doVsyscall returns the
// task's next run state.
func (t *Task) doVsyscall(addr usermem.Addr, sysno uintptr) taskRunState {
	vsyscallCount.Increment()

	// Grab the caller up front, to make sure there's a sensible stack.
	caller := t.Arch().Native(uintptr(0))
	if _, err := caller.CopyIn(t, usermem.Addr(t.Arch().Stack())); err != nil {
		t.Debugf("vsyscall %d: error reading return address from stack: %v", sysno, err)
		t.forceSignal(linux.SIGSEGV, false /* unconditional */)
		t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		return (*runApp)(nil)
	}

	// For _vsyscalls_, there is no need to translate System V calling convention
	// to syscall ABI because they both use RDI, RSI, and RDX for the first three
	// arguments and none of the vsyscalls uses more than two arguments.
	args := t.Arch().SyscallArgs()
	if t.syscallFilters.Load() != nil {
		switch r := t.checkSeccompSyscall(int32(sysno), args, addr); r {
		case linux.SECCOMP_RET_ERRNO, linux.SECCOMP_RET_TRAP:
			t.Debugf("vsyscall %d, caller %x: denied by seccomp", sysno, t.Arch().Value(caller))
			return (*runApp)(nil)
		case linux.SECCOMP_RET_ALLOW:
			// ok
		case linux.SECCOMP_RET_TRACE:
			t.Debugf("vsyscall %d, caller %x: stopping for PTRACE_EVENT_SECCOMP", sysno, t.Arch().Value(caller))
			return &runVsyscallAfterPtraceEventSeccomp{addr, sysno, caller}
		case linux.SECCOMP_RET_KILL_THREAD:
			t.Debugf("vsyscall %d: killed by seccomp", sysno)
			t.PrepareExit(ExitStatus{Signo: int(linux.SIGSYS)})
			return (*runExit)(nil)
		default:
			panic(fmt.Sprintf("Unknown seccomp result %d", r))
		}
	}

	return t.doVsyscallInvoke(sysno, args, caller)
}

type runVsyscallAfterPtraceEventSeccomp struct {
	addr   usermem.Addr
	sysno  uintptr
	caller marshal.Marshallable
}

func (r *runVsyscallAfterPtraceEventSeccomp) execute(t *Task) taskRunState {
	if t.killed() {
		return (*runInterrupt)(nil)
	}
	sysno := t.Arch().SyscallNo()
	// "... the syscall may not be changed to another system call using the
	// orig_rax register. It may only be changed to -1 order [sic] to skip the
	// currently emulated call. ... The tracer MUST NOT modify rip or rsp." -
	// Documentation/prctl/seccomp_filter.txt. On Linux, changing orig_ax or ip
	// causes do_exit(SIGSYS), and changing sp is ignored.
	if (sysno != ^uintptr(0) && sysno != r.sysno) || usermem.Addr(t.Arch().IP()) != r.addr {
		t.PrepareExit(ExitStatus{Signo: int(linux.SIGSYS)})
		return (*runExit)(nil)
	}
	if sysno == ^uintptr(0) {
		return (*runApp)(nil)
	}
	return t.doVsyscallInvoke(sysno, t.Arch().SyscallArgs(), r.caller)
}

func (t *Task) doVsyscallInvoke(sysno uintptr, args arch.SyscallArguments, caller marshal.Marshallable) taskRunState {
	rval, ctrl, err := t.executeSyscall(sysno, args)
	if ctrl != nil {
		t.Debugf("vsyscall %d, caller %x: syscall control: %v", sysno, t.Arch().Value(caller), ctrl)
		// Set the return value. The stack has already been adjusted.
		t.Arch().SetReturn(0)
	} else if err == nil {
		t.Debugf("vsyscall %d, caller %x: successfully emulated syscall", sysno, t.Arch().Value(caller))
		// Set the return value. The stack has already been adjusted.
		t.Arch().SetReturn(uintptr(rval))
	} else {
		t.Debugf("vsyscall %d, caller %x: emulated syscall returned error: %v", sysno, t.Arch().Value(caller), err)
		if err == syserror.EFAULT {
			t.forceSignal(linux.SIGSEGV, false /* unconditional */)
			t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
			// A return is not emulated in this case.
			return (*runApp)(nil)
		}
		t.Arch().SetReturn(uintptr(-ExtractErrno(err, int(sysno))))
	}
	t.Arch().SetIP(t.Arch().Value(caller))
	t.Arch().SetStack(t.Arch().Stack() + uintptr(t.Arch().Width()))
	return (*runApp)(nil)
}

// ExtractErrno extracts an integer error number from the error.
// The syscall number is purely for context in the error case. Use -1 if
// syscall number is unknown.
func ExtractErrno(err error, sysno int) int {
	switch err := err.(type) {
	case nil:
		return 0
	case syscall.Errno:
		return int(err)
	case syserror.SyscallRestartErrno:
		return int(err)
	case *memmap.BusError:
		// Bus errors may generate SIGBUS, but for syscalls they still
		// return EFAULT. See case in task_run.go where the fault is
		// handled (and the SIGBUS is delivered).
		return int(syscall.EFAULT)
	case *os.PathError:
		return ExtractErrno(err.Err, sysno)
	case *os.LinkError:
		return ExtractErrno(err.Err, sysno)
	case *os.SyscallError:
		return ExtractErrno(err.Err, sysno)
	default:
		if errno, ok := syserror.TranslateError(err); ok {
			return int(errno)
		}
	}
	panic(fmt.Sprintf("Unknown syscall %d error: %v", sysno, err))
}
