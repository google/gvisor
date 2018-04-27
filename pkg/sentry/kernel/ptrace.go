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

package kernel

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// ptrace constants from Linux's include/uapi/linux/ptrace.h.
const (
	_PTRACE_EVENT_SECCOMP  = 7
	PTRACE_SEIZE           = 0x4206
	PTRACE_INTERRUPT       = 0x4207
	PTRACE_LISTEN          = 0x4208
	PTRACE_PEEKSIGINFO     = 0x4209
	PTRACE_GETSIGMASK      = 0x420a
	PTRACE_SETSIGMASK      = 0x420b
	_PTRACE_O_EXITKILL     = 1 << 20
	_PTRACE_O_TRACESECCOMP = 1 << _PTRACE_EVENT_SECCOMP
)

// ptraceOptions are the subset of options controlling a task's ptrace behavior
// that are set by ptrace(PTRACE_SETOPTIONS).
type ptraceOptions struct {
	// ExitKill is true if the tracee should be sent SIGKILL when the tracer
	// exits.
	ExitKill bool

	// If SysGood is true, set bit 7 in the signal number for
	// syscall-entry-stop and syscall-exit-stop traps delivered to this task's
	// tracer.
	SysGood bool

	// TraceClone is true if the tracer wants to receive PTRACE_EVENT_CLONE
	// events.
	TraceClone bool

	// TraceExec is true if the tracer wants to receive PTRACE_EVENT_EXEC
	// events.
	TraceExec bool

	// TraceExit is true if the tracer wants to receive PTRACE_EVENT_EXIT
	// events.
	TraceExit bool

	// TraceFork is true if the tracer wants to receive PTRACE_EVENT_FORK
	// events.
	TraceFork bool

	// TraceSeccomp is true if the tracer wants to receive PTRACE_EVENT_SECCOMP
	// events.
	TraceSeccomp bool

	// TraceVfork is true if the tracer wants to receive PTRACE_EVENT_VFORK
	// events.
	TraceVfork bool

	// TraceVforkDone is true if the tracer wants to receive
	// PTRACE_EVENT_VFORK_DONE events.
	TraceVforkDone bool
}

// ptraceSyscallMode controls the behavior of a ptraced task at syscall entry
// and exit.
type ptraceSyscallMode int

const (
	// ptraceSyscallNone indicates that the task has never ptrace-stopped, or
	// that it was resumed from its last ptrace-stop by PTRACE_CONT or
	// PTRACE_DETACH. The task's syscalls will not be intercepted.
	ptraceSyscallNone ptraceSyscallMode = iota

	// ptraceSyscallIntercept indicates that the task was resumed from its last
	// ptrace-stop by PTRACE_SYSCALL. The next time the task enters or exits a
	// syscall, a ptrace-stop will occur.
	ptraceSyscallIntercept

	// ptraceSyscallEmu indicates that the task was resumed from its last
	// ptrace-stop by PTRACE_SYSEMU or PTRACE_SYSEMU_SINGLESTEP. The next time
	// the task enters a syscall, the syscall will be skipped, and a
	// ptrace-stop will occur.
	ptraceSyscallEmu
)

// CanTrace checks that t is permitted to access target's state, as defined by
// ptrace(2), subsection "Ptrace access mode checking". If attach is true, it
// checks for access mode PTRACE_MODE_ATTACH; otherwise, it checks for access
// mode PTRACE_MODE_READ.
func (t *Task) CanTrace(target *Task, attach bool) bool {
	// "1. If the calling thread and the target thread are in the same thread
	// group, access is always allowed." - ptrace(2)
	//
	// Note: Strictly speaking, prior to 73af963f9f30 ("__ptrace_may_access()
	// should not deny sub-threads", first released in Linux 3.12), the rule
	// only applies if t and target are the same task. But, as that commit
	// message puts it, "[any] security check is pointless when the tasks share
	// the same ->mm."
	if t.tg == target.tg {
		return true
	}

	// """
	// 2. If the access mode specifies PTRACE_MODE_FSCREDS (ED: snipped,
	// doesn't exist until Linux 4.5).
	//
	// Otherwise, the access mode specifies PTRACE_MODE_REALCREDS, so use the
	// caller's real UID and GID for the checks in the next step. (Most APIs
	// that check the caller's UID and GID use the effective IDs. For
	// historical reasons, the PTRACE_MODE_REALCREDS check uses the real IDs
	// instead.)
	//
	// 3. Deny access if neither of the following is true:
	//
	// - The real, effective, and saved-set user IDs of the target match the
	// caller's user ID, *and* the real, effective, and saved-set group IDs of
	// the target match the caller's group ID.
	//
	// - The caller has the CAP_SYS_PTRACE capability in the user namespace of
	// the target.
	//
	// 4. Deny access if the target process "dumpable" attribute has a value
	// other than 1 (SUID_DUMP_USER; see the discussion of PR_SET_DUMPABLE in
	// prctl(2)), and the caller does not have the CAP_SYS_PTRACE capability in
	// the user namespace of the target process.
	//
	// 5. The kernel LSM security_ptrace_access_check() interface is invoked to
	// see if ptrace access is permitted. The results depend on the LSM(s). The
	// implementation of this interface in the commoncap LSM performs the
	// following steps:
	//
	// a) If the access mode includes PTRACE_MODE_FSCREDS, then use the
	// caller's effective capability set; otherwise (the access mode specifies
	// PTRACE_MODE_REALCREDS, so) use the caller's permitted capability set.
	//
	// b) Deny access if neither of the following is true:
	//
	// - The caller and the target process are in the same user namespace, and
	// the caller's capabilities are a proper superset of the target process's
	// permitted capabilities.
	//
	// - The caller has the CAP_SYS_PTRACE capability in the target process's
	// user namespace.
	//
	// Note that the commoncap LSM does not distinguish between
	// PTRACE_MODE_READ and PTRACE_MODE_ATTACH. (ED: From earlier in this
	// section: "the commoncap LSM ... is always invoked".)
	// """
	callerCreds := t.Credentials()
	targetCreds := target.Credentials()
	if callerCreds.HasCapabilityIn(linux.CAP_SYS_PTRACE, targetCreds.UserNamespace) {
		return true
	}
	if cuid := callerCreds.RealKUID; cuid != targetCreds.RealKUID || cuid != targetCreds.EffectiveKUID || cuid != targetCreds.SavedKUID {
		return false
	}
	if cgid := callerCreds.RealKGID; cgid != targetCreds.RealKGID || cgid != targetCreds.EffectiveKGID || cgid != targetCreds.SavedKGID {
		return false
	}
	// TODO: dumpability check
	if callerCreds.UserNamespace != targetCreds.UserNamespace {
		return false
	}
	if targetCreds.PermittedCaps&^callerCreds.PermittedCaps != 0 {
		return false
	}
	// TODO: Yama LSM
	return true
}

// Tracer returns t's ptrace Tracer.
func (t *Task) Tracer() *Task {
	return t.ptraceTracer.Load().(*Task)
}

// hasTracer returns true if t has a ptrace tracer attached.
func (t *Task) hasTracer() bool {
	// This isn't just inlined into callers so that if Task.Tracer() turns out
	// to be too expensive because of e.g. interface conversion, we can switch
	// to having a separate atomic flag more easily.
	return t.Tracer() != nil
}

// ptraceStop is a TaskStop placed on tasks in a ptrace-stop.
type ptraceStop struct {
	// If frozen is true, the stopped task's tracer is currently operating on
	// it, so Task.Kill should not remove the stop.
	frozen bool
}

// Killable implements TaskStop.Killable.
func (s *ptraceStop) Killable() bool {
	return !s.frozen
}

// beginPtraceStopLocked initiates an unfrozen ptrace-stop on t. If t has been
// killed, the stop is skipped, and beginPtraceStopLocked returns false.
//
// beginPtraceStopLocked does not signal t's tracer or wake it if it is
// waiting.
//
// Preconditions: The TaskSet mutex must be locked. The caller must be running
// on the task goroutine.
func (t *Task) beginPtraceStopLocked() bool {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	// This is analogous to Linux's kernel/signal.c:ptrace_stop() => ... =>
	// kernel/sched/core.c:__schedule() => signal_pending_state() check, which
	// is what prevents tasks from entering ptrace-stops after being killed.
	// Note that if t was SIGKILLed and beingPtraceStopLocked is being called
	// for PTRACE_EVENT_EXIT, the task will have dequeued the signal before
	// entering the exit path, so t.killable() will no longer return true. This
	// is consistent with Linux: "Bugs: ... A SIGKILL signal may still cause a
	// PTRACE_EVENT_EXIT stop before actual signal death. This may be changed
	// in the future; SIGKILL is meant to always immediately kill tasks even
	// under ptrace. Last confirmed on Linux 3.13." - ptrace(2)
	if t.killedLocked() {
		return false
	}
	t.beginInternalStopLocked(&ptraceStop{})
	return true
}

// Preconditions: The TaskSet mutex must be locked.
func (t *Task) ptraceTrapLocked(code int32) {
	t.ptraceCode = code
	t.ptraceSiginfo = &arch.SignalInfo{
		Signo: int32(linux.SIGTRAP),
		Code:  code,
	}
	t.ptraceSiginfo.SetPid(int32(t.tg.pidns.tids[t]))
	t.ptraceSiginfo.SetUid(int32(t.Credentials().RealKUID.In(t.UserNamespace()).OrOverflow()))
	if t.beginPtraceStopLocked() {
		tracer := t.Tracer()
		tracer.signalStop(t, arch.CLD_TRAPPED, int32(linux.SIGTRAP))
		tracer.tg.eventQueue.Notify(EventTraceeStop)
	}
}

// ptraceFreeze checks if t is in a ptraceStop. If so, it freezes the
// ptraceStop, temporarily preventing it from being removed by a concurrent
// Task.Kill, and returns true. Otherwise it returns false.
//
// Preconditions: The TaskSet mutex must be locked. The caller must be running
// on the task goroutine of t's tracer.
func (t *Task) ptraceFreeze() bool {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	if t.stop == nil {
		return false
	}
	s, ok := t.stop.(*ptraceStop)
	if !ok {
		return false
	}
	s.frozen = true
	return true
}

// ptraceUnfreeze ends the effect of a previous successful call to
// ptraceFreeze.
//
// Preconditions: t must be in a frozen ptraceStop.
func (t *Task) ptraceUnfreeze() {
	// t.tg.signalHandlers is stable because t is in a frozen ptrace-stop,
	// preventing its thread group from completing execve.
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	// Do this even if the task has been killed to ensure a panic if t.stop is
	// nil or not a ptraceStop.
	t.stop.(*ptraceStop).frozen = false
	if t.killedLocked() {
		t.endInternalStopLocked()
	}
}

// ptraceUnstop implements ptrace request PTRACE_CONT, PTRACE_SYSCALL,
// PTRACE_SINGLESTEP, PTRACE_SYSEMU, or PTRACE_SYSEMU_SINGLESTEP depending on
// mode and singlestep.
//
// Preconditions: t must be in a frozen ptrace stop.
//
// Postconditions: If ptraceUnstop returns nil, t will no longer be in a ptrace
// stop.
func (t *Task) ptraceUnstop(mode ptraceSyscallMode, singlestep bool, sig linux.Signal) error {
	if sig != 0 && !sig.IsValid() {
		return syserror.EIO
	}
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	t.ptraceCode = int32(sig)
	t.ptraceSyscallMode = mode
	t.ptraceSinglestep = singlestep
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.endInternalStopLocked()
	return nil
}

func (t *Task) ptraceTraceme() error {
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	if t.hasTracer() {
		return syserror.EPERM
	}
	if t.parent == nil {
		// In Linux, only init can not have a parent, and init is assumed never
		// to invoke PTRACE_TRACEME. In the sentry, TGID 1 is an arbitrary user
		// application that may invoke PTRACE_TRACEME; having no parent can
		// also occur if all tasks in the parent thread group have exited, and
		// failed to find a living thread group to reparent to. The former case
		// is treated as if TGID 1 has an exited parent in an invisible
		// ancestor PID namespace that is an owner of the root user namespace
		// (and consequently has CAP_SYS_PTRACE), and the latter case is a
		// special form of the exited parent case below. In either case,
		// returning nil here is correct.
		return nil
	}
	if !t.parent.CanTrace(t, true) {
		return syserror.EPERM
	}
	if t.parent.exitState != TaskExitNone {
		// Fail silently, as if we were successfully attached but then
		// immediately detached. This is consistent with Linux.
		return nil
	}
	t.ptraceTracer.Store(t.parent)
	t.parent.ptraceTracees[t] = struct{}{}
	return nil
}

// ptraceAttach implements ptrace(PTRACE_ATTACH, target). t is the caller.
func (t *Task) ptraceAttach(target *Task) error {
	if t.tg == target.tg {
		return syserror.EPERM
	}
	if !t.CanTrace(target, true) {
		return syserror.EPERM
	}
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	if target.hasTracer() {
		return syserror.EPERM
	}
	// Attaching to zombies and dead tasks is not permitted; the exit
	// notification logic relies on this. Linux allows attaching to PF_EXITING
	// tasks, though.
	if target.exitState >= TaskExitZombie {
		return syserror.EPERM
	}
	target.ptraceTracer.Store(t)
	t.ptraceTracees[target] = struct{}{}
	target.tg.signalHandlers.mu.Lock()
	target.sendSignalLocked(&arch.SignalInfo{
		Signo: int32(linux.SIGSTOP),
		Code:  arch.SignalInfoUser,
	}, false /* group */)
	// Undocumented Linux feature: If the tracee is already group-stopped (and
	// consequently will not report the SIGSTOP just sent), force it to leave
	// and re-enter the stop so that it will switch to a ptrace-stop.
	if target.stop == (*groupStop)(nil) {
		target.groupStopRequired = true
		target.endInternalStopLocked()
	}
	target.tg.signalHandlers.mu.Unlock()
	return nil
}

// ptraceDetach implements ptrace(PTRACE_DETACH, target, 0, sig). t is the
// caller.
//
// Preconditions: target must be a tracee of t in a frozen ptrace stop.
//
// Postconditions: If ptraceDetach returns nil, target will no longer be in a
// ptrace stop.
func (t *Task) ptraceDetach(target *Task, sig linux.Signal) error {
	if sig != 0 && !sig.IsValid() {
		return syserror.EIO
	}
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	target.ptraceCode = int32(sig)
	target.forgetTracerLocked()
	delete(t.ptraceTracees, target)
	return nil
}

// exitPtrace is called in the exit path to detach all of t's tracees.
func (t *Task) exitPtrace() {
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	for target := range t.ptraceTracees {
		if target.ptraceOpts.ExitKill {
			target.tg.signalHandlers.mu.Lock()
			target.sendSignalLocked(&arch.SignalInfo{
				Signo: int32(linux.SIGKILL),
			}, false /* group */)
			target.tg.signalHandlers.mu.Unlock()
		}
		// Leave ptraceCode unchanged so that if the task is ptrace-stopped, it
		// observes the ptraceCode it set before it entered the stop. I believe
		// this is consistent with Linux.
		target.forgetTracerLocked()
	}
	// "nil maps cannot be saved"
	t.ptraceTracees = make(map[*Task]struct{})
}

// forgetTracerLocked detaches t's tracer and ensures that t is no longer
// ptrace-stopped.
//
// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) forgetTracerLocked() {
	t.ptraceOpts = ptraceOptions{}
	t.ptraceSyscallMode = ptraceSyscallNone
	t.ptraceSinglestep = false
	t.ptraceTracer.Store((*Task)(nil))
	if t.exitTracerNotified && !t.exitTracerAcked {
		t.exitTracerAcked = true
		t.exitNotifyLocked(true)
	}
	// If t is ptrace-stopped, but its thread group is in a group stop and t is
	// eligible to participate, make it do so. This is essentially the reverse
	// of the special case in ptraceAttach, which converts a group stop to a
	// ptrace stop. ("Handling of restart from group-stop is currently buggy,
	// but the "as planned" behavior is to leave tracee stopped and waiting for
	// SIGCONT." - ptrace(2))
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	if t.stop == nil {
		return
	}
	if _, ok := t.stop.(*ptraceStop); ok {
		if t.exitState < TaskExitInitiated && t.tg.groupStopPhase >= groupStopInitiated {
			t.groupStopRequired = true
		}
		t.endInternalStopLocked()
	}
}

// ptraceSignalLocked is called after signal dequeueing to check if t should
// enter ptrace signal-delivery-stop.
//
// Preconditions: The signal mutex must be locked. The caller must be running
// on the task goroutine.
func (t *Task) ptraceSignalLocked(info *arch.SignalInfo) bool {
	if linux.Signal(info.Signo) == linux.SIGKILL {
		return false
	}
	if !t.hasTracer() {
		return false
	}
	// The tracer might change this signal into a stop signal, in which case
	// any SIGCONT received after the signal was originally dequeued should
	// cancel it. This is consistent with Linux.
	if t.tg.groupStopPhase == groupStopNone {
		t.tg.groupStopPhase = groupStopDequeued
	}
	// Can't lock the TaskSet mutex while holding a signal mutex.
	t.tg.signalHandlers.mu.Unlock()
	defer t.tg.signalHandlers.mu.Lock()
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	tracer := t.Tracer()
	if tracer == nil {
		return false
	}
	t.ptraceCode = info.Signo
	t.ptraceSiginfo = info
	t.Debugf("Entering signal-delivery-stop for signal %d", info.Signo)
	if t.beginPtraceStopLocked() {
		tracer.signalStop(t, arch.CLD_TRAPPED, info.Signo)
		tracer.tg.eventQueue.Notify(EventTraceeStop)
	}
	return true
}

// ptraceSeccomp is called when a seccomp-bpf filter returns action
// SECCOMP_RET_TRACE to check if t should enter PTRACE_EVENT_SECCOMP stop. data
// is the lower 16 bits of the filter's return value.
func (t *Task) ptraceSeccomp(data uint16) bool {
	if !t.hasTracer() {
		return false
	}
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	if !t.ptraceOpts.TraceSeccomp {
		return false
	}
	t.Debugf("Entering PTRACE_EVENT_SECCOMP stop")
	t.ptraceEventLocked(_PTRACE_EVENT_SECCOMP, uint64(data))
	return true
}

// ptraceSyscallEnter is called immediately before entering a syscall to check
// if t should enter ptrace syscall-enter-stop.
func (t *Task) ptraceSyscallEnter() (taskRunState, bool) {
	if !t.hasTracer() {
		return nil, false
	}
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	switch t.ptraceSyscallMode {
	case ptraceSyscallNone:
		return nil, false
	case ptraceSyscallIntercept:
		t.Debugf("Entering syscall-enter-stop from PTRACE_SYSCALL")
		t.ptraceSyscallStopLocked()
		return (*runSyscallAfterSyscallEnterStop)(nil), true
	case ptraceSyscallEmu:
		t.Debugf("Entering syscall-enter-stop from PTRACE_SYSEMU")
		t.ptraceSyscallStopLocked()
		return (*runSyscallAfterSysemuStop)(nil), true
	}
	panic(fmt.Sprintf("Unknown ptraceSyscallMode: %v", t.ptraceSyscallMode))
}

// ptraceSyscallExit is called immediately after leaving a syscall to check if
// t should enter ptrace syscall-exit-stop.
func (t *Task) ptraceSyscallExit() {
	if !t.hasTracer() {
		return
	}
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	if t.ptraceSyscallMode != ptraceSyscallIntercept {
		return
	}
	t.Debugf("Entering syscall-exit-stop")
	t.ptraceSyscallStopLocked()
}

// Preconditions: The TaskSet mutex must be locked.
func (t *Task) ptraceSyscallStopLocked() {
	code := int32(linux.SIGTRAP)
	if t.ptraceOpts.SysGood {
		code |= 0x80
	}
	t.ptraceTrapLocked(code)
}

type ptraceCloneKind int32

const (
	// ptraceCloneKindClone represents a call to Task.Clone where
	// TerminationSignal is not SIGCHLD and Vfork is false.
	ptraceCloneKindClone ptraceCloneKind = iota

	// ptraceCloneKindFork represents a call to Task.Clone where
	// TerminationSignal is SIGCHLD and Vfork is false.
	ptraceCloneKindFork

	// ptraceCloneKindVfork represents a call to Task.Clone where Vfork is
	// true.
	ptraceCloneKindVfork
)

// ptraceClone is called at the end of a clone or fork syscall to check if t
// should enter PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK, or PTRACE_EVENT_VFORK
// stop. child is the new task.
func (t *Task) ptraceClone(kind ptraceCloneKind, child *Task, opts *CloneOptions) bool {
	if !t.hasTracer() {
		return false
	}
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	event := false
	if !opts.Untraced {
		switch kind {
		case ptraceCloneKindClone:
			if t.ptraceOpts.TraceClone {
				t.Debugf("Entering PTRACE_EVENT_CLONE stop")
				t.ptraceEventLocked(syscall.PTRACE_EVENT_CLONE, uint64(t.tg.pidns.tids[child]))
				event = true
			}
		case ptraceCloneKindFork:
			if t.ptraceOpts.TraceFork {
				t.Debugf("Entering PTRACE_EVENT_FORK stop")
				t.ptraceEventLocked(syscall.PTRACE_EVENT_FORK, uint64(t.tg.pidns.tids[child]))
				event = true
			}
		case ptraceCloneKindVfork:
			if t.ptraceOpts.TraceVfork {
				t.Debugf("Entering PTRACE_EVENT_VFORK stop")
				t.ptraceEventLocked(syscall.PTRACE_EVENT_VFORK, uint64(t.tg.pidns.tids[child]))
				event = true
			}
		default:
			panic(fmt.Sprintf("Unknown ptraceCloneKind: %v", kind))
		}
	}
	// "If the PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, or PTRACE_O_TRACECLONE
	// options are in effect, then children created by, respectively, vfork(2)
	// or clone(2) with the CLONE_VFORK flag, fork(2) or clone(2) with the exit
	// signal set to SIGCHLD, and other kinds of clone(2), are automatically
	// attached to the same tracer which traced their parent. SIGSTOP is
	// delivered to the children, causing them to enter signal-delivery-stop
	// after they exit the system call which created them." - ptrace(2)
	//
	// clone(2)'s documentation of CLONE_UNTRACED and CLONE_PTRACE is
	// confusingly wrong; see kernel/fork.c:_do_fork() => copy_process() =>
	// include/linux/ptrace.h:ptrace_init_task().
	if event || opts.InheritTracer {
		tracer := t.Tracer()
		if tracer != nil {
			child.ptraceTracer.Store(tracer)
			tracer.ptraceTracees[child] = struct{}{}
			// "Flags are inherited by new tracees created and "auto-attached"
			// via active PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, or
			// PTRACE_O_TRACECLONE options."
			child.ptraceOpts = t.ptraceOpts
			child.tg.signalHandlers.mu.Lock()
			// If the child is PT_SEIZED (currently not possible in the sentry
			// because PTRACE_SEIZE is unimplemented, but for future
			// reference), Linux just sets JOBCTL_TRAP_STOP instead, so the
			// child skips signal-delivery-stop and goes directly to
			// group-stop.
			//
			// The child will self-t.interrupt() when its task goroutine starts
			// running, so we don't have to.
			child.pendingSignals.enqueue(&arch.SignalInfo{
				Signo: int32(linux.SIGSTOP),
			})
			child.tg.signalHandlers.mu.Unlock()
		}
	}
	return event
}

// ptraceVforkDone is called after the end of a vfork stop to check if t should
// enter PTRACE_EVENT_VFORK_DONE stop. child is the new task's thread ID in t's
// PID namespace.
func (t *Task) ptraceVforkDone(child ThreadID) bool {
	if !t.hasTracer() {
		return false
	}
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	if !t.ptraceOpts.TraceVforkDone {
		return false
	}
	t.Debugf("Entering PTRACE_EVENT_VFORK_DONE stop")
	t.ptraceEventLocked(syscall.PTRACE_EVENT_VFORK_DONE, uint64(child))
	return true
}

// ptraceExec is called at the end of an execve syscall to check if t should
// enter PTRACE_EVENT_EXEC stop. oldTID is t's thread ID, in its *tracer's* PID
// namespace, prior to the execve. (If t did not have a tracer at the time
// oldTID was read, oldTID may be 0. This is consistent with Linux.)
func (t *Task) ptraceExec(oldTID ThreadID) {
	if !t.hasTracer() {
		return
	}
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	// Recheck with the TaskSet mutex locked. Most ptrace points don't need to
	// do this because detaching resets ptrace options, but PTRACE_EVENT_EXEC
	// is special because both TraceExec and !TraceExec do something if a
	// tracer is attached.
	if !t.hasTracer() {
		return
	}
	if t.ptraceOpts.TraceExec {
		t.Debugf("Entering PTRACE_EVENT_EXEC stop")
		t.ptraceEventLocked(syscall.PTRACE_EVENT_EXEC, uint64(oldTID))
		return
	}
	// "If the PTRACE_O_TRACEEXEC option is not in effect for the execing
	// tracee, and if the tracee was PTRACE_ATTACHed rather that [sic]
	// PTRACE_SEIZEd, the kernel delivers an extra SIGTRAP to the tracee after
	// execve(2) returns. This is an ordinary signal (similar to one which can
	// be generated by `kill -TRAP`, not a special kind of ptrace-stop.
	// Employing PTRACE_GETSIGINFO for this signal returns si_code set to 0
	// (SI_USER). This signal may be blocked by signal mask, and thus may be
	// delivered (much) later." - ptrace(2)
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.sendSignalLocked(&arch.SignalInfo{
		Signo: int32(linux.SIGTRAP),
		Code:  arch.SignalInfoUser,
	}, false /* group */)
}

// ptraceExit is called early in the task exit path to check if t should enter
// PTRACE_EVENT_EXIT stop.
func (t *Task) ptraceExit() {
	if !t.hasTracer() {
		return
	}
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	if !t.ptraceOpts.TraceExit {
		return
	}
	t.tg.signalHandlers.mu.Lock()
	status := t.exitStatus.Status()
	t.tg.signalHandlers.mu.Unlock()
	t.Debugf("Entering PTRACE_EVENT_EXIT stop")
	t.ptraceEventLocked(syscall.PTRACE_EVENT_EXIT, uint64(status))
}

// Preconditions: The TaskSet mutex must be locked.
func (t *Task) ptraceEventLocked(event int32, msg uint64) {
	t.ptraceEventMsg = msg
	// """
	// PTRACE_EVENT stops are observed by the tracer as waitpid(2) returning
	// with WIFSTOPPED(status), and WSTOPSIG(status) returns SIGTRAP. An
	// additional bit is set in the higher byte of the status word: the value
	// status>>8 will be
	//
	//   (SIGTRAP | PTRACE_EVENT_foo << 8).
	//
	// ...
	//
	// """ - ptrace(2)
	t.ptraceTrapLocked(int32(linux.SIGTRAP) | (event << 8))
}

// ptraceKill implements ptrace(PTRACE_KILL, target). t is the caller.
func (t *Task) ptraceKill(target *Task) error {
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	if target.Tracer() != t {
		return syserror.ESRCH
	}
	target.tg.signalHandlers.mu.Lock()
	defer target.tg.signalHandlers.mu.Unlock()
	// "This operation is deprecated; do not use it! Instead, send a SIGKILL
	// directly using kill(2) or tgkill(2). The problem with PTRACE_KILL is
	// that it requires the tracee to be in signal-delivery-stop, otherwise it
	// may not work (i.e., may complete successfully but won't kill the
	// tracee)." - ptrace(2)
	if target.stop == nil {
		return nil
	}
	if _, ok := target.stop.(*ptraceStop); !ok {
		return nil
	}
	target.ptraceCode = int32(linux.SIGKILL)
	target.endInternalStopLocked()
	return nil
}

// Ptrace implements the ptrace system call.
func (t *Task) Ptrace(req int64, pid ThreadID, addr, data usermem.Addr) error {
	// PTRACE_TRACEME ignores all other arguments.
	if req == syscall.PTRACE_TRACEME {
		return t.ptraceTraceme()
	}
	// All other ptrace requests operate on a current or future tracee
	// specified by pid.
	target := t.tg.pidns.TaskWithID(pid)
	if target == nil {
		return syserror.ESRCH
	}

	// PTRACE_ATTACH (and PTRACE_SEIZE, which is unimplemented) do not require
	// that target is not already a tracee.
	if req == syscall.PTRACE_ATTACH {
		return t.ptraceAttach(target)
	}
	// PTRACE_KILL (and PTRACE_INTERRUPT, which is unimplemented) require that
	// the target is a tracee, but does not require that it is ptrace-stopped.
	if req == syscall.PTRACE_KILL {
		return t.ptraceKill(target)
	}
	// All other ptrace requests require that the target is a ptrace-stopped
	// tracee, and freeze the ptrace-stop so the tracee can be operated on.
	t.tg.pidns.owner.mu.RLock()
	if target.Tracer() != t {
		t.tg.pidns.owner.mu.RUnlock()
		return syserror.ESRCH
	}
	if !target.ptraceFreeze() {
		t.tg.pidns.owner.mu.RUnlock()
		// "Most ptrace commands (all except PTRACE_ATTACH, PTRACE_SEIZE,
		// PTRACE_TRACEME, PTRACE_INTERRUPT, and PTRACE_KILL) require the
		// tracee to be in a ptrace-stop, otherwise they fail with ESRCH." -
		// ptrace(2)
		return syserror.ESRCH
	}
	t.tg.pidns.owner.mu.RUnlock()
	// Even if the target has a ptrace-stop active, the tracee's task goroutine
	// may not yet have reached Task.doStop; wait for it to do so. This is safe
	// because there's no way for target to initiate a ptrace-stop and then
	// block (by calling Task.block) before entering it.
	//
	// Caveat: If tasks were just restored, the tracee's first call to
	// Task.Activate (in Task.run) occurs before its first call to Task.doStop,
	// which may block if the tracer's address space is active.
	t.UninterruptibleSleepStart(true)
	target.waitGoroutineStoppedOrExited()
	t.UninterruptibleSleepFinish(true)

	// Resuming commands end the ptrace stop, but only if successful.
	switch req {
	case syscall.PTRACE_DETACH:
		if err := t.ptraceDetach(target, linux.Signal(data)); err != nil {
			target.ptraceUnfreeze()
			return err
		}
		return nil
	case syscall.PTRACE_CONT:
		if err := target.ptraceUnstop(ptraceSyscallNone, false, linux.Signal(data)); err != nil {
			target.ptraceUnfreeze()
			return err
		}
		return nil
	case syscall.PTRACE_SYSCALL:
		if err := target.ptraceUnstop(ptraceSyscallIntercept, false, linux.Signal(data)); err != nil {
			target.ptraceUnfreeze()
			return err
		}
		return nil
	case syscall.PTRACE_SINGLESTEP:
		if err := target.ptraceUnstop(ptraceSyscallNone, true, linux.Signal(data)); err != nil {
			target.ptraceUnfreeze()
			return err
		}
		return nil
	case syscall.PTRACE_SYSEMU:
		if err := target.ptraceUnstop(ptraceSyscallEmu, false, linux.Signal(data)); err != nil {
			target.ptraceUnfreeze()
			return err
		}
		return nil
	case syscall.PTRACE_SYSEMU_SINGLESTEP:
		if err := target.ptraceUnstop(ptraceSyscallEmu, true, linux.Signal(data)); err != nil {
			target.ptraceUnfreeze()
			return err
		}
		return nil
	}
	// All other ptrace requests expect us to unfreeze the stop.
	defer target.ptraceUnfreeze()

	switch req {
	case syscall.PTRACE_PEEKTEXT, syscall.PTRACE_PEEKDATA:
		// "At the system call level, the PTRACE_PEEKTEXT, PTRACE_PEEKDATA, and
		// PTRACE_PEEKUSER requests have a different API: they store the result
		// at the address specified by the data parameter, and the return value
		// is the error flag." - ptrace(2)
		word := t.Arch().Native(0)
		if _, err := usermem.CopyObjectIn(t, target.MemoryManager(), addr, word, usermem.IOOpts{
			IgnorePermissions: true,
		}); err != nil {
			return err
		}
		_, err := t.CopyOut(data, word)
		return err

	case syscall.PTRACE_POKETEXT, syscall.PTRACE_POKEDATA:
		_, err := usermem.CopyObjectOut(t, target.MemoryManager(), addr, t.Arch().Native(uintptr(data)), usermem.IOOpts{
			IgnorePermissions: true,
		})
		return err

	case syscall.PTRACE_PEEKUSR: // aka PTRACE_PEEKUSER
		n, err := target.Arch().PtracePeekUser(uintptr(addr))
		if err != nil {
			return err
		}
		_, err = t.CopyOut(data, n)
		return err

	case syscall.PTRACE_POKEUSR: // aka PTRACE_POKEUSER
		return target.Arch().PtracePokeUser(uintptr(addr), uintptr(data))

	case syscall.PTRACE_GETREGS:
		// "Copy the tracee's general-purpose ... registers ... to the address
		// data in the tracer. ... (addr is ignored.) Note that SPARC systems
		// have the meaning of data and addr reversed ..."
		_, err := target.Arch().PtraceGetRegs(&usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: data,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		})
		return err

	case syscall.PTRACE_GETFPREGS:
		_, err := target.Arch().PtraceGetFPRegs(&usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: data,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		})
		return err

	case syscall.PTRACE_GETREGSET:
		// "Read the tracee's registers. addr specifies, in an
		// architecture-dependent way, the type of registers to be read. ...
		// data points to a struct iovec, which describes the destination
		// buffer's location and length. On return, the kernel modifies iov.len
		// to indicate the actual number of bytes returned." - ptrace(2)
		ars, err := t.CopyInIovecs(data, 1)
		if err != nil {
			return err
		}
		ar := ars.Head()
		n, err := target.Arch().PtraceGetRegSet(uintptr(addr), &usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: ar.Start,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		}, int(ar.Length()))
		if err != nil {
			return err
		}
		ar.End -= usermem.Addr(n)
		return t.CopyOutIovecs(data, usermem.AddrRangeSeqOf(ar))

	case syscall.PTRACE_SETREGS:
		_, err := target.Arch().PtraceSetRegs(&usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: data,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		})
		return err

	case syscall.PTRACE_SETFPREGS:
		_, err := target.Arch().PtraceSetFPRegs(&usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: data,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		})
		return err

	case syscall.PTRACE_SETREGSET:
		ars, err := t.CopyInIovecs(data, 1)
		if err != nil {
			return err
		}
		ar := ars.Head()
		n, err := target.Arch().PtraceSetRegSet(uintptr(addr), &usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: ar.Start,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		}, int(ar.Length()))
		if err != nil {
			return err
		}
		ar.End -= usermem.Addr(n)
		return t.CopyOutIovecs(data, usermem.AddrRangeSeqOf(ar))

	case syscall.PTRACE_GETSIGINFO:
		t.tg.pidns.owner.mu.RLock()
		defer t.tg.pidns.owner.mu.RUnlock()
		if target.ptraceSiginfo == nil {
			return syserror.EINVAL
		}
		_, err := t.CopyOut(data, target.ptraceSiginfo)
		return err

	case syscall.PTRACE_SETSIGINFO:
		var info arch.SignalInfo
		if _, err := t.CopyIn(data, &info); err != nil {
			return err
		}
		t.tg.pidns.owner.mu.RLock()
		defer t.tg.pidns.owner.mu.RUnlock()
		if target.ptraceSiginfo == nil {
			return syserror.EINVAL
		}
		target.ptraceSiginfo = &info
		return nil

	case PTRACE_GETSIGMASK:
		if addr != linux.SignalSetSize {
			return syserror.EINVAL
		}
		target.mu.Lock()
		defer target.mu.Unlock()
		_, err := t.CopyOut(data, target.tr.SignalMask)
		return err

	case PTRACE_SETSIGMASK:
		if addr != linux.SignalSetSize {
			return syserror.EINVAL
		}
		var mask linux.SignalSet
		if _, err := t.CopyIn(data, &mask); err != nil {
			return err
		}
		// The target's task goroutine is stopped, so this is safe:
		target.SetSignalMask(mask &^ UnblockableSignals)
		return nil

	case syscall.PTRACE_SETOPTIONS:
		t.tg.pidns.owner.mu.Lock()
		defer t.tg.pidns.owner.mu.Unlock()
		validOpts := uintptr(_PTRACE_O_EXITKILL | syscall.PTRACE_O_TRACESYSGOOD | syscall.PTRACE_O_TRACECLONE |
			syscall.PTRACE_O_TRACEEXEC | syscall.PTRACE_O_TRACEEXIT | syscall.PTRACE_O_TRACEFORK |
			_PTRACE_O_TRACESECCOMP | syscall.PTRACE_O_TRACEVFORK | syscall.PTRACE_O_TRACEVFORKDONE)
		if uintptr(data)&^validOpts != 0 {
			return syserror.EINVAL
		}
		target.ptraceOpts = ptraceOptions{
			ExitKill:       data&_PTRACE_O_EXITKILL != 0,
			SysGood:        data&syscall.PTRACE_O_TRACESYSGOOD != 0,
			TraceClone:     data&syscall.PTRACE_O_TRACECLONE != 0,
			TraceExec:      data&syscall.PTRACE_O_TRACEEXEC != 0,
			TraceExit:      data&syscall.PTRACE_O_TRACEEXIT != 0,
			TraceFork:      data&syscall.PTRACE_O_TRACEFORK != 0,
			TraceSeccomp:   data&_PTRACE_O_TRACESECCOMP != 0,
			TraceVfork:     data&syscall.PTRACE_O_TRACEVFORK != 0,
			TraceVforkDone: data&syscall.PTRACE_O_TRACEVFORKDONE != 0,
		}
		return nil

	case syscall.PTRACE_GETEVENTMSG:
		t.tg.pidns.owner.mu.RLock()
		defer t.tg.pidns.owner.mu.RUnlock()
		_, err := t.CopyOut(usermem.Addr(data), target.ptraceEventMsg)
		return err

	default:
		// PEEKSIGINFO is unimplemented but seems to have no users anywhere.
		return syserror.EIO
	}
}
