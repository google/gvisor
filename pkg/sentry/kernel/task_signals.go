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

// This file defines the behavior of task signal handling.

import (
	"fmt"
	"sync/atomic"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/eventchannel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	ucspb "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/uncaught_signal_go_proto"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// SignalAction is an internal signal action.
type SignalAction int

// Available signal actions.
// Note that although we refer the complete set internally,
// the application is only capable of using the Default and
// Ignore actions from the system call interface.
const (
	SignalActionTerm SignalAction = iota
	SignalActionCore
	SignalActionStop
	SignalActionIgnore
	SignalActionHandler
)

// Default signal handler actions. Note that for most signals,
// (except SIGKILL and SIGSTOP) these can be overridden by the app.
var defaultActions = map[linux.Signal]SignalAction{
	// POSIX.1-1990 standard.
	linux.SIGHUP:  SignalActionTerm,
	linux.SIGINT:  SignalActionTerm,
	linux.SIGQUIT: SignalActionCore,
	linux.SIGILL:  SignalActionCore,
	linux.SIGABRT: SignalActionCore,
	linux.SIGFPE:  SignalActionCore,
	linux.SIGKILL: SignalActionTerm, // but see ThreadGroup.applySignalSideEffects
	linux.SIGSEGV: SignalActionCore,
	linux.SIGPIPE: SignalActionTerm,
	linux.SIGALRM: SignalActionTerm,
	linux.SIGTERM: SignalActionTerm,
	linux.SIGUSR1: SignalActionTerm,
	linux.SIGUSR2: SignalActionTerm,
	linux.SIGCHLD: SignalActionIgnore,
	linux.SIGCONT: SignalActionIgnore, // but see ThreadGroup.applySignalSideEffects
	linux.SIGSTOP: SignalActionStop,
	linux.SIGTSTP: SignalActionStop,
	linux.SIGTTIN: SignalActionStop,
	linux.SIGTTOU: SignalActionStop,
	// POSIX.1-2001 standard.
	linux.SIGBUS:    SignalActionCore,
	linux.SIGPROF:   SignalActionTerm,
	linux.SIGSYS:    SignalActionCore,
	linux.SIGTRAP:   SignalActionCore,
	linux.SIGURG:    SignalActionIgnore,
	linux.SIGVTALRM: SignalActionTerm,
	linux.SIGXCPU:   SignalActionCore,
	linux.SIGXFSZ:   SignalActionCore,
	// The rest on linux.
	linux.SIGSTKFLT: SignalActionTerm,
	linux.SIGIO:     SignalActionTerm,
	linux.SIGPWR:    SignalActionTerm,
	linux.SIGWINCH:  SignalActionIgnore,
}

// computeAction figures out what to do given a signal number
// and an arch.SignalAct. SIGSTOP always results in a SignalActionStop,
// and SIGKILL always results in a SignalActionTerm.
// Signal 0 is always ignored as many programs use it for various internal functions
// and don't expect it to do anything.
//
// In the event the signal is not one of these, act.Handler determines what
// happens next.
// If act.Handler is:
// 0, the default action is taken;
// 1, the signal is ignored;
// anything else, the function returns SignalActionHandler.
func computeAction(sig linux.Signal, act arch.SignalAct) SignalAction {
	switch sig {
	case linux.SIGSTOP:
		return SignalActionStop
	case linux.SIGKILL:
		return SignalActionTerm
	case linux.Signal(0):
		return SignalActionIgnore
	}

	switch act.Handler {
	case arch.SignalActDefault:
		return defaultActions[sig]
	case arch.SignalActIgnore:
		return SignalActionIgnore
	default:
		return SignalActionHandler
	}
}

// UnblockableSignals contains the set of signals which cannot be blocked.
var UnblockableSignals = linux.MakeSignalSet(linux.SIGKILL, linux.SIGSTOP)

// StopSignals is the set of signals whose default action is SignalActionStop.
var StopSignals = linux.MakeSignalSet(linux.SIGSTOP, linux.SIGTSTP, linux.SIGTTIN, linux.SIGTTOU)

// dequeueSignalLocked returns a pending signal that is *not* included in mask.
// If there are no pending unmasked signals, dequeueSignalLocked returns nil.
//
// Preconditions: t.tg.signalHandlers.mu must be locked.
func (t *Task) dequeueSignalLocked(mask linux.SignalSet) *arch.SignalInfo {
	if info := t.pendingSignals.dequeue(mask); info != nil {
		return info
	}
	return t.tg.pendingSignals.dequeue(mask)
}

// discardSpecificLocked removes all instances of the given signal from all
// signal queues in tg.
//
// Preconditions: The signal mutex must be locked.
func (tg *ThreadGroup) discardSpecificLocked(sig linux.Signal) {
	tg.pendingSignals.discardSpecific(sig)
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		t.pendingSignals.discardSpecific(sig)
	}
}

// PendingSignals returns the set of pending signals.
func (t *Task) PendingSignals() linux.SignalSet {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	return t.pendingSignals.pendingSet | t.tg.pendingSignals.pendingSet
}

// deliverSignal delivers the given signal and returns the following run state.
func (t *Task) deliverSignal(info *arch.SignalInfo, act arch.SignalAct) taskRunState {
	sigact := computeAction(linux.Signal(info.Signo), act)

	if t.haveSyscallReturn {
		if sre, ok := SyscallRestartErrnoFromReturn(t.Arch().Return()); ok {
			// Signals that are ignored, cause a thread group stop, or
			// terminate the thread group do not interact with interrupted
			// syscalls; in Linux terms, they are never returned to the signal
			// handling path from get_signal => get_signal_to_deliver. The
			// behavior of an interrupted syscall is determined by the first
			// signal that is actually handled (by userspace).
			if sigact == SignalActionHandler {
				switch {
				case sre == ERESTARTNOHAND:
					fallthrough
				case sre == ERESTART_RESTARTBLOCK:
					fallthrough
				case (sre == ERESTARTSYS && !act.IsRestart()):
					t.Debugf("Not restarting syscall %d after errno %d: interrupted by signal %d", t.Arch().SyscallNo(), sre, info.Signo)
					t.Arch().SetReturn(uintptr(-t.ExtractErrno(syserror.EINTR, -1)))
				default:
					t.Debugf("Restarting syscall %d after errno %d: interrupted by signal %d", t.Arch().SyscallNo(), sre, info.Signo)
					t.Arch().RestartSyscall()
				}
			}
		}
	}

	switch sigact {
	case SignalActionTerm, SignalActionCore:
		// "Default action is to terminate the process." - signal(7)
		t.Debugf("Signal %d: terminating thread group", info.Signo)

		// Emit an event channel messages related to this uncaught signal.
		ucs := &ucspb.UncaughtSignal{
			Tid:          int32(t.Kernel().TaskSet().Root.IDOfTask(t)),
			Pid:          int32(t.Kernel().TaskSet().Root.IDOfThreadGroup(t.ThreadGroup())),
			Registers:    t.Arch().StateData().Proto(),
			SignalNumber: info.Signo,
		}

		// Attach an fault address if appropriate.
		switch linux.Signal(info.Signo) {
		case linux.SIGSEGV, linux.SIGFPE, linux.SIGILL, linux.SIGTRAP, linux.SIGBUS:
			ucs.FaultAddr = info.Addr()
		}

		eventchannel.Emit(ucs)

		t.PrepareGroupExit(ExitStatus{Signo: int(info.Signo)})
		return (*runExit)(nil)

	case SignalActionStop:
		// "Default action is to stop the process."
		t.initiateGroupStop(info)

	case SignalActionIgnore:
		// "Default action is to ignore the signal."
		t.Debugf("Signal %d: ignored", info.Signo)

	case SignalActionHandler:
		// Try to deliver the signal to the user-configured handler.
		t.Debugf("Signal %d: delivering to handler", info.Signo)
		if err := t.deliverSignalToHandler(info, act); err != nil {
			// This is not a warning, it can occur during normal operation.
			t.Debugf("Failed to deliver signal %+v to user handler: %v", info, err)

			// Send a forced SIGSEGV. If the signal that couldn't be delivered
			// was a SIGSEGV, force the handler to SIG_DFL.
			t.forceSignal(linux.SIGSEGV, linux.Signal(info.Signo) == linux.SIGSEGV /* unconditional */)
			t.SendSignal(SignalInfoPriv(linux.SIGSEGV))
		}

	default:
		panic(fmt.Sprintf("Unknown signal action %+v, %d?", info, computeAction(linux.Signal(info.Signo), act)))
	}
	return (*runInterrupt)(nil)
}

// deliverSignalToHandler changes the task's userspace state to enter the given
// user-configured handler for the given signal.
func (t *Task) deliverSignalToHandler(info *arch.SignalInfo, act arch.SignalAct) error {
	// Signal delivery to an application handler interrupts restartable
	// sequences.
	t.rseqInterrupt()

	// Are executing on the main stack,
	// or the provided alternate stack?
	sp := usermem.Addr(t.Arch().Stack())

	// N.B. This is a *copy* of the alternate stack that the user's signal
	// handler expects to see in its ucontext (even if it's not in use).
	alt := t.signalStack
	if act.IsOnStack() && alt.IsEnabled() {
		alt.SetOnStack()
		if !alt.Contains(sp) {
			sp = usermem.Addr(alt.Top())
		}
	}

	// Set up the signal handler. If we have a saved signal mask, the signal
	// handler should run with the current mask, but sigreturn should restore
	// the saved one.
	st := &arch.Stack{t.Arch(), t.MemoryManager(), sp}
	mask := t.signalMask
	if t.haveSavedSignalMask {
		mask = t.savedSignalMask
	}
	if err := t.Arch().SignalSetup(st, &act, info, &alt, mask); err != nil {
		return err
	}
	t.haveSavedSignalMask = false

	// Add our signal mask.
	newMask := t.signalMask | act.Mask
	if !act.IsNoDefer() {
		newMask |= linux.SignalSetOf(linux.Signal(info.Signo))
	}
	t.SetSignalMask(newMask)

	return nil
}

var ctrlResume = &SyscallControl{ignoreReturn: true}

// SignalReturn implements sigreturn(2) (if rt is false) or rt_sigreturn(2) (if
// rt is true).
func (t *Task) SignalReturn(rt bool) (*SyscallControl, error) {
	st := t.Stack()
	sigset, alt, err := t.Arch().SignalRestore(st, rt)
	if err != nil {
		return nil, err
	}

	// Attempt to record the given signal stack. Note that we silently
	// ignore failures here, as does Linux. Only an EFAULT may be
	// generated, but SignalRestore has already deserialized the entire
	// frame successfully.
	t.SetSignalStack(alt)

	// Restore our signal mask. SIGKILL and SIGSTOP should not be blocked.
	t.SetSignalMask(sigset &^ UnblockableSignals)

	return ctrlResume, nil
}

// Sigtimedwait implements the semantics of sigtimedwait(2).
//
// Preconditions: The caller must be running on the task goroutine. t.exitState
// < TaskExitZombie.
func (t *Task) Sigtimedwait(set linux.SignalSet, timeout time.Duration) (*arch.SignalInfo, error) {
	// set is the set of signals we're interested in; invert it to get the set
	// of signals to block.
	mask := ^(set &^ UnblockableSignals)

	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	if info := t.dequeueSignalLocked(mask); info != nil {
		return info, nil
	}

	if timeout == 0 {
		return nil, syserror.EAGAIN
	}

	// Unblock signals we're waiting for. Remember the original signal mask so
	// that Task.sendSignalTimerLocked doesn't discard ignored signals that
	// we're temporarily unblocking.
	t.realSignalMask = t.signalMask
	t.setSignalMaskLocked(t.signalMask & mask)

	// Wait for a timeout or new signal.
	t.tg.signalHandlers.mu.Unlock()
	_, err := t.BlockWithTimeout(nil, true, timeout)
	t.tg.signalHandlers.mu.Lock()

	// Restore the original signal mask.
	t.setSignalMaskLocked(t.realSignalMask)
	t.realSignalMask = 0

	if info := t.dequeueSignalLocked(mask); info != nil {
		return info, nil
	}
	if err == syserror.ETIMEDOUT {
		return nil, syserror.EAGAIN
	}
	return nil, err
}

// SendSignal sends the given signal to t.
//
// The following errors may be returned:
//
//	syserror.ESRCH - The task has exited.
//	syserror.EINVAL - The signal is not valid.
//	syserror.EAGAIN - THe signal is realtime, and cannot be queued.
//
func (t *Task) SendSignal(info *arch.SignalInfo) error {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	return t.sendSignalLocked(info, false /* group */)
}

// SendGroupSignal sends the given signal to t's thread group.
func (t *Task) SendGroupSignal(info *arch.SignalInfo) error {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	return t.sendSignalLocked(info, true /* group */)
}

// SendSignal sends the given signal to tg, using tg's leader to determine if
// the signal is blocked.
func (tg *ThreadGroup) SendSignal(info *arch.SignalInfo) error {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()
	return tg.leader.sendSignalLocked(info, true /* group */)
}

func (t *Task) sendSignalLocked(info *arch.SignalInfo, group bool) error {
	return t.sendSignalTimerLocked(info, group, nil)
}

func (t *Task) sendSignalTimerLocked(info *arch.SignalInfo, group bool, timer *IntervalTimer) error {
	if t.exitState == TaskExitDead {
		return syserror.ESRCH
	}
	sig := linux.Signal(info.Signo)
	if sig == 0 {
		return nil
	}
	if !sig.IsValid() {
		return syserror.EINVAL
	}

	// Signal side effects apply even if the signal is ultimately discarded.
	t.tg.applySignalSideEffectsLocked(sig)

	// TODO: "Only signals for which the "init" process has established a
	// signal handler can be sent to the "init" process by other members of the
	// PID namespace. This restriction applies even to privileged processes,
	// and prevents other members of the PID namespace from accidentally
	// killing the "init" process." - pid_namespaces(7). We don't currently do
	// this for child namespaces, though we should; we also don't do this for
	// the root namespace (the same restriction applies to global init on
	// Linux), where whether or not we should is much murkier. In practice,
	// most sandboxed applications are not prepared to function as an init
	// process.

	// Unmasked, ignored signals are discarded without being queued, unless
	// they will be visible to a tracer. Even for group signals, it's the
	// originally-targeted task's signal mask and tracer that matter; compare
	// Linux's kernel/signal.c:__send_signal() => prepare_signal() =>
	// sig_ignored().
	ignored := computeAction(sig, t.tg.signalHandlers.actions[sig]) == SignalActionIgnore
	if sigset := linux.SignalSetOf(sig); sigset&t.signalMask == 0 && sigset&t.realSignalMask == 0 && ignored && !t.hasTracer() {
		t.Debugf("Discarding ignored signal %d", sig)
		if timer != nil {
			timer.signalRejectedLocked()
		}
		return nil
	}

	q := &t.pendingSignals
	if group {
		q = &t.tg.pendingSignals
	}
	if !q.enqueue(info, timer) {
		if sig.IsRealtime() {
			return syserror.EAGAIN
		}
		t.Debugf("Discarding duplicate signal %d", sig)
		if timer != nil {
			timer.signalRejectedLocked()
		}
		return nil
	}

	// Find a receiver to notify. Note that the task we choose to notify, if
	// any, may not be the task that actually dequeues and handles the signal;
	// e.g. a racing signal mask change may cause the notified task to become
	// ineligible, or a racing sibling task may dequeue the signal first.
	if t.canReceiveSignalLocked(sig) {
		t.Debugf("Notified of signal %d", sig)
		t.interrupt()
		return nil
	}
	if group {
		if nt := t.tg.findSignalReceiverLocked(sig); nt != nil {
			nt.Debugf("Notified of group signal %d", sig)
			nt.interrupt()
			return nil
		}
	}
	t.Debugf("No task notified of signal %d", sig)
	return nil
}

func (tg *ThreadGroup) applySignalSideEffectsLocked(sig linux.Signal) {
	switch {
	case linux.SignalSetOf(sig)&StopSignals != 0:
		// Stop signals cause all prior SIGCONT to be discarded. (This is
		// despite the fact this has little effect since SIGCONT's most
		// important effect is applied when the signal is sent in the branch
		// below, not when the signal is delivered.)
		tg.discardSpecificLocked(linux.SIGCONT)
	case sig == linux.SIGCONT:
		// "The SIGCONT signal has a side effect of waking up (all threads of)
		// a group-stopped process. This side effect happens before
		// signal-delivery-stop. The tracer can't suppress this side effect (it
		// can only suppress signal injection, which only causes the SIGCONT
		// handler to not be executed in the tracee, if such a handler is
		// installed." - ptrace(2)
		tg.endGroupStopLocked(true)
	case sig == linux.SIGKILL:
		// "SIGKILL does not generate signal-delivery-stop and therefore the
		// tracer can't suppress it. SIGKILL kills even within system calls
		// (syscall-exit-stop is not generated prior to death by SIGKILL)." -
		// ptrace(2)
		//
		// Note that this differs from ThreadGroup.requestExit in that it
		// ignores tg.execing.
		if !tg.exiting {
			tg.exiting = true
			tg.exitStatus = ExitStatus{Signo: int(linux.SIGKILL)}
		}
		for t := tg.tasks.Front(); t != nil; t = t.Next() {
			t.killLocked()
		}
	}
}

// canReceiveSignalLocked returns true if t should be interrupted to receive
// the given signal. canReceiveSignalLocked is analogous to Linux's
// kernel/signal.c:wants_signal(), but see below for divergences.
//
// Preconditions: The signal mutex must be locked.
func (t *Task) canReceiveSignalLocked(sig linux.Signal) bool {
	// - Do not choose tasks that are blocking the signal.
	if linux.SignalSetOf(sig)&t.signalMask != 0 {
		return false
	}
	// - No need to check Task.exitState, as the exit path sets every bit in the
	// signal mask when it transitions from TaskExitNone to TaskExitInitiated.
	// - No special case for SIGKILL: SIGKILL already interrupted all tasks in the
	// task group via applySignalSideEffects => killLocked.
	// - Do not choose stopped tasks, which cannot handle signals.
	if t.stop != nil {
		return false
	}
	// - TODO(b/38173783): No special case for when t is also the sending task,
	// because the identity of the sender is unknown.
	// - Do not choose tasks that have already been interrupted, as they may be
	// busy handling another signal.
	if len(t.interruptChan) != 0 {
		return false
	}
	return true
}

// findSignalReceiverLocked returns a task in tg that should be interrupted to
// receive the given signal. If no such task exists, findSignalReceiverLocked
// returns nil.
//
// Linux actually records curr_target to balance the group signal targets.
//
// Preconditions: The signal mutex must be locked.
func (tg *ThreadGroup) findSignalReceiverLocked(sig linux.Signal) *Task {
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		if t.canReceiveSignalLocked(sig) {
			return t
		}
	}
	return nil
}

// forceSignal ensures that the task is not ignoring or blocking the given
// signal. If unconditional is true, forceSignal takes action even if the
// signal isn't being ignored or blocked.
func (t *Task) forceSignal(sig linux.Signal, unconditional bool) {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.forceSignalLocked(sig, unconditional)
}

func (t *Task) forceSignalLocked(sig linux.Signal, unconditional bool) {
	blocked := linux.SignalSetOf(sig)&t.signalMask != 0
	act := t.tg.signalHandlers.actions[sig]
	ignored := act.Handler == arch.SignalActIgnore
	if blocked || ignored || unconditional {
		act.Handler = arch.SignalActDefault
		t.tg.signalHandlers.actions[sig] = act
		if blocked {
			t.setSignalMaskLocked(t.signalMask &^ linux.SignalSetOf(sig))
		}
	}
}

// SignalMask returns a copy of t's signal mask.
func (t *Task) SignalMask() linux.SignalSet {
	return linux.SignalSet(atomic.LoadUint64((*uint64)(&t.signalMask)))
}

// SetSignalMask sets t's signal mask.
//
// Preconditions: SetSignalMask can only be called by the task goroutine.
// t.exitState < TaskExitZombie.
func (t *Task) SetSignalMask(mask linux.SignalSet) {
	// By precondition, t prevents t.tg from completing an execve and mutating
	// t.tg.signalHandlers, so we can skip the TaskSet mutex.
	t.tg.signalHandlers.mu.Lock()
	t.setSignalMaskLocked(mask)
	t.tg.signalHandlers.mu.Unlock()
}

// Preconditions: The signal mutex must be locked.
func (t *Task) setSignalMaskLocked(mask linux.SignalSet) {
	oldMask := t.signalMask
	atomic.StoreUint64((*uint64)(&t.signalMask), uint64(mask))

	// If the new mask blocks any signals that were not blocked by the old
	// mask, and at least one such signal is pending in tg.pendingSignals, and
	// t has been woken, it could be the case that t was woken to handle that
	// signal, but will no longer do so as a result of its new signal mask, so
	// we have to pick a replacement.
	blocked := mask &^ oldMask
	blockedGroupPending := blocked & t.tg.pendingSignals.pendingSet
	if blockedGroupPending != 0 && t.interrupted() {
		linux.ForEachSignal(blockedGroupPending, func(sig linux.Signal) {
			if nt := t.tg.findSignalReceiverLocked(sig); nt != nil {
				nt.interrupt()
				return
			}
		})
		// We have to re-issue the interrupt consumed by t.interrupted() since
		// it might have been for a different reason.
		t.interruptSelf()
	}

	// Conversely, if the new mask unblocks any signals that were blocked by
	// the old mask, and at least one such signal is pending, we may now need
	// to handle that signal.
	unblocked := oldMask &^ mask
	unblockedPending := unblocked & (t.pendingSignals.pendingSet | t.tg.pendingSignals.pendingSet)
	if unblockedPending != 0 {
		t.interruptSelf()
	}
}

// SetSavedSignalMask sets the saved signal mask (see Task.savedSignalMask's
// comment).
//
// Preconditions: SetSavedSignalMask can only be called by the task goroutine.
func (t *Task) SetSavedSignalMask(mask linux.SignalSet) {
	t.savedSignalMask = mask
	t.haveSavedSignalMask = true
}

// SignalStack returns the task-private signal stack.
func (t *Task) SignalStack() arch.SignalStack {
	alt := t.signalStack
	if t.onSignalStack(alt) {
		alt.Flags |= arch.SignalStackFlagOnStack
	}
	return alt
}

// onSignalStack returns true if the task is executing on the given signal stack.
func (t *Task) onSignalStack(alt arch.SignalStack) bool {
	sp := usermem.Addr(t.Arch().Stack())
	return alt.Contains(sp)
}

// SetSignalStack sets the task-private signal stack.
//
// This value may not be changed if the task is currently executing on the
// signal stack, i.e. if t.onSignalStack returns true. In this case, this
// function will return false. Otherwise, true is returned.
func (t *Task) SetSignalStack(alt arch.SignalStack) bool {
	// Check that we're not executing on the stack.
	if t.onSignalStack(t.signalStack) {
		return false
	}

	if alt.Flags&arch.SignalStackFlagDisable != 0 {
		// Don't record anything beyond the flags.
		t.signalStack = arch.SignalStack{
			Flags: arch.SignalStackFlagDisable,
		}
	} else {
		// Mask out irrelevant parts: only disable matters.
		alt.Flags &= arch.SignalStackFlagDisable
		t.signalStack = alt
	}
	return true
}

// SetSignalAct atomically sets the thread group's signal action for signal sig
// to *actptr (if actptr is not nil) and returns the old signal action.
func (tg *ThreadGroup) SetSignalAct(sig linux.Signal, actptr *arch.SignalAct) (arch.SignalAct, error) {
	if !sig.IsValid() {
		return arch.SignalAct{}, syserror.EINVAL
	}

	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	sh := tg.signalHandlers
	sh.mu.Lock()
	defer sh.mu.Unlock()
	oldact := sh.actions[sig]
	if actptr != nil {
		if sig == linux.SIGKILL || sig == linux.SIGSTOP {
			return oldact, syserror.EINVAL
		}

		act := *actptr
		act.Mask &^= UnblockableSignals
		sh.actions[sig] = act
		// From POSIX, by way of Linux:
		//
		// "Setting a signal action to SIG_IGN for a signal that is pending
		// shall cause the pending signal to be discarded, whether or not it is
		// blocked."
		//
		// "Setting a signal action to SIG_DFL for a signal that is pending and
		// whose default action is to ignore the signal (for example, SIGCHLD),
		// shall cause the pending signal to be discarded, whether or not it is
		// blocked."
		if computeAction(sig, act) == SignalActionIgnore {
			tg.discardSpecificLocked(sig)
		}
	}
	return oldact, nil
}

// CopyOutSignalAct converts the given SignalAct into an architecture-specific
// type and then copies it out to task memory.
func (t *Task) CopyOutSignalAct(addr usermem.Addr, s *arch.SignalAct) error {
	n := t.Arch().NewSignalAct()
	n.SerializeFrom(s)
	_, err := t.CopyOut(addr, n)
	return err
}

// CopyInSignalAct copies an architecture-specific sigaction type from task
// memory and then converts it into a SignalAct.
func (t *Task) CopyInSignalAct(addr usermem.Addr) (arch.SignalAct, error) {
	n := t.Arch().NewSignalAct()
	var s arch.SignalAct
	if _, err := t.CopyIn(addr, n); err != nil {
		return s, err
	}
	n.DeserializeTo(&s)
	return s, nil
}

// CopyOutSignalStack converts the given SignalStack into an
// architecture-specific type and then copies it out to task memory.
func (t *Task) CopyOutSignalStack(addr usermem.Addr, s *arch.SignalStack) error {
	n := t.Arch().NewSignalStack()
	n.SerializeFrom(s)
	_, err := t.CopyOut(addr, n)
	return err
}

// CopyInSignalStack copies an architecture-specific stack_t from task memory
// and then converts it into a SignalStack.
func (t *Task) CopyInSignalStack(addr usermem.Addr) (arch.SignalStack, error) {
	n := t.Arch().NewSignalStack()
	var s arch.SignalStack
	if _, err := t.CopyIn(addr, n); err != nil {
		return s, err
	}
	n.DeserializeTo(&s)
	return s, nil
}

// groupStop is a TaskStop placed on tasks that have received a stop signal
// (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU). (The term "group-stop" originates from
// the ptrace man page.)
//
// +stateify savable
type groupStop struct{}

// Killable implements TaskStop.Killable.
func (*groupStop) Killable() bool { return true }

// initiateGroupStop attempts to initiate a group stop based on a
// previously-dequeued stop signal.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) initiateGroupStop(info *arch.SignalInfo) {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	if t.groupStopPending {
		t.Debugf("Signal %d: not stopping thread group: lost to racing stop signal", info.Signo)
		return
	}
	if !t.tg.groupStopDequeued {
		t.Debugf("Signal %d: not stopping thread group: lost to racing SIGCONT", info.Signo)
		return
	}
	if t.tg.exiting {
		t.Debugf("Signal %d: not stopping thread group: lost to racing group exit", info.Signo)
		return
	}
	if t.tg.execing != nil {
		t.Debugf("Signal %d: not stopping thread group: lost to racing execve", info.Signo)
		return
	}
	if !t.tg.groupStopComplete {
		t.tg.groupStopSignal = linux.Signal(info.Signo)
	}
	t.tg.groupStopPendingCount = 0
	for t2 := t.tg.tasks.Front(); t2 != nil; t2 = t2.Next() {
		if t2.killedLocked() || t2.exitState >= TaskExitInitiated {
			t2.groupStopPending = false
			continue
		}
		t2.groupStopPending = true
		t2.groupStopAcknowledged = false
		if t2.ptraceSeized {
			t2.trapNotifyPending = true
			if s, ok := t2.stop.(*ptraceStop); ok && s.listen {
				t2.endInternalStopLocked()
			}
		}
		t2.interrupt()
		t.tg.groupStopPendingCount++
	}
	t.Debugf("Signal %d: stopping %d threads in thread group", info.Signo, t.tg.groupStopPendingCount)
}

// endGroupStopLocked ensures that all prior stop signals received by tg are
// not stopping tg and will not stop tg in the future. If broadcast is true,
// parent and tracer notification will be scheduled if appropriate.
//
// Preconditions: The signal mutex must be locked.
func (tg *ThreadGroup) endGroupStopLocked(broadcast bool) {
	// Discard all previously-queued stop signals.
	linux.ForEachSignal(StopSignals, tg.discardSpecificLocked)

	if tg.groupStopPendingCount == 0 && !tg.groupStopComplete {
		return
	}

	completeStr := "incomplete"
	if tg.groupStopComplete {
		completeStr = "complete"
	}
	tg.leader.Debugf("Ending %s group stop with %d threads pending", completeStr, tg.groupStopPendingCount)
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		t.groupStopPending = false
		if t.ptraceSeized {
			t.trapNotifyPending = true
			if s, ok := t.stop.(*ptraceStop); ok && s.listen {
				t.endInternalStopLocked()
			}
		} else {
			if _, ok := t.stop.(*groupStop); ok {
				t.endInternalStopLocked()
			}
		}
	}
	if broadcast {
		// Instead of notifying the parent here, set groupContNotify so that
		// one of the continuing tasks does so. (Linux does something similar.)
		// The reason we do this is to keep locking sane. In order to send a
		// signal to the parent, we need to lock its signal mutex, but we're
		// already holding tg's signal mutex, and the TaskSet mutex must be
		// locked for writing for us to hold two signal mutexes. Since we don't
		// want to require this for endGroupStopLocked (which is called from
		// signal-sending paths), nor do we want to lose atomicity by releasing
		// the mutexes we're already holding, just let the continuing thread
		// group deal with it.
		tg.groupContNotify = true
		tg.groupContInterrupted = !tg.groupStopComplete
		tg.groupContWaitable = true
	}
	// Unsetting groupStopDequeued will cause racing calls to initiateGroupStop
	// to recognize that the group stop has been cancelled.
	tg.groupStopDequeued = false
	tg.groupStopSignal = 0
	tg.groupStopPendingCount = 0
	tg.groupStopComplete = false
	tg.groupStopWaitable = false
}

// participateGroupStopLocked is called to handle thread group side effects
// after t unsets t.groupStopPending. The caller must handle task side effects
// (e.g. placing the task goroutine into the group stop). It returns true if
// the caller must notify t.tg.leader's parent of a completed group stop (which
// participateGroupStopLocked cannot do due to holding the wrong locks).
//
// Preconditions: The signal mutex must be locked.
func (t *Task) participateGroupStopLocked() bool {
	if t.groupStopAcknowledged {
		return false
	}
	t.groupStopAcknowledged = true
	t.tg.groupStopPendingCount--
	if t.tg.groupStopPendingCount != 0 {
		return false
	}
	if t.tg.groupStopComplete {
		return false
	}
	t.Debugf("Completing group stop")
	t.tg.groupStopComplete = true
	t.tg.groupStopWaitable = true
	t.tg.groupContNotify = false
	t.tg.groupContWaitable = false
	return true
}

// signalStop sends a signal to t's thread group of a new group stop, group
// continue, or ptrace stop, if appropriate. code and status are set in the
// signal sent to tg, if any.
//
// Preconditions: The TaskSet mutex must be locked (for reading or writing).
func (t *Task) signalStop(target *Task, code int32, status int32) {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	act, ok := t.tg.signalHandlers.actions[linux.SIGCHLD]
	if !ok || (act.Handler != arch.SignalActIgnore && act.Flags&arch.SignalFlagNoCldStop == 0) {
		sigchld := &arch.SignalInfo{
			Signo: int32(linux.SIGCHLD),
			Code:  code,
		}
		sigchld.SetPid(int32(t.tg.pidns.tids[target]))
		sigchld.SetUid(int32(target.Credentials().RealKUID.In(t.UserNamespace()).OrOverflow()))
		sigchld.SetStatus(status)
		// TODO(b/72102453): Set utime, stime.
		t.sendSignalLocked(sigchld, true /* group */)
	}
}

// The runInterrupt state handles conditions indicated by interrupts.
//
// +stateify savable
type runInterrupt struct{}

func (*runInterrupt) execute(t *Task) taskRunState {
	// Interrupts are de-duplicated (if t is interrupted twice before
	// t.interrupted() is called, t.interrupted() will only return true once),
	// so early exits from this function must re-enter the runInterrupt state
	// to check for more interrupt-signaled conditions.

	t.tg.signalHandlers.mu.Lock()

	// Did we just leave a group stop?
	if t.tg.groupContNotify {
		t.tg.groupContNotify = false
		sig := t.tg.groupStopSignal
		intr := t.tg.groupContInterrupted
		t.tg.signalHandlers.mu.Unlock()
		t.tg.pidns.owner.mu.RLock()
		// For consistency with Linux, if the parent and (thread group
		// leader's) tracer are in the same thread group, deduplicate
		// notifications.
		notifyParent := t.tg.leader.parent != nil
		if tracer := t.tg.leader.Tracer(); tracer != nil {
			if notifyParent && tracer.tg == t.tg.leader.parent.tg {
				notifyParent = false
			}
			// Sending CLD_STOPPED to the tracer doesn't really make any sense;
			// the thread group leader may have already entered the stop and
			// notified its tracer accordingly. But it's consistent with
			// Linux...
			if intr {
				tracer.signalStop(t.tg.leader, arch.CLD_STOPPED, int32(sig))
				if !notifyParent {
					tracer.tg.eventQueue.Notify(EventGroupContinue | EventTraceeStop | EventChildGroupStop)
				} else {
					tracer.tg.eventQueue.Notify(EventGroupContinue | EventTraceeStop)
				}
			} else {
				tracer.signalStop(t.tg.leader, arch.CLD_CONTINUED, int32(sig))
				tracer.tg.eventQueue.Notify(EventGroupContinue)
			}
		}
		if notifyParent {
			// If groupContInterrupted, do as Linux does and pretend the group
			// stop completed just before it ended. The theoretical behavior in
			// this case would be to send a SIGCHLD indicating the completed
			// stop, followed by a SIGCHLD indicating the continue. However,
			// SIGCHLD is a standard signal, so the latter would always be
			// dropped. Hence sending only the former is equivalent.
			if intr {
				t.tg.leader.parent.signalStop(t.tg.leader, arch.CLD_STOPPED, int32(sig))
				t.tg.leader.parent.tg.eventQueue.Notify(EventGroupContinue | EventChildGroupStop)
			} else {
				t.tg.leader.parent.signalStop(t.tg.leader, arch.CLD_CONTINUED, int32(sig))
				t.tg.leader.parent.tg.eventQueue.Notify(EventGroupContinue)
			}
		}
		t.tg.pidns.owner.mu.RUnlock()
		return (*runInterrupt)(nil)
	}

	// Do we need to enter a group stop or related ptrace stop? This path is
	// analogous to Linux's kernel/signal.c:get_signal() => do_signal_stop()
	// (with ptrace enabled) and do_jobctl_trap().
	if t.groupStopPending || t.trapStopPending || t.trapNotifyPending {
		sig := t.tg.groupStopSignal
		notifyParent := false
		if t.groupStopPending {
			t.groupStopPending = false
			// We care about t.tg.groupStopSignal (for tracer notification)
			// even if this doesn't complete a group stop, so keep the
			// value of sig we've already read.
			notifyParent = t.participateGroupStopLocked()
		}
		t.trapStopPending = false
		t.trapNotifyPending = false
		// Drop the signal mutex so we can take the TaskSet mutex.
		t.tg.signalHandlers.mu.Unlock()

		t.tg.pidns.owner.mu.RLock()
		if t.tg.leader.parent == nil {
			notifyParent = false
		}
		if tracer := t.Tracer(); tracer != nil {
			if t.ptraceSeized {
				if sig == 0 {
					sig = linux.SIGTRAP
				}
				// "If tracee was attached using PTRACE_SEIZE, group-stop is
				// indicated by PTRACE_EVENT_STOP: status>>16 ==
				// PTRACE_EVENT_STOP. This allows detection of group-stops
				// without requiring an extra PTRACE_GETSIGINFO call." -
				// "Group-stop", ptrace(2)
				t.ptraceCode = int32(sig) | linux.PTRACE_EVENT_STOP<<8
				t.ptraceSiginfo = &arch.SignalInfo{
					Signo: int32(sig),
					Code:  t.ptraceCode,
				}
				t.ptraceSiginfo.SetPid(int32(t.tg.pidns.tids[t]))
				t.ptraceSiginfo.SetUid(int32(t.Credentials().RealKUID.In(t.UserNamespace()).OrOverflow()))
			} else {
				t.ptraceCode = int32(sig)
				t.ptraceSiginfo = nil
			}
			if t.beginPtraceStopLocked() {
				tracer.signalStop(t, arch.CLD_STOPPED, int32(sig))
				// For consistency with Linux, if the parent and tracer are in the
				// same thread group, deduplicate notification signals.
				if notifyParent && tracer.tg == t.tg.leader.parent.tg {
					notifyParent = false
					tracer.tg.eventQueue.Notify(EventChildGroupStop | EventTraceeStop)
				} else {
					tracer.tg.eventQueue.Notify(EventTraceeStop)
				}
			}
		} else {
			t.tg.signalHandlers.mu.Lock()
			if !t.killedLocked() {
				t.beginInternalStopLocked((*groupStop)(nil))
			}
			t.tg.signalHandlers.mu.Unlock()
		}
		if notifyParent {
			t.tg.leader.parent.signalStop(t.tg.leader, arch.CLD_STOPPED, int32(sig))
			t.tg.leader.parent.tg.eventQueue.Notify(EventChildGroupStop)
		}
		t.tg.pidns.owner.mu.RUnlock()

		return (*runInterrupt)(nil)
	}

	// Are there signals pending?
	if info := t.dequeueSignalLocked(t.signalMask); info != nil {
		if linux.SignalSetOf(linux.Signal(info.Signo))&StopSignals != 0 {
			// Indicate that we've dequeued a stop signal before unlocking the
			// signal mutex; initiateGroupStop will check for races with
			// endGroupStopLocked after relocking it.
			t.tg.groupStopDequeued = true
		}
		if t.ptraceSignalLocked(info) {
			// Dequeueing the signal action must wait until after the
			// signal-delivery-stop ends since the tracer can change or
			// suppress the signal.
			t.tg.signalHandlers.mu.Unlock()
			return (*runInterruptAfterSignalDeliveryStop)(nil)
		}
		act := t.tg.signalHandlers.dequeueAction(linux.Signal(info.Signo))
		t.tg.signalHandlers.mu.Unlock()
		return t.deliverSignal(info, act)
	}

	t.tg.signalHandlers.mu.Unlock()
	return (*runApp)(nil)
}

// +stateify savable
type runInterruptAfterSignalDeliveryStop struct{}

func (*runInterruptAfterSignalDeliveryStop) execute(t *Task) taskRunState {
	t.tg.pidns.owner.mu.Lock()
	// Can't defer unlock: deliverSignal must be called without holding TaskSet
	// mutex.
	sig := linux.Signal(t.ptraceCode)
	defer func() {
		t.ptraceSiginfo = nil
	}()
	if !sig.IsValid() {
		t.tg.pidns.owner.mu.Unlock()
		return (*runInterrupt)(nil)
	}
	info := t.ptraceSiginfo
	if sig != linux.Signal(info.Signo) {
		info.Signo = int32(sig)
		info.Errno = 0
		info.Code = arch.SignalInfoUser
		// pid isn't a valid field for all signal numbers, but Linux
		// doesn't care (kernel/signal.c:ptrace_signal()).
		//
		// Linux uses t->parent for the tid and uid here, which is the tracer
		// if it hasn't detached or the real parent otherwise.
		parent := t.parent
		if tracer := t.Tracer(); tracer != nil {
			parent = tracer
		}
		if parent == nil {
			// Tracer has detached and t was created by Kernel.CreateProcess().
			// Pretend the parent is in an ancestor PID + user namespace.
			info.SetPid(0)
			info.SetUid(int32(auth.OverflowUID))
		} else {
			info.SetPid(int32(t.tg.pidns.tids[parent]))
			info.SetUid(int32(parent.Credentials().RealKUID.In(t.UserNamespace()).OrOverflow()))
		}
	}
	t.tg.signalHandlers.mu.Lock()
	t.tg.pidns.owner.mu.Unlock()
	// If the signal is masked, re-queue it.
	if linux.SignalSetOf(sig)&t.signalMask != 0 {
		t.sendSignalLocked(info, false /* group */)
		t.tg.signalHandlers.mu.Unlock()
		return (*runInterrupt)(nil)
	}
	act := t.tg.signalHandlers.dequeueAction(linux.Signal(info.Signo))
	t.tg.signalHandlers.mu.Unlock()
	return t.deliverSignal(info, act)
}
