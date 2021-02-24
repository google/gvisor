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

// This file implements the task exit cycle:
//
// - Tasks are asynchronously requested to exit with Task.Kill.
//
// - When able, the task goroutine enters the exit path starting from state
// runExit.
//
// - Other tasks observe completed exits with Task.Wait (which implements the
// wait*() family of syscalls).

import (
	"errors"
	"fmt"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// An ExitStatus is a value communicated from an exiting task or thread group
// to the party that reaps it.
//
// +stateify savable
type ExitStatus struct {
	// Code is the numeric value passed to the call to exit or exit_group that
	// caused the exit. If the exit was not caused by such a call, Code is 0.
	Code int

	// Signo is the signal that caused the exit. If the exit was not caused by
	// a signal, Signo is 0.
	Signo int
}

// Signaled returns true if the ExitStatus indicates that the exiting task or
// thread group was killed by a signal.
func (es ExitStatus) Signaled() bool {
	return es.Signo != 0
}

// Status returns the numeric representation of the ExitStatus returned by e.g.
// the wait4() system call.
func (es ExitStatus) Status() uint32 {
	return ((uint32(es.Code) & 0xff) << 8) | (uint32(es.Signo) & 0xff)
}

// ShellExitCode returns the numeric exit code that Bash would return for an
// exit status of es.
func (es ExitStatus) ShellExitCode() int {
	if es.Signaled() {
		return 128 + es.Signo
	}
	return es.Code
}

// TaskExitState represents a step in the task exit path.
//
// "Exiting" and "exited" are often ambiguous; prefer to name specific states.
type TaskExitState int

const (
	// TaskExitNone indicates that the task has not begun exiting.
	TaskExitNone TaskExitState = iota

	// TaskExitInitiated indicates that the task goroutine has entered the exit
	// path, and the task is no longer eligible to participate in group stops
	// or group signal handling. TaskExitInitiated is analogous to Linux's
	// PF_EXITING.
	TaskExitInitiated

	// TaskExitZombie indicates that the task has released its resources, and
	// the task no longer prevents a sibling thread from completing execve.
	TaskExitZombie

	// TaskExitDead indicates that the task's thread IDs have been released,
	// and the task no longer prevents its thread group leader from being
	// reaped. ("Reaping" refers to the transitioning of a task from
	// TaskExitZombie to TaskExitDead.)
	TaskExitDead
)

// String implements fmt.Stringer.
func (t TaskExitState) String() string {
	switch t {
	case TaskExitNone:
		return "TaskExitNone"
	case TaskExitInitiated:
		return "TaskExitInitiated"
	case TaskExitZombie:
		return "TaskExitZombie"
	case TaskExitDead:
		return "TaskExitDead"
	default:
		return strconv.Itoa(int(t))
	}
}

// killLocked marks t as killed by enqueueing a SIGKILL, without causing the
// thread-group-affecting side effects SIGKILL usually has.
//
// Preconditions: The signal mutex must be locked.
func (t *Task) killLocked() {
	// Clear killable stops.
	if t.stop != nil && t.stop.Killable() {
		t.endInternalStopLocked()
	}
	t.pendingSignals.enqueue(&arch.SignalInfo{
		Signo: int32(linux.SIGKILL),
		// Linux just sets SIGKILL in the pending signal bitmask without
		// enqueueing an actual siginfo, such that
		// kernel/signal.c:collect_signal() initializes si_code to SI_USER.
		Code: arch.SignalInfoUser,
	}, nil)
	t.interrupt()
}

// killed returns true if t has a SIGKILL pending. killed is analogous to
// Linux's fatal_signal_pending().
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) killed() bool {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	return t.killedLocked()
}

func (t *Task) killedLocked() bool {
	return t.pendingSignals.pendingSet&linux.SignalSetOf(linux.SIGKILL) != 0
}

// PrepareExit indicates an exit with status es.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) PrepareExit(es ExitStatus) {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	t.exitStatus = es
}

// PrepareGroupExit indicates a group exit with status es to t's thread group.
//
// PrepareGroupExit is analogous to Linux's do_group_exit(), except that it
// does not tail-call do_exit(), except that it *does* set Task.exitStatus.
// (Linux does not do so until within do_exit(), since it reuses exit_code for
// ptrace.)
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) PrepareGroupExit(es ExitStatus) {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	if t.tg.exiting || t.tg.execing != nil {
		// Note that if t.tg.exiting is false but t.tg.execing is not nil, i.e.
		// this "group exit" is being executed by the killed sibling of an
		// execing task, then Task.Execve never set t.tg.exitStatus, so it's
		// still the zero value. This is consistent with Linux, both in intent
		// ("all other threads ... report death as if they exited via _exit(2)
		// with exit code 0" - ptrace(2), "execve under ptrace") and in
		// implementation (compare fs/exec.c:de_thread() =>
		// kernel/signal.c:zap_other_threads() and
		// kernel/exit.c:do_group_exit() =>
		// include/linux/sched.h:signal_group_exit()).
		t.exitStatus = t.tg.exitStatus
		return
	}
	t.tg.exiting = true
	t.tg.exitStatus = es
	t.exitStatus = es
	for sibling := t.tg.tasks.Front(); sibling != nil; sibling = sibling.Next() {
		if sibling != t {
			sibling.killLocked()
		}
	}
}

// Kill requests that all tasks in ts exit as if group exiting with status es.
// Kill does not wait for tasks to exit.
//
// Kill has no analogue in Linux; it's provided for save/restore only.
func (ts *TaskSet) Kill(es ExitStatus) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Root.exiting = true
	for t := range ts.Root.tids {
		t.tg.signalHandlers.mu.Lock()
		if !t.tg.exiting {
			t.tg.exiting = true
			t.tg.exitStatus = es
		}
		t.killLocked()
		t.tg.signalHandlers.mu.Unlock()
	}
}

// advanceExitStateLocked checks that t's current exit state is oldExit, then
// sets it to newExit. If t's current exit state is not oldExit,
// advanceExitStateLocked panics.
//
// Preconditions: The TaskSet mutex must be locked.
func (t *Task) advanceExitStateLocked(oldExit, newExit TaskExitState) {
	if t.exitState != oldExit {
		panic(fmt.Sprintf("Transitioning from exit state %v to %v: unexpected preceding state %v", oldExit, newExit, t.exitState))
	}
	t.Debugf("Transitioning from exit state %v to %v", oldExit, newExit)
	t.exitState = newExit
}

// runExit is the entry point into the task exit path.
//
// +stateify savable
type runExit struct{}

func (*runExit) execute(t *Task) taskRunState {
	t.ptraceExit()
	return (*runExitMain)(nil)
}

// +stateify savable
type runExitMain struct{}

func (*runExitMain) execute(t *Task) taskRunState {
	t.traceExitEvent()
	lastExiter := t.exitThreadGroup()

	t.ResetKcov()

	// If the task has a cleartid, and the thread group wasn't killed by a
	// signal, handle that before releasing the MM.
	if t.cleartid != 0 {
		t.tg.signalHandlers.mu.Lock()
		signaled := t.tg.exiting && t.tg.exitStatus.Signaled()
		t.tg.signalHandlers.mu.Unlock()
		if !signaled {
			zero := ThreadID(0)
			if _, err := zero.CopyOut(t, t.cleartid); err == nil {
				t.Futex().Wake(t, t.cleartid, false, ^uint32(0), 1)
			}
			// If the CopyOut fails, there's nothing we can do.
		}
	}

	// Handle the robust futex list.
	t.exitRobustList()

	// Deactivate the address space and update max RSS before releasing the
	// task's MM.
	t.Deactivate()
	t.tg.pidns.owner.mu.Lock()
	t.updateRSSLocked()
	t.tg.pidns.owner.mu.Unlock()
	t.mu.Lock()
	t.image.release()
	t.mu.Unlock()

	// Releasing the MM unblocks a blocked CLONE_VFORK parent.
	t.unstopVforkParent()

	t.fsContext.DecRef(t)
	t.fdTable.DecRef(t)

	t.mu.Lock()
	if t.mountNamespaceVFS2 != nil {
		t.mountNamespaceVFS2.DecRef(t)
		t.mountNamespaceVFS2 = nil
	}
	t.ipcns.DecRef(t)
	t.mu.Unlock()

	// If this is the last task to exit from the thread group, release the
	// thread group's resources.
	if lastExiter {
		t.tg.Release(t)
	}

	// Detach tracees.
	t.exitPtrace()

	// Reparent the task's children.
	t.exitChildren()

	// Don't tail-call runExitNotify, as exitChildren may have initiated a stop
	// to wait for a PID namespace to die.
	return (*runExitNotify)(nil)
}

// exitThreadGroup transitions t to TaskExitInitiated, indicating to t's thread
// group that it is no longer eligible to participate in group activities. It
// returns true if t is the last task in its thread group to call
// exitThreadGroup.
func (t *Task) exitThreadGroup() bool {
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	t.tg.signalHandlers.mu.Lock()
	// Can't defer unlock: see below.

	t.advanceExitStateLocked(TaskExitNone, TaskExitInitiated)
	t.tg.activeTasks--
	last := t.tg.activeTasks == 0

	// Ensure that someone will handle the signals we can't.
	t.setSignalMaskLocked(^linux.SignalSet(0))

	// Check if this task's exit interacts with an initiated group stop.
	if !t.groupStopPending {
		t.tg.signalHandlers.mu.Unlock()
		return last
	}
	t.groupStopPending = false
	sig := t.tg.groupStopSignal
	notifyParent := t.participateGroupStopLocked()
	// signalStop must be called with t's signal mutex unlocked.
	t.tg.signalHandlers.mu.Unlock()
	if notifyParent && t.tg.leader.parent != nil {
		t.tg.leader.parent.signalStop(t, arch.CLD_STOPPED, int32(sig))
		t.tg.leader.parent.tg.eventQueue.Notify(EventChildGroupStop)
	}
	return last
}

func (t *Task) exitChildren() {
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	newParent := t.findReparentTargetLocked()
	if newParent == nil {
		// "If the init process of a PID namespace terminates, the kernel
		// terminates all of the processes in the namespace via a SIGKILL
		// signal." - pid_namespaces(7)
		t.Debugf("Init process terminating, killing namespace")
		t.tg.pidns.exiting = true
		for other := range t.tg.pidns.tgids {
			if other == t.tg {
				continue
			}
			other.signalHandlers.mu.Lock()
			other.leader.sendSignalLocked(&arch.SignalInfo{
				Signo: int32(linux.SIGKILL),
			}, true /* group */)
			other.signalHandlers.mu.Unlock()
		}
		// TODO(b/37722272): The init process waits for all processes in the
		// namespace to exit before completing its own exit
		// (kernel/pid_namespace.c:zap_pid_ns_processes()). Stop until all
		// other tasks in the namespace are dead, except possibly for this
		// thread group's leader (which can't be reaped until this task exits).
	}
	// This is correct even if newParent is nil (it ensures that children don't
	// wait for a parent to reap them.)
	for c := range t.children {
		if sig := c.ParentDeathSignal(); sig != 0 {
			siginfo := &arch.SignalInfo{
				Signo: int32(sig),
				Code:  arch.SignalInfoUser,
			}
			siginfo.SetPID(int32(c.tg.pidns.tids[t]))
			siginfo.SetUID(int32(t.Credentials().RealKUID.In(c.UserNamespace()).OrOverflow()))
			c.tg.signalHandlers.mu.Lock()
			c.sendSignalLocked(siginfo, true /* group */)
			c.tg.signalHandlers.mu.Unlock()
		}
		c.reparentLocked(newParent)
		if newParent != nil {
			newParent.children[c] = struct{}{}
		}
	}
}

// findReparentTargetLocked returns the task to which t's children should be
// reparented. If no such task exists, findNewParentLocked returns nil.
//
// Preconditions: The TaskSet mutex must be locked.
func (t *Task) findReparentTargetLocked() *Task {
	// Reparent to any sibling in the same thread group that hasn't begun
	// exiting.
	if t2 := t.tg.anyNonExitingTaskLocked(); t2 != nil {
		return t2
	}
	// "A child process that is orphaned within the namespace will be
	// reparented to [the init process for the namespace] ..." -
	// pid_namespaces(7)
	if init := t.tg.pidns.tasks[InitTID]; init != nil {
		return init.tg.anyNonExitingTaskLocked()
	}
	return nil
}

func (tg *ThreadGroup) anyNonExitingTaskLocked() *Task {
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		if t.exitState == TaskExitNone {
			return t
		}
	}
	return nil
}

// reparentLocked changes t's parent. The new parent may be nil.
//
// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) reparentLocked(parent *Task) {
	oldParent := t.parent
	t.parent = parent
	if oldParent != nil {
		delete(oldParent.children, t)
	}
	if parent != nil {
		parent.children[t] = struct{}{}
	}
	// If a thread group leader's parent changes, reset the thread group's
	// termination signal to SIGCHLD and re-check exit notification. (Compare
	// kernel/exit.c:reparent_leader().)
	if t != t.tg.leader {
		return
	}
	if oldParent == nil && parent == nil {
		return
	}
	if oldParent != nil && parent != nil && oldParent.tg == parent.tg {
		return
	}
	t.tg.terminationSignal = linux.SIGCHLD
	if t.exitParentNotified && !t.exitParentAcked {
		t.exitParentNotified = false
		t.exitNotifyLocked(false)
	}
}

// When a task exits, other tasks in the system, notably the task's parent and
// ptracer, may want to be notified. The exit notification system ensures that
// interested tasks receive signals and/or are woken from blocking calls to
// wait*() syscalls; these notifications must be resolved before exiting tasks
// can be reaped and disappear from the system.
//
// Each task may have a parent task and/or a tracer task. If both a parent and
// a tracer exist, they may be the same task, different tasks in the same
// thread group, or tasks in different thread groups. (In the last case, Linux
// refers to the task as being ptrace-reparented due to an implementation
// detail; we avoid this terminology to avoid confusion.)
//
// A thread group is *empty* if all non-leader tasks in the thread group are
// dead, and the leader is either a zombie or dead. The exit of a thread group
// leader is never waitable - by either the parent or tracer - until the thread
// group is empty.
//
// There are a few ways for an exit notification to be resolved:
//
// - The exit notification may be acknowledged by a call to Task.Wait with
// WaitOptions.ConsumeEvent set (e.g. due to a wait4() syscall).
//
// - If the notified party is the parent, and the parent thread group is not
// also the tracer thread group, and the notification signal is SIGCHLD, the
// parent may explicitly ignore the notification (see quote in exitNotify).
// Note that it's possible for the notified party to ignore the signal in other
// cases, but the notification is only resolved under the above conditions.
// (Actually, there is one exception; see the last paragraph of the "leader,
// has tracer, tracer thread group is parent thread group" case below.)
//
// - If the notified party is the parent, and the parent does not exist, the
// notification is resolved as if ignored. (This is only possible in the
// sentry. In Linux, the only task / thread group without a parent is global
// init, and killing global init causes a kernel panic.)
//
// - If the notified party is a tracer, the tracer may detach the traced task.
// (Zombie tasks cannot be ptrace-attached, so the reverse is not possible.)
//
// In addition, if the notified party is the parent, the parent may exit and
// cause the notifying task to be reparented to another thread group. This does
// not resolve the notification; instead, the notification must be resent to
// the new parent.
//
// The series of notifications generated for a given task's exit depend on
// whether it is a thread group leader; whether the task is ptraced; and, if
// so, whether the tracer thread group is the same as the parent thread group.
//
// - Non-leader, no tracer: No notification is generated; the task is reaped
// immediately.
//
// - Non-leader, has tracer: SIGCHLD is sent to the tracer. When the tracer
// notification is resolved (by waiting or detaching), the task is reaped. (For
// non-leaders, whether the tracer and parent thread groups are the same is
// irrelevant.)
//
// - Leader, no tracer: The task remains a zombie, with no notification sent,
// until all other tasks in the thread group are dead. (In Linux terms, this
// condition is indicated by include/linux/sched.h:thread_group_empty(); tasks
// are removed from their thread_group list in kernel/exit.c:release_task() =>
// __exit_signal() => __unhash_process().) Then the thread group's termination
// signal is sent to the parent. When the parent notification is resolved (by
// waiting or ignoring), the task is reaped.
//
// - Leader, has tracer, tracer thread group is not parent thread group:
// SIGCHLD is sent to the tracer. When the tracer notification is resolved (by
// waiting or detaching), and all other tasks in the thread group are dead, the
// thread group's termination signal is sent to the parent. (Note that the
// tracer cannot resolve the exit notification by waiting until the thread
// group is empty.) When the parent notification is resolved, the task is
// reaped.
//
// - Leader, has tracer, tracer thread group is parent thread group:
//
// If all other tasks in the thread group are dead, the thread group's
// termination signal is sent to the parent. At this point, the notification
// can only be resolved by waiting. If the parent detaches from the task as a
// tracer, the notification is not resolved, but the notification can now be
// resolved by waiting or ignoring. When the parent notification is resolved,
// the task is reaped.
//
// If at least one task in the thread group is not dead, SIGCHLD is sent to the
// parent. At this point, the notification cannot be resolved at all; once the
// thread group becomes empty, it can be resolved only by waiting. If the
// parent detaches from the task as a tracer before all remaining tasks die,
// then exit notification proceeds as in the case where the leader never had a
// tracer. If the parent detaches from the task as a tracer after all remaining
// tasks die, the notification is not resolved, but the notification can now be
// resolved by waiting or ignoring. When the parent notification is resolved,
// the task is reaped.
//
// In both of the above cases, when the parent detaches from the task as a
// tracer while the thread group is empty, whether or not the parent resolves
// the notification by ignoring it is based on the parent's SIGCHLD signal
// action, whether or not the thread group's termination signal is SIGCHLD
// (Linux: kernel/ptrace.c:__ptrace_detach() => ignoring_children()).
//
// There is one final wrinkle: A leader can become a non-leader due to a
// sibling execve. In this case, the execing thread detaches the leader's
// tracer (if one exists) and reaps the leader immediately. In Linux, this is
// in fs/exec.c:de_thread(); in the sentry, this is in Task.promoteLocked().

// +stateify savable
type runExitNotify struct{}

func (*runExitNotify) execute(t *Task) taskRunState {
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	t.advanceExitStateLocked(TaskExitInitiated, TaskExitZombie)
	t.tg.liveTasks--
	// Check if this completes a sibling's execve.
	if t.tg.execing != nil && t.tg.liveTasks == 1 {
		// execing blocks the addition of new tasks to the thread group, so
		// the sole living task must be the execing one.
		e := t.tg.execing
		e.tg.signalHandlers.mu.Lock()
		if _, ok := e.stop.(*execStop); ok {
			e.endInternalStopLocked()
		}
		e.tg.signalHandlers.mu.Unlock()
	}
	t.exitNotifyLocked(false)
	// The task goroutine will now exit.
	return nil
}

// exitNotifyLocked is called after changes to t's state that affect exit
// notification.
//
// If fromPtraceDetach is true, the caller is ptraceDetach or exitPtrace;
// thanks to Linux's haphazard implementation of this functionality, such cases
// determine whether parent notifications are ignored based on the parent's
// handling of SIGCHLD, regardless of what the exited task's thread group's
// termination signal is.
//
// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) exitNotifyLocked(fromPtraceDetach bool) {
	if t.exitState != TaskExitZombie {
		return
	}
	if !t.exitTracerNotified {
		t.exitTracerNotified = true
		tracer := t.Tracer()
		if tracer == nil {
			t.exitTracerAcked = true
		} else if t != t.tg.leader || t.parent == nil || tracer.tg != t.parent.tg {
			// Don't set exitParentNotified if t is non-leader, even if the
			// tracer is in the parent thread group, so that if the parent
			// detaches the following call to exitNotifyLocked passes through
			// the !exitParentNotified case below and causes t to be reaped
			// immediately.
			//
			// Tracer notification doesn't care about about
			// SIG_IGN/SA_NOCLDWAIT.
			tracer.tg.signalHandlers.mu.Lock()
			tracer.sendSignalLocked(t.exitNotificationSignal(linux.SIGCHLD, tracer), true /* group */)
			tracer.tg.signalHandlers.mu.Unlock()
			// Wake EventTraceeStop waiters as well since this task will never
			// ptrace-stop again.
			tracer.tg.eventQueue.Notify(EventExit | EventTraceeStop)
		} else {
			// t is a leader and the tracer is in the parent thread group.
			t.exitParentNotified = true
			sig := linux.SIGCHLD
			if t.tg.tasksCount == 1 {
				sig = t.tg.terminationSignal
			}
			// This notification doesn't care about SIG_IGN/SA_NOCLDWAIT either
			// (in Linux, the check in do_notify_parent() is gated by
			// !tsk->ptrace.)
			t.parent.tg.signalHandlers.mu.Lock()
			t.parent.sendSignalLocked(t.exitNotificationSignal(sig, t.parent), true /* group */)
			t.parent.tg.signalHandlers.mu.Unlock()
			// See below for rationale for this event mask.
			t.parent.tg.eventQueue.Notify(EventExit | EventChildGroupStop | EventGroupContinue)
		}
	}
	if t.exitTracerAcked && !t.exitParentNotified {
		if t != t.tg.leader {
			t.exitParentNotified = true
			t.exitParentAcked = true
		} else if t.tg.tasksCount == 1 {
			t.exitParentNotified = true
			if t.parent == nil {
				t.exitParentAcked = true
			} else {
				// "POSIX.1-2001 specifies that if the disposition of SIGCHLD is
				// set to SIG_IGN or the SA_NOCLDWAIT flag is set for SIGCHLD (see
				// sigaction(2)), then children that terminate do not become
				// zombies and a call to wait() or waitpid() will block until all
				// children have terminated, and then fail with errno set to
				// ECHILD. (The original POSIX standard left the behavior of
				// setting SIGCHLD to SIG_IGN unspecified. Note that even though
				// the default disposition of SIGCHLD is "ignore", explicitly
				// setting the disposition to SIG_IGN results in different
				// treatment of zombie process children.) Linux 2.6 conforms to
				// this specification." - wait(2)
				//
				// Some undocumented Linux-specific details:
				//
				// - All of the above is ignored if the termination signal isn't
				// SIGCHLD.
				//
				// - SA_NOCLDWAIT causes the leader to be immediately reaped, but
				// does not suppress the SIGCHLD.
				signalParent := t.tg.terminationSignal.IsValid()
				t.parent.tg.signalHandlers.mu.Lock()
				if t.tg.terminationSignal == linux.SIGCHLD || fromPtraceDetach {
					if act, ok := t.parent.tg.signalHandlers.actions[linux.SIGCHLD]; ok {
						if act.Handler == arch.SignalActIgnore {
							t.exitParentAcked = true
							signalParent = false
						} else if act.Flags&arch.SignalFlagNoCldWait != 0 {
							t.exitParentAcked = true
						}
					}
				}
				if signalParent {
					t.parent.tg.leader.sendSignalLocked(t.exitNotificationSignal(t.tg.terminationSignal, t.parent), true /* group */)
				}
				t.parent.tg.signalHandlers.mu.Unlock()
				// If a task in the parent was waiting for a child group stop
				// or continue, it needs to be notified of the exit, because
				// there may be no remaining eligible tasks (so that wait
				// should return ECHILD).
				t.parent.tg.eventQueue.Notify(EventExit | EventChildGroupStop | EventGroupContinue)
			}
		}
	}
	if t.exitTracerAcked && t.exitParentAcked {
		t.advanceExitStateLocked(TaskExitZombie, TaskExitDead)
		for ns := t.tg.pidns; ns != nil; ns = ns.parent {
			tid := ns.tids[t]
			delete(ns.tasks, tid)
			delete(ns.tids, t)
			if t == t.tg.leader {
				delete(ns.tgids, t.tg)
			}
		}
		t.tg.exitedCPUStats.Accumulate(t.CPUStats())
		t.tg.ioUsage.Accumulate(t.ioUsage)
		t.tg.signalHandlers.mu.Lock()
		t.tg.tasks.Remove(t)
		t.tg.tasksCount--
		tc := t.tg.tasksCount
		t.tg.signalHandlers.mu.Unlock()
		if tc == 1 && t != t.tg.leader {
			// Our fromPtraceDetach doesn't matter here (in Linux terms, this
			// is via a call to release_task()).
			t.tg.leader.exitNotifyLocked(false)
		} else if tc == 0 {
			t.tg.processGroup.decRefWithParent(t.tg.parentPG())
		}
		if t.parent != nil {
			delete(t.parent.children, t)
			// Do not clear t.parent. It may be still be needed after the task has exited
			// (for example, to perform ptrace access checks on /proc/[pid] files).
		}
	}
}

// Preconditions: The TaskSet mutex must be locked.
func (t *Task) exitNotificationSignal(sig linux.Signal, receiver *Task) *arch.SignalInfo {
	info := &arch.SignalInfo{
		Signo: int32(sig),
	}
	info.SetPID(int32(receiver.tg.pidns.tids[t]))
	info.SetUID(int32(t.Credentials().RealKUID.In(receiver.UserNamespace()).OrOverflow()))
	if t.exitStatus.Signaled() {
		info.Code = arch.CLD_KILLED
		info.SetStatus(int32(t.exitStatus.Signo))
	} else {
		info.Code = arch.CLD_EXITED
		info.SetStatus(int32(t.exitStatus.Code))
	}
	// TODO(b/72102453): Set utime, stime.
	return info
}

// ExitStatus returns t's exit status, which is only guaranteed to be
// meaningful if t.ExitState() != TaskExitNone.
func (t *Task) ExitStatus() ExitStatus {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	return t.exitStatus
}

// ExitStatus returns the exit status that would be returned by a consuming
// wait*() on tg.
func (tg *ThreadGroup) ExitStatus() ExitStatus {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()
	if tg.exiting {
		return tg.exitStatus
	}
	return tg.leader.exitStatus
}

// TerminationSignal returns the thread group's termination signal.
func (tg *ThreadGroup) TerminationSignal() linux.Signal {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	return tg.terminationSignal
}

// Task events that can be waited for.
const (
	// EventExit represents an exit notification generated for a child thread
	// group leader or a tracee under the conditions specified in the comment
	// above runExitNotify.
	EventExit waiter.EventMask = 1 << iota

	// EventChildGroupStop occurs when a child thread group completes a group
	// stop (i.e. all tasks in the child thread group have entered a stopped
	// state as a result of a group stop).
	EventChildGroupStop

	// EventTraceeStop occurs when a task that is ptraced by a task in the
	// notified thread group enters a ptrace stop (see ptrace(2)).
	EventTraceeStop

	// EventGroupContinue occurs when a child thread group, or a thread group
	// whose leader is ptraced by a task in the notified thread group, that had
	// initiated or completed a group stop leaves the group stop, due to the
	// child thread group or any task in the child thread group being sent
	// SIGCONT.
	EventGroupContinue
)

// WaitOptions controls the behavior of Task.Wait.
type WaitOptions struct {
	// If SpecificTID is non-zero, only events from the task with thread ID
	// SpecificTID are eligible to be waited for. SpecificTID is resolved in
	// the PID namespace of the waiter (the method receiver of Task.Wait). If
	// no such task exists, or that task would not otherwise be eligible to be
	// waited for by the waiting task, then there are no waitable tasks and
	// Wait will return ECHILD.
	SpecificTID ThreadID

	// If SpecificPGID is non-zero, only events from ThreadGroups with a
	// matching ProcessGroupID are eligible to be waited for. (Same
	// constraints as SpecificTID apply.)
	SpecificPGID ProcessGroupID

	// Terminology note: Per waitpid(2), "a clone child is one which delivers
	// no signal, or a signal other than SIGCHLD to its parent upon
	// termination." In Linux, termination signal is technically a per-task
	// property rather than a per-thread-group property. However, clone()
	// forces no termination signal for tasks created with CLONE_THREAD, and
	// execve() resets the termination signal to SIGCHLD, so all
	// non-group-leader threads have no termination signal and are therefore
	// "clone tasks".

	// If NonCloneTasks is true, events from non-clone tasks are eligible to be
	// waited for.
	NonCloneTasks bool

	// If CloneTasks is true, events from clone tasks are eligible to be waited
	// for.
	CloneTasks bool

	// If SiblingChildren is true, events from children tasks of any task
	// in the thread group of the waiter are eligible to be waited for.
	SiblingChildren bool

	// Events is a bitwise combination of the events defined above that specify
	// what events are of interest to the call to Wait.
	Events waiter.EventMask

	// If ConsumeEvent is true, the Wait should consume the event such that it
	// cannot be returned by a future Wait. Note that if a task exit is
	// consumed in this way, in most cases the task will be reaped.
	ConsumeEvent bool

	// If BlockInterruptErr is not nil, Wait will block until either an event
	// is available or there are no tasks that could produce a waitable event;
	// if that blocking is interrupted, Wait returns BlockInterruptErr. If
	// BlockInterruptErr is nil, Wait will not block.
	BlockInterruptErr error
}

// Preconditions: The TaskSet mutex must be locked (for reading or writing).
func (o *WaitOptions) matchesTask(t *Task, pidns *PIDNamespace, tracee bool) bool {
	if o.SpecificTID != 0 && o.SpecificTID != pidns.tids[t] {
		return false
	}
	if o.SpecificPGID != 0 && o.SpecificPGID != pidns.pgids[t.tg.processGroup] {
		return false
	}
	// Tracees are always eligible.
	if tracee {
		return true
	}
	if t == t.tg.leader && t.tg.terminationSignal == linux.SIGCHLD {
		return o.NonCloneTasks
	}
	return o.CloneTasks
}

// ErrNoWaitableEvent is returned by non-blocking Task.Waits (e.g.
// waitpid(WNOHANG)) that find no waitable events, but determine that waitable
// events may exist in the future. (In contrast, if a non-blocking or blocking
// Wait determines that there are no tasks that can produce a waitable event,
// Task.Wait returns ECHILD.)
var ErrNoWaitableEvent = errors.New("non-blocking Wait found eligible threads but no waitable events")

// WaitResult contains information about a waited-for event.
type WaitResult struct {
	// Task is the task that reported the event.
	Task *Task

	// TID is the thread ID of Task in the PID namespace of the task that
	// called Wait (that is, the method receiver of the call to Task.Wait). TID
	// is provided because consuming exit waits cause the thread ID to be
	// deallocated.
	TID ThreadID

	// UID is the real UID of Task in the user namespace of the task that
	// called Wait.
	UID auth.UID

	// Event is exactly one of the events defined above.
	Event waiter.EventMask

	// Status is the numeric status associated with the event.
	Status uint32
}

// Wait waits for an event from a thread group that is a child of t's thread
// group, or a task in such a thread group, or a task that is ptraced by t,
// subject to the options specified in opts.
func (t *Task) Wait(opts *WaitOptions) (*WaitResult, error) {
	if opts.BlockInterruptErr == nil {
		return t.waitOnce(opts)
	}
	w, ch := waiter.NewChannelEntry(nil)
	t.tg.eventQueue.EventRegister(&w, opts.Events)
	defer t.tg.eventQueue.EventUnregister(&w)
	for {
		wr, err := t.waitOnce(opts)
		if err != ErrNoWaitableEvent {
			// This includes err == nil.
			return wr, err
		}
		if err := t.Block(ch); err != nil {
			return wr, syserror.ConvertIntr(err, opts.BlockInterruptErr)
		}
	}
}

func (t *Task) waitOnce(opts *WaitOptions) (*WaitResult, error) {
	anyWaitableTasks := false

	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()

	if opts.SiblingChildren {
		// We can wait on the children and tracees of any task in the
		// same thread group.
		for parent := t.tg.tasks.Front(); parent != nil; parent = parent.Next() {
			wr, any := t.waitParentLocked(opts, parent)
			if wr != nil {
				return wr, nil
			}
			anyWaitableTasks = anyWaitableTasks || any
		}
	} else {
		// We can only wait on this task.
		var wr *WaitResult
		wr, anyWaitableTasks = t.waitParentLocked(opts, t)
		if wr != nil {
			return wr, nil
		}
	}

	if anyWaitableTasks {
		return nil, ErrNoWaitableEvent
	}
	return nil, syserror.ECHILD
}

// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) waitParentLocked(opts *WaitOptions, parent *Task) (*WaitResult, bool) {
	anyWaitableTasks := false

	for child := range parent.children {
		if !opts.matchesTask(child, parent.tg.pidns, false) {
			continue
		}
		// Non-leaders don't notify parents on exit and aren't eligible to
		// be waited on.
		if opts.Events&EventExit != 0 && child == child.tg.leader && !child.exitParentAcked {
			anyWaitableTasks = true
			if wr := t.waitCollectZombieLocked(child, opts, false); wr != nil {
				return wr, anyWaitableTasks
			}
		}
		// Check for group stops and continues. Tasks that have passed
		// TaskExitInitiated can no longer participate in group stops.
		if opts.Events&(EventChildGroupStop|EventGroupContinue) == 0 {
			continue
		}
		if child.exitState >= TaskExitInitiated {
			continue
		}
		// If the waiter is in the same thread group as the task's
		// tracer, do not report its group stops; they will be reported
		// as ptrace stops instead. This also skips checking for group
		// continues, but they'll be checked for when scanning tracees
		// below. (Per kernel/exit.c:wait_consider_task(): "If a
		// ptracer wants to distinguish the two events for its own
		// children, it should create a separate process which takes
		// the role of real parent.")
		if tracer := child.Tracer(); tracer != nil && tracer.tg == parent.tg {
			continue
		}
		anyWaitableTasks = true
		if opts.Events&EventChildGroupStop != 0 {
			if wr := t.waitCollectChildGroupStopLocked(child, opts); wr != nil {
				return wr, anyWaitableTasks
			}
		}
		if opts.Events&EventGroupContinue != 0 {
			if wr := t.waitCollectGroupContinueLocked(child, opts); wr != nil {
				return wr, anyWaitableTasks
			}
		}
	}
	for tracee := range parent.ptraceTracees {
		if !opts.matchesTask(tracee, parent.tg.pidns, true) {
			continue
		}
		// Non-leaders do notify tracers on exit.
		if opts.Events&EventExit != 0 && !tracee.exitTracerAcked {
			anyWaitableTasks = true
			if wr := t.waitCollectZombieLocked(tracee, opts, true); wr != nil {
				return wr, anyWaitableTasks
			}
		}
		if opts.Events&(EventTraceeStop|EventGroupContinue) == 0 {
			continue
		}
		if tracee.exitState >= TaskExitInitiated {
			continue
		}
		anyWaitableTasks = true
		if opts.Events&EventTraceeStop != 0 {
			if wr := t.waitCollectTraceeStopLocked(tracee, opts); wr != nil {
				return wr, anyWaitableTasks
			}
		}
		if opts.Events&EventGroupContinue != 0 {
			if wr := t.waitCollectGroupContinueLocked(tracee, opts); wr != nil {
				return wr, anyWaitableTasks
			}
		}
	}

	return nil, anyWaitableTasks
}

// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) waitCollectZombieLocked(target *Task, opts *WaitOptions, asPtracer bool) *WaitResult {
	if asPtracer && !target.exitTracerNotified {
		return nil
	}
	if !asPtracer && !target.exitParentNotified {
		return nil
	}
	// Zombied thread group leaders are never waitable until their thread group
	// is otherwise empty. Usually this is caught by the
	// target.exitParentNotified check above, but if t is both (in the thread
	// group of) target's tracer and parent, asPtracer may be true.
	if target == target.tg.leader && target.tg.tasksCount != 1 {
		return nil
	}
	pid := t.tg.pidns.tids[target]
	uid := target.Credentials().RealKUID.In(t.UserNamespace()).OrOverflow()
	status := target.exitStatus.Status()
	if !opts.ConsumeEvent {
		return &WaitResult{
			Task:   target,
			TID:    pid,
			UID:    uid,
			Event:  EventExit,
			Status: status,
		}
	}
	// Surprisingly, the exit status reported by a non-consuming wait can
	// differ from that reported by a consuming wait; the latter will return
	// the group exit code if one is available.
	if target.tg.exiting {
		status = target.tg.exitStatus.Status()
	}
	// t may be (in the thread group of) target's parent, tracer, or both. We
	// don't need to check for !exitTracerAcked because tracees are detached
	// here, and we don't need to check for !exitParentAcked because zombies
	// will be reaped here.
	if tracer := target.Tracer(); tracer != nil && tracer.tg == t.tg && target.exitTracerNotified {
		target.exitTracerAcked = true
		target.ptraceTracer.Store((*Task)(nil))
		delete(t.ptraceTracees, target)
	}
	if target.parent != nil && target.parent.tg == t.tg && target.exitParentNotified {
		target.exitParentAcked = true
		if target == target.tg.leader {
			// target.tg.exitedCPUStats doesn't include target.CPUStats() yet,
			// and won't until after target.exitNotifyLocked() (maybe). Include
			// target.CPUStats() explicitly. This is consistent with Linux,
			// which accounts an exited task's cputime to its thread group in
			// kernel/exit.c:release_task() => __exit_signal(), and uses
			// thread_group_cputime_adjusted() in wait_task_zombie().
			t.tg.childCPUStats.Accumulate(target.CPUStats())
			t.tg.childCPUStats.Accumulate(target.tg.exitedCPUStats)
			t.tg.childCPUStats.Accumulate(target.tg.childCPUStats)
			// Update t's child max resident set size. The size will be the maximum
			// of this thread's size and all its childrens' sizes.
			if t.tg.childMaxRSS < target.tg.maxRSS {
				t.tg.childMaxRSS = target.tg.maxRSS
			}
			if t.tg.childMaxRSS < target.tg.childMaxRSS {
				t.tg.childMaxRSS = target.tg.childMaxRSS
			}
		}
	}
	target.exitNotifyLocked(false)
	return &WaitResult{
		Task:   target,
		TID:    pid,
		UID:    uid,
		Event:  EventExit,
		Status: status,
	}
}

// updateRSSLocked updates t.tg.maxRSS.
//
// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) updateRSSLocked() {
	if mmMaxRSS := t.MemoryManager().MaxResidentSetSize(); t.tg.maxRSS < mmMaxRSS {
		t.tg.maxRSS = mmMaxRSS
	}
}

// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) waitCollectChildGroupStopLocked(target *Task, opts *WaitOptions) *WaitResult {
	target.tg.signalHandlers.mu.Lock()
	defer target.tg.signalHandlers.mu.Unlock()
	if !target.tg.groupStopWaitable {
		return nil
	}
	pid := t.tg.pidns.tids[target]
	uid := target.Credentials().RealKUID.In(t.UserNamespace()).OrOverflow()
	sig := target.tg.groupStopSignal
	if opts.ConsumeEvent {
		target.tg.groupStopWaitable = false
	}
	return &WaitResult{
		Task:  target,
		TID:   pid,
		UID:   uid,
		Event: EventChildGroupStop,
		// There is no name for these status constants.
		Status: (uint32(sig)&0xff)<<8 | 0x7f,
	}
}

// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) waitCollectGroupContinueLocked(target *Task, opts *WaitOptions) *WaitResult {
	target.tg.signalHandlers.mu.Lock()
	defer target.tg.signalHandlers.mu.Unlock()
	if !target.tg.groupContWaitable {
		return nil
	}
	pid := t.tg.pidns.tids[target]
	uid := target.Credentials().RealKUID.In(t.UserNamespace()).OrOverflow()
	if opts.ConsumeEvent {
		target.tg.groupContWaitable = false
	}
	return &WaitResult{
		Task:   target,
		TID:    pid,
		UID:    uid,
		Event:  EventGroupContinue,
		Status: 0xffff,
	}
}

// Preconditions: The TaskSet mutex must be locked for writing.
func (t *Task) waitCollectTraceeStopLocked(target *Task, opts *WaitOptions) *WaitResult {
	target.tg.signalHandlers.mu.Lock()
	defer target.tg.signalHandlers.mu.Unlock()
	if target.stop == nil {
		return nil
	}
	if _, ok := target.stop.(*ptraceStop); !ok {
		return nil
	}
	if target.ptraceCode == 0 {
		return nil
	}
	pid := t.tg.pidns.tids[target]
	uid := target.Credentials().RealKUID.In(t.UserNamespace()).OrOverflow()
	code := target.ptraceCode
	if opts.ConsumeEvent {
		target.ptraceCode = 0
	}
	return &WaitResult{
		Task:   target,
		TID:    pid,
		UID:    uid,
		Event:  EventTraceeStop,
		Status: uint32(code)<<8 | 0x7f,
	}
}

// ExitState returns t's current progress through the exit path.
func (t *Task) ExitState() TaskExitState {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()
	return t.exitState
}

// ParentDeathSignal returns t's parent death signal.
func (t *Task) ParentDeathSignal() linux.Signal {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.parentDeathSignal
}

// SetParentDeathSignal sets t's parent death signal.
func (t *Task) SetParentDeathSignal(sig linux.Signal) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.parentDeathSignal = sig
}
