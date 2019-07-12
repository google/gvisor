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

// This file implements the machinery behind the execve() syscall. In brief, a
// thread executes an execve() by killing all other threads in its thread
// group, assuming the leader's identity, and then switching process images.
//
// This design is effectively mandated by Linux. From ptrace(2):
//
// """
// execve(2) under ptrace
//     When one thread in a multithreaded process calls execve(2), the
//     kernel destroys all other threads in the process, and resets the
//     thread ID of the execing thread to the thread group ID (process ID).
//     (Or, to put things another way, when a multithreaded process does an
//     execve(2), at completion of the call, it appears as though the
//     execve(2) occurred in the thread group leader, regardless of which
//     thread did the execve(2).)  This resetting of the thread ID looks
//     very confusing to tracers:
//
//     *  All other threads stop in PTRACE_EVENT_EXIT stop, if the
//        PTRACE_O_TRACEEXIT option was turned on.  Then all other threads
//        except the thread group leader report death as if they exited via
//        _exit(2) with exit code 0.
//
//     *  The execing tracee changes its thread ID while it is in the
//        execve(2).  (Remember, under ptrace, the "pid" returned from
//        waitpid(2), or fed into ptrace calls, is the tracee's thread ID.)
//        That is, the tracee's thread ID is reset to be the same as its
//        process ID, which is the same as the thread group leader's thread
//        ID.
//
//     *  Then a PTRACE_EVENT_EXEC stop happens, if the PTRACE_O_TRACEEXEC
//        option was turned on.
//
//     *  If the thread group leader has reported its PTRACE_EVENT_EXIT stop
//        by this time, it appears to the tracer that the dead thread leader
//        "reappears from nowhere".  (Note: the thread group leader does not
//        report death via WIFEXITED(status) until there is at least one
//        other live thread.  This eliminates the possibility that the
//        tracer will see it dying and then reappearing.)  If the thread
//        group leader was still alive, for the tracer this may look as if
//        thread group leader returns from a different system call than it
//        entered, or even "returned from a system call even though it was
//        not in any system call".  If the thread group leader was not
//        traced (or was traced by a different tracer), then during
//        execve(2) it will appear as if it has become a tracee of the
//        tracer of the execing tracee.
//
//     All of the above effects are the artifacts of the thread ID change in
//     the tracee.
// """

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/syserror"
)

// execStop is a TaskStop that a task sets on itself when it wants to execve
// and is waiting for the other tasks in its thread group to exit first.
//
// +stateify savable
type execStop struct{}

// Killable implements TaskStop.Killable.
func (*execStop) Killable() bool { return true }

// Execve implements the execve(2) syscall by killing all other tasks in its
// thread group and switching to newTC. Execve always takes ownership of newTC.
//
// Preconditions: The caller must be running Task.doSyscallInvoke on the task
// goroutine.
func (t *Task) Execve(newTC *TaskContext) (*SyscallControl, error) {
	t.tg.pidns.owner.mu.Lock()
	defer t.tg.pidns.owner.mu.Unlock()
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()

	if t.tg.exiting || t.tg.execing != nil {
		// We lost to a racing group-exit, kill, or exec from another thread
		// and should just exit.
		newTC.release()
		return nil, syserror.EINTR
	}

	// Cancel any racing group stops.
	t.tg.endGroupStopLocked(false)

	// If the task has any siblings, they have to exit before the exec can
	// continue.
	t.tg.execing = t
	if t.tg.tasks.Front() != t.tg.tasks.Back() {
		// "[All] other threads except the thread group leader report death as
		// if they exited via _exit(2) with exit code 0." - ptrace(2)
		for sibling := t.tg.tasks.Front(); sibling != nil; sibling = sibling.Next() {
			if t != sibling {
				sibling.killLocked()
			}
		}
		// The last sibling to exit will wake t.
		t.beginInternalStopLocked((*execStop)(nil))
	}

	return &SyscallControl{next: &runSyscallAfterExecStop{newTC}, ignoreReturn: true}, nil
}

// The runSyscallAfterExecStop state continues execve(2) after all siblings of
// a thread in the execve syscall have exited.
//
// +stateify savable
type runSyscallAfterExecStop struct {
	tc *TaskContext
}

func (r *runSyscallAfterExecStop) execute(t *Task) taskRunState {
	t.tg.pidns.owner.mu.Lock()
	t.tg.execing = nil
	if t.killed() {
		t.tg.pidns.owner.mu.Unlock()
		r.tc.release()
		return (*runInterrupt)(nil)
	}
	// We are the thread group leader now. Save our old thread ID for
	// PTRACE_EVENT_EXEC. This is racy in that if a tracer attaches after this
	// point it will get a PID of 0, but this is consistent with Linux.
	oldTID := ThreadID(0)
	if tracer := t.Tracer(); tracer != nil {
		oldTID = tracer.tg.pidns.tids[t]
	}
	t.promoteLocked()
	// "POSIX timers are not preserved (timer_create(2))." - execve(2). Handle
	// this first since POSIX timers are protected by the signal mutex, which
	// we're about to change. Note that we have to stop and destroy timers
	// without holding any mutexes to avoid circular lock ordering.
	var its []*IntervalTimer
	t.tg.signalHandlers.mu.Lock()
	for _, it := range t.tg.timers {
		its = append(its, it)
	}
	t.tg.timers = make(map[linux.TimerID]*IntervalTimer)
	t.tg.signalHandlers.mu.Unlock()
	t.tg.pidns.owner.mu.Unlock()
	for _, it := range its {
		it.DestroyTimer()
	}
	t.tg.pidns.owner.mu.Lock()
	// "During an execve(2), the dispositions of handled signals are reset to
	// the default; the dispositions of ignored signals are left unchanged. ...
	// [The] signal mask is preserved across execve(2). ... [The] pending
	// signal set is preserved across an execve(2)." - signal(7)
	//
	// Details:
	//
	// - If the thread group is sharing its signal handlers with another thread
	// group via CLONE_SIGHAND, execve forces the signal handlers to be copied
	// (see Linux's fs/exec.c:de_thread). We're not reference-counting signal
	// handlers, so we always make a copy.
	//
	// - "Disposition" only means sigaction::sa_handler/sa_sigaction; flags,
	// restorer (if present), and mask are always reset. (See Linux's
	// fs/exec.c:setup_new_exec => kernel/signal.c:flush_signal_handlers.)
	t.tg.signalHandlers = t.tg.signalHandlers.CopyForExec()
	t.endStopCond.L = &t.tg.signalHandlers.mu
	// "Any alternate signal stack is not preserved (sigaltstack(2))." - execve(2)
	t.signalStack = arch.SignalStack{Flags: arch.SignalStackFlagDisable}
	// "The termination signal is reset to SIGCHLD (see clone(2))."
	t.tg.terminationSignal = linux.SIGCHLD
	// execed indicates that the process can no longer join a process group
	// in some scenarios (namely, the parent call setpgid(2) on the child).
	// See the JoinProcessGroup function in sessions.go for more context.
	t.tg.execed = true
	// Maximum RSS is preserved across execve(2).
	t.updateRSSLocked()
	// Restartable sequence state is discarded.
	t.rseqPreempted = false
	t.rseqCPUAddr = 0
	t.rseqCPU = -1
	t.tg.rscr.Store(&RSEQCriticalRegion{})
	t.tg.pidns.owner.mu.Unlock()

	// Remove FDs with the CloseOnExec flag set.
	t.fdTable.RemoveIf(func(file *fs.File, flags FDFlags) bool {
		return flags.CloseOnExec
	})

	// NOTE(b/30815691): We currently do not implement privileged
	// executables (set-user/group-ID bits and file capabilities). This
	// allows us to unconditionally enable user dumpability on the new mm.
	// See fs/exec.c:setup_new_exec.
	r.tc.MemoryManager.SetDumpability(mm.UserDumpable)

	// Switch to the new process.
	t.MemoryManager().Deactivate()
	t.mu.Lock()
	// Update credentials to reflect the execve. This should precede switching
	// MMs to ensure that dumpability has been reset first, if needed.
	t.updateCredsForExecLocked()
	t.tc.release()
	t.tc = *r.tc
	t.mu.Unlock()
	t.unstopVforkParent()
	// NOTE(b/30316266): All locks must be dropped prior to calling Activate.
	t.MemoryManager().Activate()

	t.ptraceExec(oldTID)
	return (*runSyscallExit)(nil)
}

// promoteLocked makes t the leader of its thread group. If t is already the
// thread group leader, promoteLocked is a no-op.
//
// Preconditions: All other tasks in t's thread group, including the existing
// leader (if it is not t), have reached TaskExitZombie. The TaskSet mutex must
// be locked for writing.
func (t *Task) promoteLocked() {
	oldLeader := t.tg.leader
	if t == oldLeader {
		return
	}
	// Swap the leader's TIDs with the execing task's. The latter will be
	// released when the old leader is reaped below.
	for ns := t.tg.pidns; ns != nil; ns = ns.parent {
		oldTID, leaderTID := ns.tids[t], ns.tids[oldLeader]
		ns.tids[oldLeader] = oldTID
		ns.tids[t] = leaderTID
		ns.tasks[oldTID] = oldLeader
		ns.tasks[leaderTID] = t
		// Neither the ThreadGroup nor TGID change, so no need to
		// update ns.tgids.
	}

	// Inherit the old leader's start time.
	oldStartTime := oldLeader.StartTime()
	t.mu.Lock()
	t.startTime = oldStartTime
	t.mu.Unlock()

	t.tg.leader = t
	t.Infof("Becoming TID %d (in root PID namespace)", t.tg.pidns.owner.Root.tids[t])
	t.updateLogPrefixLocked()
	// Reap the original leader. If it has a tracer, detach it instead of
	// waiting for it to acknowledge the original leader's death.
	oldLeader.exitParentNotified = true
	oldLeader.exitParentAcked = true
	if tracer := oldLeader.Tracer(); tracer != nil {
		delete(tracer.ptraceTracees, oldLeader)
		oldLeader.forgetTracerLocked()
		// Notify the tracer that it will no longer be receiving these events
		// from the tracee.
		tracer.tg.eventQueue.Notify(EventExit | EventTraceeStop | EventGroupContinue)
	}
	oldLeader.exitNotifyLocked(false)
}
