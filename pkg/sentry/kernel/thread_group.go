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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
)

// A ThreadGroup is a logical grouping of tasks that has widespread
// significance to other kernel features (e.g. signal handling). ("Thread
// groups" are usually called "processes" in userspace documentation.)
//
// ThreadGroup is a superset of Linux's struct signal_struct.
//
// +stateify savable
type ThreadGroup struct {
	threadGroupNode

	// signalHandlers is the set of signal handlers used by every task in this
	// thread group. (signalHandlers may also be shared with other thread
	// groups.)
	//
	// signalHandlers.mu (hereafter "the signal mutex") protects state related
	// to signal handling, as well as state that usually needs to be atomic
	// with signal handling, for all ThreadGroups and Tasks using
	// signalHandlers. (This is analogous to Linux's use of struct
	// sighand_struct::siglock.)
	//
	// The signalHandlers pointer can only be mutated during an execve
	// (Task.finishExec). Consequently, when it's possible for a task in the
	// thread group to be completing an execve, signalHandlers is protected by
	// the owning TaskSet.mu. Otherwise, it is possible to read the
	// signalHandlers pointer without synchronization. In particular,
	// completing an execve requires that all other tasks in the thread group
	// have exited, so task goroutines do not need the owning TaskSet.mu to
	// read the signalHandlers pointer of their thread groups.
	signalHandlers *SignalHandlers

	// pendingSignals is the set of pending signals that may be handled by any
	// task in this thread group.
	//
	// pendingSignals is protected by the signal mutex.
	pendingSignals pendingSignals

	// If groupStopDequeued is true, a task in the thread group has dequeued a
	// stop signal, but has not yet initiated the group stop.
	//
	// groupStopDequeued is analogous to Linux's JOBCTL_STOP_DEQUEUED.
	//
	// groupStopDequeued is protected by the signal mutex.
	groupStopDequeued bool

	// groupStopSignal is the signal that caused a group stop to be initiated.
	//
	// groupStopSignal is protected by the signal mutex.
	groupStopSignal linux.Signal

	// groupStopPendingCount is the number of active tasks in the thread group
	// for which Task.groupStopPending is set.
	//
	// groupStopPendingCount is analogous to Linux's
	// signal_struct::group_stop_count.
	//
	// groupStopPendingCount is protected by the signal mutex.
	groupStopPendingCount int

	// If groupStopComplete is true, groupStopPendingCount transitioned from
	// non-zero to zero without an intervening SIGCONT.
	//
	// groupStopComplete is analogous to Linux's SIGNAL_STOP_STOPPED.
	//
	// groupStopComplete is protected by the signal mutex.
	groupStopComplete bool

	// If groupStopWaitable is true, the thread group is indicating a waitable
	// group stop event (as defined by EventChildGroupStop).
	//
	// Linux represents the analogous state as SIGNAL_STOP_STOPPED being set
	// and group_exit_code being non-zero.
	//
	// groupStopWaitable is protected by the signal mutex.
	groupStopWaitable bool

	// If groupContNotify is true, then a SIGCONT has recently ended a group
	// stop on this thread group, and the first task to observe it should
	// notify its parent. groupContInterrupted is true iff SIGCONT ended an
	// incomplete group stop. If groupContNotify is false, groupContInterrupted is
	// meaningless.
	//
	// Analogues in Linux:
	//
	//	- groupContNotify && groupContInterrupted is represented by
	//		SIGNAL_CLD_STOPPED.
	//
	//	- groupContNotify && !groupContInterrupted is represented by
	//		SIGNAL_CLD_CONTINUED.
	//
	//	- !groupContNotify is represented by neither flag being set.
	//
	// groupContNotify and groupContInterrupted are protected by the signal
	// mutex.
	groupContNotify      bool
	groupContInterrupted bool

	// If groupContWaitable is true, the thread group is indicating a waitable
	// continue event (as defined by EventGroupContinue).
	//
	// groupContWaitable is analogous to Linux's SIGNAL_STOP_CONTINUED.
	//
	// groupContWaitable is protected by the signal mutex.
	groupContWaitable bool

	// exiting is true if all tasks in the ThreadGroup should exit. exiting is
	// analogous to Linux's SIGNAL_GROUP_EXIT.
	//
	// exiting is protected by the signal mutex. exiting can only transition
	// from false to true.
	exiting bool

	// exitStatus is the thread group's exit status.
	//
	// While exiting is false, exitStatus is protected by the signal mutex.
	// When exiting becomes true, exitStatus becomes immutable.
	exitStatus linux.WaitStatus

	// terminationSignal is the signal that this thread group's leader will
	// send to its parent when it exits.
	//
	// terminationSignal is protected by the TaskSet mutex.
	terminationSignal linux.Signal

	// liveGoroutines is the number of non-exited task goroutines in the thread
	// group.
	//
	// liveGoroutines is not saved; it is reset as task goroutines are
	// restarted by Task.Start.
	liveGoroutines sync.WaitGroup `state:"nosave"`

	timerMu threadGroupTimerMutex `state:"nosave"`

	// itimerRealTimer implements ITIMER_REAL for the thread group.
	itimerRealTimer *ktime.Timer

	// itimerVirtSetting is the ITIMER_VIRTUAL setting for the thread group.
	//
	// itimerVirtSetting is protected by the signal mutex.
	itimerVirtSetting ktime.Setting

	// itimerProfSetting is the ITIMER_PROF setting for the thread group.
	//
	// itimerProfSetting is protected by the signal mutex.
	itimerProfSetting ktime.Setting

	// rlimitCPUSoftSetting is the setting for RLIMIT_CPU soft limit
	// notifications for the thread group.
	//
	// rlimitCPUSoftSetting is protected by the signal mutex.
	rlimitCPUSoftSetting ktime.Setting

	// cpuTimersEnabled is non-zero if itimerVirtSetting.Enabled is true,
	// itimerProfSetting.Enabled is true, rlimitCPUSoftSetting.Enabled is true,
	// or limits.Get(CPU) is finite.
	//
	// cpuTimersEnabled is protected by the signal mutex.
	cpuTimersEnabled atomicbitops.Uint32

	// timers is the thread group's POSIX interval timers. nextTimerID is the
	// TimerID at which allocation should begin searching for an unused ID.
	//
	// timers and nextTimerID are protected by timerMu.
	timers      map[linux.TimerID]*IntervalTimer
	nextTimerID linux.TimerID

	// exitedCPUStats is the CPU usage for all exited tasks in the thread
	// group. exitedCPUStats is protected by the TaskSet mutex.
	exitedCPUStats usage.CPUStats

	// childCPUStats is the CPU usage of all joined descendants of this thread
	// group. childCPUStats is protected by the TaskSet mutex.
	childCPUStats usage.CPUStats

	// ioUsage is the I/O usage for all exited tasks in the thread group.
	// The ioUsage pointer is immutable.
	ioUsage *usage.IO

	// maxRSS is the historical maximum resident set size of the thread group, updated when:
	//
	//	- A task in the thread group exits, since after all tasks have
	//		exited the MemoryManager is no longer reachable.
	//
	//	- The thread group completes an execve, since this changes
	//		MemoryManagers.
	//
	// maxRSS is protected by the TaskSet mutex.
	maxRSS uint64

	// childMaxRSS is the maximum resident set size in bytes of all joined
	// descendants of this thread group.
	//
	// childMaxRSS is protected by the TaskSet mutex.
	childMaxRSS uint64

	// Resource limits for this ThreadGroup. The limits pointer is immutable.
	limits *limits.LimitSet

	// processGroup is the processGroup for this thread group.
	//
	// processGroup is protected by the TaskSet mutex.
	processGroup *ProcessGroup

	// execed indicates an exec has occurred since creation. This will be
	// set by finishExec, and new TheadGroups will have this field cleared.
	// When execed is set, the processGroup may no longer be changed.
	//
	// execed is protected by the TaskSet mutex.
	execed bool

	// oldRSeqCritical is the thread group's old rseq critical region.
	oldRSeqCritical atomic.Value `state:".(*OldRSeqCriticalRegion)"`

	// tty is the thread group's controlling terminal. If nil, there is no
	// controlling terminal.
	//
	// tty is protected by the signal mutex.
	tty *TTY

	// oomScoreAdj is the thread group's OOM score adjustment. This is
	// currently not used but is maintained for consistency.
	// TODO(gvisor.dev/issue/1967)
	oomScoreAdj atomicbitops.Int32

	// isChildSubreaper and hasChildSubreaper correspond to Linux's
	// signal_struct::is_child_subreaper and has_child_subreaper.
	//
	// Both fields are protected by the TaskSet mutex.
	//
	// Quoting from signal.h:
	// "PR_SET_CHILD_SUBREAPER marks a process, like a service manager, to
	// re-parent orphan (double-forking) child processes to this process
	// instead of 'init'. The service manager is able to receive SIGCHLD
	// signals and is able to investigate the process until it calls
	// wait(). All children of this process will inherit a flag if they
	// should look for a child_subreaper process at exit"
	isChildSubreaper  bool
	hasChildSubreaper bool
}

// NewThreadGroup returns a new, empty thread group in PID namespace pidns. The
// thread group leader will send its parent terminationSignal when it exits.
// The new thread group isn't visible to the system until a task has been
// created inside of it by a successful call to TaskSet.NewTask.
func (k *Kernel) NewThreadGroup(pidns *PIDNamespace, sh *SignalHandlers, terminationSignal linux.Signal, limits *limits.LimitSet) *ThreadGroup {
	tg := &ThreadGroup{
		threadGroupNode: threadGroupNode{
			pidns: pidns,
		},
		signalHandlers:    sh,
		terminationSignal: terminationSignal,
		ioUsage:           &usage.IO{},
		limits:            limits,
	}
	tg.itimerRealTimer = ktime.NewTimer(k.timekeeper.monotonicClock, &itimerRealListener{tg: tg})
	tg.timers = make(map[linux.TimerID]*IntervalTimer)
	tg.oldRSeqCritical.Store(&OldRSeqCriticalRegion{})
	return tg
}

// saveOldRSeqCritical is invoked by stateify.
func (tg *ThreadGroup) saveOldRSeqCritical() *OldRSeqCriticalRegion {
	return tg.oldRSeqCritical.Load().(*OldRSeqCriticalRegion)
}

// loadOldRSeqCritical is invoked by stateify.
func (tg *ThreadGroup) loadOldRSeqCritical(r *OldRSeqCriticalRegion) {
	tg.oldRSeqCritical.Store(r)
}

// SignalHandlers returns the signal handlers used by tg.
//
// Preconditions: The caller must provide the synchronization required to read
// tg.signalHandlers, as described in the field's comment.
func (tg *ThreadGroup) SignalHandlers() *SignalHandlers {
	return tg.signalHandlers
}

// Limits returns tg's limits.
func (tg *ThreadGroup) Limits() *limits.LimitSet {
	return tg.limits
}

// Release releases the thread group's resources.
func (tg *ThreadGroup) Release(ctx context.Context) {
	// Timers must be destroyed without holding the TaskSet or signal mutexes
	// since timers send signals with Timer.mu locked.
	tg.itimerRealTimer.Destroy()
	var its []*IntervalTimer
	tg.pidns.owner.mu.Lock()
	tg.signalHandlers.mu.Lock()
	for _, it := range tg.timers {
		its = append(its, it)
	}
	tg.timers = make(map[linux.TimerID]*IntervalTimer) // nil maps can't be saved
	tg.signalHandlers.mu.Unlock()
	tg.pidns.owner.mu.Unlock()
	for _, it := range its {
		it.DestroyTimer()
	}
}

// forEachChildThreadGroupLocked indicates over all child ThreadGroups.
//
// Precondition: TaskSet.mu must be held.
func (tg *ThreadGroup) forEachChildThreadGroupLocked(fn func(*ThreadGroup)) {
	tg.walkDescendantThreadGroupsLocked(func(child *ThreadGroup) bool {
		fn(child)
		// Don't recurse below the immediate children.
		return false
	})
}

// walkDescendantThreadGroupsLocked recursively walks all descendent
// ThreadGroups and executes the visitor function. If visitor returns false for
// a given ThreadGroup, then that ThreadGroups descendants are excluded from
// further iteration.
//
// This corresponds to Linux's walk_process_tree.
//
// Precondition: TaskSet.mu must be held.
func (tg *ThreadGroup) walkDescendantThreadGroupsLocked(visitor func(*ThreadGroup) bool) {
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		for child := range t.children {
			if child == child.tg.leader {
				if !visitor(child.tg) {
					// Don't recurse below child.
					continue
				}
				child.tg.walkDescendantThreadGroupsLocked(visitor)
			}
		}
	}
}

// SetControllingTTY sets tty as the controlling terminal of tg.
func (tg *ThreadGroup) SetControllingTTY(tty *TTY, steal bool, isReadable bool) error {
	tty.mu.Lock()
	defer tty.mu.Unlock()

	// We might be asked to set the controlling terminal of multiple
	// processes, so we lock both the TaskSet and SignalHandlers.
	tg.pidns.owner.mu.Lock()
	defer tg.pidns.owner.mu.Unlock()
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()

	// "The calling process must be a session leader and not have a
	// controlling terminal already." - tty_ioctl(4)
	if tg.processGroup.session.leader != tg || tg.tty != nil {
		return linuxerr.EINVAL
	}

	creds := auth.CredentialsFromContext(tg.leader)
	hasAdmin := creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, creds.UserNamespace.Root())

	// "If this terminal is already the controlling terminal of a different
	// session group, then the ioctl fails with EPERM, unless the caller
	// has the CAP_SYS_ADMIN capability and arg equals 1, in which case the
	// terminal is stolen, and all processes that had it as controlling
	// terminal lose it." - tty_ioctl(4)
	if tty.tg != nil && tg.processGroup.session != tty.tg.processGroup.session {
		// Stealing requires CAP_SYS_ADMIN in the root user namespace.
		if !hasAdmin || !steal {
			return linuxerr.EPERM
		}
		// Steal the TTY away. Unlike TIOCNOTTY, don't send signals.
		for othertg := range tg.pidns.owner.Root.tgids {
			// This won't deadlock by locking tg.signalHandlers
			// because at this point:
			//	- We only lock signalHandlers if it's in the same
			//		session as the tty's controlling thread group.
			//	- We know that the calling thread group is not in
			//		the same session as the tty's controlling thread
			//		group.
			if othertg.processGroup.session == tty.tg.processGroup.session {
				othertg.signalHandlers.mu.NestedLock(signalHandlersLockTg)
				othertg.tty = nil
				othertg.signalHandlers.mu.NestedUnlock(signalHandlersLockTg)
			}
		}
	}

	if !isReadable && !hasAdmin {
		return linuxerr.EPERM
	}

	// Set the controlling terminal and foreground process group.
	tg.tty = tty
	tg.processGroup.session.foreground = tg.processGroup
	// Set this as the controlling process of the terminal.
	tty.tg = tg

	return nil
}

// ReleaseControllingTTY gives up tty as the controlling tty of tg.
func (tg *ThreadGroup) ReleaseControllingTTY(tty *TTY) error {
	tty.mu.Lock()
	defer tty.mu.Unlock()

	// We might be asked to set the controlling terminal of multiple
	// processes, so we lock both the TaskSet and SignalHandlers.
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()

	// Just below, we may re-lock signalHandlers in order to send signals.
	// Thus we can't defer Unlock here.
	tg.signalHandlers.mu.Lock()

	if tg.tty == nil || tg.tty != tty {
		tg.signalHandlers.mu.Unlock()
		return linuxerr.ENOTTY
	}

	// "If the process was session leader, then send SIGHUP and SIGCONT to
	// the foreground process group and all processes in the current
	// session lose their controlling terminal." - tty_ioctl(4)
	// Remove tty as the controlling tty for each process in the session,
	// then send them SIGHUP and SIGCONT.

	// If we're not the session leader, we don't have to do much.
	if tty.tg != tg {
		tg.tty = nil
		tg.signalHandlers.mu.Unlock()
		return nil
	}

	tg.signalHandlers.mu.Unlock()

	// We're the session leader. SIGHUP and SIGCONT the foreground process
	// group and remove all controlling terminals in the session.
	var lastErr error
	for othertg := range tg.pidns.owner.Root.tgids {
		if othertg.processGroup.session == tg.processGroup.session {
			othertg.signalHandlers.mu.Lock()
			othertg.tty = nil
			if othertg.processGroup == tg.processGroup.session.foreground {
				if err := othertg.leader.sendSignalLocked(&linux.SignalInfo{Signo: int32(linux.SIGHUP)}, true /* group */); err != nil {
					lastErr = err
				}
				if err := othertg.leader.sendSignalLocked(&linux.SignalInfo{Signo: int32(linux.SIGCONT)}, true /* group */); err != nil {
					lastErr = err
				}
			}
			othertg.signalHandlers.mu.Unlock()
		}
	}

	return lastErr
}

// ForegroundProcessGroupID returns the foreground process group ID of the
// thread group.
func (tg *ThreadGroup) ForegroundProcessGroupID(tty *TTY) (ProcessGroupID, error) {
	tty.mu.Lock()
	defer tty.mu.Unlock()

	tg.pidns.owner.mu.Lock()
	defer tg.pidns.owner.mu.Unlock()
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()

	// fd must refer to the controlling terminal of the calling process.
	// See tcgetpgrp(3)
	if tg.tty != tty {
		return 0, linuxerr.ENOTTY
	}

	return tg.processGroup.session.foreground.id, nil
}

// SetForegroundProcessGroupID sets the foreground process group of tty to
// pgid.
func (tg *ThreadGroup) SetForegroundProcessGroupID(tty *TTY, pgid ProcessGroupID) error {
	tty.mu.Lock()
	defer tty.mu.Unlock()

	tg.pidns.owner.mu.Lock()
	defer tg.pidns.owner.mu.Unlock()
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()

	// tty must be the controlling terminal.
	if tg.tty != tty {
		return linuxerr.ENOTTY
	}

	// pgid must be positive.
	if pgid < 0 {
		return linuxerr.EINVAL
	}

	// pg must not be empty. Empty process groups are removed from their
	// pid namespaces.
	pg, ok := tg.pidns.processGroups[pgid]
	if !ok {
		return linuxerr.ESRCH
	}

	// pg must be part of this process's session.
	if tg.processGroup.session != pg.session {
		return linuxerr.EPERM
	}

	signalAction := tg.signalHandlers.actions[linux.SIGTTOU]
	// If the calling process is a member of a background group, a SIGTTOU
	// signal is sent to all members of this background process group.
	// We need also need to check whether it is ignoring or blocking SIGTTOU.
	ignored := signalAction.Handler == linux.SIG_IGN
	blocked := (linux.SignalSet(tg.leader.signalMask.RacyLoad()) & linux.SignalSetOf(linux.SIGTTOU)) != 0
	if tg.processGroup.id != tg.processGroup.session.foreground.id && !ignored && !blocked {
		tg.leader.sendSignalLocked(SignalInfoPriv(linux.SIGTTOU), true)
		return linuxerr.ERESTARTSYS
	}

	tg.processGroup.session.foreground = pg
	return nil
}

// SetChildSubreaper marks this ThreadGroup sets the isChildSubreaper field on
// this ThreadGroup, and marks all child ThreadGroups as having a subreaper.
// Recursion stops if we find another subreaper process, which is either a
// ThreadGroup with isChildSubreaper bit set, or a ThreadGroup with PID=1
// inside a PID namespace.
func (tg *ThreadGroup) SetChildSubreaper(isSubreaper bool) {
	ts := tg.TaskSet()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	tg.isChildSubreaper = isSubreaper
	tg.walkDescendantThreadGroupsLocked(func(child *ThreadGroup) bool {
		// Is this child PID 1 in its PID namespace, or already a
		// subreaper?
		if child.isInitInLocked(child.PIDNamespace()) || child.isChildSubreaper {
			// Don't set hasChildSubreaper, and don't recurse.
			return false
		}
		child.hasChildSubreaper = isSubreaper
		return true // Recurse.
	})
}

// IsChildSubreaper returns whether this ThreadGroup is a child subreaper.
func (tg *ThreadGroup) IsChildSubreaper() bool {
	ts := tg.TaskSet()
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return tg.isChildSubreaper
}

// IsInitIn returns whether this ThreadGroup has TID 1 int the given
// PIDNamespace.
func (tg *ThreadGroup) IsInitIn(pidns *PIDNamespace) bool {
	ts := tg.TaskSet()
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return tg.isInitInLocked(pidns)
}

// isInitInLocked returns whether this ThreadGroup has TID 1 in the given
// PIDNamespace.
//
// Preconditions: TaskSet.mu must be locked.
func (tg *ThreadGroup) isInitInLocked(pidns *PIDNamespace) bool {
	return pidns.tgids[tg] == initTID
}

// itimerRealListener implements ktime.Listener for ITIMER_REAL expirations.
//
// +stateify savable
type itimerRealListener struct {
	tg *ThreadGroup
}

// NotifyTimer implements ktime.TimerListener.NotifyTimer.
func (l *itimerRealListener) NotifyTimer(exp uint64, setting ktime.Setting) (ktime.Setting, bool) {
	l.tg.SendSignal(SignalInfoPriv(linux.SIGALRM))
	return ktime.Setting{}, false
}
