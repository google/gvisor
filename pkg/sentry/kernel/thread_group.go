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

package kernel

import (
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
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

	// groupStopPhase indicates the state of a group stop in progress on the
	// thread group, if any.
	//
	// groupStopPhase is protected by the signal mutex.
	groupStopPhase groupStopPhase

	// groupStopSignal is the signal that caused a group stop to be initiated.
	// groupStopSignal is only meaningful if groupStopPhase is
	// groupStopInitiated or groupStopComplete.
	//
	// groupStopSignal is protected by the signal mutex.
	groupStopSignal linux.Signal

	// groupStopCount is the number of non-exited tasks in the thread group
	// that have acknowledged an initiated group stop. groupStopCount is only
	// meaningful if groupStopPhase is groupStopInitiated.
	//
	// groupStopCount is protected by the signal mutex.
	groupStopCount int

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
	// notify its parent.
	//
	// groupContNotify is protected by the signal mutex.
	groupContNotify bool

	// If groupContNotify is true, groupContInterrupted is true iff SIGCONT
	// ended a group stop in phase groupStopInitiated. If groupContNotify is
	// false, groupContInterrupted is meaningless.
	//
	// Analogues in Linux:
	//
	// - groupContNotify && groupContInterrupted is represented by
	// SIGNAL_CLD_STOPPED.
	//
	// - groupContNotify && !groupContInterrupted is represented by
	// SIGNAL_CLD_CONTINUED.
	//
	// - !groupContNotify is represented by neither flag being set.
	//
	// groupContInterrupted is protected by the signal mutex.
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
	exitStatus ExitStatus

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

	timerMu sync.Mutex `state:"nosave"`

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
	// cpuTimersEnabled is protected by the signal mutex. cpuTimersEnabled is
	// accessed using atomic memory operations.
	cpuTimersEnabled uint32

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
	// - A task in the thread group exits, since after all tasks have
	// exited the MemoryManager is no longer reachable.
	//
	// - The thread group completes an execve, since this changes
	// MemoryManagers.
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

	// rscr is the thread group's RSEQ critical region.
	rscr atomic.Value `state:".(*RSEQCriticalRegion)"`
}

// newThreadGroup returns a new, empty thread group in PID namespace ns. The
// thread group leader will send its parent terminationSignal when it exits.
// The new thread group isn't visible to the system until a task has been
// created inside of it by a successful call to TaskSet.NewTask.
func (k *Kernel) newThreadGroup(ns *PIDNamespace, sh *SignalHandlers, terminationSignal linux.Signal, limits *limits.LimitSet, monotonicClock *timekeeperClock) *ThreadGroup {
	tg := &ThreadGroup{
		threadGroupNode: threadGroupNode{
			pidns: ns,
		},
		signalHandlers:    sh,
		terminationSignal: terminationSignal,
		ioUsage:           &usage.IO{},
		limits:            limits,
	}
	tg.itimerRealTimer = ktime.NewTimer(k.monotonicClock, &itimerRealListener{tg: tg})
	tg.timers = make(map[linux.TimerID]*IntervalTimer)
	tg.rscr.Store(&RSEQCriticalRegion{})
	return tg
}

// saveRscr is invopked by stateify.
func (tg *ThreadGroup) saveRscr() *RSEQCriticalRegion {
	return tg.rscr.Load().(*RSEQCriticalRegion)
}

// loadRscr is invoked by stateify.
func (tg *ThreadGroup) loadRscr(rscr *RSEQCriticalRegion) {
	tg.rscr.Store(rscr)
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

// release releases the thread group's resources.
func (tg *ThreadGroup) release() {
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
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		for child := range t.children {
			if child == child.tg.leader {
				fn(child.tg)
			}
		}
	}
}

// itimerRealListener implements ktime.Listener for ITIMER_REAL expirations.
//
// +stateify savable
type itimerRealListener struct {
	tg *ThreadGroup
}

// Notify implements ktime.TimerListener.Notify.
func (l *itimerRealListener) Notify(exp uint64) {
	l.tg.SendSignal(sigPriv(linux.SIGALRM))
}

// Destroy implements ktime.TimerListener.Destroy.
func (l *itimerRealListener) Destroy() {
}
