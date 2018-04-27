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
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
)

// A ThreadGroup is a logical grouping of tasks that has widespread
// significance to other kernel features (e.g. signal handling). ("Thread
// groups" are usually called "processes" in userspace documentation.)
//
// ThreadGroup is a superset of Linux's struct signal_struct.
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

	// lastTimerSignalTask records the last task we deliver a process timer signal to.
	// Please see SendTimerSignal for more details.
	//
	// lastTimerSignalTask is protected by the signal mutex.
	lastTimerSignalTask *Task

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

	// tm contains process timers. TimerManager fields are immutable.
	tm TimerManager

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

// NewThreadGroup returns a new, empty thread group in PID namespace ns. The
// thread group leader will send its parent terminationSignal when it exits.
// The new thread group isn't visible to the system until a task has been
// created inside of it by a successful call to TaskSet.NewTask.
func NewThreadGroup(ns *PIDNamespace, sh *SignalHandlers, terminationSignal linux.Signal, limits *limits.LimitSet, monotonicClock *timekeeperClock) *ThreadGroup {
	tg := &ThreadGroup{
		threadGroupNode: threadGroupNode{
			pidns: ns,
		},
		signalHandlers:    sh,
		terminationSignal: terminationSignal,
		ioUsage:           &usage.IO{},
		limits:            limits,
	}
	tg.tm = newTimerManager(tg, monotonicClock)
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

// Timer returns tg's timers.
func (tg *ThreadGroup) Timer() *TimerManager {
	return &tg.tm
}

// Limits returns tg's limits.
func (tg *ThreadGroup) Limits() *limits.LimitSet {
	return tg.limits
}

// release releases the thread group's resources.
func (tg *ThreadGroup) release() {
	// This must be done without holding the TaskSet mutex since thread group
	// timers call SendSignal with Timer.mu locked.
	tg.tm.destroy()
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
