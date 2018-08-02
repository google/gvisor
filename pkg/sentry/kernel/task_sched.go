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

// CPU scheduling, real and fake.

import (
	"fmt"
	"sync/atomic"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/hostcpu"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/sched"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// TaskGoroutineState is a coarse representation of the current execution
// status of a kernel.Task goroutine.
type TaskGoroutineState int

const (
	// TaskGoroutineNonexistent indicates that the task goroutine has either
	// not yet been created by Task.Start() or has returned from Task.run().
	// This must be the zero value for TaskGoroutineState.
	TaskGoroutineNonexistent TaskGoroutineState = iota

	// TaskGoroutineRunningSys indicates that the task goroutine is executing
	// sentry code.
	TaskGoroutineRunningSys

	// TaskGoroutineRunningApp indicates that the task goroutine is executing
	// application code.
	TaskGoroutineRunningApp

	// TaskGoroutineBlockedInterruptible indicates that the task goroutine is
	// blocked in Task.block(), and hence may be woken by Task.interrupt()
	// (e.g. due to signal delivery).
	TaskGoroutineBlockedInterruptible

	// TaskGoroutineBlockedUninterruptible indicates that the task goroutine is
	// stopped outside of Task.block() and Task.doStop(), and hence cannot be
	// woken by Task.interrupt().
	TaskGoroutineBlockedUninterruptible

	// TaskGoroutineStopped indicates that the task goroutine is blocked in
	// Task.doStop(). TaskGoroutineStopped is similar to
	// TaskGoroutineBlockedUninterruptible, but is a separate state to make it
	// possible to determine when Task.stop is meaningful.
	TaskGoroutineStopped
)

// TaskGoroutineSchedInfo contains task goroutine scheduling state which must
// be read and updated atomically.
type TaskGoroutineSchedInfo struct {
	// Timestamp was the value of Kernel.cpuClock when this
	// TaskGoroutineSchedInfo was last updated.
	Timestamp uint64

	// State is the current state of the task goroutine.
	State TaskGoroutineState

	// UserTicks is the amount of time the task goroutine has spent executing
	// its associated Task's application code, in units of linux.ClockTick.
	UserTicks uint64

	// SysTicks is the amount of time the task goroutine has spent executing in
	// the sentry, in units of linux.ClockTick.
	SysTicks uint64
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) accountTaskGoroutineEnter(state TaskGoroutineState) {
	now := t.k.CPUClockNow()
	if t.gosched.State != TaskGoroutineRunningSys {
		panic(fmt.Sprintf("Task goroutine switching from state %v (expected %v) to %v", t.gosched.State, TaskGoroutineRunningSys, state))
	}
	t.goschedSeq.BeginWrite()
	// This function is very hot; avoid defer.
	t.gosched.SysTicks += now - t.gosched.Timestamp
	t.gosched.Timestamp = now
	t.gosched.State = state
	t.goschedSeq.EndWrite()
}

// Preconditions: The caller must be running on the task goroutine, and leaving
// a state indicated by a previous call to
// t.accountTaskGoroutineEnter(state).
func (t *Task) accountTaskGoroutineLeave(state TaskGoroutineState) {
	now := t.k.CPUClockNow()
	if t.gosched.State != state {
		panic(fmt.Sprintf("Task goroutine switching from state %v (expected %v) to %v", t.gosched.State, state, TaskGoroutineRunningSys))
	}
	t.goschedSeq.BeginWrite()
	// This function is very hot; avoid defer.
	if state == TaskGoroutineRunningApp {
		t.gosched.UserTicks += now - t.gosched.Timestamp
	}
	t.gosched.Timestamp = now
	t.gosched.State = TaskGoroutineRunningSys
	t.goschedSeq.EndWrite()
}

// TaskGoroutineSchedInfo returns a copy of t's task goroutine scheduling info.
// Most clients should use t.CPUStats() instead.
func (t *Task) TaskGoroutineSchedInfo() TaskGoroutineSchedInfo {
	return SeqAtomicLoadTaskGoroutineSchedInfo(&t.goschedSeq, &t.gosched)
}

// CPUStats returns the CPU usage statistics of t.
func (t *Task) CPUStats() usage.CPUStats {
	return t.cpuStatsAt(t.k.CPUClockNow())
}

// Preconditions: now <= Kernel.CPUClockNow(). (Since Kernel.cpuClock is
// monotonic, this is satisfied if now is the result of a previous call to
// Kernel.CPUClockNow().) This requirement exists because otherwise a racing
// change to t.gosched can cause cpuStatsAt to adjust stats by too much, making
// the returned stats non-monotonic.
func (t *Task) cpuStatsAt(now uint64) usage.CPUStats {
	tsched := t.TaskGoroutineSchedInfo()
	if tsched.Timestamp < now {
		// Update stats to reflect execution since the last update to
		// t.gosched.
		switch tsched.State {
		case TaskGoroutineRunningSys:
			tsched.SysTicks += now - tsched.Timestamp
		case TaskGoroutineRunningApp:
			tsched.UserTicks += now - tsched.Timestamp
		}
	}
	return usage.CPUStats{
		UserTime:          time.Duration(tsched.UserTicks * uint64(linux.ClockTick)),
		SysTime:           time.Duration(tsched.SysTicks * uint64(linux.ClockTick)),
		VoluntarySwitches: atomic.LoadUint64(&t.yieldCount),
	}
}

// CPUStats returns the combined CPU usage statistics of all past and present
// threads in tg.
func (tg *ThreadGroup) CPUStats() usage.CPUStats {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	// Hack to get a pointer to the Kernel.
	if tg.leader == nil {
		// Per comment on tg.leader, this is only possible if nothing in the
		// ThreadGroup has ever executed anyway.
		return usage.CPUStats{}
	}
	now := tg.leader.k.CPUClockNow()
	stats := tg.exitedCPUStats
	// Account for active tasks.
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		stats.Accumulate(t.cpuStatsAt(now))
	}
	return stats
}

// JoinedChildCPUStats implements the semantics of RUSAGE_CHILDREN: "Return
// resource usage statistics for all children of [tg] that have terminated and
// been waited for. These statistics will include the resources used by
// grandchildren, and further removed descendants, if all of the intervening
// descendants waited on their terminated children."
func (tg *ThreadGroup) JoinedChildCPUStats() usage.CPUStats {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	return tg.childCPUStats
}

// StateStatus returns a string representation of the task's current state,
// appropriate for /proc/[pid]/status.
func (t *Task) StateStatus() string {
	switch s := t.TaskGoroutineSchedInfo().State; s {
	case TaskGoroutineNonexistent:
		t.tg.pidns.owner.mu.RLock()
		defer t.tg.pidns.owner.mu.RUnlock()
		switch t.exitState {
		case TaskExitZombie:
			return "Z (zombie)"
		case TaskExitDead:
			return "X (dead)"
		default:
			// The task goroutine can't exit before passing through
			// runExitNotify, so this indicates that the task has been created,
			// but the task goroutine hasn't yet started. The Linux equivalent
			// is struct task_struct::state == TASK_NEW
			// (kernel/fork.c:copy_process() =>
			// kernel/sched/core.c:sched_fork()), but the TASK_NEW bit is
			// masked out by TASK_REPORT for /proc/[pid]/status, leaving only
			// TASK_RUNNING.
			return "R (running)"
		}
	case TaskGoroutineRunningSys, TaskGoroutineRunningApp:
		return "R (running)"
	case TaskGoroutineBlockedInterruptible:
		return "S (sleeping)"
	case TaskGoroutineStopped:
		t.tg.signalHandlers.mu.Lock()
		defer t.tg.signalHandlers.mu.Unlock()
		switch t.stop.(type) {
		case *groupStop:
			return "T (stopped)"
		case *ptraceStop:
			return "t (tracing stop)"
		}
		fallthrough
	case TaskGoroutineBlockedUninterruptible:
		// This is the name Linux uses for TASK_UNINTERRUPTIBLE and
		// TASK_KILLABLE (= TASK_UNINTERRUPTIBLE | TASK_WAKEKILL):
		// fs/proc/array.c:task_state_array.
		return "D (disk sleep)"
	default:
		panic(fmt.Sprintf("Invalid TaskGoroutineState: %v", s))
	}
}

// CPUMask returns a copy of t's allowed CPU mask.
func (t *Task) CPUMask() sched.CPUSet {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.allowedCPUMask.Copy()
}

// SetCPUMask sets t's allowed CPU mask based on mask. It takes ownership of
// mask.
//
// Preconditions: mask.Size() ==
// sched.CPUSetSize(t.Kernel().ApplicationCores()).
func (t *Task) SetCPUMask(mask sched.CPUSet) error {
	if want := sched.CPUSetSize(t.k.applicationCores); mask.Size() != want {
		panic(fmt.Sprintf("Invalid CPUSet %v (expected %d bytes)", mask, want))
	}

	// Remove CPUs in mask above Kernel.applicationCores.
	mask.ClearAbove(t.k.applicationCores)

	// Ensure that at least 1 CPU is still allowed.
	if mask.NumCPUs() == 0 {
		return syserror.EINVAL
	}

	if t.k.useHostCores {
		// No-op; pretend the mask was immediately changed back.
		return nil
	}

	t.tg.pidns.owner.mu.RLock()
	rootTID := t.tg.pidns.owner.Root.tids[t]
	t.tg.pidns.owner.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	t.allowedCPUMask = mask
	atomic.StoreInt32(&t.cpu, assignCPU(mask, rootTID))
	return nil
}

// CPU returns the cpu id for a given task.
func (t *Task) CPU() int32 {
	if t.k.useHostCores {
		return int32(hostcpu.GetCPU())
	}

	return atomic.LoadInt32(&t.cpu)
}

// assignCPU returns the virtualized CPU number for the task with global TID
// tid and allowedCPUMask allowed.
func assignCPU(allowed sched.CPUSet, tid ThreadID) (cpu int32) {
	// To pretend that threads are evenly distributed to allowed CPUs, choose n
	// to be less than the number of CPUs in allowed ...
	n := int(tid) % int(allowed.NumCPUs())
	// ... then pick the nth CPU in allowed.
	allowed.ForEachCPU(func(c uint) {
		if n--; n == 0 {
			cpu = int32(c)
		}
	})
	return cpu
}

// Niceness returns t's niceness.
func (t *Task) Niceness() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.niceness
}

// Priority returns t's priority.
func (t *Task) Priority() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.niceness + 20
}

// SetNiceness sets t's niceness to n.
func (t *Task) SetNiceness(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.niceness = n
}

// NumaPolicy returns t's current numa policy.
func (t *Task) NumaPolicy() (policy int32, nodeMask uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.numaPolicy, t.numaNodeMask
}

// SetNumaPolicy sets t's numa policy.
func (t *Task) SetNumaPolicy(policy int32, nodeMask uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.numaPolicy = policy
	t.numaNodeMask = nodeMask
}
