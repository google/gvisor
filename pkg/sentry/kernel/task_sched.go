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

// CPU scheduling, real and fake.

import (
	"fmt"
	"math/rand/v2"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// TaskGoroutineState is a coarse representation of the current execution
// status of a kernel.Task goroutine.
type TaskGoroutineState uint32

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

// TaskGoroutineState returns the current state of the task goroutine.
func (t *Task) TaskGoroutineState() TaskGoroutineState {
	return TaskGoroutineState(t.gostate.Load())
}

// TaskGoroutineStateTime returns the current state of the task goroutine, and
// the value of Kernel.CPUClockNow() when that state was last updated or
// refreshed.
func (t *Task) TaskGoroutineStateTime() (state TaskGoroutineState, time ktime.Time) {
	for {
		epoch := t.gostateSeq.BeginRead()
		state = t.TaskGoroutineState()
		time = ktime.FromNanoseconds(t.gostateTime.Load())
		if t.gostateSeq.ReadOk(epoch) {
			return
		}
	}
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) accountTaskGoroutineEnter(state TaskGoroutineState) {
	if oldState := t.TaskGoroutineState(); oldState != TaskGoroutineRunningSys {
		panic(fmt.Sprintf("Task goroutine switching from state %v (expected %v) to %v", oldState, TaskGoroutineRunningSys, state))
	}
	t.gostateSeq.BeginWrite()
	t.gostate.Store(uint32(state))
	t.touchGostateTime()
	t.gostateSeq.EndWrite()
	if state != TaskGoroutineRunningApp {
		// Task is blocking/stopping.
		t.k.decRunningTasks()
	}
}

// Preconditions:
//   - The caller must be running on the task goroutine.
//   - The caller must be leaving a state indicated by a previous call to
//     t.accountTaskGoroutineEnter(state).
func (t *Task) accountTaskGoroutineLeave(state TaskGoroutineState) {
	if state != TaskGoroutineRunningApp {
		// Task is unblocking/continuing.
		t.k.incRunningTasks()
	}
	if oldState := t.TaskGoroutineState(); oldState != state {
		panic(fmt.Sprintf("Task goroutine switching from state %v (expected %v) to %v", oldState, state, TaskGoroutineRunningSys))
	}
	t.gostateSeq.BeginWrite()
	t.gostate.Store(uint32(TaskGoroutineRunningSys))
	t.touchGostateTime()
	t.gostateSeq.EndWrite()
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) accountTaskGoroutineRunning() {
	if oldState := t.TaskGoroutineState(); oldState != TaskGoroutineRunningSys {
		panic(fmt.Sprintf("Task goroutine in state %v (expected %v)", oldState, TaskGoroutineRunningSys))
	}
	t.touchGostateTime()
}

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) touchGostateTime() {
	t.gostateTime.Store(t.k.cpuClock.Load())
}

// CPUClockNow returns the current value of the kernel CPU clock, which
// coarsely approximates wall time but is suspended when no tasks are running.
func (k *Kernel) CPUClockNow() ktime.Time {
	return ktime.FromNanoseconds(k.cpuClock.Load())
}

// UserCPUClock returns a clock measuring the CPU time the task has spent
// executing application code.
func (t *Task) UserCPUClock() ktime.Clock {
	return &t.appCPUClock
}

// CPUClock returns a clock measuring the CPU time the task has spent executing
// application and "kernel" code.
func (t *Task) CPUClock() ktime.Clock {
	return &t.appSysCPUClock
}

// UserCPUClock returns a ktime.Clock that measures the time that a thread
// group has spent executing.
func (tg *ThreadGroup) UserCPUClock() ktime.Clock {
	return &tg.appCPUClock
}

// CPUClock returns a ktime.Clock that measures the time that a thread group
// has spent executing, including sentry time.
func (tg *ThreadGroup) CPUClock() ktime.Clock {
	return &tg.appSysCPUClock
}

// CPUStats returns the CPU usage statistics of t.
func (t *Task) CPUStats() usage.CPUStats {
	// The CPU clock ticker advances t.appCPUClock before t.appSysCPUClock, so
	// it's possible for the former to transiently exceed the latter.
	appNS := t.appCPUClock.Now().Nanoseconds()
	appSysNS := t.appSysCPUClock.Now().Nanoseconds()
	sysNS := max(appSysNS-appNS, 0)
	return usage.CPUStats{
		UserTime:          time.Duration(appNS),
		SysTime:           time.Duration(sysNS),
		VoluntarySwitches: t.yieldCount.Load(),
	}
}

// CPUStats returns the combined CPU usage statistics of all past and present
// threads in tg.
func (tg *ThreadGroup) CPUStats() usage.CPUStats {
	// The CPU clock ticker advances tg.appCPUClock before tg.appSysCPUClock,
	// so it's possible for the former to transiently exceed the latter.
	appNS := tg.appCPUClock.Now().Nanoseconds()
	appSysNS := tg.appSysCPUClock.Now().Nanoseconds()
	sysNS := max(appSysNS-appNS, 0)
	return usage.CPUStats{
		UserTime:          time.Duration(appNS),
		SysTime:           time.Duration(sysNS),
		VoluntarySwitches: tg.yieldCount.Load(),
	}
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

func (k *Kernel) runCPUClockTicker() {
	// Storage reused between iterations of the main loop:
	var (
		allTasks []*Task
		incTasks = make([]*Task, k.applicationCores)
	)

	for {
		// Stop CPU clocks while nothing is running.
		if k.runningTasks.Load() == 0 {
			k.runningTasksMu.Lock()
			if k.runningTasks.Load() == 0 {
				k.cpuClockTickerRunning = false
				k.cpuClockTickerStopCond.Broadcast()
				k.runningTasksCond.Wait()
				// k.cpuClockTickerRunning was set to true by our waker
				// (Kernel.incRunningTasks()). For reasons described there, we must
				// process at least one CPU clock tick between calls to
				// k.runningTasksCond.Wait().
			}
			k.runningTasksMu.Unlock()
		}

		// Wait for the next CPU clock tick.
		select {
		case <-k.cpuClockTickTimer.C:
			k.cpuClockTickTimer.Reset(linux.ClockTick)
		case <-k.cpuClockTickerWakeCh:
			continue
		}

		// Advance the "kernel CPU clock".
		k.cpuClock.Add(linux.ClockTick.Nanoseconds())

		// Advance CPU clocks. gVisor generally has no knowledge of when sentry
		// or application code is actually running on a CPU (due to Go and/or
		// host kernel scheduling, with significant variation between
		// platforms), so CPU clocks are approximated. We do so by choosing up
		// to applicationCores running tasks (randomly, using reservoir
		// sampling) and accounting a full CPU clock tick to each of those
		// tasks. The alternative would be to distribute CPU time evenly to all
		// running tasks, but:
		//
		// - If the CPU time per task is between 0 and 1 (nanoseconds), then
		// neither rounded value is desirable: 0 would cause all CPU clocks to
		// cease advancing, while 1 would cause the total CPU time accrued by
		// all tasks to exceed the number of claimed CPUs.
		//
		// - This would require us to mutate CPU clocks and check timers for
		// all running tasks and their thread groups, rather than only up to
		// applicationCores running tasks (and their thread groups).
		allTasks = k.tasks.Root.TasksAppend(allTasks)
		runningTasks := 0
		for _, t := range allTasks {
			state := t.TaskGoroutineState()
			if state != TaskGoroutineRunningApp && state != TaskGoroutineRunningSys {
				continue
			}
			if runningTasks < len(incTasks) {
				incTasks[runningTasks] = t
				runningTasks++
				continue
			}
			runningTasks++
			if i := rand.IntN(runningTasks); i < len(incTasks) {
				incTasks[i] = t
			}
		}
		numIncTasks := min(runningTasks, len(incTasks))
		// Shuffle incTasks to ensure that if multiple tasks are in the same
		// thread group, then all are equally likely to be
		// ThreadGroup.app[Sys]CPUClockLast when a ThreadGroup CPU timer fires.
		rand.Shuffle(numIncTasks, func(i, j int) {
			incTasks[i], incTasks[j] = incTasks[j], incTasks[i]
		})
		for _, t := range incTasks[:numIncTasks] {
			switch t.TaskGoroutineState() {
			case TaskGoroutineRunningApp:
				t.appCPUClock.Add(linux.ClockTick)
				t.tg.appCPUClockLast.Store(t)
				t.tg.appCPUClock.Add(linux.ClockTick)
				fallthrough
			case TaskGoroutineRunningSys:
				t.appSysCPUClock.Add(linux.ClockTick)
				t.tg.appSysCPUClockLast.Store(t)
				t.tg.appSysCPUClock.Add(linux.ClockTick)
			}
		}

		// Reset storage for the next iteration.
		clear(allTasks)
		allTasks = allTasks[:0]
		clear(incTasks[:numIncTasks])
	}
}

// StateStatus returns a string representation of the task's current state,
// appropriate for /proc/[pid]/status.
func (t *Task) StateStatus() string {
	switch s := t.TaskGoroutineState(); s {
	case TaskGoroutineNonexistent, TaskGoroutineRunningSys:
		switch t.ExitState() {
		case TaskExitZombie:
			return "Z (zombie)"
		case TaskExitDead:
			return "X (dead)"
		default:
			// The task goroutine can't exit before passing through
			// runExitNotify, so if s == TaskGoroutineNonexistent, the task has
			// been created but the task goroutine hasn't yet started. The
			// Linux equivalent is struct task_struct::state == TASK_NEW
			// (kernel/fork.c:copy_process() =>
			// kernel/sched/core.c:sched_fork()), but the TASK_NEW bit is
			// masked out by TASK_REPORT for /proc/[pid]/status, leaving only
			// TASK_RUNNING.
			return "R (running)"
		}
	case TaskGoroutineRunningApp:
		return "R (running)"
	case TaskGoroutineBlockedInterruptible:
		return "S (sleeping)"
	case TaskGoroutineStopped:
		sh := t.tg.signalLock()
		defer sh.mu.Unlock()
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
		return linuxerr.EINVAL
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
	t.cpu.Store(assignCPU(mask, rootTID))
	return nil
}

// CPU returns the cpu id for a given task.
func (t *Task) CPU() int32 {
	if t.k.useHostCores {
		return int32(hostcpu.GetCPU())
	}

	return t.cpu.Load()
}

// assignCPU returns the virtualized CPU number for the task with global TID
// tid and allowedCPUMask allowed.
func assignCPU(allowed sched.CPUSet, tid ThreadID) (cpu int32) {
	// To pretend that threads are evenly distributed to allowed CPUs, choose n
	// to be less than the number of CPUs in allowed ...
	n := int(tid) % int(allowed.NumCPUs())
	// ... then pick the nth CPU in allowed.
	allowed.ForEachCPU(func(c uint) {
		if n == 0 {
			cpu = int32(c)
		}
		n--
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
func (t *Task) NumaPolicy() (policy linux.NumaPolicy, nodeMask uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.numaPolicy, t.numaNodeMask
}

// SetNumaPolicy sets t's numa policy.
func (t *Task) SetNumaPolicy(policy linux.NumaPolicy, nodeMask uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.numaPolicy = policy
	t.numaNodeMask = nodeMask
}
