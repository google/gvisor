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
	"math/rand"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/syserror"
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
//
// +stateify savable
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

// userTicksAt returns the extrapolated value of ts.UserTicks after
// Kernel.CPUClockNow() indicates a time of now.
//
// Preconditions: now <= Kernel.CPUClockNow(). (Since Kernel.cpuClock is
// monotonic, this is satisfied if now is the result of a previous call to
// Kernel.CPUClockNow().) This requirement exists because otherwise a racing
// change to t.gosched can cause userTicksAt to adjust stats by too much,
// making the observed stats non-monotonic.
func (ts *TaskGoroutineSchedInfo) userTicksAt(now uint64) uint64 {
	if ts.Timestamp < now && ts.State == TaskGoroutineRunningApp {
		// Update stats to reflect execution since the last update.
		return ts.UserTicks + (now - ts.Timestamp)
	}
	return ts.UserTicks
}

// sysTicksAt returns the extrapolated value of ts.SysTicks after
// Kernel.CPUClockNow() indicates a time of now.
//
// Preconditions: As for userTicksAt.
func (ts *TaskGoroutineSchedInfo) sysTicksAt(now uint64) uint64 {
	if ts.Timestamp < now && ts.State == TaskGoroutineRunningSys {
		return ts.SysTicks + (now - ts.Timestamp)
	}
	return ts.SysTicks
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

	if state != TaskGoroutineRunningApp {
		// Task is blocking/stopping.
		t.k.decRunningTasks()
	}
}

// Preconditions:
// * The caller must be running on the task goroutine
// * The caller must be leaving a state indicated by a previous call to
//   t.accountTaskGoroutineEnter(state).
func (t *Task) accountTaskGoroutineLeave(state TaskGoroutineState) {
	if state != TaskGoroutineRunningApp {
		// Task is unblocking/continuing.
		t.k.incRunningTasks()
	}

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

// Preconditions: The caller must be running on the task goroutine.
func (t *Task) accountTaskGoroutineRunning() {
	now := t.k.CPUClockNow()
	if t.gosched.State != TaskGoroutineRunningSys {
		panic(fmt.Sprintf("Task goroutine in state %v (expected %v)", t.gosched.State, TaskGoroutineRunningSys))
	}
	t.goschedSeq.BeginWrite()
	t.gosched.SysTicks += now - t.gosched.Timestamp
	t.gosched.Timestamp = now
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

// Preconditions: As for TaskGoroutineSchedInfo.userTicksAt.
func (t *Task) cpuStatsAt(now uint64) usage.CPUStats {
	tsched := t.TaskGoroutineSchedInfo()
	return usage.CPUStats{
		UserTime:          time.Duration(tsched.userTicksAt(now) * uint64(linux.ClockTick)),
		SysTime:           time.Duration(tsched.sysTicksAt(now) * uint64(linux.ClockTick)),
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
	return tg.cpuStatsAtLocked(tg.leader.k.CPUClockNow())
}

// Preconditions: Same as TaskGoroutineSchedInfo.userTicksAt, plus:
// * The TaskSet mutex must be locked.
func (tg *ThreadGroup) cpuStatsAtLocked(now uint64) usage.CPUStats {
	stats := tg.exitedCPUStats
	// Account for live tasks.
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

// taskClock is a ktime.Clock that measures the time that a task has spent
// executing. taskClock is primarily used to implement CLOCK_THREAD_CPUTIME_ID.
//
// +stateify savable
type taskClock struct {
	t *Task

	// If includeSys is true, the taskClock includes both time spent executing
	// application code as well as time spent in the sentry. Otherwise, the
	// taskClock includes only time spent executing application code.
	includeSys bool

	// Implements waiter.Waitable. TimeUntil wouldn't change its estimation
	// based on either of the clock events, so there's no event to be
	// notified for.
	ktime.NoClockEvents `state:"nosave"`

	// Implements ktime.Clock.WallTimeUntil.
	//
	// As an upper bound, a task's clock cannot advance faster than CPU
	// time. It would have to execute at a rate of more than 1 task-second
	// per 1 CPU-second, which isn't possible.
	ktime.WallRateClock `state:"nosave"`
}

// UserCPUClock returns a clock measuring the CPU time the task has spent
// executing application code.
func (t *Task) UserCPUClock() ktime.Clock {
	return &taskClock{t: t, includeSys: false}
}

// CPUClock returns a clock measuring the CPU time the task has spent executing
// application and "kernel" code.
func (t *Task) CPUClock() ktime.Clock {
	return &taskClock{t: t, includeSys: true}
}

// Now implements ktime.Clock.Now.
func (tc *taskClock) Now() ktime.Time {
	stats := tc.t.CPUStats()
	if tc.includeSys {
		return ktime.FromNanoseconds((stats.UserTime + stats.SysTime).Nanoseconds())
	}
	return ktime.FromNanoseconds(stats.UserTime.Nanoseconds())
}

// tgClock is a ktime.Clock that measures the time a thread group has spent
// executing. tgClock is primarily used to implement CLOCK_PROCESS_CPUTIME_ID.
//
// +stateify savable
type tgClock struct {
	tg *ThreadGroup

	// If includeSys is true, the tgClock includes both time spent executing
	// application code as well as time spent in the sentry. Otherwise, the
	// tgClock includes only time spent executing application code.
	includeSys bool

	// Implements waiter.Waitable.
	ktime.ClockEventsQueue `state:"nosave"`
}

// Now implements ktime.Clock.Now.
func (tgc *tgClock) Now() ktime.Time {
	stats := tgc.tg.CPUStats()
	if tgc.includeSys {
		return ktime.FromNanoseconds((stats.UserTime + stats.SysTime).Nanoseconds())
	}
	return ktime.FromNanoseconds(stats.UserTime.Nanoseconds())
}

// WallTimeUntil implements ktime.Clock.WallTimeUntil.
func (tgc *tgClock) WallTimeUntil(t, now ktime.Time) time.Duration {
	// Thread group CPU time should not exceed wall time * live tasks, since
	// task goroutines exit after the transition to TaskExitZombie in
	// runExitNotify.
	tgc.tg.pidns.owner.mu.RLock()
	n := tgc.tg.liveTasks
	tgc.tg.pidns.owner.mu.RUnlock()
	if n == 0 {
		if t.Before(now) {
			return 0
		}
		// The timer tick raced with thread group exit, after which no more
		// tasks can enter the thread group. So tgc.Now() will never advance
		// again. Return a large delay; the timer should be stopped long before
		// it comes again anyway.
		return time.Hour
	}
	// This is a lower bound on the amount of time that can elapse before an
	// associated timer expires, so returning this value tends to result in a
	// sequence of closely-spaced ticks just before timer expiry. To avoid
	// this, round up to the nearest ClockTick; CPU usage measurements are
	// limited to this resolution anyway.
	remaining := time.Duration(t.Sub(now).Nanoseconds()/int64(n)) * time.Nanosecond
	return ((remaining + (linux.ClockTick - time.Nanosecond)) / linux.ClockTick) * linux.ClockTick
}

// UserCPUClock returns a ktime.Clock that measures the time that a thread
// group has spent executing.
func (tg *ThreadGroup) UserCPUClock() ktime.Clock {
	return &tgClock{tg: tg, includeSys: false}
}

// CPUClock returns a ktime.Clock that measures the time that a thread group
// has spent executing, including sentry time.
func (tg *ThreadGroup) CPUClock() ktime.Clock {
	return &tgClock{tg: tg, includeSys: true}
}

type kernelCPUClockTicker struct {
	k *Kernel

	// These are essentially kernelCPUClockTicker.Notify local variables that
	// are cached between calls to reduce allocations.
	rng *rand.Rand
	tgs []*ThreadGroup
}

func newKernelCPUClockTicker(k *Kernel) *kernelCPUClockTicker {
	return &kernelCPUClockTicker{
		k:   k,
		rng: rand.New(rand.NewSource(rand.Int63())),
	}
}

// Notify implements ktime.TimerListener.Notify.
func (ticker *kernelCPUClockTicker) Notify(exp uint64, setting ktime.Setting) (ktime.Setting, bool) {
	// Only increment cpuClock by 1 regardless of the number of expirations.
	// This approximately compensates for cases where thread throttling or bad
	// Go runtime scheduling prevents the kernelCPUClockTicker goroutine, and
	// presumably task goroutines as well, from executing for a long period of
	// time. It's also necessary to prevent CPU clocks from seeing large
	// discontinuous jumps.
	now := atomic.AddUint64(&ticker.k.cpuClock, 1)

	// Check thread group CPU timers.
	tgs := ticker.k.tasks.Root.ThreadGroupsAppend(ticker.tgs)
	for _, tg := range tgs {
		if atomic.LoadUint32(&tg.cpuTimersEnabled) == 0 {
			continue
		}

		ticker.k.tasks.mu.RLock()
		if tg.leader == nil {
			// No tasks have ever run in this thread group.
			ticker.k.tasks.mu.RUnlock()
			continue
		}
		// Accumulate thread group CPU stats, and randomly select running tasks
		// using reservoir sampling to receive CPU timer signals.
		var virtReceiver *Task
		nrVirtCandidates := 0
		var profReceiver *Task
		nrProfCandidates := 0
		tgUserTime := tg.exitedCPUStats.UserTime
		tgSysTime := tg.exitedCPUStats.SysTime
		for t := tg.tasks.Front(); t != nil; t = t.Next() {
			tsched := t.TaskGoroutineSchedInfo()
			tgUserTime += time.Duration(tsched.userTicksAt(now) * uint64(linux.ClockTick))
			tgSysTime += time.Duration(tsched.sysTicksAt(now) * uint64(linux.ClockTick))
			switch tsched.State {
			case TaskGoroutineRunningApp:
				// Considered by ITIMER_VIRT, ITIMER_PROF, and RLIMIT_CPU
				// timers.
				nrVirtCandidates++
				if int(randInt31n(ticker.rng, int32(nrVirtCandidates))) == 0 {
					virtReceiver = t
				}
				fallthrough
			case TaskGoroutineRunningSys:
				// Considered by ITIMER_PROF and RLIMIT_CPU timers.
				nrProfCandidates++
				if int(randInt31n(ticker.rng, int32(nrProfCandidates))) == 0 {
					profReceiver = t
				}
			}
		}
		tgVirtNow := ktime.FromNanoseconds(tgUserTime.Nanoseconds())
		tgProfNow := ktime.FromNanoseconds((tgUserTime + tgSysTime).Nanoseconds())

		// All of the following are standard (not real-time) signals, which are
		// automatically deduplicated, so we ignore the number of expirations.
		tg.signalHandlers.mu.Lock()
		// It should only be possible for these timers to advance if we found
		// at least one running task.
		if virtReceiver != nil {
			// ITIMER_VIRTUAL
			newItimerVirtSetting, exp := tg.itimerVirtSetting.At(tgVirtNow)
			tg.itimerVirtSetting = newItimerVirtSetting
			if exp != 0 {
				virtReceiver.sendSignalLocked(SignalInfoPriv(linux.SIGVTALRM), true)
			}
		}
		if profReceiver != nil {
			// ITIMER_PROF
			newItimerProfSetting, exp := tg.itimerProfSetting.At(tgProfNow)
			tg.itimerProfSetting = newItimerProfSetting
			if exp != 0 {
				profReceiver.sendSignalLocked(SignalInfoPriv(linux.SIGPROF), true)
			}
			// RLIMIT_CPU soft limit
			newRlimitCPUSoftSetting, exp := tg.rlimitCPUSoftSetting.At(tgProfNow)
			tg.rlimitCPUSoftSetting = newRlimitCPUSoftSetting
			if exp != 0 {
				profReceiver.sendSignalLocked(SignalInfoPriv(linux.SIGXCPU), true)
			}
			// RLIMIT_CPU hard limit
			rlimitCPUMax := tg.limits.Get(limits.CPU).Max
			if rlimitCPUMax != limits.Infinity && !tgProfNow.Before(ktime.FromSeconds(int64(rlimitCPUMax))) {
				profReceiver.sendSignalLocked(SignalInfoPriv(linux.SIGKILL), true)
			}
		}
		tg.signalHandlers.mu.Unlock()

		ticker.k.tasks.mu.RUnlock()
	}

	// Retain tgs between calls to Notify to reduce allocations.
	for i := range tgs {
		tgs[i] = nil
	}
	ticker.tgs = tgs[:0]

	// If nothing is running, we can disable the timer.
	tasks := atomic.LoadInt64(&ticker.k.runningTasks)
	if tasks == 0 {
		ticker.k.runningTasksMu.Lock()
		defer ticker.k.runningTasksMu.Unlock()
		tasks := atomic.LoadInt64(&ticker.k.runningTasks)
		if tasks != 0 {
			// Raced with a 0 -> 1 transition.
			return setting, false
		}

		// Stop the timer. We must cache the current setting so the
		// kernel can access it without violating the lock order.
		ticker.k.cpuClockTickerSetting = setting
		ticker.k.cpuClockTickerDisabled = true
		setting.Enabled = false
		return setting, true
	}

	return setting, false
}

// Destroy implements ktime.TimerListener.Destroy.
func (ticker *kernelCPUClockTicker) Destroy() {
}

// randInt31n returns a random integer in [0, n).
//
// randInt31n is equivalent to math/rand.Rand.int31n(), which is unexported.
// See that function for details.
func randInt31n(rng *rand.Rand, n int32) int32 {
	v := rng.Uint32()
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < uint32(n) {
		thresh := uint32(-n) % uint32(n)
		for low < thresh {
			v = rng.Uint32()
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return int32(prod >> 32)
}

// NotifyRlimitCPUUpdated is called by setrlimit.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) NotifyRlimitCPUUpdated() {
	t.k.cpuClockTicker.Atomically(func() {
		t.tg.pidns.owner.mu.RLock()
		defer t.tg.pidns.owner.mu.RUnlock()
		t.tg.signalHandlers.mu.Lock()
		defer t.tg.signalHandlers.mu.Unlock()
		rlimitCPU := t.tg.limits.Get(limits.CPU)
		t.tg.rlimitCPUSoftSetting = ktime.Setting{
			Enabled: rlimitCPU.Cur != limits.Infinity,
			Next:    ktime.FromNanoseconds((time.Duration(rlimitCPU.Cur) * time.Second).Nanoseconds()),
			Period:  time.Second,
		}
		if rlimitCPU.Max != limits.Infinity {
			// Check if tg is already over the hard limit.
			tgcpu := t.tg.cpuStatsAtLocked(t.k.CPUClockNow())
			tgProfNow := ktime.FromNanoseconds((tgcpu.UserTime + tgcpu.SysTime).Nanoseconds())
			if !tgProfNow.Before(ktime.FromSeconds(int64(rlimitCPU.Max))) {
				t.sendSignalLocked(SignalInfoPriv(linux.SIGKILL), true)
			}
		}
		t.tg.updateCPUTimersEnabledLocked()
	})
}

// Preconditions: The signal mutex must be locked.
func (tg *ThreadGroup) updateCPUTimersEnabledLocked() {
	rlimitCPU := tg.limits.Get(limits.CPU)
	if tg.itimerVirtSetting.Enabled || tg.itimerProfSetting.Enabled || tg.rlimitCPUSoftSetting.Enabled || rlimitCPU.Max != limits.Infinity {
		atomic.StoreUint32(&tg.cpuTimersEnabled, 1)
	} else {
		atomic.StoreUint32(&tg.cpuTimersEnabled, 0)
	}
}

// StateStatus returns a string representation of the task's current state,
// appropriate for /proc/[pid]/status.
func (t *Task) StateStatus() string {
	switch s := t.TaskGoroutineSchedInfo().State; s {
	case TaskGoroutineNonexistent, TaskGoroutineRunningSys:
		t.tg.pidns.owner.mu.RLock()
		defer t.tg.pidns.owner.mu.RUnlock()
		switch t.exitState {
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
