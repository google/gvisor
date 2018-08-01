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
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	sentrytime "gvisor.googlesource.com/gvisor/pkg/sentry/time"
)

// timekeeperClock is a ktime.Clock that reads time from a
// kernel.Timekeeper-managed clock.
//
// +stateify savable
type timekeeperClock struct {
	tk *Timekeeper
	c  sentrytime.ClockID

	// Implements ktime.Clock.WallTimeUntil.
	ktime.WallRateClock `state:"nosave"`

	// Implements waiter.Waitable. (We have no ability to detect
	// discontinuities from external changes to CLOCK_REALTIME).
	ktime.NoClockEvents `state:"nosave"`
}

// Now implements ktime.Clock.Now.
func (tc *timekeeperClock) Now() ktime.Time {
	now, err := tc.tk.GetTime(tc.c)
	if err != nil {
		panic(fmt.Sprintf("timekeeperClock(ClockID=%v)).Now: %v", tc.c, err))
	}
	return ktime.FromNanoseconds(now)
}

// tgClock is a ktime.Clock that measures the time a thread group has spent
// executing.
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

// UserCPUClock returns a ktime.Clock that measures the time that a thread
// group has spent executing.
func (tg *ThreadGroup) UserCPUClock() ktime.Clock {
	return tg.tm.virtClock
}

// CPUClock returns a ktime.Clock that measures the time that a thread group
// has spent executing, including sentry time.
func (tg *ThreadGroup) CPUClock() ktime.Clock {
	return tg.tm.profClock
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
	// The assumption here is that the time spent in this process (not matter
	// virtual or prof) should not exceed wall time * active tasks, since
	// Task.exitThreadGroup stops accounting as it transitions to
	// TaskExitInitiated.
	tgc.tg.pidns.owner.mu.RLock()
	n := tgc.tg.activeTasks
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
	remaining := time.Duration(int64(t.Sub(now))/int64(n)) * time.Nanosecond
	return ((remaining + (linux.ClockTick - time.Nanosecond)) / linux.ClockTick) * linux.ClockTick
}

// taskClock is a ktime.Clock that measures the time that a task has spent
// executing.
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

// signalNotifier is a ktime.Listener that sends signals to a ThreadGroup.
//
// +stateify savable
type signalNotifier struct {
	tg         *ThreadGroup
	signal     linux.Signal
	realTimer  bool
	includeSys bool
}

// Notify implements ktime.TimerListener.Notify.
func (s *signalNotifier) Notify(exp uint64) {
	// Since all signals sent using a signalNotifier are standard (not
	// real-time) signals, we can ignore the number of expirations and send
	// only a single signal.
	if s.realTimer {
		// real timer signal sent to leader. See kernel/time/itimer.c:it_real_fn
		s.tg.SendSignal(sigPriv(s.signal))
	} else {
		s.tg.SendTimerSignal(sigPriv(s.signal), s.includeSys)
	}
}

// Destroy implements ktime.TimerListener.Destroy.
func (s *signalNotifier) Destroy() {}

// TimerManager is a collection of supported process cpu timers.
//
// +stateify savable
type TimerManager struct {
	// Clocks used to drive thread group execution time timers.
	virtClock *tgClock
	profClock *tgClock

	RealTimer      *ktime.Timer
	VirtualTimer   *ktime.Timer
	ProfTimer      *ktime.Timer
	SoftLimitTimer *ktime.Timer
	HardLimitTimer *ktime.Timer
}

// newTimerManager returns a new instance of TimerManager.
func newTimerManager(tg *ThreadGroup, monotonicClock ktime.Clock) TimerManager {
	virtClock := &tgClock{tg: tg, includeSys: false}
	profClock := &tgClock{tg: tg, includeSys: true}
	tm := TimerManager{
		virtClock: virtClock,
		profClock: profClock,
		RealTimer: ktime.NewTimer(monotonicClock, &signalNotifier{
			tg:         tg,
			signal:     linux.SIGALRM,
			realTimer:  true,
			includeSys: false,
		}),
		VirtualTimer: ktime.NewTimer(virtClock, &signalNotifier{
			tg:         tg,
			signal:     linux.SIGVTALRM,
			realTimer:  false,
			includeSys: false,
		}),
		ProfTimer: ktime.NewTimer(profClock, &signalNotifier{
			tg:         tg,
			signal:     linux.SIGPROF,
			realTimer:  false,
			includeSys: true,
		}),
		SoftLimitTimer: ktime.NewTimer(profClock, &signalNotifier{
			tg:         tg,
			signal:     linux.SIGXCPU,
			realTimer:  false,
			includeSys: true,
		}),
		HardLimitTimer: ktime.NewTimer(profClock, &signalNotifier{
			tg:         tg,
			signal:     linux.SIGKILL,
			realTimer:  false,
			includeSys: true,
		}),
	}
	tm.applyCPULimits(tg.Limits().Get(limits.CPU))
	return tm
}

// Save saves this TimerManger.

// destroy destroys all timers.
func (tm *TimerManager) destroy() {
	tm.RealTimer.Destroy()
	tm.VirtualTimer.Destroy()
	tm.ProfTimer.Destroy()
	tm.SoftLimitTimer.Destroy()
	tm.HardLimitTimer.Destroy()
}

func (tm *TimerManager) applyCPULimits(l limits.Limit) {
	tm.SoftLimitTimer.Swap(ktime.Setting{
		Enabled: l.Cur != limits.Infinity,
		Next:    ktime.FromNanoseconds((time.Duration(l.Cur) * time.Second).Nanoseconds()),
		Period:  time.Second,
	})
	tm.HardLimitTimer.Swap(ktime.Setting{
		Enabled: l.Max != limits.Infinity,
		Next:    ktime.FromNanoseconds((time.Duration(l.Max) * time.Second).Nanoseconds()),
	})
}

// kick is called when the number of threads in the thread group associated
// with tm increases.
func (tm *TimerManager) kick() {
	tm.virtClock.Notify(ktime.ClockEventRateIncrease)
	tm.profClock.Notify(ktime.ClockEventRateIncrease)
}

// pause is to pause the timers and stop timer signal delivery.
func (tm *TimerManager) pause() {
	tm.RealTimer.Pause()
	tm.VirtualTimer.Pause()
	tm.ProfTimer.Pause()
	tm.SoftLimitTimer.Pause()
	tm.HardLimitTimer.Pause()
}

// resume is to resume the timers and continue timer signal delivery.
func (tm *TimerManager) resume() {
	tm.RealTimer.Resume()
	tm.VirtualTimer.Resume()
	tm.ProfTimer.Resume()
	tm.SoftLimitTimer.Resume()
	tm.HardLimitTimer.Resume()
}
