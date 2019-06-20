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

// Accounting, limits, timers.

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Getitimer implements getitimer(2).
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) Getitimer(id int32) (linux.ItimerVal, error) {
	var tm ktime.Time
	var s ktime.Setting
	switch id {
	case linux.ITIMER_REAL:
		tm, s = t.tg.itimerRealTimer.Get()
	case linux.ITIMER_VIRTUAL:
		tm = t.tg.UserCPUClock().Now()
		t.tg.signalHandlers.mu.Lock()
		s, _ = t.tg.itimerVirtSetting.At(tm)
		t.tg.signalHandlers.mu.Unlock()
	case linux.ITIMER_PROF:
		tm = t.tg.CPUClock().Now()
		t.tg.signalHandlers.mu.Lock()
		s, _ = t.tg.itimerProfSetting.At(tm)
		t.tg.signalHandlers.mu.Unlock()
	default:
		return linux.ItimerVal{}, syserror.EINVAL
	}
	val, iv := ktime.SpecFromSetting(tm, s)
	return linux.ItimerVal{
		Value:    linux.DurationToTimeval(val),
		Interval: linux.DurationToTimeval(iv),
	}, nil
}

// Setitimer implements setitimer(2).
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) Setitimer(id int32, newitv linux.ItimerVal) (linux.ItimerVal, error) {
	var tm ktime.Time
	var olds ktime.Setting
	switch id {
	case linux.ITIMER_REAL:
		news, err := ktime.SettingFromSpec(newitv.Value.ToDuration(), newitv.Interval.ToDuration(), t.tg.itimerRealTimer.Clock())
		if err != nil {
			return linux.ItimerVal{}, err
		}
		tm, olds = t.tg.itimerRealTimer.Swap(news)
	case linux.ITIMER_VIRTUAL:
		c := t.tg.UserCPUClock()
		var err error
		t.k.cpuClockTicker.Atomically(func() {
			tm = c.Now()
			var news ktime.Setting
			news, err = ktime.SettingFromSpecAt(newitv.Value.ToDuration(), newitv.Interval.ToDuration(), tm)
			if err != nil {
				return
			}
			t.tg.signalHandlers.mu.Lock()
			olds = t.tg.itimerVirtSetting
			t.tg.itimerVirtSetting = news
			t.tg.updateCPUTimersEnabledLocked()
			t.tg.signalHandlers.mu.Unlock()
		})
		if err != nil {
			return linux.ItimerVal{}, err
		}
	case linux.ITIMER_PROF:
		c := t.tg.CPUClock()
		var err error
		t.k.cpuClockTicker.Atomically(func() {
			tm = c.Now()
			var news ktime.Setting
			news, err = ktime.SettingFromSpecAt(newitv.Value.ToDuration(), newitv.Interval.ToDuration(), tm)
			if err != nil {
				return
			}
			t.tg.signalHandlers.mu.Lock()
			olds = t.tg.itimerProfSetting
			t.tg.itimerProfSetting = news
			t.tg.updateCPUTimersEnabledLocked()
			t.tg.signalHandlers.mu.Unlock()
		})
		if err != nil {
			return linux.ItimerVal{}, err
		}
	default:
		return linux.ItimerVal{}, syserror.EINVAL
	}
	oldval, oldiv := ktime.SpecFromSetting(tm, olds)
	return linux.ItimerVal{
		Value:    linux.DurationToTimeval(oldval),
		Interval: linux.DurationToTimeval(oldiv),
	}, nil
}

// IOUsage returns the io usage of the thread.
func (t *Task) IOUsage() *usage.IO {
	return t.ioUsage
}

// IOUsage returns the total io usage of all dead and live threads in the group.
func (tg *ThreadGroup) IOUsage() *usage.IO {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()

	io := *tg.ioUsage
	// Account for active tasks.
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		io.Accumulate(t.IOUsage())
	}
	return &io
}

// Name returns t's name.
func (t *Task) Name() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tc.Name
}

// SetName changes t's name.
func (t *Task) SetName(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tc.Name = name
	t.Debugf("Set thread name to %q", name)
}

// Limits implements context.Context.Limits.
func (t *Task) Limits() *limits.LimitSet {
	return t.ThreadGroup().Limits()
}

// StartTime returns t's start time.
func (t *Task) StartTime() ktime.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.startTime
}

// MaxRSS returns the maximum resident set size of the task in bytes. which
// should be one of RUSAGE_SELF, RUSAGE_CHILDREN, RUSAGE_THREAD, or
// RUSAGE_BOTH. See getrusage(2) for documentation on the behavior of these
// flags.
func (t *Task) MaxRSS(which int32) uint64 {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()

	switch which {
	case linux.RUSAGE_SELF, linux.RUSAGE_THREAD:
		// If there's an active mm we can use its value.
		if mm := t.MemoryManager(); mm != nil {
			if mmMaxRSS := mm.MaxResidentSetSize(); mmMaxRSS > t.tg.maxRSS {
				return mmMaxRSS
			}
		}
		return t.tg.maxRSS
	case linux.RUSAGE_CHILDREN:
		return t.tg.childMaxRSS
	case linux.RUSAGE_BOTH:
		maxRSS := t.tg.maxRSS
		if maxRSS < t.tg.childMaxRSS {
			maxRSS = t.tg.childMaxRSS
		}
		if mm := t.MemoryManager(); mm != nil {
			if mmMaxRSS := mm.MaxResidentSetSize(); mmMaxRSS > maxRSS {
				return mmMaxRSS
			}
		}
		return maxRSS
	default:
		// We'll only get here if which is invalid.
		return 0
	}
}
