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
	"math"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// Getitimer implements getitimer(2).
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) Getitimer(id int32) (linux.ItimerVal, error) {
	var timer ktime.Timer
	switch id {
	case linux.ITIMER_REAL:
		timer = t.tg.itimerRealTimer
	case linux.ITIMER_VIRTUAL:
		timer = &t.tg.itimerVirtTimer
	case linux.ITIMER_PROF:
		timer = &t.tg.itimerProfTimer
	default:
		return linux.ItimerVal{}, linuxerr.EINVAL
	}
	tm, s := timer.Get()
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
	var (
		timer ktime.Timer
		last  *atomic.Pointer[Task]
	)
	switch id {
	case linux.ITIMER_REAL:
		timer = t.tg.itimerRealTimer
	case linux.ITIMER_VIRTUAL:
		timer = &t.tg.itimerVirtTimer
		last = &t.tg.appCPUClockLast
	case linux.ITIMER_PROF:
		timer = &t.tg.itimerProfTimer
		last = &t.tg.appSysCPUClockLast
	default:
		return linux.ItimerVal{}, linuxerr.EINVAL
	}
	news, err := ktime.SettingFromSpec(newitv.Value.ToDuration(), newitv.Interval.ToDuration(), timer.Clock())
	if err != nil {
		return linux.ItimerVal{}, err
	}
	if last != nil {
		last.Store(t)
	}
	tm, olds := timer.Set(news, nil)
	oldval, oldiv := ktime.SpecFromSetting(tm, olds)
	return linux.ItimerVal{
		Value:    linux.DurationToTimeval(oldval),
		Interval: linux.DurationToTimeval(oldiv),
	}, nil
}

// NotifyRlimitCPUUpdated is called by setrlimit.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) NotifyRlimitCPUUpdated() {
	t.tg.notifyRlimitCPUUpdated(t)
}

func (tg *ThreadGroup) notifyRlimitCPUUpdated(t *Task) {
	// Lock tg.timerMu to synchronize updates to these timers between tasks in
	// tg.
	tg.timerMu.Lock()
	defer tg.timerMu.Unlock()
	rlimitCPU := tg.limits.Get(limits.CPU)
	tg.appSysCPUClockLast.Store(t)
	tg.rlimitCPUSoftTimer.Set(ktime.Setting{
		Enabled: rlimitCPU.Cur != limits.Infinity,
		Next:    ktime.FromSeconds(int64(min(rlimitCPU.Cur, math.MaxInt64))),
		Period:  time.Second,
	}, nil)
	tg.rlimitCPUHardTimer.Set(ktime.Setting{
		Enabled: rlimitCPU.Max != limits.Infinity,
		Next:    ktime.FromSeconds(int64(min(rlimitCPU.Max, math.MaxInt64))),
	}, nil)
}

// +stateify savable
type itimerRealListener struct {
	tg *ThreadGroup
}

// NotifyTimer implements ktime.Listener.NotifyTimer.
func (l *itimerRealListener) NotifyTimer(exp uint64) {
	l.tg.SendSignal(SignalInfoPriv(linux.SIGALRM))
}

// +stateify savable
type itimerVirtListener struct {
	tg *ThreadGroup
}

// NotifyTimer implements ktime.Listener.NotifyTimer.
func (l *itimerVirtListener) NotifyTimer(exp uint64) {
	l.tg.appCPUClockLast.Load().SendGroupSignal(SignalInfoPriv(linux.SIGVTALRM))
}

// +stateify savable
type itimerProfListener struct {
	tg *ThreadGroup
}

// NotifyTimer implements ktime.Listener.NotifyTimer.
func (l *itimerProfListener) NotifyTimer(exp uint64) {
	l.tg.appSysCPUClockLast.Load().SendGroupSignal(SignalInfoPriv(linux.SIGPROF))
}

// +stateify savable
type rlimitCPUSoftListener struct {
	tg *ThreadGroup
}

// NotifyTimer implements ktime.Listener.NotifyTimer.
func (l *rlimitCPUSoftListener) NotifyTimer(exp uint64) {
	l.tg.appSysCPUClockLast.Load().SendGroupSignal(SignalInfoPriv(linux.SIGXCPU))
}

// +stateify savable
type rlimitCPUHardListener struct {
	tg *ThreadGroup
}

// NotifyTimer implements ktime.Listener.NotifyTimer.
func (l *rlimitCPUHardListener) NotifyTimer(exp uint64) {
	l.tg.appSysCPUClockLast.Load().SendGroupSignal(SignalInfoPriv(linux.SIGKILL))
}

// IOUsage returns the io usage of the thread.
func (t *Task) IOUsage() *usage.IO {
	return t.ioUsage
}

// IOUsage returns the total io usage of all dead and live threads in the group.
func (tg *ThreadGroup) IOUsage() *usage.IO {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()

	var io usage.IO
	tg.ioUsage.Clone(&io)
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
	return t.image.Name
}

// SetName changes t's name.
func (t *Task) SetName(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.image.Name = name
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
