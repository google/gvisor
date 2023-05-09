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
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// IntervalTimer represents a POSIX interval timer as described by
// timer_create(2).
//
// +stateify savable
type IntervalTimer struct {
	timer *ktime.Timer

	// If target is not nil, it receives signo from timer expirations. If group
	// is true, these signals are thread-group-directed. These fields are
	// immutable.
	target *Task
	signo  linux.Signal
	id     linux.TimerID
	sigval uint64
	group  bool

	// If sigpending is true, a signal to target is already queued, and timer
	// expirations should increment overrunCur instead of sending another
	// signal. sigpending is protected by target's signal mutex. (If target is
	// nil, the timer will never send signals, so sigpending will be unused.)
	sigpending bool

	// If sigorphan is true, timer's setting has been changed since sigpending
	// last became true, such that overruns should no longer be counted in the
	// pending signals si_overrun. sigorphan is protected by target's signal
	// mutex.
	sigorphan bool

	// overrunCur is the number of overruns that have occurred since the last
	// time a signal was sent. overrunCur is protected by target's signal
	// mutex.
	overrunCur uint64

	// Consider the last signal sent by this timer that has been dequeued.
	// overrunLast is the number of overruns that occurred between when this
	// signal was sent and when it was dequeued. Equivalently, overrunLast was
	// the value of overrunCur when this signal was dequeued. overrunLast is
	// protected by target's signal mutex.
	overrunLast uint64
}

// DestroyTimer releases it's resources.
func (it *IntervalTimer) DestroyTimer() {
	it.timer.Destroy()
	it.timerSettingChanged()
	// A destroyed IntervalTimer is still potentially reachable via a
	// pendingSignal; nil out timer so that it won't be saved.
	it.timer = nil
}

func (it *IntervalTimer) timerSettingChanged() {
	if it.target == nil {
		return
	}
	it.target.tg.pidns.owner.mu.RLock()
	defer it.target.tg.pidns.owner.mu.RUnlock()
	it.target.tg.signalHandlers.mu.Lock()
	defer it.target.tg.signalHandlers.mu.Unlock()
	it.sigorphan = true
	it.overrunCur = 0
	it.overrunLast = 0
}

// PauseTimer pauses the associated Timer.
func (it *IntervalTimer) PauseTimer() {
	it.timer.Pause()
}

// ResumeTimer resumes the associated Timer.
func (it *IntervalTimer) ResumeTimer() {
	it.timer.Resume()
}

// Preconditions: it.target's signal mutex must be locked.
func (it *IntervalTimer) updateDequeuedSignalLocked(si *linux.SignalInfo) {
	it.sigpending = false
	if it.sigorphan {
		return
	}
	it.overrunLast = it.overrunCur
	it.overrunCur = 0
	si.SetOverrun(saturateI32FromU64(it.overrunLast))
}

// Preconditions: it.target's signal mutex must be locked.
func (it *IntervalTimer) signalRejectedLocked() {
	it.sigpending = false
	if it.sigorphan {
		return
	}
	it.overrunCur++
}

// NotifyTimer implements ktime.TimerListener.NotifyTimer.
func (it *IntervalTimer) NotifyTimer(exp uint64, setting ktime.Setting) (ktime.Setting, bool) {
	if it.target == nil {
		return ktime.Setting{}, false
	}

	it.target.tg.pidns.owner.mu.RLock()
	defer it.target.tg.pidns.owner.mu.RUnlock()
	it.target.tg.signalHandlers.mu.Lock()
	defer it.target.tg.signalHandlers.mu.Unlock()

	if it.sigpending {
		it.overrunCur += exp
		return ktime.Setting{}, false
	}

	// sigpending must be set before sendSignalTimerLocked() so that it can be
	// unset if the signal is discarded (in which case sendSignalTimerLocked()
	// will return nil).
	it.sigpending = true
	it.sigorphan = false
	it.overrunCur += exp - 1
	si := &linux.SignalInfo{
		Signo: int32(it.signo),
		Code:  linux.SI_TIMER,
	}
	si.SetTimerID(it.id)
	si.SetSigval(it.sigval)
	// si_overrun is set when the signal is dequeued.
	if err := it.target.sendSignalTimerLocked(si, it.group, it); err != nil {
		it.signalRejectedLocked()
	}

	return ktime.Setting{}, false
}

// IntervalTimerCreate implements timer_create(2).
func (t *Task) IntervalTimerCreate(c ktime.Clock, sigev *linux.Sigevent) (linux.TimerID, error) {
	t.tg.timerMu.Lock()
	defer t.tg.timerMu.Unlock()

	// Allocate a timer ID.
	var id linux.TimerID
	end := t.tg.nextTimerID
	for {
		id = t.tg.nextTimerID
		_, ok := t.tg.timers[id]
		t.tg.nextTimerID++
		if t.tg.nextTimerID < 0 {
			t.tg.nextTimerID = 0
		}
		if !ok {
			break
		}
		if t.tg.nextTimerID == end {
			return 0, linuxerr.EAGAIN
		}
	}

	// "The implementation of the default case where evp [sic] is NULL is
	// handled inside glibc, which invokes the underlying system call with a
	// suitably populated sigevent structure." - timer_create(2). This is
	// misleading; the timer_create syscall also handles a NULL sevp as
	// described by the man page
	// (kernel/time/posix-timers.c:sys_timer_create(), do_timer_create()). This
	// must be handled here instead of the syscall wrapper since sigval is the
	// timer ID, which isn't available until we allocate it in this function.
	if sigev == nil {
		sigev = &linux.Sigevent{
			Signo:  int32(linux.SIGALRM),
			Notify: linux.SIGEV_SIGNAL,
			Value:  uint64(id),
		}
	}

	// Construct the timer.
	it := &IntervalTimer{
		id:     id,
		sigval: sigev.Value,
	}
	switch sigev.Notify {
	case linux.SIGEV_NONE:
		// leave it.target = nil
	case linux.SIGEV_SIGNAL, linux.SIGEV_THREAD:
		// POSIX SIGEV_THREAD semantics are implemented in userspace by libc;
		// to the kernel, SIGEV_THREAD and SIGEV_SIGNAL are equivalent. (See
		// Linux's kernel/time/posix-timers.c:good_sigevent().)
		it.target = t.tg.leader
		it.group = true
	case linux.SIGEV_THREAD_ID:
		t.tg.pidns.owner.mu.RLock()
		target, ok := t.tg.pidns.tasks[ThreadID(sigev.Tid)]
		t.tg.pidns.owner.mu.RUnlock()
		if !ok || target.tg != t.tg {
			return 0, linuxerr.EINVAL
		}
		it.target = target
	default:
		return 0, linuxerr.EINVAL
	}
	if sigev.Notify != linux.SIGEV_NONE {
		it.signo = linux.Signal(sigev.Signo)
		if !it.signo.IsValid() {
			return 0, linuxerr.EINVAL
		}
	}
	it.timer = ktime.NewTimer(c, it)

	t.tg.timers[id] = it
	return id, nil
}

// IntervalTimerDelete implements timer_delete(2).
func (t *Task) IntervalTimerDelete(id linux.TimerID) error {
	t.tg.timerMu.Lock()
	defer t.tg.timerMu.Unlock()
	it := t.tg.timers[id]
	if it == nil {
		return linuxerr.EINVAL
	}
	delete(t.tg.timers, id)
	it.DestroyTimer()
	return nil
}

// IntervalTimerSettime implements timer_settime(2).
func (t *Task) IntervalTimerSettime(id linux.TimerID, its linux.Itimerspec, abs bool) (linux.Itimerspec, error) {
	t.tg.timerMu.Lock()
	defer t.tg.timerMu.Unlock()
	it := t.tg.timers[id]
	if it == nil {
		return linux.Itimerspec{}, linuxerr.EINVAL
	}

	newS, err := ktime.SettingFromItimerspec(its, abs, it.timer.Clock())
	if err != nil {
		return linux.Itimerspec{}, err
	}
	tm, oldS := it.timer.SwapAnd(newS, it.timerSettingChanged)
	its = ktime.ItimerspecFromSetting(tm, oldS)
	return its, nil
}

// IntervalTimerGettime implements timer_gettime(2).
func (t *Task) IntervalTimerGettime(id linux.TimerID) (linux.Itimerspec, error) {
	t.tg.timerMu.Lock()
	defer t.tg.timerMu.Unlock()
	it := t.tg.timers[id]
	if it == nil {
		return linux.Itimerspec{}, linuxerr.EINVAL
	}

	tm, s := it.timer.Get()
	its := ktime.ItimerspecFromSetting(tm, s)
	return its, nil
}

// IntervalTimerGetoverrun implements timer_getoverrun(2).
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) IntervalTimerGetoverrun(id linux.TimerID) (int32, error) {
	t.tg.timerMu.Lock()
	defer t.tg.timerMu.Unlock()
	it := t.tg.timers[id]
	if it == nil {
		return 0, linuxerr.EINVAL
	}
	// By timer_create(2) invariant, either it.target == nil (in which case
	// it.overrunLast is immutably 0) or t.tg == it.target.tg; and the fact
	// that t is executing timer_getoverrun(2) means that t.tg can't be
	// completing execve, so t.tg.signalHandlers can't be changing, allowing us
	// to lock t.tg.signalHandlers.mu without holding the TaskSet mutex.
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	// This is consistent with Linux after 78c9c4dfbf8c ("posix-timers:
	// Sanitize overrun handling").
	return saturateI32FromU64(it.overrunLast), nil
}

func saturateI32FromU64(x uint64) int32 {
	if x > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(x)
}
