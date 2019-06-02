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
	"time"

	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// BlockWithTimeout blocks t until an event is received from C, the application
// monotonic clock indicates that timeout has elapsed (only if haveTimeout is true),
// or t is interrupted. It returns:
//
// - The remaining timeout, which is guaranteed to be 0 if the timeout expired,
// and is unspecified if haveTimeout is false.
//
// - An error which is nil if an event is received from C, ETIMEDOUT if the timeout
// expired, and syserror.ErrInterrupted if t is interrupted.
func (t *Task) BlockWithTimeout(C chan struct{}, haveTimeout bool, timeout time.Duration) (time.Duration, error) {
	if !haveTimeout {
		return timeout, t.block(C, nil)
	}

	start := t.Kernel().MonotonicClock().Now()
	deadline := start.Add(timeout)
	err := t.BlockWithDeadline(C, true, deadline)

	// Timeout, explicitly return a remaining duration of 0.
	if err == syserror.ETIMEDOUT {
		return 0, err
	}

	// Compute the remaining timeout. Note that even if block() above didn't
	// return due to a timeout, we may have used up any of the remaining time
	// since then. We cap the remaining timeout to 0 to make it easier to
	// directly use the returned duration.
	end := t.Kernel().MonotonicClock().Now()
	remainingTimeout := timeout - end.Sub(start)
	if remainingTimeout < 0 {
		remainingTimeout = 0
	}

	return remainingTimeout, err
}

// BlockWithDeadline blocks t until an event is received from C, the
// application monotonic clock indicates a time of deadline (only if
// haveDeadline is true), or t is interrupted. It returns nil if an event is
// received from C, ETIMEDOUT if the deadline expired, and
// syserror.ErrInterrupted if t is interrupted.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) BlockWithDeadline(C chan struct{}, haveDeadline bool, deadline ktime.Time) error {
	if !haveDeadline {
		return t.block(C, nil)
	}

	// Start the timeout timer.
	t.blockingTimer.Swap(ktime.Setting{
		Enabled: true,
		Next:    deadline,
	})

	err := t.block(C, t.blockingTimerChan)

	// Stop the timeout timer and drain the channel.
	t.blockingTimer.Swap(ktime.Setting{})
	select {
	case <-t.blockingTimerChan:
	default:
	}

	return err
}

// BlockWithTimer blocks t until an event is received from C or tchan, or t is
// interrupted. It returns nil if an event is received from C, ETIMEDOUT if an
// event is received from tchan, and syserror.ErrInterrupted if t is
// interrupted.
//
// Most clients should use BlockWithDeadline or BlockWithTimeout instead.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) BlockWithTimer(C <-chan struct{}, tchan <-chan struct{}) error {
	return t.block(C, tchan)
}

// Block blocks t until an event is received from C or t is interrupted. It
// returns nil if an event is received from C and syserror.ErrInterrupted if t
// is interrupted.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) Block(C <-chan struct{}) error {
	return t.block(C, nil)
}

// block blocks a task on one of many events.
// N.B. defer is too expensive to be used here.
func (t *Task) block(C <-chan struct{}, timerChan <-chan struct{}) error {
	// Fast path if the request is already done.
	select {
	case <-C:
		return nil
	default:
	}

	// Deactive our address space, we don't need it.
	interrupt := t.SleepStart()

	select {
	case <-C:
		t.SleepFinish(true)
		return nil

	case <-interrupt:
		t.SleepFinish(false)
		// Return the indicated error on interrupt.
		return syserror.ErrInterrupted

	case <-timerChan:
		// We've timed out.
		t.SleepFinish(true)
		return syserror.ETIMEDOUT
	}
}

// SleepStart implements amutex.Sleeper.SleepStart.
func (t *Task) SleepStart() <-chan struct{} {
	t.Deactivate()
	t.accountTaskGoroutineEnter(TaskGoroutineBlockedInterruptible)
	return t.interruptChan
}

// SleepFinish implements amutex.Sleeper.SleepFinish.
func (t *Task) SleepFinish(success bool) {
	if !success {
		// The interrupted notification is consumed only at the top-level
		// (Run). Therefore we attempt to reset the pending notification.
		// This will also elide our next entry back into the task, so we
		// will process signals, state changes, etc.
		t.interruptSelf()
	}
	t.accountTaskGoroutineLeave(TaskGoroutineBlockedInterruptible)
	t.Activate()
}

// Interrupted implements amutex.Sleeper.Interrupted
func (t *Task) Interrupted() bool {
	return len(t.interruptChan) != 0
}

// UninterruptibleSleepStart implements context.Context.UninterruptibleSleepStart.
func (t *Task) UninterruptibleSleepStart(deactivate bool) {
	if deactivate {
		t.Deactivate()
	}
	t.accountTaskGoroutineEnter(TaskGoroutineBlockedUninterruptible)
}

// UninterruptibleSleepFinish implements context.Context.UninterruptibleSleepFinish.
func (t *Task) UninterruptibleSleepFinish(activate bool) {
	t.accountTaskGoroutineLeave(TaskGoroutineBlockedUninterruptible)
	if activate {
		t.Activate()
	}
}

// interrupted returns true if interrupt or interruptSelf has been called at
// least once since the last call to interrupted.
func (t *Task) interrupted() bool {
	select {
	case <-t.interruptChan:
		return true
	default:
		return false
	}
}

// interrupt unblocks the task and interrupts it if it's currently running in
// userspace.
func (t *Task) interrupt() {
	t.interruptSelf()
	t.p.Interrupt()
}

// interruptSelf is like Interrupt, but can only be called by the task
// goroutine.
func (t *Task) interruptSelf() {
	select {
	case t.interruptChan <- struct{}{}:
		t.Debugf("Interrupt queued")
	default:
		t.Debugf("Dropping duplicate interrupt")
	}
	// platform.Context.Interrupt() is unnecessary since a task goroutine
	// calling interruptSelf() cannot also be blocked in
	// platform.Context.Switch().
}
