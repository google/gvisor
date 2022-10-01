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
	"os"
	"runtime"
	"runtime/trace"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

var globalTGID = int32(os.Getpid())

// BlockWithTimeout blocks t until an event is received from C, the application
// monotonic clock indicates that timeout has elapsed (only if haveTimeout is true),
// or t is interrupted. It returns:
//
//   - The remaining timeout, which is guaranteed to be 0 if the timeout expired,
//     and is unspecified if haveTimeout is false.
//
//   - An error which is nil if an event is received from C, ETIMEDOUT if the timeout
//     expired, and linuxerr.ErrInterrupted if t is interrupted.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) BlockWithTimeout(C chan struct{}, haveTimeout bool, timeout time.Duration) (time.Duration, error) {
	if !haveTimeout {
		return timeout, t.block(C, nil)
	}

	start := t.Kernel().MonotonicClock().Now()
	deadline := start.Add(timeout)
	err := t.BlockWithDeadline(C, true, deadline)

	// Timeout, explicitly return a remaining duration of 0.
	if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
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

// BlockWithTimeoutOn implements context.Context.BlockWithTimeoutOn.
func (t *Task) BlockWithTimeoutOn(w waiter.Waitable, mask waiter.EventMask, timeout time.Duration) (time.Duration, bool) {
	e, ch := waiter.NewChannelEntry(mask)
	w.EventRegister(&e)
	defer w.EventUnregister(&e)
	left, err := t.BlockWithTimeout(ch, true, timeout)
	return left, err == nil
}

// BlockWithDeadline blocks t until it is woken by an event, the
// application monotonic clock indicates a time of deadline (only if
// haveDeadline is true), or t is interrupted. It returns nil if an event is
// received from C, ETIMEDOUT if the deadline expired, and
// linuxerr.ErrInterrupted if t is interrupted.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) BlockWithDeadline(C <-chan struct{}, haveDeadline bool, deadline ktime.Time) error {
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
// event is received from tchan, and linuxerr.ErrInterrupted if t is
// interrupted.
//
// Most clients should use BlockWithDeadline or BlockWithTimeout instead.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) BlockWithTimer(C <-chan struct{}, tchan <-chan struct{}) error {
	return t.block(C, tchan)
}

// Block blocks t until an event is received from C or t is interrupted. It
// returns nil if an event is received from C and linuxerr.ErrInterrupted if t
// is interrupted.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) Block(C <-chan struct{}) error {
	return t.block(C, nil)
}

// BlockOn implements context.Context.BlockOn.
func (t *Task) BlockOn(w waiter.Waitable, mask waiter.EventMask) bool {
	e, ch := waiter.NewChannelEntry(mask)
	w.EventRegister(&e)
	defer w.EventUnregister(&e)
	err := t.Block(ch)
	return err == nil
}

// block blocks a task on one of many events.
// N.B. defer is too expensive to be used here.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) block(C <-chan struct{}, timerChan <-chan struct{}) error {
	// This function is very hot; skip this check outside of +race builds.
	if sync.RaceEnabled {
		t.assertTaskGoroutine()
	}

	// Fast path if the request is already done.
	select {
	case <-C:
		return nil
	default:
	}

	// Deactive our address space, we don't need it.
	t.prepareSleep()
	defer t.completeSleep()

	// If the request is not completed, but the timer has already expired,
	// then ensure that we run through a scheduler cycle. This is because
	// we may see applications relying on timer slack to yield the thread.
	// For example, they may attempt to sleep for some number of nanoseconds,
	// and expect that this will actually yield the CPU and sleep for at
	// least microseconds, e.g.:
	// https://github.com/LMAX-Exchange/disruptor/commit/6ca210f2bcd23f703c479804d583718e16f43c07
	if len(timerChan) > 0 {
		runtime.Gosched()
	}

	region := trace.StartRegion(t.traceContext, blockRegion)
	select {
	case <-C:
		region.End()
		// Woken by event.
		return nil

	case <-t.interruptChan:
		region.End()
		// Ensure that Task.interrupted() will return true once we return to
		// the task run loop.
		t.interruptSelf()
		// Return the indicated error on interrupt.
		return linuxerr.ErrInterrupted

	case <-timerChan:
		region.End()
		// We've timed out.
		return linuxerr.ETIMEDOUT
	}
}

// prepareSleep prepares to sleep.
func (t *Task) prepareSleep() {
	t.assertTaskGoroutine()
	t.Deactivate()
	t.accountTaskGoroutineEnter(TaskGoroutineBlockedInterruptible)
}

// completeSleep reactivates the address space.
func (t *Task) completeSleep() {
	t.accountTaskGoroutineLeave(TaskGoroutineBlockedInterruptible)
	t.Activate()
}

// BlockFD blocks until the given host FD is ready for at least one of the
// given I/O events or t is interrupted. It returns the set of ready events for
// fd.
func (t *Task) BlockFD(fd int32, mask waiter.EventMask) (waiter.EventMask, error) {
	pfds := []linux.PollFD{
		{
			FD:     fd,
			Events: int16(mask.ToLinux()),
		},
	}
	_, err := t.blockPoll(pfds, nil)
	if err != nil {
		return 0, err
	}
	return waiter.EventMaskFromLinux(uint32(pfds[0].REvents)), nil
}

// BlockFDWithDeadline is equivalent to BlockFD, but if haveDeadline is true,
// it returns ETIMEDOUT if the deadline expires before fd becomes ready.
func (t *Task) BlockFDWithDeadline(fd int32, mask waiter.EventMask, haveDeadline bool, deadline ktime.Time) (waiter.EventMask, error) {
	if !haveDeadline {
		return t.BlockFD(fd, mask)
	}

	pfds := []linux.PollFD{
		{
			FD:     fd,
			Events: int16(mask.ToLinux()),
		},
	}
	var timeout linux.Timespec
	if now := t.Kernel().MonotonicClock().Now(); now.Before(deadline) {
		timeout = linux.DurationToTimespec(deadline.Sub(now))
	}
	_, err := t.blockPoll(pfds, &timeout)
	if err != nil {
		return 0, err
	}
	return waiter.EventMaskFromLinux(uint32(pfds[0].REvents)), nil
}

func (t *Task) blockPoll(pfds []linux.PollFD, timeout *linux.Timespec) (int, error) {
	if sync.RaceEnabled {
		t.assertTaskGoroutine()
	}

	t.prepareSleep()
	defer t.completeSleep()
	region := trace.StartRegion(t.traceContext, blockRegion)
	defer region.End()

	return t.blockPollUnsafe(pfds, timeout)
}

// Interrupted implements context.Context.Interrupted.
func (t *Task) Interrupted() bool {
	if t.interrupted() {
		return true
	}
	// Indicate that t's task goroutine is still responsive (i.e. reset the
	// watchdog timer).
	t.accountTaskGoroutineRunning()
	return false
}

// UninterruptibleSleepStart implements context.Context.UninterruptibleSleepStart.
func (t *Task) UninterruptibleSleepStart(deactivate bool) {
	t.assertTaskGoroutine()
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
// least once since the last call to unsetInterrupted.
func (t *Task) interrupted() bool {
	return len(t.interruptChan) != 0
}

// unsetInterrupted causes interrupted to return false until the next call to
// interrupt or interruptSelf.
func (t *Task) unsetInterrupted() {
	select {
	case <-t.interruptChan:
	default:
	}
}

// interrupt unblocks the task and interrupts it if it's currently running in
// userspace.
func (t *Task) interrupt() {
	t.interruptSelf()
	if tid := t.syscallTID.Load(); tid != 0 {
		if err := unix.Tgkill(int(globalTGID), int(tid), unix.Signal(SignalInterruptSyscall)); err != nil && err != unix.ESRCH {
			log.Warningf("failed to tgkill blocked task goroutine thread %d: %v", tid, err)
		}
	}
	t.p.Interrupt()
}

// interruptSelf is like Interrupt, but can only be called by the task
// goroutine.
func (t *Task) interruptSelf() {
	select {
	case t.interruptChan <- struct{}{}:
	default:
	}
	// Checking syscallTID and calling platform.Context.Interrupt() are
	// unnecessary since a task goroutine calling interruptSelf() cannot also be
	// blocked in a host syscall or platform.Context.Switch().
}

// Interrupt implements context.Blocker.Interrupt.
func (t *Task) Interrupt() {
	t.interrupt()
}
