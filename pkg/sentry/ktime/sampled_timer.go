// Copyright 2024 The gVisor Authors.
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

package ktime

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SampledTimer implements Timer using a goroutine that reads a SampledClock
// whenever an expiration is expected to have occurred.
//
// +stateify savable
type SampledTimer struct {
	// clock is the time source. clock is protected by mu and clockSeq.
	clockSeq sync.SeqCount `state:"nosave"`
	clock    SampledClock

	// listener is notified of expirations. listener is immutable.
	listener Listener

	// mu protects the following mutable fields.
	mu sync.Mutex `state:"nosave"`

	// setting is the timer setting. setting is protected by mu.
	setting Setting

	pauseState timerPauseState

	// kicker is used to wake the SampledTimer goroutine. The kicker pointer is
	// immutable, but its state is protected by mu.
	kicker *time.Timer `state:"nosave"`

	// entry is registered with clock.EventRegister. entry is immutable.
	//
	// Per comment in SampledClock, entry must be re-registered after restore;
	// per comment in SampledTimer.Load, this is done in SampledTimer.Resume.
	entry waiter.Entry `state:"nosave"`

	// events is the channel that will be notified whenever entry receives an
	// event. It is also closed by SampledTimer.Destroy to instruct the
	// goroutine to exit.
	events chan struct{} `state:"nosave"`
}

type timerPauseState uint8

const (
	// timerUnpaused indicates that the SampledTimer is neither paused nor
	// destroyed.
	timerUnpaused timerPauseState = iota

	// timerPaused indicates that the SampledTimer is paused, not destroyed.
	timerPaused

	// timerDestroyed indicates that the SampledTimer is destroyed.
	timerDestroyed
)

// NewSampledTimer returns a new SampledTimer consistent with the requirements
// of Clock.NewTimer().
func NewSampledTimer(clock SampledClock, listener Listener) *SampledTimer {
	t := &SampledTimer{
		clock:    clock,
		listener: listener,
	}
	t.init()
	return t
}

// init initializes SampledTimer state that is not preserved across
// save/restore. If init has already been called, calling it again is a no-op.
//
// Preconditions: t.mu must be locked, or the caller must have exclusive access
// to t.
func (t *SampledTimer) init() {
	if t.kicker != nil {
		return
	}
	// If t.kicker is nil, the goroutine can't be running, so we can't race
	// with it.
	t.kicker = time.NewTimer(0)
	t.entry, t.events = waiter.NewChannelEntry(timerTickEvents)
	if err := t.clock.EventRegister(&t.entry); err != nil {
		panic(err)
	}
	go t.runGoroutine() // S/R-SAFE: synchronized by t.mu
}

// Destroy implements Timer.Destroy.
func (t *SampledTimer) Destroy() {
	// Stop the timer, ensuring that the goroutine will not call
	// t.kicker.Reset, before calling t.kicker.Stop.
	t.mu.Lock()
	t.setting.Enabled = false
	// Set timerDestroyed to prevent t.tick() from mutating timer state.
	t.pauseState = timerDestroyed
	t.mu.Unlock()
	t.kicker.Stop()
	// Unregister t.entry, ensuring that the Clock will not send to t.events,
	// before closing t.events to instruct the goroutine to exit.
	t.clock.EventUnregister(&t.entry)
	close(t.events)
}

// Pause implements Timer.Pause.
func (t *SampledTimer) Pause() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pauseState != timerUnpaused {
		return
	}
	t.pauseState = timerPaused
	// t.kicker may be nil if we were restored but never resumed.
	if t.kicker != nil {
		t.kicker.Stop()
	}
}

// Resume implements Timer.Resume.
func (t *SampledTimer) Resume() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pauseState != timerPaused {
		return
	}
	t.pauseState = timerUnpaused

	// Lazily initialize the SampledTimer. We can't call SampledTimer.init
	// until SampledTimer.Resume because save/restore will restore Timers
	// before kernel.Timekeeper.SetClocks() has been called, so if t.clock is
	// backed by a kernel.Timekeeper then the goroutine will panic if it calls
	// t.clock.Now().
	t.init()

	// Kick the goroutine in case it was already initialized, but the goroutine
	// was sleeping.
	t.kicker.Reset(0)
}

// Clock implements Timer.Clock.
func (t *SampledTimer) Clock() Clock {
	return SeqAtomicLoadSampledClock(&t.clockSeq, &t.clock)
}

// Get implements Timer.Get.
func (t *SampledTimer) Get() (Time, Setting) {
	// Optimistically read t.Clock().Now() before locking t.mu, as t.clock is
	// unlikely to change.
	unlockedClock := t.Clock()
	now := unlockedClock.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pauseState != timerUnpaused {
		panic(fmt.Sprintf("SampledTimer(%p).Get called in pause state %v", t, t.pauseState))
	}
	if t.clock != unlockedClock {
		now = t.clock.Now()
	}
	s, exp := t.setting.At(now)
	t.setting = s
	if exp > 0 {
		t.listener.NotifyTimer(exp)
	}
	t.resetKickerLocked(now)
	return now, s
}

// Set implements Timer.Set.
func (t *SampledTimer) Set(s Setting, f func()) (Time, Setting) {
	// Optimistically read t.Clock().Now() before locking t.mu, as t.clock is
	// unlikely to change.
	unlockedClock := t.Clock()
	now := unlockedClock.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pauseState != timerUnpaused {
		panic(fmt.Sprintf("SampledTimer(%p).Set called in pause state %v", t, t.pauseState))
	}
	if t.clock != unlockedClock {
		now = t.clock.Now()
	}
	oldS, oldExp := t.setting.At(now)
	if oldExp > 0 {
		t.listener.NotifyTimer(oldExp)
	}
	if f != nil {
		f()
	}
	newS, newExp := s.At(now)
	t.setting = newS
	if newExp > 0 {
		t.listener.NotifyTimer(newExp)
	}
	t.resetKickerLocked(now)
	return now, oldS
}

// SetClock atomically changes a SampledTimer's Clock and Setting.
func (t *SampledTimer) SetClock(c SampledClock, s Setting) {
	var now Time
	if s.Enabled {
		now = c.Now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setting = s
	if oldC := t.clock; oldC != c {
		oldC.EventUnregister(&t.entry)
		c.EventRegister(&t.entry)
		t.clockSeq.BeginWrite()
		t.clock = c
		t.clockSeq.EndWrite()
	}
	t.resetKickerLocked(now)
}

func (t *SampledTimer) runGoroutine() {
	for {
		select {
		case <-t.kicker.C:
		case _, ok := <-t.events:
			if !ok {
				// Channel closed by Destroy.
				return
			}
		}
		t.tick()
	}
}

// tick requests that the SampledTimer immediately check for expirations and
// re-evaluate when it should next check for expirations.
func (t *SampledTimer) tick() {
	// Optimistically read t.Clock().Now() before locking t.mu, as t.clock is
	// unlikely to change.
	unlockedClock := t.Clock()
	now := unlockedClock.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pauseState != timerUnpaused {
		return
	}
	if t.clock != unlockedClock {
		now = t.clock.Now()
	}
	s, exp := t.setting.At(now)
	t.setting = s
	if exp > 0 {
		t.listener.NotifyTimer(exp)
	}
	t.resetKickerLocked(now)
}

// Preconditions: t.mu must be locked.
func (t *SampledTimer) resetKickerLocked(now Time) {
	if t.setting.Enabled {
		// Clock.WallTimeUntil may return a negative value. This is fine;
		// time.when treats negative Durations as 0.
		t.kicker.Reset(t.clock.WallTimeUntil(t.setting.Next, now))
	}
	// We don't call t.kicker.Stop if !t.setting.Enabled because in most cases
	// resetKickerLocked will be called from the SampledTimer goroutine, in
	// which case t.kicker has already fired and t.kicker.Stop will be an
	// expensive no-op (time.Timer.Stop => time.stopTimer => runtime.stopTimer
	// => runtime.deltimer).
}

// A SampledClock is a Clock that can be a time source for a SampledTimer.
type SampledClock interface {
	Clock

	// WallTimeUntil returns the estimated wall time until Now will return a
	// value greater than or equal to t, given that a recent call to Now
	// returned now. If t has already passed, WallTimeUntil may return 0 or a
	// negative value.
	//
	// WallTimeUntil must be abstract to support SampledClocks that do not
	// represent wall time (e.g. thread group execution timers). SampledClocks
	// that represent wall times may embed the WallRateClock type to obtain an
	// appropriate trivial implementation of WallTimeUntil.
	//
	// WallTimeUntil is used to determine when associated SampledTimers should
	// next check for expirations. Returning too small a value may result in
	// spurious SampledTimer goroutine wakeups, while returning too large a
	// value may result in late expirations. Implementations should usually err
	// on the side of underestimating.
	WallTimeUntil(t, now Time) time.Duration

	// Waitable methods may be used to subscribe to SampledClock events.
	// Waiters will not be preserved by Save and must be re-established during
	// restore.
	//
	// Since SampledClock events are transient, implementations of
	// waiter.Waitable.Readiness should return 0.
	waiter.Waitable
}

// Events that may be generated by a SampledClock.
const (
	// ClockEventSet occurs when a SampledClock undergoes a discontinuous
	// change.
	ClockEventSet waiter.EventMask = 1 << iota

	// ClockEventRateIncrease occurs when the rate at which a SampledClock
	// advances increases significantly, such that values returned by previous
	// calls to Clock.WallTimeUntil may be too large.
	ClockEventRateIncrease
)

// timerTickEvents are SampledClock events that require the Timer goroutine to
// Tick prematurely.
const timerTickEvents = ClockEventSet | ClockEventRateIncrease

// WallRateClock implements SampledClock.WallTimeUntil for Clocks that elapse
// at the same rate as wall time.
type WallRateClock struct{}

// WallTimeUntil implements SampledClock.WallTimeUntil.
func (*WallRateClock) WallTimeUntil(t, now Time) time.Duration {
	return t.Sub(now)
}

// NoClockEvents implements waiter.Waitable for SampledClocks that do not
// generate events.
type NoClockEvents struct{}

// Readiness implements waiter.Waitable.Readiness.
func (*NoClockEvents) Readiness(mask waiter.EventMask) waiter.EventMask {
	return 0
}

// EventRegister implements waiter.Waitable.EventRegister.
func (*NoClockEvents) EventRegister(e *waiter.Entry) error {
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (*NoClockEvents) EventUnregister(e *waiter.Entry) {
}

// ClockEventsQueue implements waiter.Waitable by wrapping waiter.Queue and
// defining waiter.Waitable.Readiness as required by SampledClock.
type ClockEventsQueue struct {
	waiter.Queue
}

// EventRegister implements waiter.Waitable.
func (c *ClockEventsQueue) EventRegister(e *waiter.Entry) error {
	c.Queue.EventRegister(e)
	return nil
}

// Readiness implements waiter.Waitable.Readiness.
func (*ClockEventsQueue) Readiness(mask waiter.EventMask) waiter.EventMask {
	return 0
}
