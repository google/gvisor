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

package tcp

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

type timerState int

const (
	// The timer has not been initialized yet or has been cleaned up.
	timerUninitialized timerState = iota
	// The timer is disabled.
	timerStateDisabled
	// The timer is enabled, but the clock timer may be set to an earlier
	// expiration time due to a previous orphaned state.
	timerStateEnabled
	// The timer is disabled, but the clock timer is enabled, which means that
	// it will cause a spurious wakeup unless the timer is enabled before the
	// clock timer fires.
	timerStateOrphaned
)

// timer is a timer implementation that reduces the interactions with the
// clock timer infrastructure by letting timers run (and potentially
// eventually expire) even if they are stopped. It makes it cheaper to
// disable/re-enable timers at the expense of spurious wakes. This is useful for
// cases when the same timer is disabled/re-enabled repeatedly with relatively
// long timeouts farther into the future.
//
// TCP retransmit timers benefit from this because they the timeouts are long
// (currently at least 200ms), and get disabled when acks are received, and
// re-enabled when new pending segments are sent.
//
// It is advantageous to avoid interacting with the clock because it acquires
// a global mutex and performs O(log n) operations, where n is the global number
// of timers, whenever a timer is enabled or disabled, and may make a syscall.
//
// This struct is thread-compatible.
type timer struct {
	state timerState

	clock tcpip.Clock

	// target is the expiration time of the current timer. It is only
	// meaningful in the enabled state.
	target tcpip.MonotonicTime

	// clockTarget is the expiration time of the clock timer. It is
	// meaningful in the enabled and orphaned states.
	clockTarget tcpip.MonotonicTime

	// timer is the clock timer used to wait on.
	timer tcpip.Timer

	// callback handles a wakeup from the underlying clock timer.
	callback func()
}

// init registers expired to run under e.mu when the logical deadline is due.
func (t *timer) init(e *Endpoint, expired func() tcpip.Error) {
	t.state = timerStateDisabled
	t.clock = e.stack.Clock()
	t.callback = func() {
		e.handleTimer(func() tcpip.Error {
			if t.consumeClockWake() {
				return expired()
			}
			return nil
		})
	}
}

// cleanup frees all resources associated with the timer.
func (t *timer) cleanup() {
	if t.timer != nil {
		t.timer.Stop()
	}
	*t = timer{}
}

// isUninitialized returns true if the timer is in the uninitialized state. This
// is only true if init() has never been called or if cleanup has been called.
func (t *timer) isUninitialized() bool {
	return t.state == timerUninitialized
}

// consumeClockWake retires canceled wakeups and rearms early ones. It
// disables the timer and returns true only when the current deadline is due.
func (t *timer) consumeClockWake() bool {
	switch t.state {
	case timerUninitialized, timerStateDisabled:
		return false
	case timerStateOrphaned:
		t.state = timerStateDisabled
		return false
	}

	now := t.clock.NowMonotonic()
	if now.Before(t.target) {
		t.clockTarget = t.target
		t.timer.Reset(t.target.Sub(now))
		return false
	}

	t.state = timerStateDisabled
	return true
}

// disable leaves a scheduled timer orphaned until its callback fires.
func (t *timer) disable() {
	if t.state == timerStateEnabled {
		t.state = timerStateOrphaned
	}
}

// enabled returns true if the timer is currently enabled, false otherwise.
func (t *timer) enabled() bool {
	return t.state == timerStateEnabled
}

// enable enables the timer, programming the runtime timer if necessary.
func (t *timer) enable(d time.Duration) {
	t.target = t.clock.NowMonotonic().Add(d)

	// Check if we need to set the runtime timer.
	if t.state == timerStateDisabled || t.target.Before(t.clockTarget) {
		t.clockTarget = t.target
		t.resetOrStart(d)
	}

	t.state = timerStateEnabled
}

// resetOrStart creates the timer if it doesn't already exist or resets it with
// the given duration if it does.
func (t *timer) resetOrStart(d time.Duration) {
	if t.timer == nil {
		t.timer = t.clock.AfterFunc(d, t.callback)
	} else {
		t.timer.Reset(d)
	}
}
