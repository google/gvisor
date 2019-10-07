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

package time

import (
	"sync"
	"time"
)

type timerState int

const (
	timerStateDisabled timerState = iota
	timerStateEnabled
	timerStateOrphaned
)

// timer is a timer implementation that reduces the interactions with the
// runtime timer infrastructure by letting timers run (and potentially
// eventually expire) even if they are stopped. It makes it cheaper to
// disable/reenable timers at the expense of spurious wakes. This is useful for
// cases when the same timer is disabled/reenabled repeatedly with relatively
// long timeouts farther into the future.
//
// TCP retransmit timers benefit from this because they the timeouts are long
// (currently at least 200ms), and get disabled when acks are received, and
// reenabled when new pending segments are sent.
//
// It is advantageous to avoid interacting with the runtime because it acquires
// a global mutex and performs O(log n) operations, where n is the global number
// of timers, whenever a timer is enabled or disabled, and may make a syscall.
//
// This struct is thread-compatible.
type timer struct {
	mu sync.Mutex

	// state is the current state of the timer, it can be one of the
	// following values:
	//     disabled - the timer is disabled.
	//     orphaned - the timer is disabled, but the runtime timer is
	//                enabled, which means that it will evetually cause a
	//                spurious wake (unless it gets enabled again before
	//                then).
	//     enabled  - the timer is enabled, but the runtime timer may be set
	//                to an earlier expiration time due to a previous
	//                orphaned state.
	state timerState

	// target is the expiration time of the current timer. It is only
	// meaningful in the enabled state.
	target Time

	// runtimeTarget is the expiration time of the runtime timer. It is
	// meaningful in the enabled and orphaned states.
	runtimeTarget Time

	// timer is the runtime timer used to wait on.
	timer *time.Timer

	// clock is the time source. clock is immutable.
	clock Clock
}

// init initializes the timer. Once it expires, it writes to the
// provided channel.
func (t *timer) init(c chan<- struct{}) {
	t.mu.Lock()
	t.state = timerStateDisabled

	// Initialize a runtime timer then immediately stop it.
	t.timer = time.AfterFunc(time.Hour, func() {
		select {
		case c <- struct{}{}:
		default:
		}
	})
	t.timer.Stop()
	t.mu.Unlock()
}

// cleanup frees all resources associated with the timer.
func (t *timer) cleanup() {
	t.timer.Stop()
}

// checkExpiration checks if the given timer has actually expired, it should be
// called whenever a sleeper wakes up due to the waker being asserted, and is
// used to check if it's a supurious wake (due to a previously orphaned timer)
// or a legitimate one.
func (t *timer) checkExpiration() bool {
	t.mu.Lock()

	// Transition to fully disabled state if we're just consuming an
	// orphaned timer.
	if t.state == timerStateOrphaned {
		t.state = timerStateDisabled
		t.mu.Unlock()
		return false
	}

	// The timer is enabled, but it may have expired early. Check if that's
	// the case, and if so, reset the runtime timer to the correct time.
	now := t.clock.Now()
	if now.Before(t.target) {
		t.runtimeTarget = t.target
		t.timer.Reset(t.target.Sub(now))
		t.mu.Unlock()
		return false
	}

	// The timer has actually expired, disable it for now and inform the
	// caller.
	t.state = timerStateDisabled
	t.mu.Unlock()
	return true
}

// disable disables the timer, leaving it in an orphaned state if it wasn't
// already disabled.
func (t *timer) disable() {
	t.mu.Lock()
	if t.state != timerStateDisabled {
		t.state = timerStateOrphaned
	}
	t.mu.Unlock()
}

// enabled returns true if the timer is currently enabled, false otherwise.
func (t *timer) enabled() bool {
	t.mu.Lock()
	ret := t.state == timerStateEnabled
	t.mu.Unlock()
	return ret
}

// enable enables the timer, programming the runtime timer if necessary.
func (t *timer) enable(d time.Duration) {
	t.mu.Lock()
	t.target = t.clock.Now().Add(d)

	// Check if we need to set the runtime timer.
	if t.state == timerStateDisabled || t.target.Before(t.runtimeTarget) {
		t.runtimeTarget = t.target
		t.timer.Reset(d)
	}

	t.state = timerStateEnabled
	t.mu.Unlock()
}
