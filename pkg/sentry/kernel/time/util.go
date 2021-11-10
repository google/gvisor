// Copyright 2020 The gVisor Authors.
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

// AfterFunc waits for duration to elapse according to clock then runs fn.
// The timer is started immediately and will fire exactly once.
func AfterFunc(clock Clock, duration time.Duration, fn func()) *VariableTimer {
	timer := &VariableTimer{
		clock: clock,
	}
	timer.notifier = functionNotifier{
		fn: func() {
			// tcpip.Timer.Stop() explicitly states that the function is called in a
			// separate goroutine that Stop() does not synchronize with.
			// Timer.Destroy() synchronizes with calls to Listener.NotifyTimer().
			// This is semantically meaningful because, in the former case, it's
			// legal to call tcpip.Timer.Stop() while holding locks that may also be
			// taken by the function, but this isn't so in the latter case. Most
			// immediately, Timer calls Listener.NotifyTimer() while holding
			// Timer.mu. A deadlock occurs without spawning a goroutine:
			//   T1: (Timer expires)
			//     => Timer.Tick()           <- Timer.mu.Lock() called
			//     => Listener.NotifyTimer()
			//     => Timer.Stop()
			//     => Timer.Destroy()        <- Timer.mu.Lock() called, deadlock!
			//
			// Spawning a goroutine avoids the deadlock:
			//   T1: (Timer expires)
			//     => Timer.Tick()           <- Timer.mu.Lock() called
			//     => Listener.NotifyTimer() <- Launches T2
			//   T2:
			//     => Timer.Stop()
			//     => Timer.Destroy()        <- Timer.mu.Lock() called, blocks
			//   T1:
			//     => (returns)              <- Timer.mu.Unlock() called
			//   T2:
			//     => (continues)            <- No deadlock!
			go func() {
				timer.Stop()
				fn()
			}()
		},
	}
	timer.Reset(duration)
	return timer
}

// VariableTimer is a resettable timer with variable duration expirations.
// Implements tcpip.Timer, which does not define a Destroy method; instead, all
// resources are released after timer expiration and calls to Timer.Stop.
//
// Must be created by AfterFunc.
type VariableTimer struct {
	// clock is the time source. clock is immutable.
	clock Clock

	// notifier is called when the Timer expires. notifier is immutable.
	notifier functionNotifier

	// mu protects t.
	mu sync.Mutex

	// t stores the latest running Timer. This is replaced whenever Reset is
	// called since Timer cannot be restarted once it has been Destroyed by Stop.
	//
	// This field is nil iff Stop has been called.
	t *Timer
}

// Stop implements tcpip.Timer.Stop.
func (r *VariableTimer) Stop() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.t == nil {
		return false
	}
	_, lastSetting := r.t.Swap(Setting{})
	r.t.Destroy()
	r.t = nil
	return lastSetting.Enabled
}

// Reset implements tcpip.Timer.Reset.
func (r *VariableTimer) Reset(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.t == nil {
		r.t = NewTimer(r.clock, &r.notifier)
	}

	r.t.Swap(Setting{
		Enabled: true,
		Period:  0,
		Next:    r.clock.Now().Add(d),
	})
}

// functionNotifier is a TimerListener that runs a function.
//
// functionNotifier cannot be saved or loaded.
type functionNotifier struct {
	fn func()
}

// NotifyTimer implements ktime.TimerListener.NotifyTimer.
func (f *functionNotifier) NotifyTimer(uint64, Setting) (Setting, bool) {
	f.fn()
	return Setting{}, false
}
