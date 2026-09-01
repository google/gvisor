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
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	sentrytime "gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// mockClocks is a sentrytime.Clocks that simply returns the times in the
// struct.
type mockClocks struct {
	mu                  sync.Mutex
	monotonic           int64
	realtime            int64
	monotonicRaw        int64
	monotonicRawEnabled bool
}

// Update implements sentrytime.Clocks.Update. It does nothing.
func (*mockClocks) Update(parked bool) sentrytime.UpdateResult {
	return sentrytime.UpdateResult{}
}

// MonotonicRawEnabled implements sentrytime.Clocks.MonotonicRawEnabled.
func (c *mockClocks) MonotonicRawEnabled() bool {
	return c.monotonicRawEnabled
}

// GetTime implements sentrytime.Clocks.GetTime.
func (c *mockClocks) GetTime(id sentrytime.ClockID) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch id {
	case sentrytime.Monotonic:
		return c.monotonic, nil
	case sentrytime.Realtime:
		return c.realtime, nil
	case sentrytime.MonotonicRaw:
		if c.monotonicRawEnabled {
			return c.monotonicRaw, nil
		}
		return 0, linuxerr.EINVAL
	default:
		return 0, linuxerr.EINVAL
	}
}

// stateTestClocklessTimekeeper returns a test Timekeeper which has not had
// SetClocks called.
func stateTestClocklessTimekeeper(tb testing.TB) (*Timekeeper, *VDSOParamPage) {
	ctx := contexttest.Context(tb)
	mf := pgalloc.MemoryFileFromContext(ctx)
	fr, err := mf.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		tb.Fatalf("failed to allocate memory: %v", err)
	}
	params := NewVDSOParamPage(mf, fr)
	return &Timekeeper{}, params
}

func stateTestTimekeeper(tb testing.TB) *Timekeeper {
	t, params := stateTestClocklessTimekeeper(tb)
	t.SetClocks(sentrytime.NewCalibratedClocks(false), params)
	return t
}

// TestTimekeeperMonotonicZero tests that monotonic time starts at zero.
func TestTimekeeperMonotonicZero(t *testing.T) {
	c := &mockClocks{
		monotonic: 100000,
	}

	tk, params := stateTestClocklessTimekeeper(t)
	tk.SetClocks(c, params)
	defer tk.Destroy()

	now, err := tk.GetTime(sentrytime.Monotonic)
	if err != nil {
		t.Errorf("GetTime err got %v want nil", err)
	}
	if now != 0 {
		t.Errorf("GetTime got %d want 0", now)
	}

	c.mu.Lock()
	c.monotonic += 10
	c.mu.Unlock()

	now, err = tk.GetTime(sentrytime.Monotonic)
	if err != nil {
		t.Errorf("GetTime err got %v want nil", err)
	}
	if now != 10 {
		t.Errorf("GetTime got %d want 10", now)
	}
}

// TestTimekeeperMonotonicJumpForward tests that monotonic time jumps forward
// after restore.
func TestTimekeeperMonotonicForward(t *testing.T) {
	c := &mockClocks{
		monotonic: 900000,
		realtime:  600000,
	}

	tk, params := stateTestClocklessTimekeeper(t)
	tk.restored = make(chan struct{})
	tk.saveMonotonic = 100000
	tk.saveRealtime = 400000
	tk.SetClocks(c, params)
	defer tk.Destroy()

	// The monotonic clock should jump ahead by 200000 to 300000.
	//
	// The new system monotonic time (900000) is irrelevant to what the app
	// sees.
	now, err := tk.GetTime(sentrytime.Monotonic)
	if err != nil {
		t.Errorf("GetTime err got %v want nil", err)
	}
	if now != 300000 {
		t.Errorf("GetTime got %d want 300000", now)
	}
}

// TestTimekeeperMonotonicJumpBackwards tests that monotonic time does not jump
// backwards when realtime goes backwards.
func TestTimekeeperMonotonicJumpBackwards(t *testing.T) {
	c := &mockClocks{
		monotonic: 900000,
		realtime:  400000,
	}

	tk, params := stateTestClocklessTimekeeper(t)
	tk.restored = make(chan struct{})
	tk.saveMonotonic = 100000
	tk.saveRealtime = 600000
	tk.SetClocks(c, params)
	defer tk.Destroy()

	// The monotonic clock should remain at 100000.
	//
	// The new system monotonic time (900000) is irrelevant to what the app
	// sees and we don't want to jump the monotonic clock backwards like
	// realtime did.
	now, err := tk.GetTime(sentrytime.Monotonic)
	if err != nil {
		t.Errorf("GetTime err got %v want nil", err)
	}
	if now != 100000 {
		t.Errorf("GetTime got %d want 100000", now)
	}
}

// TestTimekeeperMonotonicRawEnabled tests that when the clock source tracks a
// distinct CLOCK_MONOTONIC_RAW, GetTime exposes it directly (absolute, not
// starting at zero), while CLOCK_MONOTONIC is unaffected.
func TestTimekeeperMonotonicRawEnabled(t *testing.T) {
	c := &mockClocks{
		monotonic:           100000,
		monotonicRaw:        999999,
		monotonicRawEnabled: true,
	}

	tk, params := stateTestClocklessTimekeeper(t)
	tk.SetClocks(c, params)
	defer tk.Destroy()

	// Monotonic is unaffected: still starts at zero.
	if now, err := tk.GetTime(sentrytime.Monotonic); err != nil || now != 0 {
		t.Errorf("GetTime(Monotonic) got (%d, %v) want (0, nil)", now, err)
	}
	// MonotonicRaw exposes the raw source's absolute value.
	if now, err := tk.GetTime(sentrytime.MonotonicRaw); err != nil || now != 999999 {
		t.Errorf("GetTime(MonotonicRaw) got (%d, %v) want (999999, nil)", now, err)
	}
}

// TestTimekeeperMonotonicRawDisabled tests that when the clock source does not
// track CLOCK_MONOTONIC_RAW, it aliases CLOCK_MONOTONIC.
func TestTimekeeperMonotonicRawDisabled(t *testing.T) {
	c := &mockClocks{
		monotonic: 100000,
	}

	tk, params := stateTestClocklessTimekeeper(t)
	tk.SetClocks(c, params)
	defer tk.Destroy()

	// MonotonicRaw aliases Monotonic: both start at zero.
	if now, err := tk.GetTime(sentrytime.MonotonicRaw); err != nil || now != 0 {
		t.Errorf("GetTime(MonotonicRaw) got (%d, %v) want (0, nil)", now, err)
	}
}

// TestTimekeeperTimerLifecycle tests timer creation, firing,
// and cancellation.
func TestTimekeeperTimerLifecycle(t *testing.T) {
	type actionFn func(tk *Timekeeper, timer tcpip.Timer, params *VDSOParamPage)

	type step struct {
		desc       string
		clockTime  time.Duration
		action     actionFn
		expectFire bool
	}

	// stopActiveTimer stops a timer that is pending expiration
	// i.e. it's deadline is in the future.
	stopActiveTimer := func(_ *Timekeeper, timer tcpip.Timer, _ *VDSOParamPage) {
		if !timer.Stop() {
			t.Fatalf("Stop() on active timer got false, want true")
		}
	}

	// stopInactiveTimer stops an inactive or already-expired timer
	// i.e. it's stopped or deadline has already passed.
	stopInactiveTimer := func(_ *Timekeeper, timer tcpip.Timer, _ *VDSOParamPage) {
		if timer.Stop() {
			t.Fatalf("Stop() on inactive/expired timer got true, want false")
		}
	}

	// resetTimer re-arms the timer with the given duration.
	resetTimer := func(d time.Duration) actionFn {
		return func(_ *Timekeeper, timer tcpip.Timer, _ *VDSOParamPage) {
			timer.Reset(d)
		}
	}

	// pauseTK pauses the Timekeeper.
	pauseTK := func(tk *Timekeeper, _ tcpip.Timer, _ *VDSOParamPage) {
		tk.Pause()
	}

	// resumeTK resumes the Timekeeper with updated VDSO parameters.
	resumeTK := func(tk *Timekeeper, _ tcpip.Timer, params *VDSOParamPage) {
		tk.Resume(params)
	}

	// setTimer directly calls SyntheticTimer.Set with the given setting.
	setTimer := func(s ktime.Setting) actionFn {
		return func(_ *Timekeeper, timer tcpip.Timer, _ *VDSOParamPage) {
			timer.(*timekeeperTimer).Set(s, nil)
		}
	}

	testCases := []struct {
		name              string
		afterFuncDuration time.Duration
		steps             []step
	}{
		{
			name:              "BasicAfterFunc",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:       "advance clock to T=50ms past 50ms deadline",
					clockTime:  50 * time.Millisecond,
					expectFire: true,
				},
			},
		},
		{
			name:              "StopAndResetLiveMonotonicTime",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:      "stop timer at T=30ms before 50ms deadline",
					clockTime: 30 * time.Millisecond,
					action:    stopActiveTimer,
				},
				{
					desc:      "advance to T=100ms: stopped timer must not fire",
					clockTime: 100 * time.Millisecond,
				},
				{
					desc:      "advance to T=200ms while scheduler is idle",
					clockTime: 200 * time.Millisecond,
				},
				{
					desc:      "re-arm timer with Reset(50ms) at T=200ms (deadline = 250ms)",
					clockTime: 200 * time.Millisecond,
					action:    resetTimer(50 * time.Millisecond),
				},
				{
					desc:      "advance to T=230ms (before true 250ms deadline): must not fire",
					clockTime: 230 * time.Millisecond,
				},
				{
					desc:       "advance to T=300ms (past 250ms deadline): must fire",
					clockTime:  300 * time.Millisecond,
					expectFire: true,
				},
				{
					desc:      "stop on expired timer must return false",
					clockTime: 300 * time.Millisecond,
					action:    stopInactiveTimer,
				},
			},
		},
		{
			name:              "PauseAndResumeOverdue",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:      "pause timekeeper at T=0",
					clockTime: 0,
					action:    pauseTK,
				},
				{
					desc:      "advance to T=100ms while paused: must not fire",
					clockTime: 100 * time.Millisecond,
				},
				{
					desc:       "resume timekeeper at T=100ms: overdue timer fires immediately",
					clockTime:  100 * time.Millisecond,
					action:     resumeTK,
					expectFire: true,
				},
			},
		},
		{
			name:              "PauseThenResetZeroDoesNotFireUntilResume",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:      "pause timekeeper at T=0",
					clockTime: 0,
					action:    pauseTK,
				},
				{
					desc:       "reset timer to 0 duration while paused: must not fire",
					clockTime:  0,
					action:     resetTimer(0),
					expectFire: false,
				},
				{
					desc:       "advance to T=50ms while paused: must not fire",
					clockTime:  50 * time.Millisecond,
					expectFire: false,
				},
				{
					desc:       "resume timekeeper at T=50ms: callback fires promptly",
					clockTime:  50 * time.Millisecond,
					action:     resumeTK,
					expectFire: true,
				},
			},
		},
		{
			name:              "PauseThenResetNegativeDoesNotFireUntilResume",
			afterFuncDuration: 100 * time.Millisecond,
			steps: []step{
				{
					desc:      "pause timekeeper at T=20ms",
					clockTime: 20 * time.Millisecond,
					action:    pauseTK,
				},
				{
					desc:       "reset timer to -10ms duration while paused: must not fire",
					clockTime:  20 * time.Millisecond,
					action:     resetTimer(-10 * time.Millisecond),
					expectFire: false,
				},
				{
					desc:       "advance to T=50ms while paused: must not fire",
					clockTime:  50 * time.Millisecond,
					expectFire: false,
				},
				{
					desc:       "resume timekeeper at T=50ms: callback fires promptly",
					clockTime:  50 * time.Millisecond,
					action:     resumeTK,
					expectFire: true,
				},
			},
		},
		{
			name:              "PauseThenSetPastDeadlineDoesNotFireUntilResume",
			afterFuncDuration: 100 * time.Millisecond,
			steps: []step{
				{
					desc:      "pause timekeeper at T=20ms",
					clockTime: 20 * time.Millisecond,
					action:    pauseTK,
				},
				{
					desc:      "Set timer with past deadline (T=10ms) while paused: must not fire",
					clockTime: 20 * time.Millisecond,
					action: setTimer(ktime.Setting{
						Enabled: true,
						Next:    ktime.FromNanoseconds((10 * time.Millisecond).Nanoseconds()),
					}),
					expectFire: false,
				},
				{
					desc:       "advance to T=50ms while paused: must not fire",
					clockTime:  50 * time.Millisecond,
					expectFire: false,
				},
				{
					desc:       "resume timekeeper at T=50ms: callback fires",
					clockTime:  50 * time.Millisecond,
					action:     resumeTK,
					expectFire: true,
				},
			},
		},
		{
			name:              "AfterFuncZeroDurationFiresImmediately",
			afterFuncDuration: 0,
			steps: []step{
				{
					desc:       "timer initialized with 0 duration fires immediately",
					clockTime:  0,
					expectFire: true,
				},
				{
					desc:       "stop on expired timer returns false and does not fire",
					clockTime:  0,
					action:     stopInactiveTimer,
					expectFire: false,
				},
			},
		},
		{
			name:              "ResetZeroDurationFiresImmediately",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:       "reset timer with 0 duration at T=0: fires immediately",
					clockTime:  0,
					action:     resetTimer(0),
					expectFire: true,
				},
				{
					desc:       "stop on expired timer returns false and does not fire",
					clockTime:  0,
					action:     stopInactiveTimer,
					expectFire: false,
				},
			},
		},
		{
			name:              "ResetZeroDurationMidFlight",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:       "advance to T=20ms (before 50ms deadline): must not fire",
					clockTime:  20 * time.Millisecond,
					expectFire: false,
				},
				{
					desc:       "call Reset(0) at T=20ms: fires immediately",
					clockTime:  20 * time.Millisecond,
					action:     resetTimer(0),
					expectFire: true,
				},
				{
					desc:       "advance to T=100ms (past original 50ms deadline): must not fire again",
					clockTime:  100 * time.Millisecond,
					expectFire: false,
				},
			},
		},
		{
			name:              "ResetFutureDurationMidFlight",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:       "advance to T=20ms (before 50ms deadline): must not fire",
					clockTime:  20 * time.Millisecond,
					expectFire: false,
				},
				{
					desc:       "call Reset(40ms) at T=20ms (new deadline = 60ms): must not fire immediately",
					clockTime:  20 * time.Millisecond,
					action:     resetTimer(40 * time.Millisecond),
					expectFire: false,
				},
				{
					desc:       "advance to T=50ms (old cancelled deadline): must not fire",
					clockTime:  50 * time.Millisecond,
					expectFire: false,
				},
				{
					desc:       "advance to T=60ms (new deadline): must fire",
					clockTime:  60 * time.Millisecond,
					expectFire: true,
				},
				{
					desc:       "advance to T=100ms: must not fire again",
					clockTime:  100 * time.Millisecond,
					expectFire: false,
				},
			},
		},
		{
			name:              "ResetExtendAndShortenDeadline",
			afterFuncDuration: 100 * time.Millisecond,
			steps: []step{
				{
					desc:       "call Reset(30ms) at T=20ms (shortens deadline to 50ms): must not fire immediately",
					clockTime:  20 * time.Millisecond,
					action:     resetTimer(30 * time.Millisecond),
					expectFire: false,
				},
				{
					desc:       "call Reset(40ms) at T=40ms (extends deadline to 80ms): must not fire immediately",
					clockTime:  40 * time.Millisecond,
					action:     resetTimer(40 * time.Millisecond),
					expectFire: false,
				},
				{
					desc:       "advance to T=50ms (cancelled 50ms deadline): must not fire",
					clockTime:  50 * time.Millisecond,
					expectFire: false,
				},
				{
					desc:       "advance to T=80ms (active 80ms deadline): must fire",
					clockTime:  80 * time.Millisecond,
					expectFire: true,
				},
				{
					desc:       "advance to T=100ms (original cancelled 100ms deadline): must not fire",
					clockTime:  100 * time.Millisecond,
					expectFire: false,
				},
			},
		},
		{
			name:              "ResetExpiredTimerForFutureDoesNotFireImmediately",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:       "advance to T=50ms: original timer fires",
					clockTime:  50 * time.Millisecond,
					expectFire: true,
				},
				{
					desc:       "re-arm expired timer with Reset(50ms) at T=50ms: must not fire immediately",
					clockTime:  50 * time.Millisecond,
					action:     resetTimer(50 * time.Millisecond),
					expectFire: false,
				},
				{
					desc:       "advance to T=70ms (before 100ms deadline): must not fire",
					clockTime:  70 * time.Millisecond,
					expectFire: false,
				},
				{
					desc:       "advance to T=100ms: re-armed timer fires",
					clockTime:  100 * time.Millisecond,
					expectFire: true,
				},
			},
		},
		{
			name:              "StopStoppedTimerDoesNotFire",
			afterFuncDuration: 50 * time.Millisecond,
			steps: []step{
				{
					desc:      "stop active timer at T=10ms: returns true",
					clockTime: 10 * time.Millisecond,
					action:    stopActiveTimer,
				},
				{
					desc:       "stop already stopped timer at T=20ms: returns false and must not fire",
					clockTime:  20 * time.Millisecond,
					action:     stopInactiveTimer,
					expectFire: false,
				},
				{
					desc:       "advance to T=100ms: stopped timer must not fire",
					clockTime:  100 * time.Millisecond,
					expectFire: false,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &mockClocks{}
			tk, params := stateTestClocklessTimekeeper(t)
			tk.SetClocks(c, params)
			defer tk.Destroy()

			fired := make(chan struct{}, 10)
			timer := tk.AfterFunc(tc.afterFuncDuration, func() {
				fired <- struct{}{}
			})
			defer timer.Stop()

			for _, s := range tc.steps {
				// Advance the mock monotonic clock to the step timestamp.
				c.mu.Lock()
				c.monotonic = s.clockTime.Nanoseconds()
				c.mu.Unlock()

				// Execute step action (e.g., Stop, Reset, Pause, Resume).
				if s.action != nil {
					s.action(tk, timer, params)
				}

				// Wait up to 2s when expecting a callback, or 20ms to verify silence.
				timeout := 20 * time.Millisecond
				if s.expectFire {
					timeout = 2 * time.Second
				}

				var gotFired bool
				select {
				case <-fired:
					gotFired = true
				case <-time.After(timeout):
					gotFired = false
				}

				if gotFired != s.expectFire {
					t.Fatalf("[%s] step %q: gotFired = %v, want %v", tc.name, s.desc, gotFired, s.expectFire)
				}
			}
		})
	}
}

// TestTimekeeperPauseWaitsForInFlightAfterFunc tests that Pause() blocks until
// any already-running AfterFunc callback goroutine finishes.
func TestTimekeeperPauseWaitsForInFlightAfterFunc(t *testing.T) {
	c := &mockClocks{}
	tk, params := stateTestClocklessTimekeeper(t)
	tk.SetClocks(c, params)
	defer tk.Destroy()

	started := make(chan struct{})
	done := make(chan struct{})
	tk.AfterFunc(10*time.Millisecond, func() {
		close(started)
		time.Sleep(50 * time.Millisecond)
		close(done)
	})

	// Trigger the callback.
	c.mu.Lock()
	c.monotonic += (20 * time.Millisecond).Nanoseconds()
	c.mu.Unlock()

	// Wait until the callback has actually started executing in its goroutine.
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("AfterFunc callback never started")
	}

	tk.Pause()

	// Pause() must have blocked until the callback finished.
	select {
	case <-done:
		// Success.
	default:
		t.Fatal("Pause() returned while AfterFunc was still running")
	}
}
