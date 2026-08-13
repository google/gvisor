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
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	sentrytime "gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// mockClocks is a sentrytime.Clocks that simply returns the times in the
// struct.
type mockClocks struct {
	mu        sync.Mutex
	monotonic int64
	realtime  int64
}

// Update implements sentrytime.Clocks.Update. It does nothing.
func (*mockClocks) Update(parked bool) (monotonicParams sentrytime.Parameters, monotonicOk bool, realtimeParam sentrytime.Parameters, realtimeOk bool) {
	return
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
	t.SetClocks(sentrytime.NewCalibratedClocks(), params)
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

	stopTimer := func(_ *Timekeeper, timer tcpip.Timer, _ *VDSOParamPage) {
		if !timer.Stop() {
			t.Fatalf("Stop() on active timer got false, want true")
		}
	}
	resetTimer := func(d time.Duration) actionFn {
		return func(_ *Timekeeper, timer tcpip.Timer, _ *VDSOParamPage) {
			timer.Reset(d)
		}
	}
	pauseTK := func(tk *Timekeeper, _ tcpip.Timer, _ *VDSOParamPage) {
		tk.Pause()
	}
	resumeTK := func(tk *Timekeeper, _ tcpip.Timer, params *VDSOParamPage) {
		tk.Resume(params)
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
					action:    stopTimer,
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
					action: func(_ *Timekeeper, timer tcpip.Timer, _ *VDSOParamPage) {
						if timer.Stop() {
							t.Fatalf("Stop() on expired timer got true, want false")
						}
					},
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
