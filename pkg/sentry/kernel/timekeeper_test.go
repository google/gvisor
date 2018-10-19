// Copyright 2018 Google LLC
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

	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	sentrytime "gvisor.googlesource.com/gvisor/pkg/sentry/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// mockClocks is a sentrytime.Clocks that simply returns the times in the
// struct.
type mockClocks struct {
	monotonic int64
	realtime  int64
}

// Update implements sentrytime.Clocks.Update. It does nothing.
func (*mockClocks) Update() (monotonicParams sentrytime.Parameters, monotonicOk bool, realtimeParam sentrytime.Parameters, realtimeOk bool) {
	return
}

// Update implements sentrytime.Clocks.GetTime.
func (c *mockClocks) GetTime(id sentrytime.ClockID) (int64, error) {
	switch id {
	case sentrytime.Monotonic:
		return c.monotonic, nil
	case sentrytime.Realtime:
		return c.realtime, nil
	default:
		return 0, syserror.EINVAL
	}
}

// stateTestClocklessTimekeeper returns a test Timekeeper which has not had
// SetClocks called.
func stateTestClocklessTimekeeper(tb testing.TB) *Timekeeper {
	ctx := contexttest.Context(tb)
	p := platform.FromContext(ctx)
	fr, err := p.Memory().Allocate(usermem.PageSize, usage.Anonymous)
	if err != nil {
		tb.Fatalf("failed to allocate memory: %v", err)
	}
	return &Timekeeper{
		params: NewVDSOParamPage(p, fr),
	}
}

func stateTestTimekeeper(tb testing.TB) *Timekeeper {
	t := stateTestClocklessTimekeeper(tb)
	t.SetClocks(sentrytime.NewCalibratedClocks())
	return t
}

// TestTimekeeperMonotonicZero tests that monotonic time starts at zero.
func TestTimekeeperMonotonicZero(t *testing.T) {
	c := &mockClocks{
		monotonic: 100000,
	}

	tk := stateTestClocklessTimekeeper(t)
	tk.SetClocks(c)
	defer tk.Destroy()

	now, err := tk.GetTime(sentrytime.Monotonic)
	if err != nil {
		t.Errorf("GetTime err got %v want nil", err)
	}
	if now != 0 {
		t.Errorf("GetTime got %d want 0", now)
	}

	c.monotonic += 10

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

	tk := stateTestClocklessTimekeeper(t)
	tk.restored = make(chan struct{})
	tk.saveMonotonic = 100000
	tk.saveRealtime = 400000
	tk.SetClocks(c)
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

	tk := stateTestClocklessTimekeeper(t)
	tk.restored = make(chan struct{})
	tk.saveMonotonic = 100000
	tk.saveRealtime = 600000
	tk.SetClocks(c)
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
