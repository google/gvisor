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
	"math"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
)

// newTestCalibratedClock returns a CalibratedClock that collects samples from
// the given sample list and cycle counts from the given cycle list.
func newTestCalibratedClock(samples []sample, cycles []TSCValue) *CalibratedClock {
	return &CalibratedClock{
		ref: newTestSampler(samples, cycles),
	}
}

func TestConstantFrequency(t *testing.T) {
	// Perfectly constant frequency.
	samples := []sample{
		{before: 100000, after: 100000 + 1, ref: 100},
		{before: 200000, after: 200000 + 1, ref: 200},
		{before: 300000, after: 300000 + 1, ref: 300},
		{before: 400000, after: 400000 + 1, ref: 400},
		{before: 500000, after: 500000 + 1, ref: 500},
		{before: 600000, after: 600000 + 1, ref: 600},
		{before: 700000, after: 700000 + 1, ref: 700},
	}

	c := newTestCalibratedClock(samples, nil)

	// Update from all samples.
	for range samples {
		c.Update(false)
	}

	c.mu.RLock()
	if !c.ready {
		c.mu.RUnlock()
		t.Fatalf("clock not ready")
		return // For checklocks consistency.
	}
	// A bit after the last sample.
	now, ok := c.params.ComputeTime(750000)
	c.mu.RUnlock()
	if !ok {
		t.Fatalf("ComputeTime ok got %v want true", ok)
	}

	t.Logf("now: %v", now)

	// Time should be between the current sample and where we'd expect the
	// next sample.
	if now < 700 || now > 800 {
		t.Errorf("now got %v want > 700 && < 800", now)
	}
}

func TestGetTimeOverflow(t *testing.T) {
	c := newTestCalibratedClock([]sample{{ref: 123}}, []TSCValue{math.MaxInt64})
	c.mu.Lock()
	c.ready = true
	c.params = Parameters{Frequency: 1}
	c.mu.Unlock()

	// Shared reader locks do not order the old reset's write with this read.
	// An exclusive reset instead waits for this reader to unlock.
	c.mu.RLock()
	var got int64
	var err error
	var wg sync.WaitGroup
	wg.Go(func() {
		got, err = c.GetTime()
	})
	readyWhileReadLocked := c.ready
	c.mu.RUnlock()
	wg.Wait()
	if !readyWhileReadLocked {
		t.Error("clock reset while a reader held the mutex")
	}
	if err != nil {
		t.Fatalf("GetTime: %v", err)
	}
	if got != 123 {
		t.Errorf("GetTime = %d, want 123 from reference clock", got)
	}
	c.mu.RLock()
	ready := c.ready
	c.mu.RUnlock()
	if ready {
		t.Error("clock remains ready after time computation overflow")
	}
}

func TestUpdateReportsCalibrationReset(t *testing.T) {
	c := newTestCalibratedClock([]sample{
		{before: 0, after: 1, ref: 0},
		{before: 1_000_000_000, after: 1_000_000_001, ref: 1_000_000_000},
		// This reference jump cannot be corrected within one update interval.
		// updateParams must discard the calibration instead.
		{before: 2_000_000_000, after: 2_000_000_001, ref: 4_000_000_000},
	}, nil)

	_, ready := c.Update(false)
	if got, want := ready, false; got != want {
		t.Fatalf("first Update ready = %t, want %t", got, want)
	}
	_, ready = c.Update(false)
	if got, want := ready, true; got != want {
		t.Fatalf("second Update ready = %t, want %t", got, want)
	}
	_, ready = c.Update(false)
	c.mu.RLock()
	clockReady := c.ready
	c.mu.RUnlock()
	if got, want := clockReady, false; got != want {
		t.Fatalf("clock ready after rejected calibration = %t, want %t", got, want)
	}
	if got, want := ready, false; got != want {
		t.Errorf("Update ready after rejected calibration = %t, want %t", got, want)
	}
}

func TestErrorCorrection(t *testing.T) {
	testCases := []struct {
		name               string
		samples            [5]sample
		projectedTimeStart int64
		projectedTimeEnd   int64
	}{
		// Initial calibration should be ~1MHz for each of these, and
		// the reference clock changes in samples[2].
		{
			name: "slow-down",
			samples: [5]sample{
				{before: 1000000, after: 1000001, ref: ReferenceNS(1 * ApproxUpdateInterval.Nanoseconds())},
				{before: 2000000, after: 2000001, ref: ReferenceNS(2 * ApproxUpdateInterval.Nanoseconds())},
				// Reference clock has slowed down, causing 100ms of error.
				{before: 3010000, after: 3010001, ref: ReferenceNS(3 * ApproxUpdateInterval.Nanoseconds())},
				{before: 4020000, after: 4020001, ref: ReferenceNS(4 * ApproxUpdateInterval.Nanoseconds())},
				{before: 5030000, after: 5030001, ref: ReferenceNS(5 * ApproxUpdateInterval.Nanoseconds())},
			},
			projectedTimeStart: 3005 * time.Millisecond.Nanoseconds(),
			projectedTimeEnd:   3015 * time.Millisecond.Nanoseconds(),
		},
		{
			name: "speed-up",
			samples: [5]sample{
				{before: 1000000, after: 1000001, ref: ReferenceNS(1 * ApproxUpdateInterval.Nanoseconds())},
				{before: 2000000, after: 2000001, ref: ReferenceNS(2 * ApproxUpdateInterval.Nanoseconds())},
				// Reference clock has sped up, causing 100ms of error.
				{before: 2990000, after: 2990001, ref: ReferenceNS(3 * ApproxUpdateInterval.Nanoseconds())},
				{before: 3980000, after: 3980001, ref: ReferenceNS(4 * ApproxUpdateInterval.Nanoseconds())},
				{before: 4970000, after: 4970001, ref: ReferenceNS(5 * ApproxUpdateInterval.Nanoseconds())},
			},
			projectedTimeStart: 2985 * time.Millisecond.Nanoseconds(),
			projectedTimeEnd:   2995 * time.Millisecond.Nanoseconds(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCalibratedClock(tc.samples[:], nil)

			// Initial calibration takes two updates.
			_, ok := c.Update(false)
			if ok {
				t.Fatalf("Update ready too early")
			}

			params, ok := c.Update(false)
			if !ok {
				t.Fatalf("Update not ready")
			}

			// Initial calibration is ~1MHz.
			hz := params.Frequency
			if hz < 990000 || hz > 1010000 {
				t.Fatalf("Frequency got %v want > 990kHz && < 1010kHz", hz)
			}

			// Project time at the next update. Given the 1MHz
			// calibration, it is expected to be ~3.1s/2.9s, not
			// the actual 3s.
			//
			// N.B. the next update time is the "after" time above.
			projected, ok := params.ComputeTime(tc.samples[2].after)
			if !ok {
				t.Fatalf("ComputeTime ok got %v want true", ok)
			}
			if projected < tc.projectedTimeStart || projected > tc.projectedTimeEnd {
				t.Fatalf("ComputeTime(%v) got %v want > %v && < %v", tc.samples[2].after, projected, tc.projectedTimeStart, tc.projectedTimeEnd)
			}

			// Update again to see the changed reference clock.
			params, ok = c.Update(false)
			if !ok {
				t.Fatalf("Update not ready")
			}

			// We now know that TSC = tc.samples[2].after -> 3s,
			// but with the previous params indicated that TSC
			// tc.samples[2].after -> 3.5s/2.5s. We can't allow the
			// clock to go backwards, and having the clock jump
			// forwards is undesirable. There should be a smooth
			// transition that corrects the clock error over time.
			// Check that the clock is continuous at TSC =
			// tc.samples[2].after.
			newProjected, ok := params.ComputeTime(tc.samples[2].after)
			if !ok {
				t.Fatalf("ComputeTime ok got %v want true", ok)
			}
			if newProjected != projected {
				t.Errorf("Discontinuous time; ComputeTime(%v) got %v want %v", tc.samples[2].after, newProjected, projected)
			}

			// As the reference clock stabilizes, ensure that the clock error
			// decreases.
			c.mu.RLock()
			initialErr := c.errorNS
			c.mu.RUnlock()
			t.Logf("initial error: %v ns", initialErr)

			_, ok = c.Update(false)
			if !ok {
				t.Fatalf("Update not ready")
			}
			c.mu.RLock()
			currentErr := c.errorNS
			c.mu.RUnlock()
			if currentErr.Magnitude() > initialErr.Magnitude() {
				t.Errorf("errorNS increased, got %v want |%v| <= |%v|", currentErr, currentErr, initialErr)
			}

			_, ok = c.Update(false)
			if !ok {
				t.Fatalf("Update not ready")
			}
			c.mu.RLock()
			currentErr = c.errorNS
			c.mu.RUnlock()
			if currentErr.Magnitude() > initialErr.Magnitude() {
				t.Errorf("errorNS increased, got %v want |%v| <= |%v|", currentErr, currentErr, initialErr)
			}

			t.Logf("final error: %v ns", currentErr)
		})
	}
}

// TestInitialCalibrationError tests that a clock sampled at a short interval
// becomes ready only once its samples bound the frequency to within
// maxInitialFrequencyErrorPPM, or once they span ApproxUpdateInterval.
func TestInitialCalibrationError(t *testing.T) {
	// Count cycles at the rate that makes defaultOverheadCycles 1µs, as it is
	// for the arm64 counter.
	hz := int64(defaultOverheadCycles) * 1_000_000
	const interval = 10 * time.Millisecond
	for _, tc := range []struct {
		name     string
		overhead TSCValue
		// readyAt is the number of samples, 10ms apart, after which the
		// clock is ready, or 0 if it is not ready within maxSamples.
		readyAt int
	}{
		{name: "low overhead", overhead: defaultOverheadCycles / 10, readyAt: 2},
		{name: "high overhead", overhead: defaultOverheadCycles * 5 / 2, readyAt: 4},
		{name: "max overhead", overhead: maxOverheadCycles, readyAt: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The reference clock is read at the start of the first sample's
			// overhead and the end of the others', so the frequency estimate
			// is off by the full uncertainty.
			at := func(ref time.Duration, first bool) sample {
				cycles := TSCValue(ref.Nanoseconds() * hz / time.Second.Nanoseconds())
				if !first {
					cycles -= tc.overhead
				}
				return sample{before: cycles, after: cycles + tc.overhead, ref: ReferenceNS(ref.Nanoseconds())}
			}
			samples := []sample{at(0, true)}
			for i := 1; i < maxSamples; i++ {
				samples = append(samples, at(time.Duration(i)*interval, false))
			}
			samples = append(samples, at((maxSamples-1)*interval+ApproxUpdateInterval, false))
			c := newTestCalibratedClock(samples, nil)
			c.ref.overhead = maxOverheadCycles

			checkError := func(p Parameters) {
				t.Helper()
				if errPPM := math.Abs(float64(p.Frequency)-float64(hz)) * 1e6 / float64(hz); errPPM > maxInitialFrequencyErrorPPM {
					t.Errorf("Frequency = %d, %.0fppm from %d, want at most %dppm", p.Frequency, errPPM, hz, maxInitialFrequencyErrorPPM)
				}
			}
			for i := 1; i <= maxSamples; i++ {
				p, ok := c.Update(false)
				if want := tc.readyAt != 0 && i >= tc.readyAt; ok != want {
					t.Fatalf("Update %d ready = %t, want %t", i, ok, want)
				}
				if ok {
					checkError(p)
				}
			}
			// A sample ApproxUpdateInterval later makes any clock ready.
			p, ok := c.Update(false)
			if !ok {
				t.Fatalf("not ready after a sample %v later", ApproxUpdateInterval)
			}
			if tc.readyAt == 0 {
				checkError(p)
			}
		})
	}
}

// TestRealtimeStep tests that a host realtime step between samples taken less
// than ApproxUpdateInterval apart doesn't make the realtime clock ready with a
// frequency that differs from monotonic's.
func TestRealtimeStep(t *testing.T) {
	hz := int64(defaultOverheadCycles) * 1_000_000
	const interval = 10 * time.Millisecond
	// samples returns n samples 10ms apart. step is added to the reference
	// of every sample after the first.
	samples := func(n int, step time.Duration) []sample {
		var s []sample
		for i := 0; i < n; i++ {
			ref := time.Duration(i) * interval
			cycles := TSCValue(ref.Nanoseconds() * hz / time.Second.Nanoseconds())
			if i > 0 {
				ref += step
			}
			s = append(s, sample{before: cycles, after: cycles + defaultOverheadCycles/10, ref: ReferenceNS(ref.Nanoseconds())})
		}
		return s
	}
	const updates = 4
	for _, tc := range []struct {
		name string
		step time.Duration
		// readyAt is the update after which realtime is ready, or 0 if it
		// is not ready within updates.
		readyAt int
	}{
		{name: "no step", step: 0, readyAt: 2},
		{name: "forward", step: 3 * time.Millisecond, readyAt: 0},
		// The clock resets at the second sample, then calibrates from
		// the third and fourth.
		{name: "backward", step: -20 * time.Millisecond, readyAt: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &CalibratedClocks{
				monotonic: newTestCalibratedClock(samples(updates, 0), nil),
				realtime:  newTestCalibratedClock(samples(updates, tc.step), nil),
			}
			for i := 1; i <= updates; i++ {
				res := c.Update(false)
				if want := i >= 2; res.MonotonicOk != want {
					t.Fatalf("Update %d monotonic ready = %t, want %t", i, res.MonotonicOk, want)
				}
				if want := tc.readyAt != 0 && i >= tc.readyAt; res.RealtimeOk != want {
					t.Fatalf("Update %d realtime ready = %t (Frequency %d), want %t", i, res.RealtimeOk, res.Realtime.Frequency, want)
				}
				if res.RealtimeOk {
					if errPPM := math.Abs(float64(res.Realtime.Frequency)-float64(hz)) * 1e6 / float64(hz); errPPM > maxInitialFrequencyErrorPPM {
						t.Errorf("Update %d realtime Frequency = %d, %.0fppm from %d", i, res.Realtime.Frequency, errPPM, hz)
					}
				}
			}
		})
	}
}
