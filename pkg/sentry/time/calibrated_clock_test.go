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
	"testing"
	"time"
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
		{before: 100000, after: 100000 + defaultOverheadCycles, ref: 100},
		{before: 200000, after: 200000 + defaultOverheadCycles, ref: 200},
		{before: 300000, after: 300000 + defaultOverheadCycles, ref: 300},
		{before: 400000, after: 400000 + defaultOverheadCycles, ref: 400},
		{before: 500000, after: 500000 + defaultOverheadCycles, ref: 500},
		{before: 600000, after: 600000 + defaultOverheadCycles, ref: 600},
		{before: 700000, after: 700000 + defaultOverheadCycles, ref: 700},
	}

	c := newTestCalibratedClock(samples, nil)

	// Update from all samples.
	for range samples {
		c.Update()
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
			_, ok := c.Update()
			if ok {
				t.Fatalf("Update ready too early")
			}

			params, ok := c.Update()
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
			params, ok = c.Update()
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

			// As the reference clock stablizes, ensure that the clock error
			// decreases.
			initialErr := c.errorNS
			t.Logf("initial error: %v ns", initialErr)

			_, ok = c.Update()
			if !ok {
				t.Fatalf("Update not ready")
			}
			if c.errorNS.Magnitude() > initialErr.Magnitude() {
				t.Errorf("errorNS increased, got %v want |%v| <= |%v|", c.errorNS, c.errorNS, initialErr)
			}

			_, ok = c.Update()
			if !ok {
				t.Fatalf("Update not ready")
			}
			if c.errorNS.Magnitude() > initialErr.Magnitude() {
				t.Errorf("errorNS increased, got %v want |%v| <= |%v|", c.errorNS, c.errorNS, initialErr)
			}

			t.Logf("final error: %v ns", c.errorNS)
		})
	}
}
