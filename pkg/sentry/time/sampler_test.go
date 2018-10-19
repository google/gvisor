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

package time

import (
	"errors"
	"testing"
)

// errNoSamples is returned when testReferenceClocks runs out of samples.
var errNoSamples = errors.New("no samples available")

// testReferenceClocks returns a preset list of samples and cycle counts.
type testReferenceClocks struct {
	samples []sample
	cycles  []TSCValue
}

// Sample implements referenceClocks.Sample, returning the next sample in the list.
func (t *testReferenceClocks) Sample(_ ClockID) (sample, error) {
	if len(t.samples) == 0 {
		return sample{}, errNoSamples
	}

	s := t.samples[0]
	if len(t.samples) == 1 {
		t.samples = nil
	} else {
		t.samples = t.samples[1:]
	}

	return s, nil
}

// Cycles implements referenceClocks.Cycles, returning the next TSCValue in the list.
func (t *testReferenceClocks) Cycles() TSCValue {
	if len(t.cycles) == 0 {
		return 0
	}

	c := t.cycles[0]
	if len(t.cycles) == 1 {
		t.cycles = nil
	} else {
		t.cycles = t.cycles[1:]
	}

	return c
}

// newTestSampler returns a sampler that collects samples from
// the given sample list and cycle counts from the given cycle list.
func newTestSampler(samples []sample, cycles []TSCValue) *sampler {
	return &sampler{
		clocks: &testReferenceClocks{
			samples: samples,
			cycles:  cycles,
		},
		overhead: defaultOverheadCycles,
	}
}

// generateSamples generates n samples with the given overhead.
func generateSamples(n int, overhead TSCValue) []sample {
	samples := []sample{{before: 1000000, after: 1000000 + overhead, ref: 100}}
	for i := 0; i < n-1; i++ {
		prev := samples[len(samples)-1]
		samples = append(samples, sample{
			before: prev.before + 1000000,
			after:  prev.after + 1000000,
			ref:    prev.ref + 100,
		})
	}
	return samples
}

// TestSample ensures that samples can be collected.
func TestSample(t *testing.T) {
	testCases := []struct {
		name    string
		samples []sample
		err     error
	}{
		{
			name: "basic",
			samples: []sample{
				{before: 100000, after: 100000 + defaultOverheadCycles, ref: 100},
			},
			err: nil,
		},
		{
			// Sample with backwards TSC ignored.
			// referenceClock should retry and get errNoSamples.
			name: "backwards-tsc-ignored",
			samples: []sample{
				{before: 100000, after: 90000, ref: 100},
			},
			err: errNoSamples,
		},
		{
			// Sample far above overhead skipped.
			// referenceClock should retry and get errNoSamples.
			name: "reject-overhead",
			samples: []sample{
				{before: 100000, after: 100000 + 5*defaultOverheadCycles, ref: 100},
			},
			err: errNoSamples,
		},
		{
			// Maximum overhead allowed is bounded.
			name: "over-max-overhead",
			// Generate a bunch of samples. The reference clock
			// needs a while to ramp up its expected overhead.
			samples: generateSamples(100, 2*maxOverheadCycles),
			err:     errOverheadTooHigh,
		},
		{
			// Overhead at maximum overhead is allowed.
			name: "max-overhead",
			// Generate a bunch of samples. The reference clock
			// needs a while to ramp up its expected overhead.
			samples: generateSamples(100, maxOverheadCycles),
			err:     nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSampler(tc.samples, nil)
			err := s.Sample()
			if err != tc.err {
				t.Errorf("Sample err got %v want %v", err, tc.err)
			}
		})
	}
}

// TestOutliersIgnored tests that referenceClock ignores samples with very high
// overhead.
func TestOutliersIgnored(t *testing.T) {
	s := newTestSampler([]sample{
		{before: 100000, after: 100000 + defaultOverheadCycles, ref: 100},
		{before: 200000, after: 200000 + defaultOverheadCycles, ref: 200},
		{before: 300000, after: 300000 + defaultOverheadCycles, ref: 300},
		{before: 400000, after: 400000 + defaultOverheadCycles, ref: 400},
		{before: 500000, after: 500000 + 5*defaultOverheadCycles, ref: 500}, // Ignored
		{before: 600000, after: 600000 + defaultOverheadCycles, ref: 600},
		{before: 700000, after: 700000 + defaultOverheadCycles, ref: 700},
	}, nil)

	// Collect 5 samples.
	for i := 0; i < 5; i++ {
		err := s.Sample()
		if err != nil {
			t.Fatalf("Unexpected error while sampling: %v", err)
		}
	}

	oldest, newest, ok := s.Range()
	if !ok {
		t.Fatalf("Range not ok")
	}

	if oldest.ref != 100 {
		t.Errorf("oldest.ref got %v want %v", oldest.ref, 100)
	}

	// We skipped the high-overhead sample.
	if newest.ref != 600 {
		t.Errorf("newest.ref got %v want %v", newest.ref, 600)
	}
}
