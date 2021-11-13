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
	"errors"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	// maxSampleLoops is the maximum number of times to try to get a clock sample
	// under the expected overhead.
	maxSampleLoops = 5

	// maxSamples is the maximum number of samples to collect.
	maxSamples = 10
)

// errOverheadTooHigh is returned from sampler.Sample if the syscall
// overhead is too high.
var errOverheadTooHigh = errors.New("time syscall overhead exceeds maximum")

// TSCValue is a value from the TSC.
type TSCValue int64

// Rdtsc reads the TSC.
//
// Intel SDM, Vol 3, Ch 17.15:
// "The RDTSC instruction reads the time-stamp counter and is guaranteed to
// return a monotonically increasing unique value whenever executed, except for
// a 64-bit counter wraparound. Intel guarantees that the time-stamp counter
// will not wraparound within 10 years after being reset."
//
// We use int64, so we have 5 years before wrap-around.
func Rdtsc() TSCValue

// ReferenceNS are nanoseconds in the reference clock domain.
// int64 gives us ~290 years before this overflows.
type ReferenceNS int64

// Magnitude returns the absolute value of r.
func (r ReferenceNS) Magnitude() ReferenceNS {
	if r < 0 {
		return -r
	}
	return r
}

// cycleClock is a TSC-based cycle clock.
type cycleClock interface {
	// Cycles returns a count value from the TSC.
	Cycles() TSCValue
}

// tscCycleClock is a cycleClock that uses the real TSC.
type tscCycleClock struct{}

// Cycles implements cycleClock.Cycles.
func (tscCycleClock) Cycles() TSCValue {
	return Rdtsc()
}

// sample contains a sample from the reference clock, with TSC values from
// before and after the reference clock value was captured.
type sample struct {
	before TSCValue
	after  TSCValue
	ref    ReferenceNS
}

// Overhead returns the sample overhead in TSC cycles.
func (s *sample) Overhead() TSCValue {
	return s.after - s.before
}

// referenceClocks collects individual samples from a reference clock ID and
// TSC.
type referenceClocks interface {
	cycleClock

	// Sample returns a single sample from the reference clock ID.
	Sample(c ClockID) (sample, error)
}

// sampler collects samples from a reference system clock, minimizing
// the overhead in each sample.
type sampler struct {
	// clockID is the reference clock ID (e.g., CLOCK_MONOTONIC).
	clockID ClockID

	// clocks provides raw samples.
	clocks referenceClocks

	// overhead is the estimated sample overhead in TSC cycles.
	overhead TSCValue

	// samples is a ring buffer of the latest samples collected.
	samples []sample
}

// newSampler creates a sampler for clockID.
func newSampler(c ClockID) *sampler {
	return &sampler{
		clockID:  c,
		clocks:   syscallTSCReferenceClocks{},
		overhead: defaultOverheadCycles,
	}
}

// Reset discards previously collected clock samples.
func (s *sampler) Reset() {
	s.overhead = defaultOverheadCycles
	s.samples = []sample{}
}

// lowOverheadSample returns a reference clock sample with minimized syscall overhead.
func (s *sampler) lowOverheadSample() (sample, error) {
	for {
		for i := 0; i < maxSampleLoops; i++ {
			samp, err := s.clocks.Sample(s.clockID)
			if err != nil {
				return sample{}, err
			}

			if samp.before > samp.after {
				log.Warningf("TSC went backwards: %v > %v", samp.before, samp.after)
				continue
			}

			if samp.Overhead() <= s.overhead {
				return samp, nil
			}
		}

		// Couldn't get a sample with the current overhead. Increase it.
		newOverhead := 2 * s.overhead
		if newOverhead > maxOverheadCycles {
			// We'll give it one more shot with the max overhead.

			if s.overhead == maxOverheadCycles {
				return sample{}, errOverheadTooHigh
			}

			newOverhead = maxOverheadCycles
		}

		s.overhead = newOverhead
		log.Debugf("Time: Adjusting syscall overhead up to %v", s.overhead)
	}
}

// Sample collects a reference clock sample.
func (s *sampler) Sample() error {
	sample, err := s.lowOverheadSample()
	if err != nil {
		return err
	}

	s.samples = append(s.samples, sample)
	if len(s.samples) > maxSamples {
		s.samples = s.samples[1:]
	}

	// If the 4 most recent samples all have an overhead less than half the
	// expected overhead, adjust downwards.
	if len(s.samples) < 4 {
		return nil
	}

	for _, sample := range s.samples[len(s.samples)-4:] {
		if sample.Overhead() > s.overhead/2 {
			return nil
		}
	}

	s.overhead -= s.overhead / 8
	log.Debugf("Time: Adjusting syscall overhead down to %v", s.overhead)

	return nil
}

// Syscall returns the current raw reference time without storing TSC
// samples.
func (s *sampler) Syscall() (ReferenceNS, error) {
	sample, err := s.clocks.Sample(s.clockID)
	if err != nil {
		return 0, err
	}

	return sample.ref, nil
}

// Cycles returns a raw TSC value.
func (s *sampler) Cycles() TSCValue {
	return s.clocks.Cycles()
}

// Range returns the widest range of clock samples available.
func (s *sampler) Range() (sample, sample, bool) {
	if len(s.samples) < 2 {
		return sample{}, sample{}, false
	}

	return s.samples[0], s.samples[len(s.samples)-1], true
}

// syscallTSCReferenceClocks is the standard referenceClocks, collecting
// samples using CLOCK_GETTIME and RDTSC.
type syscallTSCReferenceClocks struct {
	tscCycleClock
}

// Sample implements sampler.Sample.
func (syscallTSCReferenceClocks) Sample(c ClockID) (sample, error) {
	var s sample

	s.before = Rdtsc()

	// Don't call clockGettime to avoid a call which may call morestack.
	var ts unix.Timespec

	vdsoClockGettime(c, &ts)

	s.after = Rdtsc()
	s.ref = ReferenceNS(ts.Nano())

	return s, nil
}

// clockGettime calls SYS_CLOCK_GETTIME, returning time in nanoseconds.
func clockGettime(c ClockID) (ReferenceNS, error) {
	var ts unix.Timespec

	vdsoClockGettime(c, &ts)

	return ReferenceNS(ts.Nano()), nil
}
