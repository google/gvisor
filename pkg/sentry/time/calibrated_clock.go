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

// Package time provides a calibrated clock synchronized to a system reference
// clock.
package time

import (
	"time"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/sync"
)

// CalibratedClock implements a clock that tracks a reference clock.
//
// Users should call Update at regular intervals of around approxUpdateInterval
// to ensure that the clock does not drift significantly from the reference
// clock.
type CalibratedClock struct {
	// mu protects ref's mutable sampling state.
	mu sync.Mutex

	// seq orders lockless reads of params with Update.
	seq sync.SeqCount

	// ref samples the reference clock that this clock is calibrated against.
	// The pointer is immutable; its samples and overhead are protected by mu.
	// The sampler has no link back to this clock, so checklocks cannot name
	// the owning mutex for the sampler's fields and methods.
	ref *sampler

	// ready indicates that the fields below are ready for use calculating
	// time.
	//
	// +checklocks:mu
	ready bool

	// params are the current timekeeping parameters, or zero while the clock
	// is not ready. Writing params requires that mu is locked and that seq is
	// in a writer critical section. Reading params requires either that mu is
	// locked, or using seq and SeqAtomicLoadParameters. checklocks cannot
	// express this.
	params Parameters

	// errorNS is the estimated clock error in nanoseconds.
	//
	// +checklocks:mu
	errorNS ReferenceNS
}

// NewCalibratedClock creates a CalibratedClock that tracks the given ClockID.
func NewCalibratedClock(c ClockID) *CalibratedClock {
	return &CalibratedClock{
		ref: newSampler(c),
	}
}

// Debugf logs at debug level.
func (c *CalibratedClock) Debugf(format string, v ...any) {
	if log.IsLogging(log.Debug) {
		args := []any{c.ref.clockID}
		args = append(args, v...)
		log.Debugf("CalibratedClock(%v): "+format, args...)
	}
}

// Infof logs at info level.
func (c *CalibratedClock) Infof(format string, v ...any) {
	if log.IsLogging(log.Info) {
		args := []any{c.ref.clockID}
		args = append(args, v...)
		log.Infof("CalibratedClock(%v): "+format, args...)
	}
}

// Warningf logs at warning level.
func (c *CalibratedClock) Warningf(format string, v ...any) {
	if log.IsLogging(log.Warning) {
		args := []any{c.ref.clockID}
		args = append(args, v...)
		log.Warningf("CalibratedClock(%v): "+format, args...)
	}
}

// reset forces the clock to restart the calibration process, logging the
// passed message.
//
// +checklocksexclude:c.mu
func (c *CalibratedClock) reset(str string, v ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq.BeginWrite()
	c.resetLocked(str, v...)
	c.seq.EndWrite()
}

// resetLocked is equivalent to reset with c.mu already held.
//
// Preconditions: c.seq is in a writer critical section.
//
// +checklocks:c.mu
func (c *CalibratedClock) resetLocked(str string, v ...any) {
	c.Warningf(str+" Resetting clock; time may jump.", v...)
	c.ready = false
	c.params = Parameters{}
	c.ref.Reset()
	metric.WeirdnessMetric.Increment(&metric.WeirdnessTypeTimeFallback)
}

// updateParams updates the timekeeping parameters based on the passed
// parameters.
//
// actual is the actual estimated timekeeping parameters. The stored parameters
// may need to be adjusted slightly from these values to compensate for error.
//
// +checklocks:c.mu
func (c *CalibratedClock) updateParams(actual Parameters, parked bool) {
	if !c.ready || parked {
		// when parked nothing has read the time for a whole interval, so
		// assume errors have been compensated and recalibrate from scratch
		c.params = actual
		if !c.ready {
			c.ready = true
			c.Infof("ready")
		}
		return
	}

	// Otherwise, adjust the params to correct for errors.
	newParams, errorNS, err := errorAdjust(c.params, actual, actual.BaseCycles)
	if err != nil {
		// Something is very wrong. Reset and try again from the
		// beginning.
		c.resetLocked("Unable to update params: %v.", err)
		return
	}

	if errorNS.Magnitude() >= MaxClockError {
		// We should never get such extreme error, something is very
		// wrong. Reset everything and start again.
		//
		// TODO(mpratt): We could allow Realtime clock jumps here.
		log.Warningf("Clock(%v): error: %v ns, adjusted frequency from %v Hz to %v Hz", c.ref.clockID, errorNS, c.params.Frequency, newParams.Frequency)
		c.resetLocked("Extreme clock error.")
		return
	}

	c.params = newParams
	c.errorNS = errorNS
}

// Update runs the update step of the clock, updating its synchronization with
// the reference clock.
//
// Update returns timekeeping and true with the new timekeeping parameters if
// the clock is calibrated. Update should be called regularly to prevent the
// clock from getting significantly out of sync from the reference clock.
//
// parked indicates that this Update resumes a parked (unobserved) period; see
// updateParams.
//
// The returned timekeeping parameters are invalidated on the next call to
// Update.
//
// +checklocksexclude:c.mu
func (c *CalibratedClock) Update(parked bool) (Parameters, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// A reader that uses the old parameters must also read the TSC before the
	// new sample, so the writer critical section spans the whole update.
	c.seq.BeginWrite()
	defer c.seq.EndWrite()

	if err := c.ref.Sample(); err != nil {
		c.resetLocked("Unable to update calibrated clock: %v.", err)
		return Parameters{}, false
	}

	oldest, newest, ok := c.ref.Range()
	if !ok {
		// Not ready yet.
		return Parameters{}, false
	}

	minCount := uint64(newest.before - oldest.after)
	maxCount := uint64(newest.after - oldest.before)
	refInterval := uint64(newest.ref - oldest.ref)

	// freq hz = count / (interval ns) * (nsPerS ns) / (1 s)
	nsPerS := uint64(time.Second.Nanoseconds())

	minHz, ok := muldiv64(minCount, nsPerS, refInterval)
	if !ok {
		c.resetLocked("Unable to update calibrated clock: (%v - %v) * %v / %v overflows.", newest.before, oldest.after, nsPerS, refInterval)
		return Parameters{}, false
	}

	maxHz, ok := muldiv64(maxCount, nsPerS, refInterval)
	if !ok {
		c.resetLocked("Unable to update calibrated clock: (%v - %v) * %v / %v overflows.", newest.after, oldest.before, nsPerS, refInterval)
		return Parameters{}, false
	}

	c.updateParams(Parameters{
		Frequency:  (minHz + maxHz) / 2,
		BaseRef:    newest.ref,
		BaseCycles: newest.after,
	}, parked)

	return c.params, c.ready
}

// GetTime returns the current time based on the clock calibration.
//
// +checklocksexclude:c.mu
func (c *CalibratedClock) GetTime() (int64, error) {
	for {
		// Read the TSC within the read critical section, so that it is not
		// later than a concurrent Update's sample.
		epoch := c.seq.BeginRead()
		params, ok := SeqAtomicTryLoadParameters(&c.seq, epoch, &c.params)
		if !ok {
			continue
		}
		if params.Frequency == 0 {
			// Not calibrated. Fallback to a syscall.
			c.mu.Lock()
			now, err := c.ref.Syscall()
			c.mu.Unlock()
			return int64(now), err
		}
		now := c.ref.Cycles()
		if !c.seq.ReadOk(epoch) {
			continue
		}

		v, ok := params.ComputeTime(now)
		if !ok {
			// The calibrated computation overflowed. Fall back to the
			// reference clock.
			c.mu.Lock()
			// Reset only if the overflowing calibration is still current.
			if c.ready && c.params == params {
				c.seq.BeginWrite()
				c.resetLocked("Time computation overflowed. params = %+v, now = %v.", params, now)
				c.seq.EndWrite()
			}
			now, err := c.ref.Syscall()
			c.mu.Unlock()
			return int64(now), err
		}
		return v, nil
	}
}

// Params returns the current timekeeping parameters, and whether the clock is
// calibrated. The parameters are in whatever cycle domain c.ref samples, which
// for the real TSC clock includes any guest TSC offset.
func (c *CalibratedClock) Params() (Parameters, bool) {
	p := SeqAtomicLoadParameters(&c.seq, &c.params)
	return p, p.Frequency != 0
}

// CalibratedClocks contains calibrated monotonic and realtime clocks.
//
// TODO(mpratt): We know that Linux runs the monotonic and realtime clocks at
// the same rate, so rather than tracking both individually, we could do one
// calibration for both clocks.
type CalibratedClocks struct {
	// monotonic is the clock tracking the system monotonic clock.
	monotonic *CalibratedClock

	// realtime is the realtime equivalent of monotonic.
	realtime *CalibratedClock

	// monotonicRaw tracks the host CLOCK_MONOTONIC_RAW clock. It is nil unless
	// enabled via NewCalibratedClocks.
	monotonicRaw *CalibratedClock
}

// NewCalibratedClocks creates a CalibratedClocks. If monotonicRawEnabled is
// true, host CLOCK_MONOTONIC_RAW is additionally tracked as a distinct clock
// (addressable as MonotonicRaw).
func NewCalibratedClocks(monotonicRawEnabled bool) *CalibratedClocks {
	c := &CalibratedClocks{
		monotonic: NewCalibratedClock(Monotonic),
		realtime:  NewCalibratedClock(Realtime),
	}
	if monotonicRawEnabled {
		c.monotonicRaw = NewCalibratedClock(MonotonicRaw)
	}
	return c
}

// Update implements Clocks.Update.
//
// +checklocksexclude:c.monotonic.mu
// +checklocksexclude:c.realtime.mu
// +checklocksexclude:c.monotonicRaw.mu
func (c *CalibratedClocks) Update(parked bool) UpdateResult {
	var res UpdateResult
	res.Monotonic, res.MonotonicOk = c.monotonic.Update(parked)
	res.Realtime, res.RealtimeOk = c.realtime.Update(parked)
	if c.monotonicRaw != nil {
		res.MonotonicRaw, res.MonotonicRawOk = c.monotonicRaw.Update(parked)
	}

	return res
}

// MonotonicRawEnabled implements Clocks.MonotonicRawEnabled.
func (c *CalibratedClocks) MonotonicRawEnabled() bool {
	return c.monotonicRaw != nil
}

// GetTime implements Clocks.GetTime.
//
// +checklocksexclude:c.monotonic.mu
// +checklocksexclude:c.realtime.mu
// +checklocksexclude:c.monotonicRaw.mu
func (c *CalibratedClocks) GetTime(id ClockID) (int64, error) {
	switch id {
	case Monotonic:
		return c.monotonic.GetTime()
	case Realtime:
		return c.realtime.GetTime()
	case MonotonicRaw:
		if c.monotonicRaw != nil {
			return c.monotonicRaw.GetTime()
		}
		return 0, linuxerr.EINVAL
	default:
		return 0, linuxerr.EINVAL
	}
}

// TSCSnapshot implements Clocks.TSCSnapshot.
func (c *CalibratedClocks) TSCSnapshot() (TSCSnapshot, bool) {
	p, ok := c.realtime.Params()
	if !ok {
		return TSCSnapshot{}, false
	}

	// p.BaseCycles comes from tscCycleClock, which reports the guest TSC,
	// so it is already in the snapshot's domain.
	return TSCSnapshot{
		Cycle:        uint64(p.BaseCycles),
		RealtimeNsec: uint64(p.BaseRef),
		Frequency:    p.Frequency,
	}, true
}
