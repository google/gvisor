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

// Package time provides a calibrated clock synchronized to a system reference
// clock.
package time

import (
	"sync"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/metric"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// fallbackMetric tracks failed updates. It is not sync, as it is not critical
// that all occurrences are captured and CalibratedClock may fallback many
// times.
var fallbackMetric = metric.MustCreateNewUint64Metric("/time/fallback", false /* sync */, "Incremented when a clock falls back to system calls due to a failed update")

// CalibratedClock implements a clock that tracks a reference clock.
//
// Users should call Update at regular intervals of around approxUpdateInterval
// to ensure that the clock does not drift significantly from the reference
// clock.
type CalibratedClock struct {
	// mu protects the fields below.
	// TODO: consider a sequence counter for read locking.
	mu sync.RWMutex

	// ref sample the reference clock that this clock is calibrated
	// against.
	ref *sampler

	// ready indicates that the fields below are ready for use calculating
	// time.
	ready bool

	// params are the current timekeeping parameters.
	params Parameters

	// errorNS is the estimated clock error in nanoseconds.
	errorNS ReferenceNS
}

// NewCalibratedClock creates a CalibratedClock that tracks the given ClockID.
func NewCalibratedClock(c ClockID) *CalibratedClock {
	return &CalibratedClock{
		ref: newSampler(c),
	}
}

// Debugf logs at debug level.
func (c *CalibratedClock) Debugf(format string, v ...interface{}) {
	if log.IsLogging(log.Debug) {
		args := []interface{}{c.ref.clockID}
		args = append(args, v...)
		log.Debugf("CalibratedClock(%v): "+format, args...)
	}
}

// Infof logs at debug level.
func (c *CalibratedClock) Infof(format string, v ...interface{}) {
	if log.IsLogging(log.Info) {
		args := []interface{}{c.ref.clockID}
		args = append(args, v...)
		log.Infof("CalibratedClock(%v): "+format, args...)
	}
}

// Warningf logs at debug level.
func (c *CalibratedClock) Warningf(format string, v ...interface{}) {
	if log.IsLogging(log.Warning) {
		args := []interface{}{c.ref.clockID}
		args = append(args, v...)
		log.Warningf("CalibratedClock(%v): "+format, args...)
	}
}

// reset forces the clock to restart the calibration process, logging the
// passed message.
func (c *CalibratedClock) reset(str string, v ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked(str, v...)
}

// resetLocked is equivalent to reset with c.mu already held for writing.
func (c *CalibratedClock) resetLocked(str string, v ...interface{}) {
	c.Warningf(str+" Resetting clock; time may jump.", v...)
	c.ready = false
	c.ref.Reset()
	fallbackMetric.Increment()
}

// updateParams updates the timekeeping parameters based on the passed
// parameters.
//
// actual is the actual estimated timekeeping parameters. The stored parameters
// may need to be adjusted slightly from these values to compensate for error.
//
// Preconditions: c.mu must be held for writing.
func (c *CalibratedClock) updateParams(actual Parameters) {
	if !c.ready {
		// At initial calibration there is nothing to correct.
		c.params = actual
		c.ready = true

		c.Infof("ready")

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
	logErrorAdjustment(c.ref.clockID, errorNS, c.params, newParams)

	if errorNS.Magnitude() >= MaxClockError {
		// We should never get such extreme error, something is very
		// wrong. Reset everything and start again.
		//
		// N.B. logErrorAdjustment will have already logged the error
		// at warning level.
		//
		// TODO: We could allow Realtime clock jumps here.
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
// The returned timekeeping parameters are invalidated on the next call to
// Update.
func (c *CalibratedClock) Update() (Parameters, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	})

	return c.params, true
}

// GetTime returns the current time based on the clock calibration.
func (c *CalibratedClock) GetTime() (int64, error) {
	c.mu.RLock()

	if !c.ready {
		// Fallback to a syscall.
		now, err := c.ref.Syscall()
		c.mu.RUnlock()
		return int64(now), err
	}

	now := c.ref.Cycles()
	v, ok := c.params.ComputeTime(now)
	if !ok {
		// Something is seriously wrong with the clock. Try
		// again with syscalls.
		c.resetLocked("Time computation overflowed. params = %+v, now = %v.", c.params, now)
		now, err := c.ref.Syscall()
		c.mu.RUnlock()
		return int64(now), err
	}

	c.mu.RUnlock()
	return v, nil
}

// CalibratedClocks contains calibrated monotonic and realtime clocks.
//
// TODO: We know that Linux runs the monotonic and realtime clocks at
// the same rate, so rather than tracking both individually, we could do one
// calibration for both clocks.
type CalibratedClocks struct {
	// monotonic is the clock tracking the system monotonic clock.
	monotonic *CalibratedClock

	// realtime is the realtime equivalent of monotonic.
	realtime *CalibratedClock
}

// NewCalibratedClocks creates a CalibratedClocks.
func NewCalibratedClocks() *CalibratedClocks {
	return &CalibratedClocks{
		monotonic: NewCalibratedClock(Monotonic),
		realtime:  NewCalibratedClock(Realtime),
	}
}

// Update implements Clocks.Update.
func (c *CalibratedClocks) Update() (Parameters, bool, Parameters, bool) {
	monotonicParams, monotonicOk := c.monotonic.Update()
	realtimeParams, realtimeOk := c.realtime.Update()

	return monotonicParams, monotonicOk, realtimeParams, realtimeOk
}

// GetTime implements Clocks.GetTime.
func (c *CalibratedClocks) GetTime(id ClockID) (int64, error) {
	switch id {
	case Monotonic:
		return c.monotonic.GetTime()
	case Realtime:
		return c.realtime.GetTime()
	default:
		return 0, syserror.EINVAL
	}
}
