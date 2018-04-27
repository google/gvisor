// Copyright 2018 Google Inc.
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
	"fmt"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/log"
)

const (
	// ApproxUpdateInterval is the approximate interval that parameters
	// should be updated at.
	//
	// Error correction assumes that the next update will occur after this
	// much time.
	//
	// If an update occurs before ApproxUpdateInterval passes, it has no
	// adverse effect on error correction behavior.
	//
	// If an update occurs after ApproxUpdateInterval passes, the clock
	// will overshoot its error correction target and begin accumulating
	// error in the other direction.
	//
	// If updates occur after more than 2*ApproxUpdateInterval passes, the
	// clock becomes unstable, accumulating more error than it had
	// originally. Repeated updates after more than 2*ApproxUpdateInterval
	// will cause unbounded increases in error.
	//
	// These statements assume that the host clock does not change. Actual
	// error will depend upon host clock changes.
	//
	// TODO: make error correction more robust to delayed
	// updates.
	ApproxUpdateInterval = 1 * time.Second

	// MaxClockError is the maximum amount of error that the clocks will
	// try to correct.
	//
	// This limit:
	//
	//  * Puts a limit on cases of otherwise unbounded increases in error.
	//
	//  * Avoids unreasonably large frequency adjustments required to
	//    correct large errors over a single update interval.
	MaxClockError = ReferenceNS(ApproxUpdateInterval) / 4
)

// Parameters are the timekeeping parameters needed to compute the current
// time.
type Parameters struct {
	// BaseCycles was the TSC counter value when the time was BaseRef.
	BaseCycles TSCValue

	// BaseRef is the reference clock time in nanoseconds corresponding to
	// BaseCycles.
	BaseRef ReferenceNS

	// Frequency is the frequency of the cycle clock in Hertz.
	Frequency uint64
}

// muldiv64 multiplies two 64-bit numbers, then divides the result by another
// 64-bit number.
//
// It requires that the result fit in 64 bits, but doesn't require that
// intermediate values do; in particular, the result of the multiplication may
// require 128 bits.
//
// It returns !ok if divisor is zero or the result does not fit in 64 bits.
func muldiv64(value, multiplier, divisor uint64) (uint64, bool)

// ComputeTime calculates the current time from a "now" TSC value.
//
// time = ref + (now - base) / f
func (p Parameters) ComputeTime(nowCycles TSCValue) (int64, bool) {
	diffCycles := nowCycles - p.BaseCycles
	if diffCycles < 0 {
		log.Warningf("now cycles %v < base cycles %v", nowCycles, p.BaseCycles)
		diffCycles = 0
	}

	// Overflow "won't ever happen". If diffCycles is the max value
	// (2^63 - 1), then to overflow,
	//
	// frequency <= ((2^63 - 1) * 10^9) / 2^64 = 500Mhz
	//
	// A TSC running at 2GHz takes 201 years to reach 2^63-1. 805 years at
	// 500MHz.
	diffNS, ok := muldiv64(uint64(diffCycles), uint64(time.Second.Nanoseconds()), p.Frequency)
	return int64(uint64(p.BaseRef) + diffNS), ok
}

// errorAdjust returns a new Parameters struct "adjusted" that satisfies:
//
// 1. adjusted.ComputeTime(now) = prevParams.ComputeTime(now)
//   * i.e., the current time does not jump.
//
// 2. adjusted.ComputeTime(TSC at next update) = newParams.ComputeTime(TSC at next update)
//   * i.e., Any error between prevParams and newParams will be corrected over
//     the course of the next update period.
//
// errorAdjust also returns the current clock error.
//
// Preconditions:
// * newParams.BaseCycles >= prevParams.BaseCycles; i.e., TSC must not go
//   backwards.
// * newParams.BaseCycles <= now; i.e., the new parameters be computed at or
//   before now.
func errorAdjust(prevParams Parameters, newParams Parameters, now TSCValue) (Parameters, ReferenceNS, error) {
	if newParams.BaseCycles < prevParams.BaseCycles {
		// Oh dear! Something is very wrong.
		return Parameters{}, 0, fmt.Errorf("TSC went backwards in updated clock params: %v < %v", newParams.BaseCycles, prevParams.BaseCycles)
	}
	if newParams.BaseCycles > now {
		return Parameters{}, 0, fmt.Errorf("parameters contain base cycles later than now: %v > %v", newParams.BaseCycles, now)
	}

	intervalNS := int64(ApproxUpdateInterval.Nanoseconds())
	nsPerSec := uint64(time.Second.Nanoseconds())

	// Current time as computed by prevParams.
	oldNowNS, ok := prevParams.ComputeTime(now)
	if !ok {
		return Parameters{}, 0, fmt.Errorf("old now time computation overflowed. params = %+v, now = %v", prevParams, now)
	}

	// We expect the update ticker to run based on this clock (i.e., it has
	// been using prevParams and will use the returned adjusted
	// parameters). Hence it will decide to fire intervalNS from the
	// current (oldNowNS) "now".
	nextNS := oldNowNS + intervalNS

	if nextNS <= int64(newParams.BaseRef) {
		// The next update time already passed before the new
		// parameters were created! We definitely can't correct the
		// error by then.
		return Parameters{}, 0, fmt.Errorf("unable to correct error in single period. oldNowNS = %v, nextNS = %v, p = %v", oldNowNS, nextNS, newParams)
	}

	// For what TSC value next will newParams.ComputeTime(next) = nextNS?
	//
	// Solve ComputeTime for next:
	//
	// next = newParams.Frequency * (nextNS - newParams.BaseRef) + newParams.BaseCycles
	c, ok := muldiv64(newParams.Frequency, uint64(nextNS-int64(newParams.BaseRef)), nsPerSec)
	if !ok {
		return Parameters{}, 0, fmt.Errorf("%v * (%v - %v) / %v overflows", newParams.Frequency, nextNS, newParams.BaseRef, nsPerSec)
	}

	cycles := TSCValue(c)
	next := cycles + newParams.BaseCycles

	if next <= now {
		// The next update time already passed now with the new
		// parameters! We can't correct the error in a single period.
		return Parameters{}, 0, fmt.Errorf("unable to correct error in single period. oldNowNS = %v, nextNS = %v, now = %v, next = %v", oldNowNS, nextNS, now, next)
	}

	// We want to solve for parameters that satisfy:
	//
	// adjusted.ComputeTime(now) = oldNowNS
	//
	// adjusted.ComputeTime(next) = nextNS
	//
	// i.e., the current time does not change, but by the time we reach
	// next we reach the same time as newParams.

	// We choose to keep BaseCycles fixed.
	adjusted := Parameters{
		BaseCycles: newParams.BaseCycles,
	}

	// We want a slope such that time goes from oldNowNS to nextNS when
	// we reach next.
	//
	// In other words, cycles should increase by next - now in the next
	// interval.

	cycles = next - now
	ns := intervalNS

	// adjusted.Frequency = cycles / ns
	adjusted.Frequency, ok = muldiv64(uint64(cycles), nsPerSec, uint64(ns))
	if !ok {
		return Parameters{}, 0, fmt.Errorf("(%v - %v) * %v / %v overflows", next, now, nsPerSec, ns)
	}

	// Now choose a base reference such that the current time remains the
	// same. Note that this is just ComputeTime, solving for BaseRef:
	//
	// oldNowNS = BaseRef + (now - BaseCycles) / Frequency
	// BaseRef = oldNowNS - (now - BaseCycles) / Frequency
	diffNS, ok := muldiv64(uint64(now-adjusted.BaseCycles), nsPerSec, adjusted.Frequency)
	if !ok {
		return Parameters{}, 0, fmt.Errorf("(%v - %v) * %v / %v overflows", now, adjusted.BaseCycles, nsPerSec, adjusted.Frequency)
	}

	adjusted.BaseRef = ReferenceNS(oldNowNS - int64(diffNS))

	// The error is the difference between the current time and what the
	// new parameters say the current time should be.
	newNowNS, ok := newParams.ComputeTime(now)
	if !ok {
		return Parameters{}, 0, fmt.Errorf("new now time computation overflowed. params = %+v, now = %v", newParams, now)
	}

	errorNS := ReferenceNS(oldNowNS - newNowNS)

	return adjusted, errorNS, nil
}

// logErrorAdjustment logs the clock error and associated error correction
// frequency adjustment.
//
// The log level is determined by the error severity.
func logErrorAdjustment(clock ClockID, errorNS ReferenceNS, orig, adjusted Parameters) {
	fn := log.Debugf
	if int64(errorNS.Magnitude()) > time.Millisecond.Nanoseconds() {
		fn = log.Warningf
	} else if int64(errorNS.Magnitude()) > 10*time.Microsecond.Nanoseconds() {
		fn = log.Infof
	}

	fn("Clock(%v): error: %v ns, adjusted frequency from %v Hz to %v Hz", clock, errorNS, orig.Frequency, adjusted.Frequency)
}
