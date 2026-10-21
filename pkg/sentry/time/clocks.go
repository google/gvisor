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

// UpdateResult holds the timekeeping parameters produced by Clocks.Update.
//
// Each *Ok field reports whether the corresponding *Params were successfully
// calibrated and may be published to the VDSO. MonotonicRaw is only populated
// by clock sources that track a distinct CLOCK_MONOTONIC_RAW; otherwise
// MonotonicRawOk is false.
type UpdateResult struct {
	Monotonic      Parameters
	MonotonicOk    bool
	Realtime       Parameters
	RealtimeOk     bool
	MonotonicRaw   Parameters
	MonotonicRawOk bool
}

// TSCSnapshot is a correspondence between a guest TSC value and the realtime
// clock, plus the TSC frequency needed to extrapolate between them.
//
// It is captured at save time and consumed on restore to re-derive the guest
// TSC offset required to keep time moving forward across a migration.
type TSCSnapshot struct {
	// Cycle is a TSC value in the guest TSC domain, i.e. the value the
	// application observes, including any guest TSC offset applied by the
	// platform. This keeps the application TSC continuous across repeated
	// save/restore cycles.
	Cycle uint64

	// RealtimeNsec is CLOCK_REALTIME, in nanoseconds, at Cycle.
	RealtimeNsec uint64

	// Frequency is the TSC frequency in Hz.
	Frequency uint64
}

// Clocks represents a clock source that contains both a monotonic and realtime
// clock.
type Clocks interface {
	// Update performs an update step, keeping the clocks in sync with the
	// reference host clocks, and returning the new timekeeping parameters.
	//
	// Update should be called at approximately ApproxUpdateInterval.
	//
	// parked indicates that the clock was not read for at least ApproxUpdateInterval
	Update(parked bool) UpdateResult

	// GetTime returns the current time in nanoseconds for the given clock.
	//
	// Clocks implementations must support at least Monotonic and
	// Realtime.
	GetTime(c ClockID) (int64, error)

	// MonotonicRawEnabled reports whether this clock source tracks a distinct
	// CLOCK_MONOTONIC_RAW, i.e. whether GetTime(MonotonicRaw) returns the
	// host's absolute CLOCK_MONOTONIC_RAW rather than aliasing Monotonic.
	//
	// It must return the same value for the lifetime of the Clocks.
	MonotonicRawEnabled() bool

	// TSCSnapshot returns the realtime clock's current base point, expressed
	// in the guest TSC domain, and whether it is valid.
	TSCSnapshot() (TSCSnapshot, bool)
}
