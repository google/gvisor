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

// Clocks represents a clock source that contains both a monotonic and realtime
// clock.
type Clocks interface {
	// Update performs an update step, keeping the clocks in sync with the
	// reference host clocks, and returning the new timekeeping parameters.
	//
	// Update should be called at approximately ApproxUpdateInterval.
	Update() (monotonicParams Parameters, monotonicOk bool, realtimeParam Parameters, realtimeOk bool)

	// GetTime returns the current time in nanoseconds for the given clock.
	//
	// Clocks implementations must support at least Monotonic and
	// Realtime.
	GetTime(c ClockID) (int64, error)
}
