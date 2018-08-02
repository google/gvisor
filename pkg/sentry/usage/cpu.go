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

package usage

import (
	"time"
)

// CPUStats contains the subset of struct rusage fields that relate to CPU
// scheduling.
type CPUStats struct {
	// UserTime is the amount of time spent executing application code.
	UserTime time.Duration

	// SysTime is the amount of time spent executing sentry code.
	SysTime time.Duration

	// VoluntarySwitches is the number of times control has been voluntarily
	// ceded due to blocking, etc.
	VoluntarySwitches uint64

	// InvoluntarySwitches (struct rusage::ru_nivcsw) is unsupported, since
	// "preemptive" scheduling is managed by the Go runtime, which doesn't
	// provide this information.
}

// Accumulate adds s2 to s.
func (s *CPUStats) Accumulate(s2 CPUStats) {
	s.UserTime += s2.UserTime
	s.SysTime += s2.SysTime
	s.VoluntarySwitches += s2.VoluntarySwitches
}
