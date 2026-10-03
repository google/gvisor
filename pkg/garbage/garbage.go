// Copyright 2026 The gVisor Authors.
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

// Package garbage manages the Go garbage collector.
package garbage

import (
	gcdebug "runtime/debug"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

var (
	// suspensions counts `Suspend` calls not yet matched by a `Resume`.
	suspensions atomicbitops.Int64

	// resumePercent is the collection target percentage in effect before the
	// first `Suspend`, restored by the last `Resume`.
	resumePercent int
)

// Suspend turns garbage collection off until a matching `Resume`.
// Every `Suspend` must be matched by a `Resume`.
func Suspend() {
	if suspensions.Add(1) == 1 {
		resumePercent = gcdebug.SetGCPercent(-1)
	}
}

// Resume releases one `Suspend`.
// Once all suspensions are released, garbage collection resumes.
func Resume() {
	n := suspensions.Add(-1)
	if n < 0 {
		suspensions.Add(1)
		panic("garbage.Resume without a matching Suspend")
	}
	if n == 0 {
		gcdebug.SetGCPercent(resumePercent)
	}
}
