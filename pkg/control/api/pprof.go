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

package api

import (
	"time"

	"gvisor.dev/gvisor/pkg/urpc"
)

const (
	// DefaultBlockProfileRate is the default profiling rate for block
	// profiles.
	//
	// The default here is 10%, which will record a stacktrace 10% of the
	// time when blocking occurs. Since these events should not be super
	// frequent, we expect this to achieve a reasonable balance between
	// collecting the data we need and imposing a high performance cost
	// (e.g. skewing even the CPU profile).
	DefaultBlockProfileRate = 10

	// DefaultMutexProfileRate is the default profiling rate for mutex
	// profiles. Like the block rate above, we use a default rate of 10%
	// for the same reasons.
	DefaultMutexProfileRate = 10
)

// CPUProfileOpts contains options specifically for CPU profiles.
type CPUProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Duration is the duration of the profile.
	Duration time.Duration `json:"duration"`
}

// HeapProfileOpts contains options specifically for heap profiles.
type HeapProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Delay is the sleep time, similar to Duration. This may
	// not affect the data collected however, as the heap will
	// continue only the memory associated with the last alloc.
	Delay time.Duration `json:"delay"`
}

// GoroutineProfileOpts contains options specifically for goroutine profiles.
type GoroutineProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload
}

// BlockProfileOpts contains options specifically for block profiles.
type BlockProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Duration is the duration of the profile.
	Duration time.Duration `json:"duration"`

	// Rate is the block profile rate.
	Rate int `json:"rate"`
}

// MutexProfileOpts contains options specifically for mutex profiles.
type MutexProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Duration is the duration of the profile.
	Duration time.Duration `json:"duration"`

	// Fraction is the mutex profile fraction.
	Fraction int `json:"fraction"`
}

// TraceProfileOpts contains options specifically for traces.
type TraceProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Duration is the duration of the profile.
	Duration time.Duration `json:"duration"`
}
