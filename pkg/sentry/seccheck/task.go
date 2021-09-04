// Copyright 2021 The gVisor Authors.
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

package seccheck

import (
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// TaskInfo contains information unambiguously identifying a single thread
// and/or its containing process.
//
// +fieldenum Task
type TaskInfo struct {
	// ThreadID is the thread's ID in the root PID namespace.
	ThreadID int32

	// ThreadStartTime is the thread's CLOCK_REALTIME start time.
	ThreadStartTime ktime.Time

	// ThreadGroupID is the thread's group leader's ID in the root PID
	// namespace.
	ThreadGroupID int32

	// ThreadGroupStartTime is the thread's group leader's CLOCK_REALTIME start
	// time.
	ThreadGroupStartTime ktime.Time
}
