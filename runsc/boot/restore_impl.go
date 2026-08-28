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

//go:build !false
// +build !false

package boot

import (
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/time"
)

// hostTSCRealtime returns the current raw host TSC value and the host
// CLOCK_REALTIME value in nanoseconds.
func hostTSCRealtime() (uint64, uint64, bool) {
	cycle, realtime, err := time.HostTSCRealtime()
	if err != nil {
		log.Warningf("Failed to sample host TSC for TSC offset: %v", err)
		return 0, 0, false
	}
	return uint64(cycle), uint64(realtime), true
}
