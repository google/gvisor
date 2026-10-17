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

package time

import "gvisor.dev/gvisor/pkg/errors/linuxerr"

// ReferenceClocks reads the host clocks directly. It does not publish a raw
// counter calibration, so application VDSO reads fall back to the Sentry.
// This avoids requiring synchronized hardware counters across host CPUs.
type ReferenceClocks struct {
	monotonicRawEnabled bool
}

// NewReferenceClocks returns clocks backed by the host clock_gettime helper.
// monotonicRawEnabled has the same meaning as in NewCalibratedClocks.
func NewReferenceClocks(monotonicRawEnabled bool) *ReferenceClocks {
	return &ReferenceClocks{monotonicRawEnabled: monotonicRawEnabled}
}

// Update implements Clocks.Update. Reference clocks never publish calibration
// parameters, including after an idle period or restore.
func (*ReferenceClocks) Update(bool) UpdateResult {
	return UpdateResult{}
}

// GetTime implements Clocks.GetTime.
func (c *ReferenceClocks) GetTime(id ClockID) (int64, error) {
	switch id {
	case Monotonic, Realtime:
	case MonotonicRaw:
		if !c.monotonicRawEnabled {
			return 0, linuxerr.EINVAL
		}
	default:
		return 0, linuxerr.EINVAL
	}
	now, err := clockGettime(id)
	return int64(now), err
}

// MonotonicRawEnabled implements Clocks.MonotonicRawEnabled.
func (c *ReferenceClocks) MonotonicRawEnabled() bool {
	return c.monotonicRawEnabled
}
