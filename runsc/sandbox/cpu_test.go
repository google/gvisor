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

package sandbox

import (
	"testing"

	"gvisor.dev/gvisor/runsc/config"
)

func TestCPUNumForSandbox(t *testing.T) {
	const period = 100000 // 100ms, the usual CFS period.
	for _, tc := range []struct {
		name      string
		fixed     int
		fromQuota bool
		cpuNum    int
		quota     int64
		want      int
	}{
		{
			name:      "fixed overrides quota and may exceed host cpus",
			fixed:     16,
			fromQuota: true,
			cpuNum:    8,
			quota:     1 * period,
			want:      16,
		},
		{
			name:      "fixed overrides an unlimited quota",
			fixed:     8,
			fromQuota: true,
			cpuNum:    4,
			quota:     0,
			want:      8,
		},
		{
			name:      "from quota rounds up",
			fromQuota: true,
			cpuNum:    8,
			quota:     150000, // 1.5 CPUs
			want:      2,
		},
		{
			name:      "from quota floors at two cpus",
			fromQuota: true,
			cpuNum:    8,
			quota:     50000, // 0.5 CPUs
			want:      2,
		},
		{
			name:      "from quota only lowers, never raises",
			fromQuota: true,
			cpuNum:    8,
			quota:     16 * period,
			want:      8,
		},
		{
			name:      "from quota disabled leaves cpu count unchanged",
			fromQuota: false,
			cpuNum:    8,
			quota:     1 * period,
			want:      8,
		},
		{
			name:      "unlimited quota leaves cpu count unchanged",
			fromQuota: true,
			cpuNum:    8,
			quota:     0,
			want:      8,
		},
		{
			name:      "no cgroup, no fixed count defaults to host (zero)",
			fromQuota: true,
			cpuNum:    0,
			quota:     0,
			want:      0,
		},
		{
			name:   "fixed count with no cgroup",
			fixed:  8,
			cpuNum: 0,
			quota:  0,
			want:   8,
		},
		{
			name:   "fixed count wins with from-quota disabled",
			fixed:  8,
			cpuNum: 4,
			quota:  16 * period,
			want:   8,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &config.Config{
				CPUNumFixed:     tc.fixed,
				CPUNumFromQuota: tc.fromQuota,
			}
			if got := cpuNumForSandbox(conf, tc.cpuNum, tc.quota, period); got != tc.want {
				t.Errorf("cpuNumForSandbox(fixed=%d, fromQuota=%t, cpuNum=%d, quota=%d) = %d, want %d",
					tc.fixed, tc.fromQuota, tc.cpuNum, tc.quota, got, tc.want)
			}
		})
	}
}
