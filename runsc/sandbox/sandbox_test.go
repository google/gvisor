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
	"errors"
	"runtime"
	"testing"

	"gvisor.dev/gvisor/runsc/cgroup"
)

type fakeCgroup struct {
	cgroup.Cgroup
	numCPU    int
	numCPUErr error
	cpuQuota  int64
	cpuPeriod int64
}

func (f *fakeCgroup) NumCPU() (int, error) {
	return f.numCPU, f.numCPUErr
}

func (f *fakeCgroup) CPUQuota() (int64, error) {
	return f.cpuQuota, nil
}

func (f *fakeCgroup) CPUPeriod() (int64, error) {
	return f.cpuPeriod, nil
}

func TestCalculateCPUNum(t *testing.T) {
	for _, tc := range []struct {
		name            string
		numCPU          int
		numCPUErr       error
		cpuQuota        int64
		cpuPeriod       int64
		cpuNumFromQuota bool
		want            int
	}{
		{
			name:      "cgroup NumCPU error fallback to runtime.NumCPU",
			numCPUErr: errors.New("cgroup cpuset read error"),
			want:      runtime.NumCPU(),
		},
		{
			name:   "cgroup NumCPU success",
			numCPU: 8,
			want:   8,
		},
		{
			name:            "cgroup NumCPU error fallback with quota limit",
			numCPUErr:       errors.New("cgroup cpuset read error"),
			cpuQuota:        400000,
			cpuPeriod:       100000,
			cpuNumFromQuota: true,
			want:            min(runtime.NumCPU(), 4),
		},
		{
			name:            "cgroup NumCPU error fallback with low quota minCPUs floor",
			numCPUErr:       errors.New("cgroup cpuset read error"),
			cpuQuota:        100000,
			cpuPeriod:       100000,
			cpuNumFromQuota: true,
			want:            min(runtime.NumCPU(), 2),
		},
		{
			name:            "cgroup NumCPU success with quota limit",
			numCPU:          16,
			cpuQuota:        400000,
			cpuPeriod:       100000,
			cpuNumFromQuota: true,
			want:            4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg := &fakeCgroup{
				numCPU:    tc.numCPU,
				numCPUErr: tc.numCPUErr,
				cpuQuota:  tc.cpuQuota,
				cpuPeriod: tc.cpuPeriod,
			}
			gotNum, gotQuota, gotPeriod, err := calculateCPUNum(cg, tc.cpuNumFromQuota)
			if err != nil {
				t.Fatalf("calculateCPUNum failed: %v", err)
			}
			if gotNum != tc.want {
				t.Errorf("calculateCPUNum() got cpuNum = %d, want %d", gotNum, tc.want)
			}
			if gotQuota != tc.cpuQuota {
				t.Errorf("calculateCPUNum() got cpuQuota = %d, want %d", gotQuota, tc.cpuQuota)
			}
			if gotPeriod != tc.cpuPeriod {
				t.Errorf("calculateCPUNum() got cpuPeriod = %d, want %d", gotPeriod, tc.cpuPeriod)
			}
		})
	}
}
