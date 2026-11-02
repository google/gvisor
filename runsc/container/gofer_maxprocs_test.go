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

package container

import (
	"errors"
	"runtime"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/sandbox"
)

type fakeGoferCgroup struct {
	cgroup.Cgroup
	numCPU       int
	numCPUErr    error
	cpuQuota     int64
	cpuQuotaErr  error
	cpuPeriod    int64
	cpuPeriodErr error
}

func (f *fakeGoferCgroup) NumCPU() (int, error) {
	return f.numCPU, f.numCPUErr
}

func (f *fakeGoferCgroup) CPUQuota() (int64, error) {
	return f.cpuQuota, f.cpuQuotaErr
}

func (f *fakeGoferCgroup) CPUPeriod() (int64, error) {
	return f.cpuPeriod, f.cpuPeriodErr
}

func TestGoferGOMAXPROCS(t *testing.T) {
	hostCap := max(1, min(runtime.NumCPU(), goferMaxProcs))

	for _, tc := range []struct {
		name   string
		cg     cgroup.Cgroup
		selfCg func() (cgroup.Cgroup, error)
		limits *sandbox.CPULimits
		want   int
	}{
		{
			name: "wide cgroup caps at goferMaxProcs",
			cg:   &fakeGoferCgroup{numCPU: 64, cpuQuota: -1, cpuPeriod: 100000},
			want: goferMaxProcs,
		},
		{
			name: "quota above cap is capped at goferMaxProcs",
			cg:   &fakeGoferCgroup{numCPU: 64, cpuQuota: 1200000, cpuPeriod: 100000},
			want: goferMaxProcs,
		},
		{
			name: "quota below cap is honored",
			cg:   &fakeGoferCgroup{numCPU: 64, cpuQuota: 300000, cpuPeriod: 100000},
			want: 3,
		},
		{
			name: "application CPULimits applied while creation cgroup is uncapped",
			cg:   &fakeGoferCgroup{numCPU: 64, cpuQuota: -1, cpuPeriod: 100000},
			limits: &sandbox.CPULimits{
				App: specs.LinuxCPU{Quota: new(int64(25000)), Period: new(uint64(100000))},
			},
			want: 2,
		},
		{
			name: "nil container cgroup respects runsc own cgroup quota",
			cg:   nil,
			selfCg: func() (cgroup.Cgroup, error) {
				return &fakeGoferCgroup{numCPU: 96, cpuQuota: 50000, cpuPeriod: 100000}, nil
			},
			want: 2,
		},
		{
			name: "nil container cgroup respects runsc own cpuset",
			cg:   nil,
			selfCg: func() (cgroup.Cgroup, error) {
				return &fakeGoferCgroup{numCPU: 3, cpuQuota: -1, cpuPeriod: 100000}, nil
			},
			want: 3,
		},
		{
			name: "nil container cgroup falls back to host CPUs when self cgroup fails",
			cg:   nil,
			selfCg: func() (cgroup.Cgroup, error) {
				return nil, errors.New("cgroupfs unavailable")
			},
			want: hostCap,
		},
		{
			name: "quota error preserves cpuset bound",
			cg: &fakeGoferCgroup{
				numCPU:      4,
				cpuQuotaErr: errors.New("cpu.max unavailable"),
			},
			want: 4,
		},
		{
			name: "zero cpuset floors at 1",
			cg:   &fakeGoferCgroup{numCPU: 0, cpuQuota: -1, cpuPeriod: 100000},
			want: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := goferGOMAXPROCSWithSelf(tc.cg, tc.limits, tc.selfCg); got != tc.want {
				t.Errorf("goferGOMAXPROCSWithSelf() = %d, want %d", got, tc.want)
			}
		})
	}
}
