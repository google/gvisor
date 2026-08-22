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
	"os"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
)

// fakeCgroup is a minimal cgroup.Cgroup for exercising cpuNumForCgroup.
type fakeCgroup struct {
	numCPU    int
	cpuQuota  int64
	cpuPeriod int64
}

func (f *fakeCgroup) Install(*specs.LinuxResources) error { return nil }
func (f *fakeCgroup) Update(*specs.LinuxResources) error  { return nil }
func (f *fakeCgroup) Uninstall() error                    { return nil }
func (f *fakeCgroup) Join() (func(), error)               { return func() {}, nil }
func (f *fakeCgroup) CloneIntoCgroup() (*os.File, error)  { return nil, nil }
func (f *fakeCgroup) CPUQuota() (int64, error)            { return f.cpuQuota, nil }
func (f *fakeCgroup) CPUPeriod() (int64, error)           { return f.cpuPeriod, nil }
func (f *fakeCgroup) CPUUsage() (uint64, error)           { return 0, nil }
func (f *fakeCgroup) NumCPU() (int, error)                { return f.numCPU, nil }
func (f *fakeCgroup) MemoryLimit() (uint64, error)        { return 0, nil }
func (f *fakeCgroup) MakePath(string) string              { return "" }

var _ cgroup.Cgroup = (*fakeCgroup)(nil)

func TestCPUNumForCgroup(t *testing.T) {
	for _, test := range []struct {
		name            string
		cg              *fakeCgroup
		cpuNumFromQuota bool
		wantCPUNum      int
	}{
		{
			name:            "quota disabled uses cpuset",
			cg:              &fakeCgroup{numCPU: 12, cpuQuota: 100000, cpuPeriod: 100000},
			cpuNumFromQuota: false,
			wantCPUNum:      12,
		},
		{
			name:            "quota below minimum clamps to 2",
			cg:              &fakeCgroup{numCPU: 12, cpuQuota: 100000, cpuPeriod: 100000},
			cpuNumFromQuota: true,
			wantCPUNum:      2,
		},
		{
			name:            "quota above minimum, below cpuset",
			cg:              &fakeCgroup{numCPU: 12, cpuQuota: 800000, cpuPeriod: 100000},
			cpuNumFromQuota: true,
			wantCPUNum:      8,
		},
		{
			name:            "quota never raises above cpuset",
			cg:              &fakeCgroup{numCPU: 4, cpuQuota: 800000, cpuPeriod: 100000},
			cpuNumFromQuota: true,
			wantCPUNum:      4,
		},
		{
			name:            "unlimited quota uses cpuset",
			cg:              &fakeCgroup{numCPU: 12, cpuQuota: -1, cpuPeriod: 100000},
			cpuNumFromQuota: true,
			wantCPUNum:      12,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := &config.Config{CPUNumFromQuota: test.cpuNumFromQuota}
			cpuNum, cpuQuota, cpuPeriod, err := cpuNumForCgroup(test.cg, conf)
			if err != nil {
				t.Fatalf("cpuNumForCgroup() failed: %v", err)
			}
			if cpuNum != test.wantCPUNum {
				t.Errorf("cpuNumForCgroup() cpuNum = %d, want %d", cpuNum, test.wantCPUNum)
			}
			if cpuQuota != test.cg.cpuQuota {
				t.Errorf("cpuNumForCgroup() cpuQuota = %d, want %d", cpuQuota, test.cg.cpuQuota)
			}
			if cpuPeriod != test.cg.cpuPeriod {
				t.Errorf("cpuNumForCgroup() cpuPeriod = %d, want %d", cpuPeriod, test.cg.cpuPeriod)
			}
		})
	}
}
