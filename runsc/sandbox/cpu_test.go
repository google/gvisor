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

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
)

// Pointers for the optional cpu fields in specs.LinuxCPU.
func int64Ptr(v int64) *int64    { return &v }
func uint64Ptr(v uint64) *uint64 { return &v }

// TestCPUNumForUpdate checks an update derives its count from the quota it
// carries, not from the sandbox cgroup. Under Kubernetes pod-level resources the
// kubelet writes the quota to the pod cgroup and leaves the sandbox's own at max,
// so a cgroup-only derivation keeps the boot-time count and the update is lost.
func TestCPUNumForUpdate(t *testing.T) {
	// The sandbox cgroup a Kubernetes pod-level-resources sandbox actually has:
	// no quota of its own, cpuset unrestricted.
	noQuota := &fakeCgroup{numCPU: 32, cpuQuota: -1, cpuPeriod: 100000}

	for _, test := range []struct {
		name            string
		cg              *fakeCgroup
		res             *specs.LinuxResources
		cpuNumFromQuota bool
		wantCPUNum      int
	}{
		{
			// The case that was broken: 4 CPUs requested, cgroup carries nothing.
			name:            "quota from update, none on cgroup",
			cg:              noQuota,
			res:             &specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: int64Ptr(400000), Period: uint64Ptr(100000)}},
			cpuNumFromQuota: true,
			wantCPUNum:      4,
		},
		{
			name:            "update quota wins over the cgroup's",
			cg:              &fakeCgroup{numCPU: 32, cpuQuota: 50000, cpuPeriod: 100000},
			res:             &specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: int64Ptr(400000), Period: uint64Ptr(100000)}},
			cpuNumFromQuota: true,
			wantCPUNum:      4,
		},
		{
			name:            "update quota still clamps to the minimum",
			cg:              noQuota,
			res:             &specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: int64Ptr(50000), Period: uint64Ptr(100000)}},
			cpuNumFromQuota: true,
			wantCPUNum:      2,
		},
		{
			name:            "update quota never raises above the cpuset",
			cg:              &fakeCgroup{numCPU: 2, cpuQuota: -1, cpuPeriod: 100000},
			res:             &specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: int64Ptr(800000), Period: uint64Ptr(100000)}},
			cpuNumFromQuota: true,
			wantCPUNum:      2,
		},
		{
			name:            "config opt-out ignores the update quota",
			cg:              noQuota,
			res:             &specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: int64Ptr(400000), Period: uint64Ptr(100000)}},
			cpuNumFromQuota: false,
			wantCPUNum:      32,
		},
		// Below: res carries no usable quota, so the cgroup decides as before.
		{
			name:            "nil resources fall back to the cgroup",
			cg:              &fakeCgroup{numCPU: 32, cpuQuota: 800000, cpuPeriod: 100000},
			res:             nil,
			cpuNumFromQuota: true,
			wantCPUNum:      8,
		},
		{
			name:            "resources without a cpu section fall back",
			cg:              &fakeCgroup{numCPU: 32, cpuQuota: 800000, cpuPeriod: 100000},
			res:             &specs.LinuxResources{},
			cpuNumFromQuota: true,
			wantCPUNum:      8,
		},
		{
			// A memory-only update must not be read as "quota removed".
			name:            "quota set without period falls back",
			cg:              &fakeCgroup{numCPU: 32, cpuQuota: 800000, cpuPeriod: 100000},
			res:             &specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: int64Ptr(400000)}},
			cpuNumFromQuota: true,
			wantCPUNum:      8,
		},
		{
			name:            "unlimited quota in the update falls back",
			cg:              &fakeCgroup{numCPU: 32, cpuQuota: 800000, cpuPeriod: 100000},
			res:             &specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: int64Ptr(-1), Period: uint64Ptr(100000)}},
			cpuNumFromQuota: true,
			wantCPUNum:      8,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := &config.Config{CPUNumFromQuota: test.cpuNumFromQuota}
			cpuNum, err := cpuNumForUpdate(test.cg, conf, test.res)
			if err != nil {
				t.Fatalf("cpuNumForUpdate() failed: %v", err)
			}
			if cpuNum != test.wantCPUNum {
				t.Errorf("cpuNumForUpdate() = %d, want %d", cpuNum, test.wantCPUNum)
			}
		})
	}
}
