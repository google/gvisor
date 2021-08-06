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

package mitigate

import "strings"

// MockCPU represents data from CPUs that will be mitigated.
type MockCPU struct {
	Name           string
	VendorID       string
	Family         int64
	Model          int64
	ModelName      string
	Bugs           string
	PhysicalCores  int64
	Cores          int64
	ThreadsPerCore int64
}

// CascadeLake2 is a two core Intel CascadeLake machine.
var CascadeLake2 = MockCPU{
	Name:           "CascadeLake",
	VendorID:       "GenuineIntel",
	Family:         6,
	Model:          85,
	ModelName:      "Intel(R) Xeon(R) CPU",
	Bugs:           "spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa",
	PhysicalCores:  1,
	Cores:          1,
	ThreadsPerCore: 2,
}

// CascadeLake4 is a four core Intel CascadeLake machine.
var CascadeLake4 = MockCPU{
	Name:           "CascadeLake",
	VendorID:       "GenuineIntel",
	Family:         6,
	Model:          85,
	ModelName:      "Intel(R) Xeon(R) CPU",
	Bugs:           "spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa",
	PhysicalCores:  1,
	Cores:          2,
	ThreadsPerCore: 2,
}

// Haswell2 is a two core Intel Haswell machine.
var Haswell2 = MockCPU{
	Name:           "Haswell",
	VendorID:       "GenuineIntel",
	Family:         6,
	Model:          63,
	ModelName:      "Intel(R) Xeon(R) CPU",
	Bugs:           "cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs",
	PhysicalCores:  1,
	Cores:          1,
	ThreadsPerCore: 2,
}

// Haswell2core is a 2 core Intel Haswell machine with no hyperthread pairs.
var Haswell2core = MockCPU{
	Name:           "Haswell2Physical",
	VendorID:       "GenuineIntel",
	Family:         6,
	Model:          63,
	ModelName:      "Intel(R) Xeon(R) CPU",
	Bugs:           "cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs",
	PhysicalCores:  2,
	Cores:          1,
	ThreadsPerCore: 1,
}

// AMD2 is an two core AMD machine.
var AMD2 = MockCPU{
	Name:           "AMD",
	VendorID:       "AuthenticAMD",
	Family:         23,
	Model:          49,
	ModelName:      "AMD EPYC 7B12",
	Bugs:           "sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass",
	PhysicalCores:  1,
	Cores:          1,
	ThreadsPerCore: 2,
}

// AMD8 is an eight core AMD machine.
var AMD8 = MockCPU{
	Name:           "AMD",
	VendorID:       "AuthenticAMD",
	Family:         23,
	Model:          49,
	ModelName:      "AMD EPYC 7B12",
	Bugs:           "sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass",
	PhysicalCores:  4,
	Cores:          1,
	ThreadsPerCore: 2,
}

// Empty is an empty CPU set.
var Empty = MockCPU{
	Name: "Empty",
}

// MakeCPUSet makes a cpuSet from a MockCPU.
func (tc MockCPU) MakeCPUSet() CPUSet {
	bugs := make(map[string]struct{})
	for _, bug := range strings.Split(tc.Bugs, " ") {
		bugs[bug] = struct{}{}
	}
	var cpus CPUSet = []*CPU{}
	for i := int64(0); i < tc.PhysicalCores; i++ {
		for j := int64(0); j < tc.Cores; j++ {
			for k := int64(0); k < tc.ThreadsPerCore; k++ {
				processorNum := (i*tc.Cores+j)*tc.ThreadsPerCore + k
				cpu := &CPU{
					processorNumber: processorNum,
					vendorID:        tc.VendorID,
					cpuFamily:       tc.Family,
					model:           tc.Model,
					physicalID:      i,
					coreID:          j,
					bugs:            bugs,
				}
				cpus = append(cpus, cpu)
			}
		}
	}
	return cpus
}

// NumCPUs returns the number of CPUs for this CPU.
func (tc MockCPU) NumCPUs() int {
	return int(tc.PhysicalCores * tc.Cores * tc.ThreadsPerCore)
}
