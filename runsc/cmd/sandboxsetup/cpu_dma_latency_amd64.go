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

//go:build amd64
// +build amd64

package sandboxsetup

import (
	"gvisor.dev/gvisor/pkg/cpuid"
)

// slowDeepIdleCPU returns whether the host CPU's deepest idle state has a
// very high exit latency.
func slowDeepIdleCPU() bool {
	cpuid.Initialize()
	fs := cpuid.HostFeatureSet()
	if !fs.Intel() || fs.Family() != 6 {
		return false
	}
	// Recent Intel Xeon server CPUs take ~150-230us to wake a CPU from C6, an
	// order of magnitude more than other CPUs (e.g. AMD EPYC's deepest state
	// measures ~5-15us). Advertised sysfs exit latencies do not distinguish
	// them; only measurement does. To decide whether a new CPU model belongs
	// here, run tools/cstate_wake_probe on an otherwise idle machine.
	switch uint16(fs.ExtendedModel())<<4 | uint16(fs.Model()) {
	case 0x8f, // Sapphire Rapids
		0xcf, // Emerald Rapids
		0xad, // Granite Rapids
		0xae: // Granite Rapids D
		return true
	}
	return false
}
