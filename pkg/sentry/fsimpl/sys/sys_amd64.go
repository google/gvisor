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

package sys

// topologyHasDie is true if cpuN/topology has die_id and die_cpus{,_list}.
// Linux defines TOPOLOGY_DIE_SYSFS when the architecture defines
// topology_die_id() and topology_die_cpumask() (include/linux/topology.h),
// which x86 does (arch/x86/include/asm/topology.h).
const topologyHasDie = true
