// Copyright 2018 Google Inc.
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

package specutils

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// CalculateCPUNumber calculates the number of CPUs that should be exposed
// inside the sandbox.
func CalculateCPUNumber(spec *specs.Spec) (int, error) {
	// If spec does not contain CPU field, then return the number of host CPUs.
	if spec == nil || spec.Linux == nil || spec.Linux.Resources == nil || spec.Linux.Resources.CPU == nil {
		return runtime.NumCPU(), nil
	}
	cpuSpec := spec.Linux.Resources.CPU

	// If cpuSpec.Cpus is specified, then parse and return that. They must be in
	// the list format for cpusets, which is "a comma-separated list of CPU
	// numbers and ranges of numbers, in ASCII decimal." --man 7 cpuset.
	cpus := cpuSpec.Cpus
	if cpus != "" {
		cpuNum := 0
		for _, subs := range strings.Split(cpus, ",") {
			result, err := parseCPUNumber(subs)
			if err != nil {
				return 0, err
			}
			cpuNum += result
		}
		return cpuNum, nil
	}

	// If CPU.Quota and CPU.Period are specified, we can divide them to get an
	// approximation of the number of CPUs needed.
	if cpuSpec.Quota != nil && cpuSpec.Period != nil && *cpuSpec.Period != 0 {
		cpuQuota := *cpuSpec.Quota
		cpuPeriod := *cpuSpec.Period
		return int(cpuQuota)/int(cpuPeriod) + 1, nil
	}

	// Default to number of host cpus.
	return runtime.NumCPU(), nil
}

// parseCPUNumber converts a cpuset string into the number of cpus included in
// the string , e.g. "3-6" -> 4.
func parseCPUNumber(cpus string) (int, error) {
	switch cpusSlice := strings.Split(cpus, "-"); len(cpusSlice) {
	case 1:
		// cpus is not a range. We must only check that it is a valid number.
		if _, err := strconv.Atoi(cpus); err != nil {
			return 0, fmt.Errorf("invalid individual cpu number %q", cpus)
		}
		return 1, nil
	case 2:
		// cpus is a range. We must check that start and end are valid numbers,
		// and calculate their difference (inclusively).
		first, err := strconv.Atoi(cpusSlice[0])
		if err != nil || first < 0 {
			return 0, fmt.Errorf("invalid first cpu number %q in range %q", cpusSlice[0], cpus)
		}
		last, err := strconv.Atoi(cpusSlice[1])
		if err != nil || last < 0 {
			return 0, fmt.Errorf("invalid last cpu number %q in range %q", cpusSlice[1], cpus)
		}
		cpuNum := last - first + 1
		if cpuNum <= 0 {
			return 0, fmt.Errorf("cpu range %q does not include positive number of cpus", cpus)
		}
	}
	return 0, fmt.Errorf("invalid cpu string %q", cpus)
}
