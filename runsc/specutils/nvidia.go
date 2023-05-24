// Copyright 2023 The gVisor Authors.
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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
)

const nvdEnvVar = "NVIDIA_VISIBLE_DEVICES"

// HaveNvidiaVisibleDevices returns true if the NVIDIA_VISIBLE_DEVICES
// environment variable for the specified container enables Nvidia GPU usage.
func HaveNvidiaVisibleDevices(spec *specs.Spec, conf *config.Config) bool {
	if !conf.NVProxy || !conf.NVProxyDocker || spec.Process == nil {
		return false
	}
	nvd, _ := EnvVar(spec.Process.Env, nvdEnvVar)
	return nvd != "" && nvd != "void"
}

// NvidiaVisibleDevices returns the Nvidia GPU device minor numbers enabled by
// the NVIDIA_VISIBLE_DEVICES environment variable for the specified container.
func NvidiaVisibleDevices(spec *specs.Spec, conf *config.Config) ([]uint32, error) {
	if !conf.NVProxy || !conf.NVProxyDocker || spec.Process == nil {
		return nil, nil
	}
	nvd, _ := EnvVar(spec.Process.Env, nvdEnvVar)
	if nvd == "" || nvd == "void" || nvd == "none" {
		return nil, nil
	}
	var devMinors []uint32
	if nvd == "all" {
		paths, err := filepath.Glob("/dev/nvidia*")
		if err != nil {
			return nil, fmt.Errorf("enumerating Nvidia device files: %w", err)
		}
		re := regexp.MustCompile(`^/dev/nvidia(\d+)$`)
		for _, path := range paths {
			if ms := re.FindStringSubmatch(path); ms != nil {
				index, err := strconv.ParseUint(ms[1], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid host device file %q: %w", path, err)
				}
				devMinors = append(devMinors, uint32(index))
			}
		}
		return devMinors, nil
	}
	// Expect nvd to be a list of indices; UUIDs aren't supported
	// yet.
	for _, indexStr := range strings.Split(nvd, ",") {
		index, err := strconv.ParseUint(indexStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid %q in NVIDIA_VISIBLE_DEVICES %q: %w", indexStr, nvd, err)
		}
		devMinors = append(devMinors, uint32(index))
	}
	return devMinors, nil
}
