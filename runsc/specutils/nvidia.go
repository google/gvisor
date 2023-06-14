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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
)

const nvdEnvVar = "NVIDIA_VISIBLE_DEVICES"

// GPUFunctionalityRequested returns true if the user intends for the sandbox
// to have access to GPU functionality (e.g. access to /dev/nvidiactl),
// irrespective of whether or not they want access to any specific GPU.
func GPUFunctionalityRequested(spec *specs.Spec, conf *config.Config) bool {
	if !conf.NVProxy {
		// nvproxy disabled.
		return false
	}
	if !conf.NVProxyDocker {
		// nvproxy enabled in non-Docker mode.
		return true
	}
	// nvproxy enabled in Docker mode.
	// GPU access is only requested if NVIDIA_VISIBLE_DEVICES is non-empty
	// and set to a value that doesn't mean "no GPU".
	if spec.Process == nil {
		return false
	}
	nvd, _ := EnvVar(spec.Process.Env, nvdEnvVar)
	// A value of "none" means "no GPU device, but still access to driver
	// functionality", so it is not a value we check for here.
	return nvd != "" && nvd != "void"
}

// CanAccessAtLeastOneGPU returns true if the sandbox and container should
// be able to access at least one Nvidia GPU. This is a function of the
// sandbox configuration and the container spec's NVIDIA_VISIBLE_DEVICES
// environment variable.
func CanAccessAtLeastOneGPU(spec *specs.Spec, conf *config.Config) bool {
	gpus, err := NvidiaDeviceNumbers(spec, conf)
	if err != nil {
		log.Warningf("Cannot determine if the container should have access to GPUs: %v", err)
		return false
	}
	return len(gpus) > 0
}

// nvidiaDeviceRegex matches Nvidia GPU device paths.
var nvidiaDeviceRegex = regexp.MustCompile(`^/dev/nvidia(\d+)$`)

// findAllGPUDevices returns the Nvidia GPU device minor numbers of all GPUs
// on the machine.
func findAllGPUDevices() ([]uint32, error) {
	paths, err := filepath.Glob("/dev/nvidia*")
	if err != nil {
		return nil, fmt.Errorf("enumerating Nvidia device files: %w", err)
	}
	var devMinors []uint32
	for _, path := range paths {
		if ms := nvidiaDeviceRegex.FindStringSubmatch(path); ms != nil {
			index, err := strconv.ParseUint(ms[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid host device file %q: %w", path, err)
			}
			devMinors = append(devMinors, uint32(index))
		}
	}
	return devMinors, nil
}

// NvidiaDeviceNumbers returns the Nvidia GPU device minor numbers that
// should be visible to the specified container.
// In Docker mode, this is the set of devices specified in
// NVIDIA_VISIBLE_DEVICES.
// In non-Docker mode, this is all Nvidia devices, as we cannot know the set
// of usable GPUs until subcontainer creation.
func NvidiaDeviceNumbers(spec *specs.Spec, conf *config.Config) ([]uint32, error) {
	if !GPUFunctionalityRequested(spec, conf) {
		return nil, nil
	}
	if !conf.NVProxyDocker {
		// nvproxy enabled in non-Docker mode.
		// Return all GPUs on the machine.
		return findAllGPUDevices()
	}
	// nvproxy is enabled in Docker mode.
	nvd, _ := EnvVar(spec.Process.Env, nvdEnvVar)
	if nvd == "none" {
		return nil, nil
	}
	if nvd == "all" {
		return findAllGPUDevices()
	}
	var devMinors []uint32
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
