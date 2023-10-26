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
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
)

const nvdEnvVar = "NVIDIA_VISIBLE_DEVICES"

// annotationNVProxy enables nvproxy.
const annotationNVProxy = "dev.gvisor.internal.nvproxy"

// NVProxyEnabled checks both the nvproxy annotation and conf.NVProxy to see if nvproxy is enabled.
func NVProxyEnabled(spec *specs.Spec, conf *config.Config) bool {
	if conf.NVProxy {
		return true
	}
	val, ok := spec.Annotations[annotationNVProxy]
	if ok {
		ret, err := strconv.ParseBool(val)
		if val != "" && err != nil {
			log.Warningf("tpuproxy annotation set to invalid value %q. Skipping.", val)
		}
		return ret
	}
	return false
}

// GPUFunctionalityRequested returns true if the user intends for the sandbox
// to have access to GPU functionality (e.g. access to /dev/nvidiactl),
// irrespective of whether or not they want access to any specific GPU.
func GPUFunctionalityRequested(spec *specs.Spec, conf *config.Config) bool {
	if !NVProxyEnabled(spec, conf) {
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

// FindAllGPUDevices returns the Nvidia GPU device minor numbers of all GPUs
// mounted in the provided rootfs.
func FindAllGPUDevices(rootfs string) ([]uint32, error) {
	devPathPrefix := path.Join(rootfs, "dev/nvidia")
	nvidiaDeviceRegex := regexp.MustCompile(fmt.Sprintf(`^%s(\d+)$`, devPathPrefix))
	paths, err := filepath.Glob(devPathPrefix + "*")
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

// NvidiaDeviceList returns the list of devices that should be visible to the
// sandbox. In Docker mode, this is the set of devices specified in
// NVIDIA_VISIBLE_DEVICES. In non-Docker mode, this is all Nvidia devices, as
// we cannot know the set of usable GPUs until subcontainer creation.
func NvidiaDeviceList(spec *specs.Spec, conf *config.Config) (string, error) {
	if !GPUFunctionalityRequested(spec, conf) {
		return "", nil
	}
	if !conf.NVProxyDocker {
		// nvproxy enabled in non-Docker mode.
		// Return all GPUs on the machine.
		return "all", nil
	}
	// nvproxy is enabled in Docker mode.
	nvd, _ := EnvVar(spec.Process.Env, nvdEnvVar)
	if nvd == "none" {
		return "", nil
	}
	if nvd == "all" {
		return "all", nil
	}
	// Expect nvd to be a list of indices; UUIDs aren't supported
	// yet.
	for _, gpuDev := range strings.Split(nvd, ",") {
		// Validate gpuDev. We only support the following formats for now:
		// * GPU indices (e.g. 0,1,2)
		// * GPU UUIDs (e.g. GPU-fef8089b)
		//
		// We do not support MIG devices yet.
		if strings.HasPrefix(gpuDev, "GPU-") {
			continue
		}
		_, err := strconv.ParseUint(gpuDev, 10, 32)
		if err != nil {
			return "", fmt.Errorf("invalid %q in NVIDIA_VISIBLE_DEVICES %q: %w", gpuDev, nvd, err)
		}
	}
	return nvd, nil
}
