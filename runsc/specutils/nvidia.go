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
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
)

const nvdEnvVar = "NVIDIA_VISIBLE_DEVICES"

// AnnotationNVProxy enables nvproxy.
const AnnotationNVProxy = "dev.gvisor.internal.nvproxy"

// NVProxyEnabled checks both the nvproxy annotation and conf.NVProxy to see if nvproxy is enabled.
func NVProxyEnabled(spec *specs.Spec, conf *config.Config) bool {
	if conf.NVProxy {
		return true
	}
	return AnnotationToBool(spec, AnnotationNVProxy)
}

// GPUFunctionalityRequested returns true if the container should have access
// to GPU functionality.
func GPUFunctionalityRequested(spec *specs.Spec, conf *config.Config) bool {
	if !NVProxyEnabled(spec, conf) {
		// nvproxy disabled.
		return false
	}
	// In GKE, the nvidia_gpu device plugin injects NVIDIA devices into
	// spec.Linux.Devices when GPUs are allocated to a container.
	if spec.Linux != nil {
		for _, dev := range spec.Linux.Devices {
			if dev.Path == "/dev/nvidiactl" {
				return true
			}
		}
	}
	return gpuFunctionalityRequestedViaHook(spec, conf)
}

// GPUFunctionalityRequestedViaHook returns true if the container should have
// access to GPU functionality configured via nvidia-container-runtime-hook.
// This hook is used by:
// - Docker when using `--gpus` flag from the CLI.
// - nvidia-container-runtime when using its legacy mode.
func GPUFunctionalityRequestedViaHook(spec *specs.Spec, conf *config.Config) bool {
	if !NVProxyEnabled(spec, conf) {
		// nvproxy disabled.
		return false
	}
	return gpuFunctionalityRequestedViaHook(spec, conf)
}

// Precondition: NVProxyEnabled(spec, conf).
func gpuFunctionalityRequestedViaHook(spec *specs.Spec, conf *config.Config) bool {
	if !isNvidiaHookPresent(spec, conf) {
		return false
	}
	// In Docker mode, GPU access is only requested if NVIDIA_VISIBLE_DEVICES is
	// non-empty and set to a value that doesn't mean "no GPU".
	if spec.Process == nil {
		return false
	}
	nvd, _ := EnvVar(spec.Process.Env, nvdEnvVar)
	// A value of "none" means "no GPU device, but still access to driver
	// functionality", so it is not a value we check for here.
	return nvd != "" && nvd != "void"
}

func isNvidiaHookPresent(spec *specs.Spec, conf *config.Config) bool {
	if conf.NVProxyDocker {
		// This has the effect of injecting the nvidia-container-runtime-hook.
		return true
	}

	if spec.Hooks != nil {
		for _, h := range spec.Hooks.Prestart {
			if strings.HasSuffix(h.Path, "/nvidia-container-runtime-hook") {
				return true
			}
		}
	}
	return false
}

// ParseNvidiaVisibleDevices parses NVIDIA_VISIBLE_DEVICES env var and returns
// the devices specified in it. This can be passed to nvidia-container-cli.
//
// Precondition: conf.NVProxyDocker && GPUFunctionalityRequested(spec, conf).
func ParseNvidiaVisibleDevices(spec *specs.Spec) (string, error) {
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
