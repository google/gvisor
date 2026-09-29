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

package specutils

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/amdgpu"
	"gvisor.dev/gvisor/runsc/config"
)

// AMDGPUDevicesInSpec returns the AMD GPU compute devices granted by spec.
func AMDGPUDevicesInSpec(spec *specs.Spec) []amdgpu.Device {
	if spec.Linux == nil {
		return nil
	}
	var devices []amdgpu.Device
	for _, d := range spec.Linux.Devices {
		if (d.Type == "c" || d.Type == "u") && amdgpu.IsDevicePath(d.Path) {
			devices = append(devices, amdgpu.Device{Path: d.Path, Major: uint32(d.Major), Minor: uint32(d.Minor)})
		}
	}
	return devices
}

// AMDGPUProxyEnabled reports whether the sandbox proxies AMD GPU devices: the
// proxy is enabled and /dev/kfd is granted.
func AMDGPUProxyEnabled(spec *specs.Spec, conf *config.Config) bool {
	if conf.AMDGPUProxy != config.AMDGPUProxyCompute {
		return false
	}
	for _, d := range AMDGPUDevicesInSpec(spec) {
		if d.Path == "/dev/kfd" {
			return true
		}
	}
	return false
}
