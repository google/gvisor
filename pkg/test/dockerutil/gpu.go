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

// Package dockerutil provides utility functions for GPU tests.
package dockerutil

import (
	"flag"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
)

// Flags.
var (
	setCOSGPU = flag.Bool("cos-gpu", false, "set to configure GPU settings for COS, as opposed to Docker")
)

// GPURunOpts returns Docker run options with GPU support enabled.
func GPURunOpts() RunOpts {
	if !*setCOSGPU {
		return RunOpts{
			DeviceRequests: []container.DeviceRequest{
				{
					Count:        -1,
					Capabilities: [][]string{[]string{"gpu"}},
					Options:      map[string]string{},
				},
			},
		}
	}

	// COS has specific settings since it has a custom installer for GPU drivers.
	// See: https://cloud.google.com/container-optimized-os/docs/how-to/run-gpus#install-driver
	devices := []container.DeviceMapping{}
	nvidia0Device := "/dev/nvidia0"
	nvidiaUvmDevice := "/dev/nvidia-uvm"
	nvidiactlDevice := "/dev/nvidiactl"
	for _, device := range []string{nvidia0Device, nvidiaUvmDevice, nvidiactlDevice} {
		devices = append(devices, container.DeviceMapping{
			PathOnHost:        device,
			PathInContainer:   device,
			CgroupPermissions: "rwm",
		})
	}

	var mounts []mount.Mount
	for _, nvidiaBin := range []string{
		"/home/kubernetes/bin/nvidia/bin",
		"/var/lib/nvidia/bin",
	} {
		if st, err := os.Stat(nvidiaBin); err == nil && st.IsDir() {
			mounts = append(mounts, mount.Mount{
				Source:   nvidiaBin,
				Target:   "/usr/local/nvidia/bin",
				Type:     mount.TypeBind,
				ReadOnly: true,
			})
		}
	}
	for _, nvidiaLib64 := range []string{
		"/home/kubernetes/bin/nvidia/lib64",
		"/var/lib/nvidia/lib64",
	} {
		if st, err := os.Stat(nvidiaLib64); err == nil && st.IsDir() {
			mounts = append(mounts, mount.Mount{
				Source:   nvidiaLib64,
				Target:   "/usr/local/nvidia/lib64",
				Type:     mount.TypeBind,
				ReadOnly: true,
			})
		}
	}

	return RunOpts{
		Mounts:  mounts,
		Devices: devices,
	}
}
