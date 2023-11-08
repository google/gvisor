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

// Package cos_gpu_test tests that GPUs work on Container Optimized OS (COS) images in GCP. This
// will probably only work on COS images.
package cos_gpu_test

import (
	"context"
	"flag"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

var setCOSGPU = flag.Bool("cos-gpu", false, "set to configure GPU settings for cos")

func TestGPUHello(t *testing.T) {
	ctx := context.Background()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	opts := getGPURunOpts()
	opts.Image = "basic/cuda-vector-add"
	out, err := c.Run(ctx, opts)
	if err != nil {
		t.Fatalf("could not run cuda-vector-add: %v", err)
	}
	t.Logf("cuda-vector-add output: %s", string(out))
}

func TestCUDATests(t *testing.T) {
	ctx := context.Background()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	opts := getGPURunOpts()
	opts.Image = "gpu/cuda-tests"
	out, err := c.Run(ctx, opts)
	if err != nil {
		t.Fatalf("could not run cuda-tests: %v", err)
	}
	t.Logf("cuda-tests output: %s", string(out))
}

func getGPURunOpts() dockerutil.RunOpts {
	if !*setCOSGPU {
		return dockerutil.RunOpts{
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

	mounts := []mount.Mount{
		{
			Source: "/var/lib/nvidia/lib64",
			Target: "/usr/local/nvidia/lib64",
			Type:   mount.TypeBind,
		},
		{
			Source: "/var/lib/nvidia/bin",
			Target: "/usr/local/nvidia/bin",
			Type:   mount.TypeBind,
		},
	}

	return dockerutil.RunOpts{
		Mounts:  mounts,
		Devices: devices,
	}
}
