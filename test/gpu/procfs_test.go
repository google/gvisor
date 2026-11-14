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

// Package procfs_test tests the NVIDIA driver files in /proc/driver/nvidia.
package procfs_test

import (
	"context"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// TestProcDriverNvidiaVersion checks that /proc/driver/nvidia/version in the
// container is the host's file verbatim.
func TestProcDriverNvidiaVersion(t *testing.T) {
	want, err := os.ReadFile("/proc/driver/nvidia/version")
	if err != nil {
		t.Fatalf("failed to read the host's /proc/driver/nvidia/version: %v", err)
	}
	ctx := context.Background()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{
		Capabilities:         "all",
		DisableSnifferReason: "reads a procfs file and makes no ioctls",
	})
	if err != nil {
		t.Fatalf("failed to get GPU run options: %v", err)
	}
	opts.Image = "gpu/cuda-tests"
	got, err := c.Run(ctx, opts, "cat", "/proc/driver/nvidia/version")
	if err != nil {
		t.Fatalf("could not read /proc/driver/nvidia/version: %v", err)
	}
	if got != string(want) {
		t.Errorf("/proc/driver/nvidia/version = %q, want %q", got, string(want))
	}
}
