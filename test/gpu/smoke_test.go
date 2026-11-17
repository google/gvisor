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

// Package smoke_test tests basic GPU functionality.
package smoke_test

import (
	"context"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

func TestNvidiaSmi(t *testing.T) {
	ctx := context.Background()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{
		Capabilities: "all",
	})
	if err != nil {
		t.Fatalf("failed to get GPU run options: %v", err)
	}
	opts.Image = "gpu/cuda-tests"
	cmd := "nvidia-smi"
	out, err := c.Run(ctx, opts, cmd)
	t.Logf("%q output:", cmd)
	for _, line := range strings.Split(string(out), "\n") {
		t.Logf("%q: %s", cmd, line)
	}
	if err != nil {
		t.Fatalf("could not run %q: %v", cmd, err)
	}
}

// TestNvidiaSmiTopology checks that NVML finds the GPUs in the PCI topology as
// on the host.
func TestNvidiaSmiTopology(t *testing.T) {
	ctx := context.Background()
	// run runs cmd in a new container with GPUs, natively if native is set.
	run := func(native bool, cmd ...string) string {
		t.Helper()
		sniff := dockerutil.SniffGPUOpts{Capabilities: "all"}
		var c *dockerutil.Container
		if native {
			// The sniffer would only allow the ioctls that nvproxy supports.
			sniff.DisableSnifferReason = "native reference run"
			c = dockerutil.MakeNativeContainer(ctx, t)
		} else {
			c = dockerutil.MakeContainer(ctx, t)
		}
		defer c.CleanUp(ctx)
		// Cleaning up a container deletes the files of its GPU run options,
		// so every container needs new ones.
		opts, err := dockerutil.GPURunOpts(sniff)
		if err != nil {
			t.Fatalf("failed to get GPU run options: %v", err)
		}
		opts.Image = "gpu/cuda-tests"
		out, err := c.Run(ctx, opts, cmd...)
		t.Logf("%q output:\n%s", cmd, out)
		if err != nil {
			t.Fatalf("could not run %q: %v", cmd, err)
		}
		return out
	}

	// The PCI addresses of the GPUs resolve to the same sysfs paths as on the
	// host. NVML prints PCI domains with 8 digits, sysfs with 4.
	readlink := []string{"readlink", "-f"}
	for _, busID := range strings.Fields(run(false, "nvidia-smi", "--query-gpu=pci.bus_id", "--format=csv,noheader")) {
		readlink = append(readlink, "/sys/bus/pci/devices/"+strings.ToLower(strings.TrimPrefix(busID, "0000")))
	}
	if len(readlink) == 2 {
		t.Fatal("nvidia-smi found no GPUs")
	}
	if got, want := run(false, readlink...), run(true, readlink...); got != want {
		t.Errorf("%q returned %q, want %q as on the host", readlink, got, want)
	}

	// GPU pairs have the same topology as on the host, except that pairs on
	// different host NUMA nodes may show as NODE instead of SYS, since the
	// sandbox has a single NUMA node.
	got, want := gpuPairs(run(false, "nvidia-smi", "topo", "-m")), gpuPairs(run(true, "nvidia-smi", "topo", "-m"))
	if len(got) != len(want) {
		t.Fatalf("nvidia-smi topo -m shows %d GPU pairs, want %d as on the host", len(got), len(want))
	}
	for pair, w := range want {
		if g := got[pair]; g != w && (w != "SYS" || g != "NODE") {
			t.Errorf("%s has topology %q, want %q as on the host", pair, g, w)
		}
	}
}

var (
	// ansiEscapeRE matches the terminal escape sequences that nvidia-smi uses
	// to underline the topology header.
	ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	gpuNameRE    = regexp.MustCompile(`^GPU[0-9]+$`)
)

// gpuPairs returns the topology of each pair of GPUs, keyed by "GPUi-GPUj", in
// the matrix that `nvidia-smi topo -m` prints.
func gpuPairs(out string) map[string]string {
	pairs := make(map[string]string)
	var gpus []string
	for _, line := range strings.Split(ansiEscapeRE.ReplaceAllString(out, ""), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !gpuNameRE.MatchString(fields[0]) {
			continue
		}
		if gpus == nil {
			// The header names the GPU columns first.
			for _, f := range fields {
				if !gpuNameRE.MatchString(f) {
					break
				}
				gpus = append(gpus, f)
			}
			continue
		}
		for i, gpu := range gpus {
			if i+1 < len(fields) {
				pairs[fields[0]+"-"+gpu] = fields[i+1]
			}
		}
	}
	return pairs
}

func TestGPUHello(t *testing.T) {
	ctx := context.Background()
	if strings.HasPrefix(runtime.GOARCH, "arm") {
		t.Skip("Test does not cross compile on arm")
	}
	runGPUHello(ctx, t, "gpu/cuda-tests")
}

func TestGPUHello_12_8(t *testing.T) {
	ctx := context.Background()
	const image = "gpu/cuda-tests-12-8"

	cudaVersion, err := dockerutil.MaxSuportedCUDAVersion(ctx, t)
	if err != nil {
		t.Fatalf("failed to get CUDA version: %v", err)
	}

	if !cudaVersion.IsAtLeast(dockerutil.MustParseCudaVersion("12.8")) {
		t.Skipf("CUDA version %s is not at least 12.8, skipping test", cudaVersion)
	}
	runGPUHello(ctx, t, image)
}

func runGPUHello(ctx context.Context, t *testing.T, image string) {
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{
		Capabilities: "all",
	})
	if err != nil {
		t.Fatalf("failed to get GPU run options: %v", err)
	}
	opts.Image = image
	out, err := c.Run(ctx, opts, "/run_sample", "--timeout=120s", "0_Introduction/vectorAdd")
	t.Logf("0_Introduction/vectorAdd output: %s", string(out))
	if err != nil {
		t.Fatalf("could not run 0_Introduction/vectorAdd: %v", err)
	}
}

func TestCUDASmokeTests(t *testing.T) {
	runCUDASmokeTests(context.Background(), t, "gpu/cuda-tests")
}

func TestCUDASmokeTests_12_8(t *testing.T) {
	ctx := context.Background()
	const image = "gpu/cuda-tests-12-8"

	cudaVersion, err := dockerutil.MaxSuportedCUDAVersion(ctx, t)
	if err != nil {
		t.Fatalf("failed to get CUDA version: %v", err)
	}
	if !cudaVersion.IsAtLeast(dockerutil.MustParseCudaVersion("12.8")) {
		t.Skipf("CUDA version %s is not at least 12.8, skipping test", cudaVersion)
	}
	runCUDASmokeTests(ctx, t, image)
}

func runCUDASmokeTests(ctx context.Context, t *testing.T, image string) {
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{AllowIncompatibleIoctl: true})
	if err != nil {
		t.Fatalf("failed to get GPU run options: %v", err)
	}
	opts.Image = image
	out, err := c.Run(ctx, opts, "/run_smoke.sh")
	t.Logf("cuda-tests smoke tests output: %s", string(out))
	if err != nil {
		t.Fatalf("could not run cuda-tests smoke tests: %v", err)
	}
}
