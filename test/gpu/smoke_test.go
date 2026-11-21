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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/mount"
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

func TestNvidiaProcfsGPUDirectories(t *testing.T) {
	ctx := t.Context()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	defer func() {
		if !t.Failed() {
			return
		}
		logs, err := c.Logs(ctx)
		if err != nil {
			t.Errorf("Could not get container logs: %v", err)
			return
		}
		t.Logf("Container logs:\n%v", logs)
	}()

	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{
		Capabilities:         "all",
		DisableSnifferReason: "Tests procfs GPU directory visibility",
	})
	if err != nil {
		t.Fatalf("failed to get GPU run options: %v", err)
	}
	opts.Image = "gpu/cuda-tests"
	opts.NetworkMode = "none"
	// A filename in /dev does not establish that it is an assigned GPU.
	unrelated := filepath.Join(t.TempDir(), "nvidia247")
	if err := os.WriteFile(unrelated, nil, 0o644); err != nil {
		t.Fatalf("failed to create unrelated /dev entry: %v", err)
	}
	opts.Mounts = append(opts.Mounts, mount.Mount{
		Type:   mount.TypeBind,
		Source: unrelated,
		Target: "/dev/nvidia247",
	})
	native := dockerutil.MakeNativeContainer(ctx, t)
	defer native.CleanUp(ctx)
	queryOut, err := native.Run(ctx, opts, "nvidia-smi", "--query-gpu=pci.bus_id", "--format=csv,noheader")
	if err != nil {
		t.Fatalf("failed to query native GPU PCI addresses: %v; output: %q", err, queryOut)
	}

	opts.CapAdd = []string{"SYS_ADMIN"}
	opts.SecurityOpts = []string{"seccomp=unconfined", "apparmor=unconfined"}
	if err := c.Spawn(ctx, opts, "sleep", "infinity"); err != nil {
		t.Fatalf("could not start cuda-tests container: %v", err)
	}
	originalOut, err := c.Exec(ctx, dockerutil.ExecOpts{},
		"find", "/proc/driver/nvidia/gpus", "-mindepth", "1", "-maxdepth", "1", "-type", "d", "-printf", "%f\n")
	if err != nil {
		t.Fatalf("failed to list GPU directories in the original procfs: %v; output: %q", err, originalOut)
	}

	const freshProcScript = `set -e
fresh_proc=$(mktemp -d /tmp/nvidia-procfs.XXXXXX)
umount -l /proc
mount -t proc proc "$fresh_proc"
trap 'umount "$fresh_proc"; rmdir "$fresh_proc"' EXIT
find "$fresh_proc/driver/nvidia/gpus" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'
`
	freshOut, err := c.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", freshProcScript)
	if err != nil {
		t.Fatalf("failed to list GPU directories in a fresh procfs: %v; output: %q", err, freshOut)
	}

	pciAddresses := func(output string) []string {
		t.Helper()
		var addresses []string
		for line := range strings.FieldsSeq(output) {
			var domain, bus, device, function uint64
			if _, err := fmt.Sscanf(line, "%x:%x:%x.%x", &domain, &bus, &device, &function); err != nil {
				t.Fatalf("invalid GPU PCI address %q: %v", line, err)
			}
			addresses = append(addresses, fmt.Sprintf("%04x:%02x:%02x.%x", domain, bus, device, function))
		}
		slices.Sort(addresses)
		return addresses
	}
	want := pciAddresses(queryOut)
	if len(want) == 0 {
		t.Fatal("nvidia-smi returned no GPU PCI addresses")
	}
	for _, procfs := range []struct {
		name   string
		output string
	}{
		{name: "original", output: originalOut},
		{name: "fresh", output: freshOut},
	} {
		if got := pciAddresses(procfs.output); !slices.Equal(got, want) {
			t.Errorf("%s GPU procfs directories do not match nvidia-smi: got %v, want %v", procfs.name, got, want)
		}
	}
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
