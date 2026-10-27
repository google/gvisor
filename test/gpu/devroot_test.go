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

// Package devroot_test tests that runsc finds the NVIDIA device files under
// --nvproxy-dev-roots.
package devroot_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

const (
	// runtimeSuffix is the suffix of the runtime that the Makefile installs
	// with --nvproxy-dev-roots=devRoot.
	runtimeSuffix = "-nvproxy-devroot"

	// devRoot must match the --nvproxy-dev-roots of the runtime above. It is
	// the only root that runtime looks in, so the host's /dev, where the
	// driver's device files normally are, is not used.
	devRoot = "/tmp/nvproxy-dev-root"
)

// deviceNames are the NVIDIA device files that the containers get. The first
// is the control device.
var deviceNames = []string{"nvidiactl", "nvidia-uvm", "nvidia0"}

// hostDevices returns the host's NVIDIA device files, as the spec's
// linux.devices entries. It skips the test if the host has none.
func hostDevices(t *testing.T) ([]container.DeviceMapping, map[string]unix.Stat_t) {
	t.Helper()
	var devices []container.DeviceMapping
	stats := make(map[string]unix.Stat_t)
	for _, name := range deviceNames {
		path := filepath.Join("/dev", name)
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			t.Skipf("the host has no %s: %v", path, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFCHR {
			t.Fatalf("%s is not a character device", path)
		}
		devices = append(devices, container.DeviceMapping{
			PathOnHost:        path,
			PathInContainer:   path,
			CgroupPermissions: "rwm",
		})
		stats[name] = st
	}
	return devices, stats
}

// resetDevRoot replaces devRoot with an empty one that has a dev directory.
func resetDevRoot(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll(devRoot); err != nil {
		t.Fatalf("failed to remove %s: %v", devRoot, err)
	}
	if err := os.MkdirAll(filepath.Join(devRoot, "dev"), 0755); err != nil {
		t.Fatalf("failed to create %s/dev: %v", devRoot, err)
	}
	t.Cleanup(func() { os.RemoveAll(devRoot) })
}

// run runs ls on the NVIDIA device files in a container that has them as
// linux.devices, and returns its output and error.
func run(ctx context.Context, t *testing.T, devices []container.DeviceMapping) (string, error) {
	t.Helper()
	c := dockerutil.MakeContainerWithRuntime(ctx, t, runtimeSuffix)
	defer c.CleanUp(ctx)
	args := []string{"ls", "-l"}
	for _, name := range deviceNames {
		args = append(args, filepath.Join("/dev", name))
	}
	out, err := c.Run(ctx, dockerutil.RunOpts{
		Image:   "gpu/cuda-tests",
		Devices: devices,
	}, args...)
	if err != nil && strings.Contains(err.Error(), "Unknown runtime specified") {
		t.Fatalf("docker failed because the %s runtime was not installed", runtimeSuffix)
	}
	return out, err
}

// TestDeviceFilesUnderDevRoot tests that a container starts, and gets its
// NVIDIA devices, when the only dev root has copies of the host's device files.
func TestDeviceFilesUnderDevRoot(t *testing.T) {
	ctx := context.Background()
	devices, stats := hostDevices(t)

	resetDevRoot(t)
	for _, name := range deviceNames {
		path := filepath.Join(devRoot, "dev", name)
		if err := unix.Mknod(path, unix.S_IFCHR|0666, int(stats[name].Rdev)); err != nil {
			t.Fatalf("failed to create %s: %v", path, err)
		}
	}

	out, err := run(ctx, t, devices)
	if err != nil {
		t.Fatalf("container failed to start: %v\n%s", err, out)
	}
	for _, name := range deviceNames {
		path := filepath.Join("/dev", name)
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "c") && strings.HasSuffix(line, path) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not a character device in the container:\n%s", path, out)
		}
	}
}

// TestDevRootWithoutDeviceFiles tests that the root is the only place runsc
// looks. The host's /dev has the device files, but a root without them must
// stop the container from starting.
func TestDevRootWithoutDeviceFiles(t *testing.T) {
	ctx := context.Background()
	devices, _ := hostDevices(t)

	resetDevRoot(t)
	out, err := run(ctx, t, devices)
	if err == nil {
		t.Fatalf("container started with an empty dev root:\n%s", out)
	}
	if want := "no NVIDIA control device found"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err, want)
	}
}

// TestDevRootWithRegularFile tests that a regular file at dev/nvidiactl does
// not count as the control device, since a dev root belongs to whatever
// installed the driver.
func TestDevRootWithRegularFile(t *testing.T) {
	ctx := context.Background()
	devices, _ := hostDevices(t)

	resetDevRoot(t)
	for _, name := range deviceNames {
		path := filepath.Join(devRoot, "dev", name)
		if err := os.WriteFile(path, nil, 0666); err != nil {
			t.Fatalf("failed to create %s: %v", path, err)
		}
	}
	out, err := run(ctx, t, devices)
	if err == nil {
		t.Fatalf("container started with regular files as device files:\n%s", out)
	}
	if want := "not a character device"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err, want)
	}
}
