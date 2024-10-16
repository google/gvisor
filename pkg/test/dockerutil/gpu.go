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
	"fmt"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"

	// Needed for go:embed
	_ "embed"
)

// Flags.
var (
	setCOSGPU = flag.Bool("cos-gpu", false, "set to configure GPU settings for COS, as opposed to Docker")
)

//go:embed run_sniffer_copy
var runSnifferBinary []byte

const (
	// ioctlSnifferMountPath is the in-container path at which the ioctl sniffer is mounted.
	ioctlSnifferMountPath = "/ioctl_sniffer"
)

const (
	// AllGPUCapabilities is the environment variable that enables all NVIDIA
	// GPU capabilities within a container.
	AllGPUCapabilities = "NVIDIA_DRIVER_CAPABILITIES=all"

	// DefaultGPUCapabilities is the environment variable that enables default
	// NVIDIA GPU capabilities within a container.
	DefaultGPUCapabilities = "NVIDIA_DRIVER_CAPABILITIES=compute,utility"
)

// GPURunOpts returns Docker run options with GPU support enabled.
func GPURunOpts(sniffGPUOpts SniffGPUOpts) (RunOpts, error) {
	var mounts []mount.Mount
	if sniffGPUOpts.DisableSnifferReason == "" {
		// Extract the sniffer binary to a temporary location.
		runSniffer, err := os.CreateTemp("", "run_sniffer.*")
		if err != nil {
			return RunOpts{}, fmt.Errorf("failed to create temporary file: %w", err)
		}
		if _, err := runSniffer.Write(runSnifferBinary); err != nil {
			return RunOpts{}, fmt.Errorf("failed to write to temporary file: %w", err)
		}
		if err := runSniffer.Sync(); err != nil {
			return RunOpts{}, fmt.Errorf("failed to sync temporary file: %w", err)
		}
		if err := runSniffer.Chmod(0o555); err != nil {
			return RunOpts{}, fmt.Errorf("failed to chmod temporary file: %w", err)
		}
		if err := runSniffer.Close(); err != nil {
			return RunOpts{}, fmt.Errorf("failed to close temporary file: %w", err)
		}
		sniffGPUOpts.runSniffer = runSniffer
		mounts = append(mounts, mount.Mount{
			Source:   runSniffer.Name(),
			Target:   ioctlSnifferMountPath,
			Type:     mount.TypeBind,
			ReadOnly: true,
		})
	}
	gpuEnv := []string{sniffGPUOpts.GPUCapabilities()}

	if !*setCOSGPU {
		return RunOpts{
			Env: gpuEnv,
			DeviceRequests: []container.DeviceRequest{
				{
					Count:        -1,
					Capabilities: [][]string{{"gpu"}},
					Options:      map[string]string{},
				},
			},
			Mounts:       mounts,
			sniffGPUOpts: &sniffGPUOpts,
		}, nil
	}

	// COS has specific settings since it has a custom installer for GPU drivers.
	// See: https://cloud.google.com/container-optimized-os/docs/how-to/run-gpus#install-driver
	devices := []container.DeviceMapping{}
	var nvidiaDevices []string
	for i := 0; true; i++ {
		devicePath := fmt.Sprintf("/dev/nvidia%d", i)
		if _, err := os.Stat(devicePath); err != nil {
			break
		}
		nvidiaDevices = append(nvidiaDevices, devicePath)
	}
	nvidiaDevices = append(nvidiaDevices, "/dev/nvidia-uvm", "/dev/nvidiactl")
	for _, device := range nvidiaDevices {
		devices = append(devices, container.DeviceMapping{
			PathOnHost:        device,
			PathInContainer:   device,
			CgroupPermissions: "rwm",
		})
	}

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
		Env:          gpuEnv,
		Mounts:       mounts,
		Devices:      devices,
		sniffGPUOpts: &sniffGPUOpts,
	}, nil
}

// SniffGPUOpts dictates options to sniffer GPU workloads.
type SniffGPUOpts struct {
	// If set, explains why the sniffer should be disabled for this test.
	// If unset or empty, the sniffer is enabled.
	DisableSnifferReason string

	// If true, the test will not fail even when the workload calls incompatible
	// ioctls. Useful for debugging.
	// TODO(b/340955577): Should be converted to a flag and removed from this
	// struct once all GPU tests have no incompatible ioctls.
	AllowIncompatibleIoctl bool

	// The set of GPU capabilities exposed to the container.
	// If unset, defaults to `DefaultGPUCapabilities`.
	Capabilities string

	// The fields below are set internally.
	runSniffer *os.File
}

// GPUCapabilities returns the set of GPU capabilities meant to be
// exposed to the container.
func (sgo *SniffGPUOpts) GPUCapabilities() string {
	if sgo.Capabilities == "" {
		return DefaultGPUCapabilities
	}
	return sgo.Capabilities
}

// prepend prepends the sniffer arguments to the given command.
func (sgo *SniffGPUOpts) prepend(argv []string) []string {
	if sgo.DisableSnifferReason != "" {
		return argv
	}
	snifferArgv := []string{
		ioctlSnifferMountPath,
		"--verbose=true",
		// TODO(eperot): Add flag to enforce capability set here once implemented.
	}
	if !sgo.AllowIncompatibleIoctl {
		snifferArgv = append(snifferArgv, "--enforce_compatibility=INSTANT")
	}
	return append(snifferArgv, argv...)
}

func (sgo *SniffGPUOpts) cleanup() error {
	if sgo.DisableSnifferReason != "" {
		return nil // Sniffer disabled, so nothing to clean up.
	}
	if err := os.Remove(sgo.runSniffer.Name()); err != nil {
		return fmt.Errorf("failed to unlink temporary file %q: %w", sgo.runSniffer.Name(), err)
	}
	return nil
}

// NumGPU crudely estimates the number of NVIDIA GPUs on the host.
func NumGPU() int {
	numGPU := 0
	for {
		_, err := os.Stat(fmt.Sprintf("/dev/nvidia%d", numGPU))
		if err != nil {
			break
		}
		numGPU++
	}
	return numGPU
}
