// Copyright 2024 The gVisor Authors.
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

// Package sniffer_test tests the ioctl_sniffer against simple cuda workloads.
package sniffer_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"

	// Needed for go:embed
	_ "embed"
)

const maxDuration = 1 * time.Minute

//go:embed run_sniffer_copy
var runSnifferBinary []byte

// RunCommand runs the given command via the sniffer, with the -enforce_compatibility flag.
//
//	It's run in a docker container, with the cuda-tests image.
func runCUDATestsCommand(t *testing.T, cmd ...string) (string, error) {
	// Extract the sniffer binary to a temporary location.
	runSniffer, err := os.CreateTemp("/tmp", "run_sniffer.*")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer func() {
		if err := runSniffer.Close(); err != nil {
			t.Fatalf("Failed to close temporary file: %v", err)
		}
		if err := os.Remove(runSniffer.Name()); err != nil {
			t.Fatalf("Failed to unlink temporary file: %v", err)
		}
	}()
	if _, err := runSniffer.Write(runSnifferBinary); err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	if err := runSniffer.Sync(); err != nil {
		t.Fatalf("Failed to sync temporary file: %v", err)
	}
	if err := runSniffer.Chmod(0o555); err != nil {
		t.Fatalf("Failed to chmod temporary file: %v", err)
	}

	// Set up our docker container
	ctx, cancel := context.WithTimeoutCause(context.Background(), maxDuration, errors.New("overall test timed out"))
	defer cancel()

	listContainer := dockerutil.MakeContainer(ctx, t)
	defer listContainer.CleanUp(ctx)

	// Mount the sniffer binary into the container
	opts := dockerutil.GPURunOpts()
	opts.Image = "gpu/cuda-tests"
	opts.Mounts = append(opts.Mounts, mount.Mount{
		Type:     mount.TypeBind,
		Source:   runSniffer.Name(),
		Target:   "/run_sniffer",
		ReadOnly: false,
	})

	command := append([]string{"/run_sniffer", "-enforce_compatibility", "-verbose"}, cmd...)
	output, err := listContainer.Run(ctx, opts, command...)
	return output, err
}

func TestSupportedCUDAProgram(t *testing.T) {
	output, err := runCUDATestsCommand(t, "/run_smoke.sh")
	t.Logf("%s", output)
	if err != nil {
		t.Logf("Error: %v", err)
		if strings.Contains(output, "unsupported ioctls found") {
			t.Fatalf("'unsupported ioctls found' found in output")
		}
		t.Fatalf("Failed to run run_smoke.sh")
	}
}

func TestUnsupportedCUDAProgram(t *testing.T) {
	output, err := runCUDATestsCommand(t, "/unsupported_ioctl")
	t.Logf("%s", output)
	if err == nil {
		t.Fatalf("Expected run_sniffer to fail")
	}
	if !strings.Contains(output, "unsupported ioctls found") {
		t.Fatalf("Expected to find 'unsupported ioctls found' in output")
	}
}
