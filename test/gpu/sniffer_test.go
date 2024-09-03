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
	"fmt"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

const maxDuration = 1 * time.Minute

// runCUDATestsCommand runs the given command via the sniffer with compatibility
// enforcement enabled.
// It's run in a docker container, with the cuda-tests image.
func runCUDATestsCommand(t *testing.T, cmd ...string) (string, error) {
	ctx, cancel := context.WithTimeoutCause(context.Background(), maxDuration, errors.New("overall test timed out"))
	defer cancel()
	container := dockerutil.MakeContainer(ctx, t)
	defer container.CleanUp(ctx)
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{
		AllowIncompatibleIoctl: false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get GPU run options: %w", err)
	}
	opts.Image = "gpu/cuda-tests"
	return container.Run(ctx, opts, cmd...)
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
