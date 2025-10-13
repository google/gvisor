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

// Package sr_test runs checkpoint/restore tests for nvproxy.
package sr_test

import (
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

func TestGPUCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()
	if !dockerutil.IsRestoreSupported() {
		t.Skip("Restore is not supported.")
	}

	ctx := context.Background()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{
		Capabilities: "all",
	})
	if err != nil {
		t.Fatalf("failed to get GPU run options: %v", err)
	}
	opts.Image = "gpu/cuda-tests-12-8"
	if err := c.Spawn(ctx, opts, "sleep", "infinity"); err != nil {
		t.Fatalf("could not start cuda-tests container: %v", err)
	}
	defer func() {
		logs, err := c.Logs(ctx)
		if err != nil {
			t.Errorf("Could not get container logs: %v", err)
		}
		t.Logf("Container logs:\n%v", logs)
	}()

	// Run the vector add program.
	vectorAddCmd := []string{"/run_sample", "--timeout=120s", "0_Introduction/vectorAdd"}
	if output, err := c.Exec(ctx, dockerutil.ExecOpts{}, vectorAddCmd...); err != nil {
		t.Fatalf("docker exec failed: %v; output: %v", err, strings.TrimSpace(output))
	}

	// Create a snapshot.
	const ckptName = "test"
	if err := c.Checkpoint(ctx, ckptName); err != nil {
		t.Fatalf("docker checkpoint failed: %v", err)
	}
	if err := c.WaitTimeout(ctx, time.Minute); err != nil {
		t.Fatalf("wait failed: %v", err)
	}

	// Restore the snapshot.
	c.RestoreInTest(ctx, t, ckptName)

	// Run the vector add program again to ensure GPUs are functional.
	if _, err := c.Exec(ctx, dockerutil.ExecOpts{}, vectorAddCmd...); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
}
