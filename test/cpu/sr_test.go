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

// Package sr_test runs checkpoint/restore tests for CPU.
package sr_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const defaultWait = time.Minute

func httpRequestSucceeds(client http.Client, server string, port int) error {
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/", server, port))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %v", resp.StatusCode)
	}
	return nil
}

func TestCPUCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()
	if !dockerutil.IsRestoreSupported() {
		t.Skip("Restore is not supported.")
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	port := 8080
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/python",
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Create a snapshot.
	const ckptName = "test"
	if err := d.Checkpoint(ctx, ckptName); err != nil {
		t.Fatalf("docker checkpoint failed: %v", err)
	}
	if err := d.WaitTimeout(ctx, defaultWait); err != nil {
		t.Fatalf("wait failed: %v", err)
	}

	d.RestoreInTest(ctx, t, ckptName)

	// Find container IP address.
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check if container is working again.
	client := http.Client{Timeout: defaultWait}
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Error("http request failed:", err)
	}
}
