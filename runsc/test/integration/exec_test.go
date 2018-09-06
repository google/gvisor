// Copyright 2018 Google Inc.
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

// Package image provides end-to-end integration tests for runsc. These tests require
// docker and runsc to be installed on the machine. To set it up, run:
//
//     ./runsc/test/install.sh [--runtime <name>]
//
// The tests expect the runtime name to be provided in the RUNSC_RUNTIME
// environment variable (default: runsc-test).
//
// Each test calls docker commands to start up a container, and tests that it is
// behaving properly, with various runsc commands. The container is killed and deleted
// at the end.

package integration

import (
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

func TestExecCapabilities(t *testing.T) {
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("exec-test")

	// Start the container.
	if _, err := d.Run("alpine", "sh", "-c", "cat /proc/self/status; sleep 100"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	want, err := d.WaitForOutput("CapEff:\t[0-9a-f]+\n", 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForOutput() timeout: %v", err)
	}
	t.Log("Root capabilities:", want)

	// Now check that exec'd process capabilities match the root.
	got, err := d.Exec("grep", "CapEff:", "/proc/self/status")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if got != want {
		t.Errorf("wrong capabilities, got: %q, want: %q", got, want)
	}
}
