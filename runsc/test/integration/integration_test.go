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
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

// This container is a docker image for the Flask microframework hello world application.
const container = "python-hello-test"

// httpRequestSucceeds sends a request to a given url and checks that the status is OK.
func httpRequestSucceeds(client http.Client, url string) error {
	// Ensure that content is being served.
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("error reaching http server: %v", err)
	}
	if want := http.StatusOK; resp.StatusCode != want {
		return fmt.Errorf("wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}
	return nil
}

// TestLifeCycle tests a basic Create/Start/Stop docker container life cycle.
func TestLifeCycle(t *testing.T) {
	d := testutil.MakeDocker(container)

	// Test docker create.
	if out, err := d.Do("create", "--runtime", d.Runtime, "--name", d.Name, "-p", "8080", "google/python-hello"); err != nil {
		t.Fatalf("docker create failed: %v\nout: %s", err, out)
	}

	// Test docker start.
	if out, err := d.Do("start", d.Name); err != nil {
		d.CleanUp()
		t.Fatalf("docker start failed: %v\nout: %s", err, out)
	}

	// Test docker stop.
	if out, err := d.Do("stop", d.Name); err != nil {
		d.CleanUp()
		t.Fatalf("docker stop failed: %v\nout: %s", err, out)
	}

	// Test removing the container.
	if out, err := d.Do("rm", d.Name); err != nil {
		t.Fatalf("docker rm failed: %v\nout: %s", err, out)
	}
}

func TestPauseResume(t *testing.T) {
	d := testutil.MakeDocker(container)
	if out, err := d.Run("-p", "8080", "google/python-hello"); err != nil {
		t.Fatalf("docker run failed: %v\nout: %s", err, out)
	}
	defer d.CleanUp()

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatalf("docker.FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := d.WaitForHTTP(port, 5*time.Second); err != nil {
		t.Fatalf("docker.WaitForHTTP() timeout: %v", err)
	}

	timeout := time.Duration(2 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	url := fmt.Sprintf("http://localhost:%d", port)
	// Check that container is working.
	if err := httpRequestSucceeds(client, url); err != nil {
		t.Errorf("http request failed: %v", err)
	}

	// Pause container.
	if out, err := d.Do("pause", d.Name); err != nil {
		t.Fatalf("docker pause failed: %v\nout: %s", err, out)
	}

	// Check if container is paused.
	switch _, err := client.Get(url); v := err.(type) {
	case nil:
		t.Errorf("http req expected to fail but it succeeded")
	case net.Error:
		if !v.Timeout() {
			t.Errorf("http req got error %v, wanted timeout", v)
		}
	default:
		t.Errorf("http req got unexpected error %v", v)
	}

	// Resume container.
	if out, err := d.Do("unpause", d.Name); err != nil {
		t.Fatalf("docker unpause failed: %v\nout: %s", err, out)
	}

	// Wait until it's up and running.
	if err := d.WaitForHTTP(port, 5*time.Second); err != nil {
		t.Fatalf("docker.WaitForHTTP() timeout: %v", err)
	}

	// Check if container is working again.
	if err := httpRequestSucceeds(client, url); err != nil {
		t.Errorf("http request failed: %v", err)
	}
}

func MainTest(m *testing.M) {
	testutil.EnsureSupportedDockerVersion()
	os.Exit(m.Run())
}
