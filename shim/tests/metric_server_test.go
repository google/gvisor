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

package shim_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	"gvisor.dev/gvisor/shim/shimutils"
)

// Helper methods to reduce boilerplate.

// startMetricServer starts the runsc metric-server process pointing to the
// given rootDir, binding to metricSock, and writing logs to logDir.
// It waits for the server to be ready (socket created) before returning.
// It also registers a cleanup hook to kill the process at the end of the test.
func startMetricServer(t *testing.T, rootDir, metricSock, logDir string) {
	t.Helper()
	runscPath, err := shimutils.GetRunscPath()
	if err != nil {
		t.Fatalf("failed to get runsc path: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), runscPath, "--root", rootDir, "--metric-server", metricSock, "metric-server")

	logFile, err := os.Create(filepath.Join(logDir, "metric-server.log"))
	if err != nil {
		t.Fatalf("failed to create metric server log file: %v", err)
	}

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("failed to start metric server: %v", err)
	}
	logFile.Close()

	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	})

	// Wait for the metric server to start (wait for the socket file to appear).
	deadline := time.Now().Add(5 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		if _, err := os.Stat(metricSock); err == nil {
			started = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !started {
		t.Fatalf("metric server did not start in time")
	}
}

// queryMetrics queries the metric server over the Unix domain socket at
// metricSock and returns the raw Prometheus metrics string. It fails the
// test if the query fails or returns a non-200 status.
func queryMetrics(t *testing.T, metricSock string) string {
	t.Helper()
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", metricSock)
			},
		},
	}

	resp, err := httpClient.Get("http://localhost/metrics")
	if err != nil {
		t.Fatalf("failed to query metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	return string(body)
}

// hasMetricServer returns true if the runsc binary supports the metric-server
// subcommand (i.e., it is not elided as in fastbuild).
func hasMetricServer(t *testing.T) bool {
	t.Helper()
	runscPath, err := shimutils.GetRunscPath()
	if err != nil {
		t.Fatalf("failed to get runsc path: %v", err)
	}

	// Run "runsc metric-server" with no arguments.
	// In elided build, it will immediately fail with the "not support" message.
	// In embedded build, it might fail with flag errors, but NOT the "not support" message.
	cmd := exec.Command(runscPath, "metric-server")
	out, _ := cmd.CombinedOutput()

	return !strings.Contains(string(out), "this build does not support the metric-server subcommand")
}

// Test variants for grouping.

type metricServerTestCase struct {
	name     string
	shimArgs map[string]any
}

var metricServerTestCases = []metricServerTestCase{
	{
		name: "default",
	},
	{
		name: "grouping",
		shimArgs: map[string]any{
			"grouping": true,
		},
	},
}

// TestMetricServer is a basic smoke test that verifies the runsc metric-server
// can start, bind to a Unix domain socket, and export Prometheus metrics
// containing the ID of a running sandbox.
func TestMetricServer(t *testing.T) {
	if !hasMetricServer(t) {
		t.Skip("Skipping: runsc binary does not support metric-server (elided in fastbuild). Run with -c opt to enable.")
	}
	for _, tc := range metricServerTestCases {
		t.Run(tc.name, func(t *testing.T) {
			metricSock := filepath.Join(t.TempDir(), "metrics.sock")
			runscArgs := map[string]any{
				"metric-server": metricSock,
			}
			containerd := shimutils.NewMockContainerd(t, tc.shimArgs, runscArgs)

			sandbox, client := setupSandbox(t, containerd)

			rootDir := filepath.Join(containerd.WorkingDir(), "containers", "default")
			startMetricServer(t, rootDir, metricSock, containerd.WorkingDir())

			metricsStr := queryMetrics(t, metricSock)
			t.Logf("Metrics received:\n%s", metricsStr)

			if !strings.Contains(metricsStr, sandbox.ID()) {
				t.Errorf("expected metrics to contain sandbox ID %q, but they did not", sandbox.ID())
			}

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to kill sandbox: %v", err)
			}
		})
	}
}

// TestMetricServerMultipleSandboxes verifies that the metric server can
// concurrently discover and scrape metrics from multiple sandboxes that
// share the same runsc root directory. It asserts that metrics for both
// sandboxes are present and that the running sandbox count is correct.
func TestMetricServerMultipleSandboxes(t *testing.T) {
	if !hasMetricServer(t) {
		t.Skip("Skipping: runsc binary does not support metric-server (elided in fastbuild). Run with -c opt to enable.")
	}
	for _, tc := range metricServerTestCases {
		t.Run(tc.name, func(t *testing.T) {
			sharedRoot := filepath.Join(t.TempDir(), "shared_containers")
			metricSock := filepath.Join(t.TempDir(), "metrics.sock")
			shimArgs := map[string]any{
				"root": sharedRoot,
			}
			for k, v := range tc.shimArgs {
				shimArgs[k] = v
			}
			runscArgs := map[string]any{
				"metric-server": metricSock,
			}

			containerd1 := shimutils.NewMockContainerdWithSuffix(t, "sb1", shimArgs, runscArgs)
			containerd2 := shimutils.NewMockContainerdWithSuffix(t, "sb2", shimArgs, runscArgs)

			sandbox1, client1 := setupSandbox(t, containerd1)
			sandbox2, client2 := setupSandbox(t, containerd2)

			rootDir := filepath.Join(sharedRoot, "default")
			startMetricServer(t, rootDir, metricSock, containerd1.WorkingDir())

			metricsStr := queryMetrics(t, metricSock)
			t.Logf("Metrics received:\n%s", metricsStr)

			if !strings.Contains(metricsStr, sandbox1.ID()) {
				t.Errorf("expected metrics to contain sandbox 1 ID %q", sandbox1.ID())
			}
			if !strings.Contains(metricsStr, sandbox2.ID()) {
				t.Errorf("expected metrics to contain sandbox 2 ID %q", sandbox2.ID())
			}
			if !strings.Contains(metricsStr, "runsc_meta_num_sandboxes_running 2") {
				t.Errorf("expected runsc_meta_num_sandboxes_running to be 2")
			}

			if err := killAndWaitForContainer(t.Context(), client1, sandbox1.ID(), containerd1); err != nil {
				t.Fatalf("failed to kill sandbox 1: %v", err)
			}
			if err := killAndWaitForContainer(t.Context(), client2, sandbox2.ID(), containerd2); err != nil {
				t.Fatalf("failed to kill sandbox 2: %v", err)
			}
		})
	}
}

// TestMetricServerMultiContainer verifies that adding a second container
// to a sandbox does not break metrics export, and that the sandbox
// remains discoverable by the metric server.
func TestMetricServerMultiContainer(t *testing.T) {
	if !hasMetricServer(t) {
		t.Skip("Skipping: runsc binary does not support metric-server (elided in fastbuild). Run with -c opt to enable.")
	}
	for _, tc := range metricServerTestCases {
		t.Run(tc.name, func(t *testing.T) {
			metricSock := filepath.Join(t.TempDir(), "metrics.sock")
			runscArgs := map[string]any{
				"metric-server": metricSock,
			}
			containerd := shimutils.NewMockContainerd(t, tc.shimArgs, runscArgs)

			sandbox, client := setupSandbox(t, containerd)

			opts, err := containerd.GetRuntimeOptions()
			if err != nil {
				t.Fatalf("failed to get runtime options: %v", err)
			}

			// Create and start a second container in the same sandbox.
			containerSpec := shimutils.NewContainerSpec(sandbox.ID(), []string{"sleep", "10000"})
			container, err := shimutils.NewContainer(containerSpec, containerd)
			if err != nil {
				t.Fatalf("failed to create container: %v", err)
			}

			if err := createAndWaitForContainer(t.Context(), client, container, opts); err != nil {
				t.Fatalf("failed to create container: %v", err)
			}

			startReq := &task.StartRequest{
				ID: container.ID(),
			}
			if _, err := client.Start(t.Context(), startReq); err != nil {
				t.Fatalf("failed to start container: %v", err)
			}

			rootDir := filepath.Join(containerd.WorkingDir(), "containers", "default")
			startMetricServer(t, rootDir, metricSock, containerd.WorkingDir())

			metricsStr := queryMetrics(t, metricSock)
			t.Logf("Metrics received:\n%s", metricsStr)

			if !strings.Contains(metricsStr, sandbox.ID()) {
				t.Errorf("expected metrics to contain sandbox ID %q", sandbox.ID())
			}

			if err := killAndWaitForContainer(t.Context(), client, container.ID(), containerd); err != nil {
				t.Fatalf("failed to kill container: %v", err)
			}

			// Verify that the metric server still responds after the second container is killed.
			metricsStrAfterKill := queryMetrics(t, metricSock)
			if !strings.Contains(metricsStrAfterKill, sandbox.ID()) {
				t.Errorf("expected metrics to still contain sandbox ID %q after sub-container was killed", sandbox.ID())
			}

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to kill sandbox: %v", err)
			}
		})
	}
}

// TestMetricServerLifecycle verifies that the metric server dynamically
// updates its exported metrics as sandboxes are started and stopped.
// It asserts that the active running sandbox count updates correctly
// (1 -> 0 -> 1) as sandboxes transition through their lifecycles.
func TestMetricServerLifecycle(t *testing.T) {
	if !hasMetricServer(t) {
		t.Skip("Skipping: runsc binary does not support metric-server (elided in fastbuild). Run with -c opt to enable.")
	}
	for _, tc := range metricServerTestCases {
		t.Run(tc.name, func(t *testing.T) {
			sharedRoot := filepath.Join(t.TempDir(), "shared_containers")
			metricSock := filepath.Join(t.TempDir(), "metrics.sock")
			shimArgs := map[string]any{
				"root": sharedRoot,
			}
			for k, v := range tc.shimArgs {
				shimArgs[k] = v
			}
			runscArgs := map[string]any{
				"metric-server": metricSock,
			}

			// 1. Start the first sandbox.
			containerd1 := shimutils.NewMockContainerdWithSuffix(t, "sb1", shimArgs, runscArgs)
			sandbox1, client1 := setupSandbox(t, containerd1)

			// 2. Start the metric server.
			rootDir := filepath.Join(sharedRoot, "default")
			startMetricServer(t, rootDir, metricSock, containerd1.WorkingDir())

			// 3. Verify sandbox 1 is running.
			metricsStr1 := queryMetrics(t, metricSock)
			if !strings.Contains(metricsStr1, sandbox1.ID()) {
				t.Errorf("expected metrics to contain sandbox 1 ID %q", sandbox1.ID())
			}
			if !strings.Contains(metricsStr1, "runsc_meta_num_sandboxes_running 1") {
				t.Errorf("expected runsc_meta_num_sandboxes_running to be 1")
			}

			// 4. Stop sandbox 1.
			if err := killAndWaitForContainer(t.Context(), client1, sandbox1.ID(), containerd1); err != nil {
				t.Fatalf("failed to kill sandbox 1: %v", err)
			}

			// 5. Verify metrics show 0 running sandboxes.
			metricsStr2 := queryMetrics(t, metricSock)
			if strings.Contains(metricsStr2, sandbox1.ID()) {
				t.Errorf("expected metrics to NOT contain sandbox 1 ID %q after it stopped", sandbox1.ID())
			}
			if !strings.Contains(metricsStr2, "runsc_meta_num_sandboxes_running 0") {
				t.Errorf("expected runsc_meta_num_sandboxes_running to be 0")
			}

			// 6. Start a second sandbox.
			containerd2 := shimutils.NewMockContainerdWithSuffix(t, "sb2", shimArgs, runscArgs)
			sandbox2, client2 := setupSandbox(t, containerd2)

			// 7. Verify sandbox 2 is running and sandbox 1 is still gone.
			metricsStr3 := queryMetrics(t, metricSock)
			if strings.Contains(metricsStr3, sandbox1.ID()) {
				t.Errorf("expected metrics to NOT contain sandbox 1 ID %q", sandbox1.ID())
			}
			if !strings.Contains(metricsStr3, sandbox2.ID()) {
				t.Errorf("expected metrics to contain sandbox 2 ID %q", sandbox2.ID())
			}
			if !strings.Contains(metricsStr3, "runsc_meta_num_sandboxes_running 1") {
				t.Errorf("expected runsc_meta_num_sandboxes_running to be 1")
			}

			// Clean up sandbox 2.
			if err := killAndWaitForContainer(t.Context(), client2, sandbox2.ID(), containerd2); err != nil {
				t.Fatalf("failed to kill sandbox 2: %v", err)
			}
		})
	}
}
