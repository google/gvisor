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

package container

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/test/metricclient"
)

const (
	// podAnnotation contains the name of the pod that a sandbox represents when running in
	// Kubernetes.
	podAnnotation = "io.kubernetes.cri.sandbox-name"
	// namespaceAnnotation contains the name of the namespace that a sandbox is in when running in
	// Kubernetes.
	namespaceAnnotation = "io.kubernetes.cri.sandbox-namespace"
)

// metricsTest is returned by setupMetrics.
type metricsTest struct {
	testCtx   context.Context
	rootDir   string
	bundleDir string
	sleepSpec *specs.Spec
	sleepConf *config.Config
	udsPath   string
	client    *metricclient.MetricClient
}

// setupMetrics sets up a container configuration with metrics enabled, and returns it all.
// Also returns a cleanup function.
func setupMetrics(t *testing.T) (*metricsTest, func()) {
	// Start the child reaper.
	childReaper := &testutil.Reaper{}
	childReaper.Start()
	cu := cleanup.Make(childReaper.Stop)

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	cu.Add(cleanupCancel)
	testCtx, testCancel := context.WithTimeout(cleanupCtx, 50*time.Second)
	cu.Add(testCancel)

	spec, conf := sleepSpecConf(t)
	conf.MetricServer = "%RUNTIME_ROOT%/metrics.sock"
	conf.MetricExporterPrefix = "testmetric_"
	rootDir, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	cu.Add(cleanup)
	udsPath := filepath.Join(rootDir, "metrics.sock")
	if len(udsPath) >= 100 {
		// This is longer than the max UDS path length allowed by Linux. Try somewhere else in /tmp.
		tmpDir, err := os.MkdirTemp("/tmp", "metrics-")
		if err != nil {
			t.Fatalf("Runtime root is %s which means the metrics UDS %s (%d bytes) is longer than the maximum length allowed for a UDS path. The test could also not create a temporary directory in /tmp as a fallback (%v).", rootDir, udsPath, len(udsPath), err)
		}
		cu.Add(func() { os.RemoveAll(tmpDir) })
		udsPathTmp := filepath.Join(tmpDir, "metrics.sock")
		if len(udsPathTmp) >= 100 {
			t.Fatalf("Runtime root is %s which means the metrics UDS %s (%d bytes) is longer than the maximum length allowed for a UDS path. The test tried to create a fallback in /tmp but it was too long too (%q is %d characters).", rootDir, udsPath, len(udsPath), udsPathTmp, len(udsPathTmp))
		}
		udsPath = udsPathTmp
		conf.MetricServer = udsPathTmp
	}
	// The UDS should be deleted by the metrics server itself, but we clean it up here anyway just in case:
	cu.Add(func() { os.Remove(udsPath) })

	metricClient := metricclient.NewMetricClient(udsPath, rootDir)
	if err := metricClient.SpawnServer(testCtx, conf); err != nil {
		t.Fatalf("Cannot start metric server: %v", err)
	}
	cu.Add(func() { metricClient.ShutdownServer(cleanupCtx) })

	return &metricsTest{
		testCtx:   testCtx,
		rootDir:   rootDir,
		bundleDir: bundleDir,
		sleepSpec: spec,
		sleepConf: conf,
		udsPath:   udsPath,
		client:    metricClient,
	}, cu.Clean
}

// TestContainerMetrics verifies basic functionality of the metric server works.
func TestContainerMetrics(t *testing.T) {
	targetOpens := 200

	te, cleanup := setupMetrics(t)
	defer cleanup()

	if _, err := te.client.GetMetrics(te.testCtx); err != nil {
		t.Fatal("GetMetrics failed prior to container start")
	}
	if te.sleepSpec.Annotations == nil {
		te.sleepSpec.Annotations = make(map[string]string)
	}
	te.sleepSpec.Annotations[podAnnotation] = "foopod"
	te.sleepSpec.Annotations[namespaceAnnotation] = "foons"
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      te.sleepSpec,
		BundleDir: te.bundleDir,
	}
	cont, err := New(te.sleepConf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	udsStat, udsStatErr := os.Stat(te.udsPath)
	if udsStatErr != nil {
		t.Fatalf("Stat(%s) failed after creating container: %v", te.udsPath, udsStatErr)
	}
	if udsStat.Mode()&os.ModeSocket == 0 {
		t.Errorf("Stat(%s): Got mode %x, expected socket (mode %x)", te.udsPath, udsStat.Mode(), os.ModeSocket)
	}
	initialData, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Errorf("Cannot get metrics after creating container: %v", err)
	}
	t.Logf("Metrics prior to container start:\n\n%s\n\n", initialData)
	if err := cont.Start(te.sleepConf); err != nil {
		t.Fatalf("Cannot start container: %v", err)
	}
	postStartData, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Fatalf("Cannot get metrics after starting container: %v", err)
	}
	postStartOpens, postStartTimestamp, err := postStartData.GetPrometheusContainerInteger(metricclient.WantMetric{
		Metric:    "testmetric_fs_opens",
		Sandbox:   args.ID,
		Pod:       "foopod",
		Namespace: "foons",
	})
	if err != nil {
		t.Errorf("Cannot get testmetric_fs_opens from following data (err: %v):\n\n%s\n\n", err, postStartData)
	}
	t.Logf("After container start, fs_opens=%d (snapshotted at %v)", postStartOpens, postStartTimestamp)
	// The touch operation may fail from permission errors, but the metric should still be incremented.
	shOutput, err := executeCombinedOutput(te.sleepConf, cont, "/bin/bash", "-c", fmt.Sprintf("for i in $(seq 1 %d); do touch /tmp/$i || true; done", targetOpens))
	if err != nil {
		t.Fatalf("Exec failed: %v; output: %v", err, shOutput)
	}
	postExecData, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Fatalf("Cannot get metrics after a bunch of open() calls: %v", err)
	}
	postExecOpens, postExecTimestamp, err := postExecData.GetPrometheusContainerInteger(metricclient.WantMetric{
		Metric:    "testmetric_fs_opens",
		Sandbox:   args.ID,
		Pod:       "foopod",
		Namespace: "foons",
	})
	if err != nil {
		t.Errorf("Cannot get testmetric_fs_opens from following data (err: %v):\n\n%s\n\n", err, postExecData)
	}
	t.Logf("After exec'ing %d open()s, fs_opens=%d (snapshotted at %v)", targetOpens, postExecOpens, postExecTimestamp)
	diffOpens := postExecOpens - postStartOpens
	if diffOpens < int64(targetOpens) {
		t.Errorf("testmetric_fs_opens went from %d to %d (diff: %d), expected the difference to be at least %d", postStartOpens, postExecOpens, diffOpens, targetOpens)
	}
}

// TestContainerMetricsRobustAgainstRestarts that exporting metrics is robust against metric server
// unavailability or restarts.
func TestContainerMetricsRobustAgainstRestarts(t *testing.T) {
	targetOpens := 200
	te, cleanup := setupMetrics(t)
	defer cleanup()

	// First, start a container which will kick off the metric server as normal.
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      te.sleepSpec,
		BundleDir: te.bundleDir,
	}
	cont, err := New(te.sleepConf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(te.sleepConf); err != nil {
		t.Fatalf("Cannot start container: %v", err)
	}
	shOutput, err := executeCombinedOutput(te.sleepConf, cont, "/bin/bash", "-c", fmt.Sprintf("for i in $(seq 1 %d); do touch /tmp/$i || true; done", targetOpens))
	if err != nil {
		t.Fatalf("Exec failed: %v; output: %v", err, shOutput)
	}
	preRestartData, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Fatalf("Cannot get metrics after a bunch of open() calls: %v", err)
	}

	// Retain the value of fs_opens for the first container. We'll use it when comparing to the data
	// from the restarted metric server.
	preRestartOpens, postExecTimestamp, err := preRestartData.GetPrometheusContainerInteger(metricclient.WantMetric{
		Metric:  "testmetric_fs_opens",
		Sandbox: args.ID,
	})
	if err != nil {
		t.Errorf("Cannot get testmetric_fs_opens from following data (err: %v):\n\n%s\n\n", err, preRestartData)
	}
	t.Logf("After exec'ing %d open()s, fs_opens=%d (snapshotted at %v)", targetOpens, preRestartOpens, postExecTimestamp)

	// Now shut down the metric server and verify we can no longer fetch metrics.
	if err := te.client.ShutdownServer(te.testCtx); err != nil {
		t.Fatalf("Cannot shutdown server: %v", err)
	}
	if rawData, err := te.client.GetMetrics(te.testCtx); err == nil {
		t.Fatalf("Unexpectedly was able to get metric data despite shutting down server:\n\n%s\n\n", rawData)
	}

	// Do a bunch of touches again. The metric server is down during this time.
	// This verifies that metric value modifications does not depend on the metric server being up.
	shOutput, err = executeCombinedOutput(te.sleepConf, cont, "/bin/bash", "-c", fmt.Sprintf("for i in $(seq 1 %d); do touch /tmp/$i || true; done", targetOpens))
	if err != nil {
		t.Fatalf("Exec failed: %v; output: %v", err, shOutput)
	}

	// Start a second container.
	// This container should be picked up by a metric server we will start afterwards.
	// This verifies that a metric server being down does not cause sandbox creation to fail.
	args2 := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      te.sleepSpec,
		BundleDir: te.bundleDir,
	}
	cont2, err := New(te.sleepConf, args2)
	if err != nil {
		t.Fatalf("error creating second container: %v", err)
	}
	defer cont2.Destroy()
	if rawData, err := te.client.GetMetrics(te.testCtx); err == nil {
		t.Fatalf("Unexpectedly was able to get metric data after creating second container:\n\n%s\n\n", rawData)
	}
	if err := cont2.Start(te.sleepConf); err != nil {
		t.Fatalf("Cannot start second container: %v", err)
	}
	if rawData, err := te.client.GetMetrics(te.testCtx); err == nil {
		t.Fatalf("Unexpectedly was able to get metric data after starting second container:\n\n%s\n\n", rawData)
	}

	// Start the metric server.
	if err := te.client.SpawnServer(te.testCtx, te.sleepConf); err != nil {
		t.Fatalf("Cannot re-spawn server: %v", err)
	}

	// Now start a third container.
	// This should be picked up by the server we just started.
	args3 := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      te.sleepSpec,
		BundleDir: te.bundleDir,
	}
	cont3, err := New(te.sleepConf, args3)
	if err != nil {
		t.Fatalf("error creating second container: %v", err)
	}
	defer cont3.Destroy()
	if err := cont3.Start(te.sleepConf); err != nil {
		t.Fatalf("Cannot start third container: %v", err)
	}

	// Verify that the metric server was restarted and that we can indeed get all the data we expect
	// from all the containers this test has started.
	postRestartData, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Fatalf("Cannot get metrics after restarting server: %v", err)
	}
	postRestartOpens, _, err := postRestartData.GetPrometheusContainerInteger(metricclient.WantMetric{
		Metric:  "testmetric_fs_opens",
		Sandbox: args.ID,
	})
	if err != nil {
		t.Fatalf("Cannot get testmetric_fs_opens for first container (%s) from following data (err: %v):\n\n%s\n\n", args.ID, err, postRestartData)
	}
	if diff := postRestartOpens - preRestartOpens; diff < int64(targetOpens) {
		t.Errorf("testmetric_fs_opens for first container did not increase by at least %d after metric server restart: went from %d to %d (diff: %d)", targetOpens, preRestartOpens, postRestartOpens, diff)
	}
	_, _, err = postRestartData.GetPrometheusContainerInteger(metricclient.WantMetric{
		Metric:  "testmetric_fs_opens",
		Sandbox: args2.ID,
	})
	if err != nil {
		t.Fatalf("Cannot get testmetric_fs_opens for second container (%s) from following data (err: %v):\n\n%s\n\n", args2.ID, err, postRestartData)
	}
	_, _, err = postRestartData.GetPrometheusContainerInteger(metricclient.WantMetric{
		Metric:  "testmetric_fs_opens",
		Sandbox: args3.ID,
	})
	if err != nil {
		t.Fatalf("Cannot get testmetric_fs_opens for third container (%s) from following data (err: %v):\n\n%s\n\n", args3.ID, err, postRestartData)
	}
}

// TestContainerMetricsMultiple verifies that the metric server spawned for one container
// serves metrics for all containers, and survives past its initial container's lifetime.
func TestContainerMetricsMultiple(t *testing.T) {
	numConcurrentContainers := 5

	te, cleanup := setupMetrics(t)
	defer cleanup()
	var containers []*Container
	needCleanup := map[*Container]struct{}{}
	toDestroy := map[*Container]struct{}{}
	defer func() {
		for container := range needCleanup {
			container.Destroy()
		}
	}()

	// Start a bunch of containers with metrics.
	for i := 0; i < numConcurrentContainers; i++ {
		cont, err := New(te.sleepConf, Args{
			ID:        testutil.RandomContainerID(),
			Spec:      te.sleepSpec,
			BundleDir: te.bundleDir,
		})
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		containers = append(containers, cont)
		needCleanup[cont] = struct{}{}
		// Note that this includes the first container, which will be the one that
		// starts the metrics server.
		if i%2 == 0 {
			toDestroy[cont] = struct{}{}
		}
		if err := cont.Start(te.sleepConf); err != nil {
			t.Fatalf("Cannot start container: %v", err)
		}
	}

	// Start one container with metrics turned off.
	sleepConfNoMetrics := *te.sleepConf
	sleepConfNoMetrics.MetricServer = ""
	noMetricsCont, err := New(&sleepConfNoMetrics, Args{
		ID:        testutil.RandomContainerID(),
		Spec:      te.sleepSpec,
		BundleDir: te.bundleDir,
	})
	if err != nil {
		t.Fatalf("error creating no-metrics container: %v", err)
	}
	defer noMetricsCont.Destroy()

	// Verify that the metrics server says what we expect.
	gotData, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Fatalf("Cannot get metrics after starting containers: %v", err)
	}
	t.Logf("Metrics after starting all containers:\n\n%s\n\n", gotData)
	for _, container := range containers {
		if _, _, err := gotData.GetPrometheusContainerInteger(metricclient.WantMetric{
			Metric:  "testmetric_fs_opens",
			Sandbox: container.ID,
		}); err != nil {
			t.Errorf("Cannot get testmetric_fs_opens for container %s: %v", container.ID, err)
		}
	}
	if val, _, err := gotData.GetPrometheusContainerInteger(metricclient.WantMetric{
		Metric:  "testmetric_fs_opens",
		Sandbox: noMetricsCont.ID,
	}); err == nil {
		t.Errorf("Unexpectedly found testmetric_fs_opens metric data for no-metrics container %s: %v", noMetricsCont.ID, val)
	}

	// Stop every other container.
	for container := range toDestroy {
		if err := container.Destroy(); err != nil {
			t.Logf("Warning: cannot destroy container %s: %v", container.ID, err)
			continue
		}
		delete(needCleanup, container)
	}

	// Verify that now we only have half the containers.
	gotData, err = te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Fatalf("Cannot get metrics after stopping half the containers: %v", err)
	}
	t.Logf("Metrics after stopping half the containers:\n\n%s\n\n", gotData)
	for _, container := range containers {
		val, _, err := gotData.GetPrometheusContainerInteger(metricclient.WantMetric{
			Metric:  "testmetric_fs_opens",
			Sandbox: container.ID,
		})
		_, wantErr := toDestroy[container]
		if gotErr := err != nil; gotErr && !wantErr {
			t.Errorf("Wanted to find data for container %s but didn't: %v", container.ID, err)
		} else if !gotErr && wantErr {
			t.Errorf("Wanted to find no data for container %s but found this value instead: %v", container.ID, val)
		}
	}
	if val, _, err := gotData.GetPrometheusContainerInteger(metricclient.WantMetric{
		Metric:  "testmetric_fs_opens",
		Sandbox: noMetricsCont.ID,
	}); err == nil {
		t.Errorf("Unexpectedly found testmetric_fs_opens metric data for no-metrics container %s: %v", noMetricsCont.ID, val)
	}
}
