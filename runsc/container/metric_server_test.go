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
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
	testCtx         context.Context
	rootDir         string
	bundleDir       string
	sleepSpec       *specs.Spec
	sleepConf       *config.Config
	udsPath         string
	client          *metricclient.MetricClient
	serverExtraArgs []string
}

// applyConf applies metric-server-related configuration options to the given config.
// Returns the passed-in config itself.
func (mt *metricsTest) applyConf(conf *config.Config) *config.Config {
	conf.MetricServer = mt.sleepConf.MetricServer
	conf.RootDir = mt.rootDir
	return conf
}

// setupMetrics sets up a container configuration with metrics enabled, and returns it all.
// Also returns a cleanup function.
func setupMetrics(t *testing.T, forceTempUDS bool) (*metricsTest, func()) {
	// Start the child reaper.
	childReaper := &testutil.Reaper{}
	childReaper.Start()
	cu := cleanup.Make(childReaper.Stop)

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Minute+30*time.Second)
	cu.Add(cleanupCancel)
	testCtx, testCancel := context.WithTimeout(cleanupCtx, 3*time.Minute)
	cu.Add(testCancel)

	spec, conf := sleepSpecConf(t)
	conf.MetricServer = "%RUNTIME_ROOT%/metrics.sock"
	serverExtraArgs := []string{"--exporter-prefix=testmetric_"}
	rootDir, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	cu.Add(cleanup)
	tmpDir, err := os.MkdirTemp("/tmp", "metrics-")
	if err != nil {
		t.Fatalf("Cannot create temporary directory in /tmp: %v", err)
	}
	cu.Add(func() { os.RemoveAll(tmpDir) })
	udsPath := filepath.Join(rootDir, "metrics.sock")
	if forceTempUDS || len(udsPath) >= 100 {
		udsPath = filepath.Join(tmpDir, "metrics.sock")
	}
	if len(udsPath) >= 100 {
		t.Fatalf("Cannot come up with a UDS path shorter than the maximum length allowed by Linux (tried to use %q)", udsPath)
	}
	conf.MetricServer = udsPath
	// The UDS should be deleted by the metrics server itself, but we clean it up here anyway just in case:
	cu.Add(func() { os.Remove(udsPath) })

	metricClient := metricclient.NewMetricClient(udsPath, rootDir)
	if err := metricClient.SpawnServer(testCtx, conf, serverExtraArgs...); err != nil {
		t.Fatalf("Cannot start metric server: %v", err)
	}
	cu.Add(func() { metricClient.ShutdownServer(cleanupCtx) })

	return &metricsTest{
		testCtx:         testCtx,
		rootDir:         rootDir,
		bundleDir:       bundleDir,
		sleepSpec:       spec,
		sleepConf:       conf,
		udsPath:         udsPath,
		client:          metricClient,
		serverExtraArgs: serverExtraArgs,
	}, cu.Clean
}

// TestContainerMetrics verifies basic functionality of the metric server works.
func TestContainerMetrics(t *testing.T) {
	targetOpens := 200

	te, cleanup := setupMetrics(t /* forceTempUDS= */, false)
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
	gotMetadata, err := initialData.GetSandboxMetadataMetric(metricclient.WantMetric{
		Metric:    "testmetric_meta_sandbox_metadata",
		Sandbox:   args.ID,
		Pod:       "foopod",
		Namespace: "foons",
	})
	if err != nil {
		t.Errorf("Cannot get sandbox metadata: %v", err)
	}
	if gotMetadata["platform"] == "" || gotMetadata["platform"] != te.sleepConf.Platform {
		t.Errorf("Invalid platform: Metric metadata says %v, config says %v", gotMetadata["platform"], te.sleepConf.Platform)
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
	shOutput, err := executeCombinedOutput(te.sleepConf, cont, nil, "/bin/bash", "-c", fmt.Sprintf("for i in $(seq 1 %d); do touch /tmp/$i || true; done", targetOpens))
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

// TestContainerMetricsIterationID verifies that two successive containers with the same ID
// do not have the same iteration ID.
func TestContainerMetricsIterationID(t *testing.T) {
	te, cleanup := setupMetrics(t /* forceTempUDS= */, false)
	defer cleanup()

	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      te.sleepSpec,
		BundleDir: te.bundleDir,
	}
	cont1, err := New(te.sleepConf, args)
	if err != nil {
		t.Fatalf("error creating container 1: %v", err)
	}
	defer cont1.Destroy()
	data1, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Errorf("Cannot get metrics after creating container 1: %v", err)
	}
	metadata1, err := data1.GetSandboxMetadataMetric(metricclient.WantMetric{
		Metric:  "testmetric_meta_sandbox_metadata",
		Sandbox: args.ID,
	})
	if err != nil {
		t.Errorf("Cannot get sandbox 1 metadata: %v", err)
	}
	t.Logf("Container 1 metadata: %v", metadata1)
	iterationID1 := metadata1["iteration"]
	if iterationID1 == "" {
		t.Fatalf("Cannot find iteration ID in metadata 1: %v", metadata1)
	}
	if err := cont1.Destroy(); err != nil && !strings.Contains(err.Error(), "no child process") {
		t.Fatalf("Cannot destroy container 1: %v", err)
	}
	cont2, err := New(te.sleepConf, args)
	if err != nil {
		t.Fatalf("error creating container 2: %v", err)
	}
	defer cont2.Destroy()
	data2, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Errorf("Cannot get metrics after creating container 2: %v", err)
	}
	metadata2, err := data2.GetSandboxMetadataMetric(metricclient.WantMetric{
		Metric:  "testmetric_meta_sandbox_metadata",
		Sandbox: args.ID,
	})
	if err != nil {
		t.Errorf("Cannot get sandbox 2 metadata: %v", err)
	}
	t.Logf("Container 2 metadata: %v", metadata2)
	iterationID2 := metadata2["iteration"]
	if iterationID2 == "" {
		t.Fatalf("Cannot find iteration ID in metadata 2: %v", metadata2)
	}
	if iterationID1 == iterationID2 {
		t.Errorf("Iteration IDs of successive instances with the same ID unexpectedly matched: %v", iterationID1)
	}
}

// TestContainerMetricsRobustAgainstRestarts that exporting metrics is robust against metric server
// unavailability or restarts.
func TestContainerMetricsRobustAgainstRestarts(t *testing.T) {
	targetOpens := 200
	te, cleanup := setupMetrics(t /* forceTempUDS= */, false)
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
	shOutput, err := executeCombinedOutput(te.sleepConf, cont, nil, "/bin/bash", "-c", fmt.Sprintf("for i in $(seq 1 %d); do touch /tmp/$i || true; done", targetOpens))
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
	preRestartMetadata, err := preRestartData.GetSandboxMetadataMetric(metricclient.WantMetric{
		Metric:  "testmetric_meta_sandbox_metadata",
		Sandbox: args.ID,
	})
	if err != nil {
		t.Errorf("Cannot get sandbox metadata: %v", err)
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
	shOutput, err = executeCombinedOutput(te.sleepConf, cont, nil, "/bin/bash", "-c", fmt.Sprintf("for i in $(seq 1 %d); do touch /tmp/$i || true; done", targetOpens))
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
	if err := te.client.SpawnServer(te.testCtx, te.sleepConf, te.serverExtraArgs...); err != nil {
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
	postRestartMetadata, err := postRestartData.GetSandboxMetadataMetric(metricclient.WantMetric{
		Metric:  "testmetric_meta_sandbox_metadata",
		Sandbox: args.ID,
	})
	if err != nil {
		t.Fatalf("Cannot get post-restart sandbox metadata: %v", err)
	}
	if diff := cmp.Diff(preRestartMetadata, postRestartMetadata); diff != "" {
		t.Errorf("Sandbox metadata changed after restart:\nBefore: %v\nAfter: %v\nDiff: %v", preRestartMetadata, postRestartMetadata, diff)
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

	te, cleanup := setupMetrics(t /* forceTempUDS= */, false)
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

func TestMetricServerChecksRootDirectoryAccess(t *testing.T) {
	te, cleanup := setupMetrics(t /* forceTempUDS= */, false)
	defer cleanup()
	if err := te.client.ShutdownServer(te.testCtx); err != nil {
		t.Fatalf("Cannot stop metric server: %v", err)
	}
	prevStat, err := os.Lstat(te.sleepConf.RootDir)
	if err != nil {
		t.Fatalf("cannot stat %q: %v", te.sleepConf.RootDir, err)
	}
	if err := os.Chmod(te.sleepConf.RootDir, 0); err != nil {
		t.Fatalf("cannot chmod %q as 000: %v", te.sleepConf.RootDir, err)
	}
	defer os.Chmod(te.sleepConf.RootDir, prevStat.Mode())
	if _, err := ioutil.ReadDir(te.sleepConf.RootDir); err == nil {
		t.Logf("Can still read directory %v despite chmodding it to 0. Maybe we are running as root? Skipping test.", te.sleepConf.RootDir)
		return
	}
	shorterCtx, shorterCtxCancel := context.WithTimeout(te.testCtx, time.Second)
	defer shorterCtxCancel()
	if err := te.client.SpawnServer(shorterCtx, te.sleepConf, te.serverExtraArgs...); err == nil {
		t.Error("Metric server was successfully able to be spawned despite not having access to the root directory")
	}
}

func TestMetricServerToleratesNoRootDirectory(t *testing.T) {
	te, cleanup := setupMetrics(t /* forceTempUDS= */, true)
	defer cleanup()
	if err := te.client.ShutdownServer(te.testCtx); err != nil {
		t.Fatalf("Cannot stop metric server: %v", err)
	}
	if err := os.RemoveAll(te.sleepConf.RootDir); err != nil {
		t.Fatalf("cannot remove root directory %q: %v", te.sleepConf.RootDir, err)
	}
	shortCtx, shortCtxCancel := context.WithTimeout(te.testCtx, time.Second)
	defer shortCtxCancel()
	if err := te.client.SpawnServer(shortCtx, te.sleepConf, append([]string{"--allow-unknown-root=false"}, te.serverExtraArgs...)...); err == nil {
		t.Fatalf("Metric server was successfully able to be spawned despite a non-existent root directory")
	}
	if err := te.client.SpawnServer(te.testCtx, te.sleepConf, append([]string{"--allow-unknown-root=true"}, te.serverExtraArgs...)...); err != nil {
		t.Errorf("Metric server was not able to be spawned despite being configured to tolerate a non-existent root directory: %v", err)
	}
}

func TestMetricServerDoesNotExportZeroValueCounters(t *testing.T) {
	te, cleanup := setupMetrics(t, false /* forceTempUDS */)
	defer cleanup()
	app, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		t.Fatalf("error finding test_app: %v", err)
	}
	unimpl1Spec := testutil.NewSpecWithArgs("sh", "-c", fmt.Sprintf("%s syscall --syscall=1337; sleep 1h", app))
	unimpl1Conf := te.applyConf(testutil.TestConfig(t))
	unimpl1Bundle, cleanup, err := testutil.SetupBundleDir(unimpl1Spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()
	unimpl2Spec := testutil.NewSpecWithArgs("sh", "-c", fmt.Sprintf("%s syscall --syscall=1338; sleep 1h", app))
	unimpl2Conf := te.applyConf(testutil.TestConfig(t))
	unimpl2Bundle, cleanup, err := testutil.SetupBundleDir(unimpl2Spec)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()
	unimpl1, err := New(unimpl1Conf, Args{
		ID:        testutil.RandomContainerID(),
		Spec:      unimpl1Spec,
		BundleDir: unimpl1Bundle,
	})
	if err != nil {
		t.Fatalf("error creating first container: %v", err)
	}
	defer unimpl1.Destroy()
	if err := unimpl1.Start(unimpl1Conf); err != nil {
		t.Fatalf("Cannot start first container: %v", err)
	}
	unimpl2, err := New(unimpl2Conf, Args{
		ID:        testutil.RandomContainerID(),
		Spec:      unimpl2Spec,
		BundleDir: unimpl2Bundle,
	})
	if err != nil {
		t.Fatalf("error creating second container: %v", err)
	}
	defer unimpl2.Destroy()
	if err := unimpl2.Start(unimpl2Conf); err != nil {
		t.Fatalf("Cannot start second container: %v", err)
	}
	metricData, err := te.client.GetMetrics(te.testCtx)
	if err != nil {
		t.Fatalf("Cannot get metrics: %v", err)
	}
	metricDataPtr := &metricData

	// For this test to work, it must wait for long enough such that the containers have
	// actually tried to call the unimplemented syscall so that it shows up in metrics.
	waitCtx, waitCtxCancel := context.WithTimeout(te.testCtx, 50*time.Second)
	defer waitCtxCancel()

	for _, test := range []struct {
		cont          *Container
		sysno         uintptr
		wantExistence bool
	}{
		{unimpl1, 1337, true},
		{unimpl1, 1338, false},
		{unimpl2, 1337, false},
		{unimpl2, 1338, true},
	} {
		t.Run(fmt.Sprintf("container %s syscall %d", test.cont.ID, test.sysno), func(t *testing.T) {
			check := func() error {
				got, _, err := metricDataPtr.GetPrometheusContainerInteger(metricclient.WantMetric{
					Metric:      "testmetric_unimplemented_syscalls",
					Sandbox:     test.cont.sandboxID(),
					ExtraLabels: map[string]string{"sysno": strconv.Itoa(int(test.sysno))},
				})
				if test.wantExistence {
					if err != nil {
						return fmt.Errorf("cannot get unimplemented syscall metric for sysno=%d even though we expected its presence: %v", test.sysno, err)
					}
					if got != 1 {
						return fmt.Errorf("expected counter value for unimplemented syscall %d be exactly 1, got %d", test.sysno, got)
					}
				} else /* !test.wantExistence */ {
					if err == nil {
						return fmt.Errorf("unimplemented syscall metric for sysno=%d was unexpectedly present (value: %d)", test.sysno, got)
					}
				}
				return nil
			}
			for waitCtx.Err() == nil {
				if check() == nil {
					break
				}
				select {
				case <-time.After(20 * time.Millisecond):
					newMetricData, err := te.client.GetMetrics(te.testCtx)
					if err != nil {
						t.Fatalf("Cannot get metrics: %v", err)
					}
					*metricDataPtr = newMetricData
				case <-waitCtx.Done():
				}
			}
			if err := check(); err != nil {
				t.Error(err.Error())
			}
		})
	}
	if t.Failed() {
		t.Logf("Last metric data:\n\n%s\n\n", metricData)
	}
}
