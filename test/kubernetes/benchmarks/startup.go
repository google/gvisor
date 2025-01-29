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

// Package startup benchmarks the time it takes for an empty alpine container to complete successfully.
package startup

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
)

const (
	benchName = "StartUp"
)

var (
	command = []string{"/bin/sh", "-c", "echo hello"}
)

// MeasureStartup benchmarks the time it takes for an empty alpine container
// to complete successfully.
// Note: WRT gVisor startup latency, this is not a meaningful benchmark.
// Startup time is dominated by Kubernetes control plane API calls and not
// actual container startups. This benchmark is provided for illustrative
// purposes only.
func MeasureStartup(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	t.Logf("Warning: This is not a meaningful benchmark. Read the comments.")

	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)
	endProfiling, err := profiling.MaybeSetup(ctx, t, k8sCtx, cluster, benchmarkNS)
	if err != nil {
		t.Fatalf("Failed to setup profiling: %v", err)
	}
	defer endProfiling()

	podName := "startup"
	image, err := k8sCtx.ResolveImage(ctx, "alpine")
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	p, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, benchmarkNS.NewAlpinePod(podName, image, command))
	if err != nil {
		t.Fatalf("failed to set pod for test nodepool: %v", err)
	}

	start := time.Now()
	p, err = cluster.CreatePod(ctx, p)
	if err != nil {
		t.Fatalf("Failed to create pod: %v", err)
	}
	defer cluster.DeletePod(ctx, p)
	if err := cluster.WaitForPodCompleted(ctx, p); err != nil {
		t.Fatalf("Failed to wait for pod to complete: %v", err)
	}
	reader, err := cluster.GetLogReader(ctx, p, v13.PodLogOptions{})
	if err != nil {
		t.Fatalf("Failed to get log reader on cluster %q: %v", cluster.GetName(), err)
	}
	defer reader.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		t.Fatalf("Failed to read log on cluster %q: %v", cluster.GetName(), err)
	}
	if strings.TrimSpace(buf.String()) != "hello" {
		t.Fatalf("Mismatched output: got: %q want: %q", buf.String(), "hello")
	}

	// For longer running containers, and where the desired duration to
	// measure is the time it takes to run a command within a container,
	// this should use `GetTimedContainerDuration` instead.
	// However, since this benchmark's goal is to measure container runtime
	// overhead, it uses the Kubernetes-level metrics for container
	// duration.
	containerDuration, err := cluster.ContainerDurationSecondsByName(ctx, p, p.GetName())
	if err != nil {
		t.Fatalf("Failed to get container duration: %v", err)
	}
	overallDuration := time.Since(start)
	recorder, err := benchmetric.GetRecorder(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize benchmark recorder: %v", err)
	}
	err = recorder.Record(ctx, benchName,
		benchmetric.BenchmarkDuration(overallDuration),
		benchmetric.SpecificDuration(containerDuration, "container-runtime"),
	)
	if err != nil {
		t.Fatalf("Failed to record benchmark data: %v", err)
	}
}
