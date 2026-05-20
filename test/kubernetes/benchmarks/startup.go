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
	"bufio"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
)

const (
	benchName = "StartUp"
)

// PodRunMetrics contains the durations metrics for a single pod run.
type PodRunMetrics struct {
	// SchedulingDuration is the time it takes for the pod to be scheduled.
	SchedulingDuration time.Duration
	// CreationDuration is the time it takes for the pod to be created after scheduling.
	CreationDuration time.Duration
	// StartDuration is the time it takes for the pod to start after creation.
	StartDuration time.Duration
	// TotalRuntimeInitializationDuration is the time it takes for the pod to finish
	// scheduling to the time it starts producing output.
	TotalRuntimeInitializationDuration time.Duration
}

// String returns a human-readable representation of the PodRunMetrics.
func (p *PodRunMetrics) String() string {
	return fmt.Sprintf("SchedulingDuration: %v, CreationDuration: %v, StartDuration: %v, TotalRuntimeInitializationDuration: %v",
		p.SchedulingDuration, p.CreationDuration, p.StartDuration, p.TotalRuntimeInitializationDuration)
}

// MeasureStartup benchmarks the time it takes for an empty alpine container
// to complete successfully.
func MeasureStartup(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
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

	// Run a pod once without recording metrics to warm up caches,
	// e.g. image cache on the node, and to determine whether to use
	// the new Kubernetes Events API or not.
	t.Logf("Running warm-up pod run...")
	useNewEventsAPI.Store(true)
	if _, err := runPodAndGetMetrics(ctx, t, k8sCtx, cluster, benchmarkNS, 0); err != nil {
		t.Fatalf("Failed to run pod on warm-up run: %v", err)
	}

	const (
		// Number of times to run the pod.
		numRuns = 128

		// Number of times the pod must successfully run to be considered a valid
		// set of results.
		numMinSuccessfulRuns = 32
	)
	var schedulingDurations []time.Duration
	var creationDurations []time.Duration
	var startDurations []time.Duration
	var totalRuntimeInitializationDurations []time.Duration

	for i := 1; i <= numRuns; i++ {
		t.Logf("Running pod run %d/%d...", i, numRuns)
		metrics, err := runPodAndGetMetrics(ctx, t, k8sCtx, cluster, benchmarkNS, i)
		if err != nil {
			t.Logf("Failed to run pod on run %d: %v", i, err)
			break // Assume further runs will fail too.
		}
		t.Logf("Pod run %d/%d metrics: %v", i, numRuns, metrics)
		schedulingDurations = append(schedulingDurations, metrics.SchedulingDuration)
		creationDurations = append(creationDurations, metrics.CreationDuration)
		startDurations = append(startDurations, metrics.StartDuration)
		totalRuntimeInitializationDurations = append(totalRuntimeInitializationDurations, metrics.TotalRuntimeInitializationDuration)
	}
	if len(schedulingDurations) < numMinSuccessfulRuns {
		t.Fatalf("Not enough successful runs, got %d, want at least %d", len(schedulingDurations), numMinSuccessfulRuns)
	}

	percentile := func(durs []time.Duration, p float64) time.Duration {
		sorted := make([]time.Duration, len(durs))
		copy(sorted, durs)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		if p <= 0.0 {
			return sorted[0]
		}
		if p >= 1.0 {
			return sorted[len(sorted)-1]
		}
		return sorted[int(float64(len(sorted)-1)*p)]
	}

	recorder, err := benchmetric.GetRecorder(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize benchmark recorder: %v", err)
	}
	err = recorder.Record(ctx, benchName,
		benchmetric.BenchmarkDuration(percentile(totalRuntimeInitializationDurations, 0.50)),
		benchmetric.SpecificDuration(percentile(schedulingDurations, 0.00), "scheduling-min"),
		benchmetric.SpecificDuration(percentile(schedulingDurations, 0.05), "scheduling-p05"),
		benchmetric.SpecificDuration(percentile(schedulingDurations, 0.50), "scheduling-p50"),
		benchmetric.SpecificDuration(percentile(schedulingDurations, 0.95), "scheduling-p95"),
		benchmetric.SpecificDuration(percentile(schedulingDurations, 1.00), "scheduling-max"),
		benchmetric.SpecificDuration(percentile(creationDurations, 0.00), "podcreation-min"),
		benchmetric.SpecificDuration(percentile(creationDurations, 0.05), "podcreation-p05"),
		benchmetric.SpecificDuration(percentile(creationDurations, 0.50), "podcreation-p50"),
		benchmetric.SpecificDuration(percentile(creationDurations, 0.95), "podcreation-p95"),
		benchmetric.SpecificDuration(percentile(creationDurations, 1.00), "podcreation-max"),
		benchmetric.SpecificDuration(percentile(startDurations, 0.00), "podstart-min"),
		benchmetric.SpecificDuration(percentile(startDurations, 0.05), "podstart-p05"),
		benchmetric.SpecificDuration(percentile(startDurations, 0.50), "podstart-p50"),
		benchmetric.SpecificDuration(percentile(startDurations, 0.95), "podstart-p95"),
		benchmetric.SpecificDuration(percentile(startDurations, 1.00), "podstart-max"),
		benchmetric.SpecificDuration(percentile(totalRuntimeInitializationDurations, 0.00), "totalruntimeinit-min"),
		benchmetric.SpecificDuration(percentile(totalRuntimeInitializationDurations, 0.05), "totalruntimeinit-p05"),
		benchmetric.SpecificDuration(percentile(totalRuntimeInitializationDurations, 0.50), "totalruntimeinit-p50"),
		benchmetric.SpecificDuration(percentile(totalRuntimeInitializationDurations, 0.95), "totalruntimeinit-p95"),
		benchmetric.SpecificDuration(percentile(totalRuntimeInitializationDurations, 1.00), "totalruntimeinit-max"),
	)
	if err != nil {
		t.Fatalf("Failed to record benchmark data: %v", err)
	}
}

// If true, use the new Kubernetes Events API with microsecond-level timestamps.
// Otherwise, use the legacy Kubernetes Events API and measure from the client side.
var useNewEventsAPI atomicbitops.Bool

// runPodAndGetMetrics creates a new pod on the cluster, waits for its completion,
// and returns a PodRunMetrics containing the scheduling, creation, start, and total durations.
func runPodAndGetMetrics(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster, benchmarkNS *testcluster.Namespace, iteration int) (*PodRunMetrics, error) {
	podName := fmt.Sprintf("startup-%d", iteration)
	newEventsAPI := useNewEventsAPI.Load()
	// Can't use Alpine or Busybox here because their `date -Ins` implementation
	// doesn't actually have better than per-second resolution.
	image, err := k8sCtx.ResolveImage(ctx, "debian")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve image: %w", err)
	}
	const (
		numCalibrations = 24
		minCalibrations = 6
	)
	cmd := fmt.Sprintf("date -Ins && echo hello %q world && sleep 1 && for i in $(seq 1 %d); do date -Ins && sleep .2; done", podName, numCalibrations)
	podTmpl := benchmarkNS.NewPod(podName)
	podTmpl.Spec.Containers = []v13.Container{
		{Name: podName, Image: image, Command: []string{"/bin/sh", "-c", cmd}},
	}
	p, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, podTmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to set pod for test nodepool: %w", err)
	}
	createdAt := time.Now()
	p, err = cluster.CreatePod(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("failed to create pod: %w", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			if err := cluster.DeletePod(ctx, p); err != nil {
				t.Errorf("Failed to delete pod: %v", err)
			}
			deleted = true
		}
	}()
	parseTimestamp := func(s string) (time.Time, error) {
		s = strings.Replace(strings.TrimSpace(s), ",", ".", 1)
		parsed, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse timestamp %q: %w", s, err)
		}
		return parsed, nil
	}
	wantLogLine := fmt.Sprintf("hello %s world", podName)
	var createdTime, scheduledTime, startedTime, producedOutputTime time.Time
	if !newEventsAPI {
		// Fallback to measuring timestamps from the client side in a busy-loop.
		waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Minute)
		logSometimes := rate.Sometimes{Interval: 10 * time.Second}
		errSometimes := rate.Sometimes{Interval: 3 * time.Second}
		startSignalCh := make(chan struct{}, 1)
		defer close(startSignalCh)
		logProcessErrCh := make(chan error, 1)
		go func() {
			logProcessErrCh <- (func() error {
				var rdr io.ReadCloser
			waitStartLoop:
				for {
					select {
					case <-waitCtx.Done():
						return fmt.Errorf("context expired while waiting for start signal: %w", waitCtx.Err())
					case <-startSignalCh:
						break waitStartLoop
					}
				}
				for rdr == nil && waitCtx.Err() == nil {
					r, err := cluster.GetLogReader(waitCtx, p, v13.PodLogOptions{Follow: true})
					if err != nil {
						// Can happen before pod is started. This is normal.
						time.Sleep(20 * time.Millisecond)
						continue
					}
					rdr = r
				}
				if rdr == nil {
					return fmt.Errorf("failed to get log reader before context expiry: %w", waitCtx.Err())
				}
				defer rdr.Close()
				foundHelloWorld := false
				var firstLogLineTimestamp time.Time
				var logDeltas []time.Duration
				var lastLineAt time.Time
				var logs []string
				scanner := bufio.NewScanner(rdr)
				for waitCtx.Err() == nil && scanner.Scan() {
					line := scanner.Text()
					now := time.Now()
					if line == "" {
						continue
					}
					line = strings.TrimSpace(line)
					logs = append(logs, line)
					if strings.Contains(line, wantLogLine) {
						foundHelloWorld = true
						continue
					}
					ts, err := parseTimestamp(line)
					if err != nil {
						lastLineAt = now
						continue
					}
					if !foundHelloWorld && firstLogLineTimestamp.IsZero() {
						firstLogLineTimestamp = ts
					} else if foundHelloWorld && now.Sub(lastLineAt) > 100*time.Millisecond {
						logDeltas = append(logDeltas, now.Sub(ts))
					}
					lastLineAt = now
				}
				if ctxErr := waitCtx.Err(); ctxErr != nil {
					return fmt.Errorf("context expired while reading logs: %w", ctxErr)
				}
				if !foundHelloWorld {
					return fmt.Errorf("hello world not found in logs: %q", strings.Join(logs, "\n"))
				}
				if firstLogLineTimestamp.IsZero() {
					return fmt.Errorf("did not find initial timestamp in logs: %q", strings.Join(logs, "\n"))
				}
				if len(logDeltas) == 0 {
					return fmt.Errorf("did not find any calibration timestamps in logs: %q", strings.Join(logs, "\n"))
				}
				if len(logDeltas) < minCalibrations {
					return fmt.Errorf("not enough calibration timestamps in logs: got %d, want at least %d", len(logDeltas), minCalibrations)
				}
				var sum time.Duration
				for _, d := range logDeltas {
					sum += d
				}
				averageLogDelta := sum / time.Duration(len(logDeltas))
				producedOutputTime = firstLogLineTimestamp.Add(averageLogDelta)
				t.Logf("Average log delta: %v; adjusting pod-reported start time from %v to %v", averageLogDelta, firstLogLineTimestamp, producedOutputTime)
				return nil
			})()
		}()
		for waitCtx.Err() == nil {
			pNow, err := cluster.GetPod(waitCtx, p)
			now := time.Now()
			if err != nil {
				// Can happen when hammering the API server quickly.
				errSometimes.Do(func() { t.Logf("Failed to get pod %v: %v", p.Name, err) })
				time.Sleep(1 * time.Millisecond)
				continue
			}
			logSometimes.Do(func() { t.Logf("Pod %v status: %v", p.Name, pNow.Status.Phase) })
			if scheduledTime.IsZero() && pNow.Spec.NodeName != "" {
				scheduledTime = now
			}
			if createdTime.IsZero() && len(pNow.Status.ContainerStatuses) > 0 {
				createdTime = now
			}
			if startedTime.IsZero() && (string(pNow.Status.Phase) == "Running" || string(pNow.Status.Phase) == "Succeeded" || string(pNow.Status.Phase) == "Failed") {
				startedTime = now
				startSignalCh <- struct{}{}
			}
			if !scheduledTime.IsZero() && !createdTime.IsZero() && !startedTime.IsZero() {
				break
			}
			time.Sleep(1 * time.Millisecond)
		}
		if err := cluster.WaitForPodCompleted(waitCtx, p); err != nil {
			waitCancel()
			return nil, fmt.Errorf("failed to wait for pod to complete: %w", err)
		}
		defer waitCancel()
		waitLogFinishCtx, waitLogFinishCancel := context.WithTimeout(ctx, 15*time.Second)
		defer waitLogFinishCancel()
		select {
		case <-waitLogFinishCtx.Done():
			return nil, fmt.Errorf("context expired while waiting for log processing to finish: %w", waitLogFinishCtx.Err())
		case err := <-logProcessErrCh:
			if err != nil {
				return nil, fmt.Errorf("failed to process pod logs: %w", err)
			}
		}
	} else {
		if err := cluster.WaitForPodCompleted(ctx, p); err != nil {
			return nil, fmt.Errorf("failed to wait for pod to complete: %w", err)
		}
		events, err := cluster.ListPodEvents(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("failed to list events: %w", err)
		}

		for _, ev := range events.Items {
			switch ev.Reason {
			case "Scheduled":
				if scheduledTime.IsZero() || ev.EventTime.Time.Before(scheduledTime) {
					scheduledTime = ev.EventTime.Time
				}
			case "Created":
				if createdTime.IsZero() || ev.EventTime.Time.Before(createdTime) {
					createdTime = ev.EventTime.Time
				}
			case "Started":
				if startedTime.IsZero() || ev.EventTime.Time.Before(startedTime) {
					startedTime = ev.EventTime.Time
				}
			}
		}
		logs, err := cluster.ReadPodLogs(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod logs: %w", err)
		}
		for _, line := range strings.Split(logs, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if parsed, err := parseTimestamp(line); err == nil {
				producedOutputTime = parsed
			}
			if strings.Contains(line, wantLogLine) {
				break
			}
		}
		if scheduledTime.IsZero() || createdTime.IsZero() || startedTime.IsZero() || producedOutputTime.IsZero() {
			t.Logf("Events missing microsecond-level timestamp information: got scheduled: %v, created: %v, started: %v; produced output at: %v", scheduledTime, createdTime, startedTime, producedOutputTime)
			t.Logf("This can happen if not all Kubernetes components are upgraded to the new Kubernetes Events API. Switching to legacy Events API and client-side timestamp measurement.")
			useNewEventsAPI.Store(false)
			if err := cluster.DeletePod(ctx, p); err != nil {
				return nil, fmt.Errorf("failed to delete pod: %w", err)
			}
			deleted = true
			return runPodAndGetMetrics(ctx, t, k8sCtx, cluster, benchmarkNS, iteration)
		}
	}
	if scheduledTime.IsZero() || createdTime.IsZero() || startedTime.IsZero() || producedOutputTime.IsZero() {
		return nil, fmt.Errorf("events missing; got scheduled: %v, created: %v, started: %v", scheduledTime, createdTime, startedTime)
	}

	t.Logf("Pod %v was scheduled at %v, created at %v, started at %v, produced output at: %v", p.Name, scheduledTime, createdTime, startedTime, producedOutputTime)
	metrics := &PodRunMetrics{
		SchedulingDuration:                 scheduledTime.Sub(createdAt),
		CreationDuration:                   createdTime.Sub(scheduledTime),
		StartDuration:                      startedTime.Sub(createdTime),
		TotalRuntimeInitializationDuration: producedOutputTime.Sub(scheduledTime),
	}
	if err := cluster.DeletePod(ctx, p); err != nil {
		return metrics, fmt.Errorf("failed to delete pod: %w", err)
	}
	deleted = true
	return metrics, nil
}
