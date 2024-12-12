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

// Package httpbench provides a library for benchmarking an HTTP server.
package httpbench

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InfiniteQPS is a stand-in value for "a lot of QPS".
// Running a benchmark round at this load level amounts to saturating
// the HTTP server with load on a single connection.
const InfiniteQPS = 1 << 16

const wrk2ImageAMD = k8s.ImageRepoPrefix + "benchmarks/wrk2_x86_64:latest"

// MetricType is a type of metric to report.
type MetricType int

// List of metric types.
const (
	Latency MetricType = iota
	RequestsPerSecond
	BytesPerSecond
)

// Round is a single round of benchmarking.
type Round struct {
	// NumThreads is the number of concurrent threads and connections to make.
	NumThreads int

	// TargetQPS is the aggregate load on the server that will be spread across
	// the `NumThreads` threads.
	TargetQPS int

	// Duration is the total duration of the round. It should be longer than 10s
	// as wrk2 uses the first 10 seconds as calibration period.
	Duration time.Duration

	// If set, only report the metric types listed here.
	OnlyReport []MetricType
}

// HTTPBenchmark helps manage an HTTP-based benchmark.
// A benchmark that wishes to run an HTTP-based benchmark should set up
// the HTTP server pod and a Kubernetes Service pointing at it, and this
// library takes care of the rest.
type HTTPBenchmark struct {
	// Name is the name of the benchmark. It is used as a prefix for all
	// benchstat output metrics.
	Name string

	// Cluster is the test cluster.
	Cluster *testcluster.TestCluster

	// Namespace is the benchmark namespace where pods are created.
	Namespace *testcluster.Namespace

	// Service is a Kubernetes service pointing to the HTTP server.
	Service *v13.Service

	// Port is the port that the HTTP server is bound to.
	Port int

	// Path is the HTTP path that the benchmark should use in its requests.
	// It should start by "/", e.g. "/index.html".
	Path string

	// Timeout is the maximum allowable duration of requests for Path.
	Timeout time.Duration

	// Rounds is the set of rounds to run the benchmark for. Must be non-empty.
	Rounds []Round

	// WantPercentiles is the list of percentiles to report.
	WantPercentiles []int
}

// Run runs the HTTP-based benchmark.
func (h *HTTPBenchmark) Run(ctx context.Context, t *testing.T) {
	t.Helper()
	serverWaitCtx, serverWaitCancel := context.WithTimeout(ctx, 10*time.Minute)
	if err := h.Cluster.WaitForServiceReady(serverWaitCtx, h.Service); err != nil {
		t.Fatalf("Failed to wait for service: %v", err)
	}
	ip := testcluster.GetIPFromService(h.Service)
	if ip == "" {
		t.Fatalf("did not get valid ip: %s", ip)
	}
	if err := h.waitForServer(serverWaitCtx, ip); err != nil {
		t.Fatalf("Failed to wait for server: %v", err)
	}
	serverWaitCancel()
	for _, round := range h.Rounds {
		qpsText := fmt.Sprintf("%d", round.TargetQPS)
		if round.TargetQPS == InfiniteQPS {
			qpsText = "max"
		}
		t.Run(fmt.Sprintf("%dthreads_%sqps", round.NumThreads, qpsText), func(t *testing.T) {
			h.runRound(ctx, t, round, ip)
		})
	}
}

// runRound runs a single round of an HTTP benchmark.
func (h *HTTPBenchmark) runRound(ctx context.Context, t *testing.T, round Round, ip string) {
	t.Helper()
	qpsText := fmt.Sprintf("%d", round.TargetQPS)
	if round.TargetQPS == InfiniteQPS {
		qpsText = "max"
	}
	name := fmt.Sprintf("wrk2-%dthreads-%sqps", round.NumThreads, qpsText)
	client := h.newWrk2Client(name, ip, round)
	client, err := h.Cluster.ConfigurePodForClientNodepool(ctx, client)
	if err != nil {
		t.Fatalf("failed to configure wrk2 pod for client nodepool: %v", err)
	}

	client, err = h.Cluster.CreatePod(ctx, client)
	if err != nil {
		t.Fatalf("failed to create wrk2 pod: %v", err)
	}
	defer h.Cluster.DeletePod(ctx, client)

	waitCtx, waitCancel := context.WithTimeout(ctx, round.Duration+2*time.Minute)
	err = h.Cluster.WaitForPodCompleted(waitCtx, client)
	waitCancel()
	if err != nil {
		t.Fatalf("failed to wait for wrk2 pod: %v", err)
	}

	rdr, err := h.Cluster.GetLogReader(ctx, client, v13.PodLogOptions{})
	if err != nil {
		t.Fatalf("failed to get log reader: %v", err)
	}

	out, err := io.ReadAll(rdr)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	numRequests, data, err := getMeasurements(string(out), round.OnlyReport, h.WantPercentiles)
	if err != nil {
		t.Fatalf("failed to get measurement: %v", err)
	}
	recorder, err := benchmetric.GetRecorder(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize benchmark recorder: %v", err)
	}
	if err := recorder.RecordIters(ctx, fmt.Sprintf("%s/%dThreads/%sQPS", strings.Title(h.Name), round.NumThreads, qpsText), numRequests, data...); err != nil {
		t.Fatalf("Failed to record benchmark data: %v", err)
	}
}

// newWrk2Client returns a new pod that benchmarks the given HTTP server.
func (h *HTTPBenchmark) newWrk2Client(name, ip string, round Round) *v13.Pod {
	cmd := []string{
		"wrk2",
		"--threads", fmt.Sprintf("%d", round.NumThreads), // Run N threads in parallel.
		"--connections", fmt.Sprintf("%d", round.NumThreads), // Each with 1 connection.
		"--rate", fmt.Sprintf("%d", round.TargetQPS), // Target QPS split across all threads.
		"--duration", fmt.Sprintf("%d", uint64(round.Duration.Seconds())),
		"--timeout", fmt.Sprintf("%d", uint64(h.Timeout.Seconds())),
		"--latency", // Print detailed latency statistics.
		fmt.Sprintf("http://%s:%d%s", ip, h.Port, h.Path),
	}
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: h.Namespace.Namespace,
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:    name,
					Image:   wrk2ImageAMD,
					Command: cmd,
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

// getWgetPod creates a wget spider pod that waits for timeout on IP/port and never fails.
func (h *HTTPBenchmark) getWgetPod(ip string) *v13.Pod {
	name := fmt.Sprintf("wget-%d", time.Now().UnixNano())
	// We don't use h.Path in the path here because the purpose of this pod is
	// only to verify that the server is up, not that the page at h.Path exists.
	cmd := fmt.Sprintf("wget --spider -T 10 http://%s:%d/", ip, h.Port)
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: h.Namespace.Namespace,
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:    name,
					Image:   "alpine",
					Command: []string{"/bin/sh", "-c", cmd},
					Resources: v13.ResourceRequirements{
						Requests: v13.ResourceList{
							v13.ResourceCPU: resource.MustParse("500m"),
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

// waitForServer waits for an HTTP server to start responding on the given
// IP and port.
func (h *HTTPBenchmark) waitForServer(ctx context.Context, ip string) error {
	lastPhase := v13.PodUnknown
	var lastLogs string
	for ctx.Err() == nil {
		wget, err := h.Cluster.ConfigurePodForClientNodepool(ctx, h.getWgetPod(ip))
		if err != nil {
			return fmt.Errorf("failed to configure wget pod for client nodepool: %w", err)
		}
		wget, err = h.Cluster.CreatePod(ctx, wget)
		if err != nil {
			return fmt.Errorf("failed to create wget pod: %w", err)
		}
		phase, waitErr := h.Cluster.WaitForPodTerminated(ctx, wget)
		if phase != v13.PodSucceeded {
			logs, err := h.Cluster.ReadPodLogs(ctx, wget)
			if err != nil {
				_ = h.Cluster.DeletePod(ctx, wget) // Best-effort delete.
				return fmt.Errorf("failed to read wget pod logs: %w", err)
			}
			lastLogs = logs
		}
		deleteErr := h.Cluster.DeletePod(ctx, wget)
		if waitErr != nil {
			return fmt.Errorf("failed to wait for wget pod: %w", waitErr)
		}
		if deleteErr != nil {
			return fmt.Errorf("failed to delete wget pod: %w", deleteErr)
		}
		if phase == v13.PodSucceeded {
			return nil
		}
	}
	return fmt.Errorf("wget pod still fails after context expiry (last phase: %v; last logs: %q)", lastPhase, lastLogs)
}

/*
Sample wrk2 output:

Running 30s test @ http://google.com
  2 threads and 2 connections
  Thread calibration: mean lat.: 25.351ms, rate sampling interval: 55ms
  Thread calibration: mean lat.: 26.040ms, rate sampling interval: 56ms
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    25.34ms    7.16ms 137.73ms   96.88%
    Req/Sec    19.75      6.40    53.00     86.63%
  Latency Distribution (HdrHistogram - Recorded Latency)
 50.000%   24.09ms
 75.000%   25.50ms
 90.000%   27.50ms
 99.000%   58.85ms
 99.900%  111.74ms
 99.990%  137.85ms
 99.999%  137.85ms
100.000%  137.85ms

  Detailed Percentile spectrum:
       Value   Percentile   TotalCount 1/(1-Percentile)

      20.783     0.000000            1         1.00
       [...]
     137.855     1.000000          800          inf
#[Mean    =       25.341, StdDeviation   =        7.155]
#[Max     =      137.728, Total count    =          800]
#[Buckets =           27, SubBuckets     =         2048]
----------------------------------------------------------
  1200 requests in 30.01s, 2.22MB read
Requests/sec:     39.99
Transfer/sec:     75.60KB
*/

var (
	wrk2TotalRequestsRe     = regexp.MustCompile(`^\s*([,\d]+) requests in .*$`)
	wrk2LatencyPercentileRE = regexp.MustCompile(`^\s*(\d+\.?\d+?)%\s+([,\d]+\.?\d+?\w+)\s*$`)
	wrk2ReqPerSecondRE      = regexp.MustCompile(`^Requests/sec:\s*([,\d]+\.?\d+?)\s*$`)
	wrk2TransferPerSecondRE = regexp.MustCompile(`^Transfer/sec:\s*([,\d]+\.?\d+?\w+)\s*$`)
)

// getMeasurements parses wrk2 output.
// It returns the number of requests that were made, and benchmark data.
func getMeasurements(data string, onlyReport []MetricType, wantPercentiles []int) (int, []benchmetric.MetricValue, error) {
	report := func(m MetricType) bool {
		if len(onlyReport) == 0 {
			return true
		}
		for _, typ := range onlyReport {
			if typ == m {
				return true
			}
		}
		return false
	}
	var metricValues []benchmetric.MetricValue
	totalRequests := 0
	totalRequestsFound := false
	for _, line := range strings.Split(data, "\n") {
		if match := wrk2TotalRequestsRe.FindStringSubmatch(line); match != nil {
			gotRequests, err := strconv.ParseInt(strings.ReplaceAll(match[1], ",", ""), 10, 64)
			if err != nil {
				return 0, nil, fmt.Errorf("failed to parse %q from line %q: %v", match[1], line, err)
			}
			if totalRequestsFound {
				return 0, nil, fmt.Errorf("found multiple lines matching 'total requests' regex: %d vs %d (%q)", totalRequests, gotRequests, line)
			}
			totalRequests = int(gotRequests)
			totalRequestsFound = true
			continue
		}
		if match := wrk2LatencyPercentileRE.FindStringSubmatch(line); match != nil {
			pctile, err := strconv.ParseFloat(match[1], 64)
			if err != nil {
				return 0, nil, fmt.Errorf("failed to parse %q from line %q as float: %v", match[1], line, err)
			}
			wantPctile := 0
			for _, want := range wantPercentiles {
				if want*1e3 == int(pctile*1e3) {
					wantPctile = want
					break
				}
			}
			if wantPctile == 0 {
				continue
			}
			latency, err := time.ParseDuration(strings.ReplaceAll(match[2], ",", ""))
			if err != nil {
				return 0, nil, fmt.Errorf("failed to parse %q from line %q as duration: %v", match[2], line, err)
			}
			if report(Latency) {
				metricValues = append(metricValues, benchmetric.SpecificDuration(latency, fmt.Sprintf("p%d", wantPctile)))
			}
			continue
		}
		if match := wrk2ReqPerSecondRE.FindStringSubmatch(line); match != nil {
			qps, err := strconv.ParseFloat(strings.ReplaceAll(match[1], ",", ""), 64)
			if err != nil {
				return 0, nil, fmt.Errorf("failed to parse %q from line %q as float: %v", match[1], line, err)
			}
			if report(RequestsPerSecond) {
				metricValues = append(metricValues, benchmetric.RequestsPerSecond(qps))
			}
			continue
		}
		if match := wrk2TransferPerSecondRE.FindStringSubmatch(line); match != nil {
			bps, err := parseTransfer(match[1])
			if err != nil {
				return 0, nil, fmt.Errorf("failed to parse %q from line %q: %v", match[1], line, err)
			}
			if report(BytesPerSecond) {
				metricValues = append(metricValues, benchmetric.BytesPerSecond(bps))
			}
			continue
		}
	}
	if !totalRequestsFound {
		return 0, nil, fmt.Errorf("could not find total requests in output: %q", data)
	}
	return totalRequests, metricValues, nil
}

// parseTransfer parses a string like "75.60KB" in the output above,
// and returns a bandwidth rate in bytes/sec.
func parseTransfer(s string) (float64, error) {
	s = strings.ReplaceAll(s, ",", "")
	var multiplier uint64
	var suffix string
	for unit, m := range map[string]uint64{
		"KB":  1000,
		"KiB": 1024,
		"MB":  1000 * 1000,
		"MiB": 1024 * 1024,
		"GB":  1000 * 1000 * 1000,
		"GiB": 1024 * 1024 * 1024,
		"TB":  1000 * 1000 * 1000 * 1000,
		"TiB": 1024 * 1024 * 1024 * 1024,
	} {
		if strings.HasSuffix(s, unit) {
			suffix = unit
			multiplier = m
			break
		}
	}
	if multiplier == 0 {
		if !strings.HasSuffix(s, "B") {
			return 0, fmt.Errorf("failed to parse %q: found no unit suffix", s)
		}
		// Otherwise, it's just bytes/sec.
		// But we can't put this in the for loop above, otherwise it would
		// match every suffix ("KB" ends in "B").
		suffix = "B"
		multiplier = 1
	}
	s = strings.TrimSuffix(s, suffix)
	floatPart, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse %q as float: %v", s, err)
	}
	return floatPart * float64(multiplier), nil
}
