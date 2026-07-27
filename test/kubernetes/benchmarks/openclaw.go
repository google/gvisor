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

// Package openclaw benchmarks the maximum pod density and amortized memory
// footprint of OpenClaw Node.js gateways running inside Kata microVM sandboxes
// (Cloud Hypervisor and Firecracker) on GKE.
//
// Methodology:
//
//   - Density & Health Monitoring: Target pods are launched sequentially on a single
//     dedicated test node. A client pod running on a separate client node polls the
//     new pod's readyz endpoint via HTTP, while continuously checking that all previously
//     started neighbor pods remain responsive (pings successful) and are in the 'Running'
//     phase (not evicted or terminated by GKE). A single failure terminates the scaling loop.
//
//   - Memory Footprint: A background unsandboxed helper container logs host /proc/meminfo
//     throughout the benchmark run. At any timestamp, host Memory Used is calculated as:
//     Memory Used = MemTotal - MemAvailable.
//
//     We isolate the marginal memory footprint of the sandboxes by taking the delta between
//     peak density (N pods) and baseline (0 pods):
//
//     Marginal Memory
//     = Memory Used (Peak) - Memory Used (Baseline)
//     = (MemTotal_Peak - MemAvailable_Peak) - (MemTotal_Baseline - MemAvailable_Baseline)
//
//     The footprint per pod is calculated as: Marginal Memory / SuccessCount.
package openclaw

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

const (
	// The container image used for the OpenClaw Node.js gateway targets.
	openclawImage = "ghcr.io/openclaw/openclaw:slim"
	// The target port exposed by the OpenClaw HTTP gateway.
	openclawPort = 18789
	// The authentication bearer token configured for the OpenClaw readyz endpoints.
	gatewayToken = "benchmark-token"
	// The GKE Headless Service name used for target pod DNS routing.
	serviceName = "openclaw-svc"
	// The duration the client pinger sleeps between consecutive HTTP requests.
	clientPingIntervalSec = 0.5
	// The maximum duration we wait for a target pod to schedule and successfully respond.
	podBootTimeout = 60 * time.Second
)

// Default to 256 because max number of pods per node allowed by GKE is 256.
// https://docs.cloud.google.com/kubernetes-engine/docs/how-to/flexible-pod-cidr#max_pods_default
var maxPodsTarget = flag.Int("openclaw-benchmark-max-pods", 256, "Target number of pods for MaxPods benchmark (acts as a cap)")

// Number of pods to provision and verify concurrently in each scaling iteration.
// Batching significantly speeds up execution on high-capacity clusters.
var batchSize = flag.Int("openclaw-benchmark-batch-size", 1, "Number of target pods to launch in each batch")

// Resource requirements for the target pods. Parameterizing these values allows
// dynamically testing node capacity under different VM sizing bounds and CPU/Memory constraints.
var targetCPURequest = flag.String("openclaw-target-cpu-request", "250m", "CPU request for target openclaw pods (e.g. 250m, 1)")
var targetMemRequest = flag.String("openclaw-target-mem-request", "256Mi", "Memory request for target openclaw pods (e.g. 256Mi, 1Gi)")
var targetCPULimit = flag.String("openclaw-target-cpu-limit", "4", "CPU limit for target openclaw pods")
var targetMemLimit = flag.String("openclaw-target-mem-limit", "16Gi", "Memory limit for target openclaw pods")
var clientPingTimeoutSec = flag.Int("openclaw-client-ping-timeout-sec", 10, "The client pinger's curl timeout limit for individual readyz HTTP requests")

// RunOpenClaw benchmarks OpenClaw.
func RunOpenClaw(ctx context.Context, t *testing.T, _ k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)

	// Create ConfigMap for openclaw.json
	configMap := &v13.ConfigMap{
		ObjectMeta: v1.ObjectMeta{
			Name:      "openclaw-config",
			Namespace: benchmarkNS.Namespace,
		},
		Data: map[string]string{
			"openclaw.json": `{
				"gateway": {
					"mode": "local",
					"port": 18789,
					"bind": "lan",
					"auth": {
						"mode": "token",
						"token": "` + gatewayToken + `"
					}
				}
			}`,
		},
	}
	err := cluster.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		_, err := client.CoreV1().ConfigMaps(benchmarkNS.Namespace).Create(ctx, configMap, v1.CreateOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("Failed to create ConfigMap: %v", err)
	}

	// Create Secret for gateway token
	secret := &v13.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "openclaw-secrets",
			Namespace: benchmarkNS.Namespace,
		},
		StringData: map[string]string{
			"OPENCLAW_GATEWAY_TOKEN": gatewayToken,
		},
	}
	err = cluster.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		_, err := client.CoreV1().Secrets(benchmarkNS.Namespace).Create(ctx, secret, v1.CreateOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("Failed to create Secret: %v", err)
	}

	// Create Headless Service for DNS resolution of pods
	service := newOpenClawService(benchmarkNS, serviceName, true)
	service, err = cluster.CreateService(ctx, service)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer cluster.DeleteService(ctx, service)

	t.Run("MaxPods", func(t *testing.T) {
		measureMaxPods(ctx, t, cluster, benchmarkNS)
	})
}

// measureMaxPods orchestrates the OpenClaw pod density test.
func measureMaxPods(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, ns *testcluster.Namespace) {
	maxPodsCap := *maxPodsTarget
	t.Logf("Testing max pods density (cap: %d)...", maxPodsCap)

	dnsNames, podNames := generatePodNames(ns, maxPodsCap)

	// 1. Start the memory monitor pod first to log host memory dynamically.
	memMonitor, err := startMemoryMonitor(ctx, cluster, ns.Namespace)
	if err != nil {
		t.Fatalf("Failed to start memory monitor pod: %v", err)
	}
	defer cluster.DeletePod(ctx, memMonitor)

	// 2. Setup the client pinger pod for health checking.
	clientPod, err := createClientPod(ctx, t, cluster, ns, dnsNames)
	if err != nil {
		t.Fatalf("Failed to setup client pod: %v", err)
	}
	defer cluster.DeletePod(ctx, clientPod)

	startSec := time.Now().Unix()

	// 3. Main loop: launch and verify pods sequentially.
	successCount, pods, stopReason, lastGoodMem := launchAndVerifyTestPods(ctx, t, cluster, ns, podNames, clientPod, memMonitor, startSec)

	defer func() {
		t.Logf("Cleaning up %d OpenClaw pods...", len(pods))
		for _, p := range pods {
			if p != nil {
				cluster.DeletePod(ctx, p)
			}
		}
	}()

	// 4. Verify they all ended up on the same test node.
	verifySameNode(ctx, t, cluster, pods)

	// 5. Measure node memory usage, record to BigQuery, and print summary.
	recordAndPrintResults(ctx, t, cluster, successCount, lastGoodMem, stopReason)
}

// generatePodNames creates DNS and pod names for all possible openclaw pods.
func generatePodNames(ns *testcluster.Namespace, cap int) (dnsNames []string, podNames []string) {
	dnsNames = make([]string, cap)
	podNames = make([]string, cap)
	for i := 0; i < cap; i++ {
		podName := fmt.Sprintf("openclaw-maxpods-%d", i)
		podNames[i] = podName
		dnsNames[i] = fmt.Sprintf("%s.%s.%s.svc.cluster.local", podName, serviceName, ns.Namespace)
	}
	return
}

// createClientPod creates and configures the client pod, and waits for it to start running.
//
// The client pod script runs a persistent background loop for each DNS name. Once it
// connects successfully, it logs "SUCCESS". If a previously healthy pod fails to respond
// to a readyz check, it immediately logs "DEAD" and exits.
func createClientPod(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, ns *testcluster.Namespace, dnsNames []string) (*v13.Pod, error) {
	clientCmd := `
echo "CLIENT_READY"
i=0
for dns in $DNS_NAMES; do
	(
		active=0
		idx=$i
		err_file="/tmp/curl_err_${idx}"
		while true; do
			code=$(curl -s -S -o /dev/null -w "%{http_code}" -m $PING_TIMEOUT -H "Authorization: Bearer $GATEWAY_TOKEN" http://${dns}:${OPENCLAW_PORT}/readyz 2> $err_file)
			curl_status=$?
			if [ "$code" = "200" ] && [ $curl_status -eq 0 ]; then
				if [ $active -eq 0 ]; then
					end=$(($(date +%s) * 1000000000))
					echo "SUCCESS ${idx}: $end ($(date -u '+%Y-%m-%d %H:%M:%S'))"
					active=1
				fi
			else
				if [ $active -eq 1 ]; then
					dead_time=$(($(date +%s) * 1000000000))
					curl_err=$(cat $err_file 2>/dev/null || true)
					curl_err=$(echo $curl_err | tr '\n' ' ')
					echo "DEAD ${idx}: $dead_time (status=$code, curl=$curl_status, err=\"$curl_err\") ($(date -u '+%Y-%m-%d %H:%M:%S'))"
					rm -f $err_file
					exit 1
				fi
			fi
			sleep $PING_INTERVAL
		done
	) &
	i=$((i + 1))
done
wait
`

	clientPodName := "client-poll-maxpods"
	clientPod := &v13.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      clientPodName,
			Namespace: ns.Namespace,
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:    "client",
					Image:   "curlimages/curl:latest",
					Command: []string{"/bin/sh", "-c", clientCmd},
					Env: []v13.EnvVar{
						{Name: "DNS_NAMES", Value: strings.Join(dnsNames, " ")},
						{Name: "PING_TIMEOUT", Value: strconv.Itoa(*clientPingTimeoutSec)},
						{Name: "GATEWAY_TOKEN", Value: gatewayToken},
						{Name: "OPENCLAW_PORT", Value: strconv.Itoa(openclawPort)},
						{Name: "PING_INTERVAL", Value: fmt.Sprintf("%.1f", clientPingIntervalSec)},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
	clientPod, err := cluster.ConfigurePodForClientNodepool(ctx, clientPod)
	if err != nil {
		return nil, fmt.Errorf("failed to configure client pod: %w", err)
	}

	clientPod, err = cluster.CreatePod(ctx, clientPod)
	if err != nil {
		return nil, fmt.Errorf("failed to create client pod: %w", err)
	}

	// Wait for client pod to be running
	if err := cluster.WaitForPodRunning(ctx, clientPod); err != nil {
		cluster.DeletePod(ctx, clientPod)
		return nil, fmt.Errorf("client pod did not start running: %w", err)
	}

	return clientPod, nil
}

// launchAndVerifyTestPods runs the sequential launch loop, checking for scheduling issues
// and ensuring previously started pods remain responsive.
//
// To ensure density stability, the harness:
// 1. Checks GKE API once per second to verify all previous pods are in 'Running' phase and not Evicted.
// 2. Scans client logs to ensure no previous pod has reported "DEAD" (unresponsive due to CPU contention).
// 3. If any previous pod fails, we immediately stop the launch loop and record the current success count.
func launchAndVerifyTestPods(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, ns *testcluster.Namespace, podNames []string, clientPod *v13.Pod, memMonitor *v13.Pod, startSec int64) (successCount int, pods []*v13.Pod, stopReason string, lastGoodMem int64) {
	cap := len(podNames)
	stopReason = "reached-cap"
	bSize := *batchSize
	if bSize < 1 {
		bSize = 1
	}

	for i := 0; i < cap; i += bSize {
		batchEnd := i + bSize
		if batchEnd > cap {
			batchEnd = cap
		}

		t.Logf("Launching batch of pods from %d to %d...", i, batchEnd-1)
		createdAt := time.Now()

		// Launch pods in this batch
		var batchPods []*v13.Pod
		var launchErr error
		for j := i; j < batchEnd; j++ {
			pod, err := launchTestPod(ctx, cluster, ns, podNames[j])
			if err != nil {
				t.Logf("Failed to launch pod %s: %v", podNames[j], err)
				launchErr = err
				stopReason = fmt.Sprintf("launch-failed-%s", podNames[j])
				break
			}
			batchPods = append(batchPods, pod)
			pods = append(pods, pod)
		}
		if launchErr != nil {
			break
		}

		// Wait for scheduling of all pods in this batch
		var schedErr error
		var schedFailed bool
		var scheduledCount int
		for _, pod := range batchPods {
			sReason, sErr := waitForPodScheduling(ctx, t, cluster, pod)
			if sErr != nil || sReason != "" {
				stopReason = sReason
				schedErr = sErr
				schedFailed = true
				break
			}
			scheduledCount++
		}

		// Verify health of all pods that scheduled successfully
		actualBatchEnd := i + scheduledCount
		if scheduledCount > 0 {
			stableDensity, hReason, hErr := verifyBatchHealth(ctx, t, cluster, clientPod, pods, podNames, i, actualBatchEnd, createdAt)
			if hErr != nil {
				if stableDensity > successCount {
					successCount = stableDensity
				}
				stopReason = hReason
				break
			}
			successCount = stableDensity
		}

		if schedErr != nil || schedFailed {
			break
		}

		t.Logf("Batch %d to %d is healthy. Total healthy pods: %d", i, batchEnd-1, successCount)

		// Measure memory progress while the node is healthy
		nowSec := time.Now().Unix()
		mem, err := getMarginalMemory(ctx, cluster, memMonitor, startSec, nowSec)
		if err == nil {
			lastGoodMem = mem
			t.Logf("Marginal memory at density %d: %d bytes (%.3f GiB)", successCount, mem, float64(mem)/(1024*1024*1024))
		} else {
			t.Logf("Warning: Failed to get memory progress at density %d: %v", successCount, err)
		}

		// Settle time
		time.Sleep(1 * time.Second)
	}

	return successCount, pods, stopReason, lastGoodMem
}

// launchTestPod configures and creates a new test pod target.
func launchTestPod(ctx context.Context, cluster *testcluster.TestCluster, ns *testcluster.Namespace, podName string) (*v13.Pod, error) {
	pod := newOpenClawPod(ns, podName, openclawImage, podName, serviceName)
	pod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to configure pod: %w", err)
	}
	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to create pod: %w", err)
	}
	return pod, nil
}

// waitForPodScheduling checks GKE API until NodeName is assigned or detects Unschedulable status.
func waitForPodScheduling(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, pod *v13.Pod) (stopReason string, err error) {
	podName := pod.Name
	startWait := time.Now()
	for time.Since(startWait) < 10*time.Second {
		p, err := cluster.GetPod(ctx, pod)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		isUnschedulable := false
		var unschedulableMessage string
		for _, cond := range p.Status.Conditions {
			if cond.Type == v13.PodScheduled && cond.Status == v13.ConditionFalse && cond.Reason == v13.PodReasonUnschedulable {
				isUnschedulable = true
				unschedulableMessage = cond.Message
				break
			}
		}
		if isUnschedulable {
			t.Logf("Pod %s is unschedulable: %s", podName, unschedulableMessage)

			return fmt.Sprintf("unschedulable-%s: %s", podName, unschedulableMessage), nil
		}
		if p.Spec.NodeName != "" {
			return "", nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("Pod %s failed to schedule (or was unschedulable)", podName)
	return fmt.Sprintf("schedule-timeout-%s", podName), fmt.Errorf("scheduling timeout")
}

// verifyBatchHealth polls the GKE API and client logs until all current batch pods respond successfully.
// If any pod experiences an involuntary disruption (eviction, crash, deletion) or pinger failure,
// it returns the last known stable density, a stop reason, and a non-nil error to terminate the loop.
//
// Returns:
//   - stableDensity (int): The number of pods verified to be running stably.
//   - stopReason (string): Text describing the condition that stopped the benchmark.
//   - err (error): Non-nil error if the benchmark must stop due to a failure.
func verifyBatchHealth(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, clientPod *v13.Pod, pods []*v13.Pod, podNames []string, batchStart, batchEnd int, createdAt time.Time) (int, string, error) {
	lastK8sCheck := time.Now()
	hasReachedRunning := make(map[string]bool)

	for time.Since(createdAt) < podBootTimeout {
		// 1. Check GKE API status once per second
		if time.Since(lastK8sCheck) > 1*time.Second {
			stableDensity, stopReason, err := checkTargetPodsAPI(ctx, t, cluster, clientPod, pods, podNames, batchStart, batchEnd, hasReachedRunning)
			if err != nil {
				return stableDensity, stopReason, err
			}
			lastK8sCheck = time.Now()
		}

		// 2. Read client logs
		logs, err := cluster.ReadPodLogs(ctx, clientPod)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		// 3. Scan client logs for DEAD/SUCCESS pinger markers
		stableDensity, stopReason, err := checkClientLogs(t, logs, batchStart, batchEnd)
		if err != nil {
			return stableDensity, stopReason, err
		}
		if stopReason == "all-success" {
			return batchEnd, "", nil
		}

		time.Sleep(200 * time.Millisecond)
	}

	t.Logf("Stopped sequence at batch %d-%d due to boot timeout.", batchStart, batchEnd-1)
	logs, logErr := cluster.ReadPodLogs(ctx, clientPod)
	if logErr == nil {
		t.Logf("Client logs on failure:\n%s", logs)
	}
	res, _ := parseClientLogs(logs)
	return res.uniqueSuccesses, fmt.Sprintf("health-timeout-batch-%d-%d", batchStart, batchEnd-1), fmt.Errorf("health check timeout")
}

// checkTargetPodsAPI queries the GKE API for target pods to detect lifecycle failures:
// - Pod disappearance from GKE (NotFound)
// - Pod deletion in progress (DeletionTimestamp)
// - Previously running pods falling out of PodRunning state
// - New pods crashing during boot (PodFailed)
// - Container process terminations (Terminated state)
//
// Returns:
//   - stableDensity (int): Last known stable density if a failure is detected, 0 otherwise.
//   - stopReason (string): Descriptive failure reason if stopped, empty otherwise.
//   - err (error): Non-nil if a lifecycle failure was detected.
func checkTargetPodsAPI(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, clientPod *v13.Pod, pods []*v13.Pod, podNames []string, batchStart, batchEnd int, hasReachedRunning map[string]bool) (int, string, error) {
	if len(pods) == 0 || pods[0] == nil {
		return 0, "", nil
	}
	podList, err := cluster.ListPods(ctx, pods[0].Namespace)
	if err != nil {
		t.Logf("Warning: ListPods failed during health check: %v", err)
		return 0, "", nil
	}
	podMap := make(map[string]*v13.Pod, len(podList.Items))
	for i := range podList.Items {
		podMap[podList.Items[i].Name] = &podList.Items[i]
	}

	for j := 0; j < batchEnd; j++ {
		p, ok := podMap[podNames[j]]
		if !ok {
			// Failure 1: Pod has been completely deleted and removed from the API.
			t.Logf("Pod %d (%s) disappeared from GKE", j, podNames[j])
			uniqueSuccesses := countUniqueSuccesses(ctx, cluster, clientPod)
			stableDensity := uniqueSuccesses
			if j < uniqueSuccesses {
				stableDensity = uniqueSuccesses - 1
			}
			return stableDensity, fmt.Sprintf("peer-not-found-%s", podNames[j]), fmt.Errorf("pod disappeared from GKE")
		}

		// Failure 2: Pod is undergoing graceful shutdown (DeletionTimestamp is set).
		if p.DeletionTimestamp != nil {
			t.Logf("Pod %d (%s) is being deleted (DeletionTimestamp: %v)", j, podNames[j], p.DeletionTimestamp)
			uniqueSuccesses := countUniqueSuccesses(ctx, cluster, clientPod)
			stableDensity := uniqueSuccesses
			if j < uniqueSuccesses {
				stableDensity = uniqueSuccesses - 1
			}
			return stableDensity, fmt.Sprintf("peer-deleted-%s", podNames[j]), fmt.Errorf("pod is being deleted")
		}

		isPrevious := j < batchStart
		// Enforce PodRunning dynamically for all previous pods, and any current-batch pods that have already reached Running state.
		if isPrevious || hasReachedRunning[p.Name] {
			// Failure 3: Pod fell out of Running phase (e.g. rescheduling or eviction).
			if p.Status.Phase != v13.PodRunning {
				t.Logf("Pod %d (%s) fell out of Running phase (Phase: %s)", j, podNames[j], p.Status.Phase)
				uniqueSuccesses := countUniqueSuccesses(ctx, cluster, clientPod)
				stableDensity := uniqueSuccesses
				if j < uniqueSuccesses {
					stableDensity = uniqueSuccesses - 1
				}
				return stableDensity, fmt.Sprintf("peer-unhealthy-%s", podNames[j]), fmt.Errorf("pod fell out of Running phase")
			}
		} else {
			// Lock in the Running status for current-batch pods once they transition
			if p.Status.Phase == v13.PodRunning {
				hasReachedRunning[p.Name] = true
			} else if p.Status.Phase == v13.PodFailed {
				// Failure 4: Newly launched pod crashed during startup.
				t.Logf("Current batch pod %d (%s) failed during startup (Phase: %s)", j, podNames[j], p.Status.Phase)
				uniqueSuccesses := countUniqueSuccesses(ctx, cluster, clientPod)
				stableDensity := uniqueSuccesses
				if j < uniqueSuccesses {
					stableDensity = uniqueSuccesses - 1
				}
				return stableDensity, fmt.Sprintf("peer-failed-%s", podNames[j]), fmt.Errorf("pod failed during startup")
			}
		}

		// Failure 5: Individual container process exited (VMM or application crash).
		for _, cStatus := range p.Status.ContainerStatuses {
			if cStatus.State.Terminated != nil {
				exitCode := cStatus.State.Terminated.ExitCode
				t.Logf("Pod %d (%s) container %s terminated: ExitCode=%d, Reason=%s, Message=%s", j, podNames[j], cStatus.Name, exitCode, cStatus.State.Terminated.Reason, cStatus.State.Terminated.Message)
				uniqueSuccesses := countUniqueSuccesses(ctx, cluster, clientPod)
				stableDensity := uniqueSuccesses
				if j < uniqueSuccesses {
					stableDensity = uniqueSuccesses - 1
				}
				return stableDensity, fmt.Sprintf("container-crashed-%s", podNames[j]), fmt.Errorf("container terminated unexpectedly")
			}
		}
	}
	return 0, "", nil
}

type clientLogParseResult struct {
	failedPodIndex  int
	failureDetail   string
	uniqueSuccesses int
}

// parseClientLogs scans client logs to detect the first DEAD event and extract details,
// while also counting unique SUCCESS events before that failure.
func parseClientLogs(logs string) (clientLogParseResult, error) {
	lines := strings.Split(logs, "\n")
	successes := make(map[int]bool)
	var res clientLogParseResult
	res.failedPodIndex = -1

	for _, line := range lines {
		if strings.HasPrefix(line, "SUCCESS ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				idxStr := strings.TrimSuffix(parts[1], ":")
				idx, err := strconv.Atoi(idxStr)
				if err == nil {
					successes[idx] = true
				}
			}
		} else if strings.HasPrefix(line, "DEAD ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				idxStr := strings.TrimSuffix(parts[1], ":")
				idx, err := strconv.Atoi(idxStr)
				if err == nil {
					res.failedPodIndex = idx

					// Extract details between parentheses
					header := fmt.Sprintf("DEAD %d:", idx)
					idxOfHeader := strings.Index(line, header)
					if idxOfHeader != -1 {
						detailPart := line[idxOfHeader+len(header):]
						startIdx := strings.Index(detailPart, "(")
						if startIdx != -1 {
							openParens := 0
							for i := startIdx; i < len(detailPart); i++ {
								if detailPart[i] == '(' {
									openParens++
								} else if detailPart[i] == ')' {
									openParens--
									if openParens == 0 {
										res.failureDetail = detailPart[startIdx+1 : i]
										break
									}
								}
							}
						}
					}

					res.uniqueSuccesses = len(successes)
					return res, nil
				}
			}
		}
	}
	res.uniqueSuccesses = len(successes)
	return res, fmt.Errorf("no failure detected")
}

func countUniqueSuccesses(ctx context.Context, cluster *testcluster.TestCluster, clientPod *v13.Pod) int {
	logs, err := cluster.ReadPodLogs(ctx, clientPod)
	if err != nil {
		return 0
	}
	res, _ := parseClientLogs(logs)
	return res.uniqueSuccesses
}

// checkClientLogs scans client pinger logs for:
// - DEAD pinger reports (indicating readyz HTTP timeout or guest kernel panic)
// - Boot success markers (SUCCESS) for all pods in the current batch
//
// Returns:
//   - stableDensity (int): Last known stable density if a failure is detected,
//     or batchEnd if all pods in the batch succeeded.
//   - stopReason (string): "all-success" if all batch pods are verified healthy,
//     or a failure description if a pod reported DEAD.
//   - err (error): Non-nil if a pod failure (DEAD) is found.
func checkClientLogs(t *testing.T, logs string, batchStart, batchEnd int) (int, string, error) {
	res, err := parseClientLogs(logs)
	if err == nil {
		t.Logf("Pod %d reported DEAD in client logs: %s", res.failedPodIndex, res.failureDetail)
		stableDensity := res.uniqueSuccesses
		if res.failedPodIndex < res.uniqueSuccesses {
			stableDensity = res.uniqueSuccesses - 1
		}
		return stableDensity, fmt.Sprintf("peer-died-%d (%s)", res.failedPodIndex, res.failureDetail), fmt.Errorf("pod died")
	}

	// Verify all pods in the current batch have successfully booted
	allSuccess := true
	for j := batchStart; j < batchEnd; j++ {
		successPattern := fmt.Sprintf("SUCCESS %d:", j)
		if !strings.Contains(logs, successPattern) {
			allSuccess = false
			break
		}
	}
	if allSuccess {
		return batchEnd, "all-success", nil
	}

	return res.uniqueSuccesses, "", nil
}

// verifySameNode logs all nodes where the pods were scheduled and issues a warning
// if they ended up on multiple nodes.
func verifySameNode(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, pods []*v13.Pod) {
	nodeNames := make(map[string]struct{})
	if len(pods) == 0 || pods[0] == nil {
		return
	}
	podList, err := cluster.ListPods(ctx, pods[0].Namespace)
	if err != nil {
		t.Logf("Warning: ListPods failed in verifySameNode: %v", err)
		return
	}
	for _, p := range podList.Items {
		if p.Spec.NodeName != "" && strings.HasPrefix(p.Name, "openclaw-maxpods-") {
			nodeNames[p.Spec.NodeName] = struct{}{}
		}
	}
	t.Logf("Pods scheduled on nodes: %v", nodeNames)
	if len(nodeNames) > 1 {
		t.Errorf("WARNING: Pods are scheduled on multiple nodes: %v, want 1 node", nodeNames)
	}
}

// recordAndPrintResults calculates the true marginal memory usage on the host node,
// records results (density and memory) to BigQuery, and prints the BENCHMARK SUMMARY.
//
// Memory calculation: We read the logs of the background mem-monitor pod. We extract
// the MemTotal and MemAvailable values at startSec and endSec, and calculate the delta:
// Marginal Memory = (MemTotal_Peak - MemAvailable_Peak) - (MemTotal_Baseline - MemAvailable_Baseline)
// This is recorded as the true marginal memory footprint consumed by the sandboxes.
func recordAndPrintResults(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, successCount int, marginalMem int64, stopReason string) {
	recorder, err := benchmetric.GetRecorder(ctx)
	if err != nil {
		t.Fatalf("Failed to get recorder: %v", err)
	}

	// Record metrics: Max Density (success count) to BigQuery.
	err = recorder.Record(ctx, "OpenClawMaxDensity",
		benchmetric.Count(uint64(successCount), "max-healthy-pods"),
	)
	if err != nil {
		t.Fatalf("Failed to record metrics: %v", err)
	}

	if successCount > 0 && marginalMem > 0 {
		avgMem := float64(marginalMem) / float64(successCount)

		t.Logf("Marginal Memory Used:      %d bytes (%.3f GiB)", marginalMem, float64(marginalMem)/(1024*1024*1024))
		t.Logf("Amortized Marginal Memory per pod: %.0f bytes (%.3f GiB)", avgMem, avgMem/(1024*1024*1024))

		// Record memory metrics to BigQuery.
		// Metric name is 'marginal-memory-B' and 'marginal-memory-per-pod-B'
		err = recorder.Record(ctx, "OpenClawMaxDensityMem",
			benchmetric.SpecificBytes(float64(marginalMem), "marginal-memory"),
			benchmetric.SpecificBytes(avgMem, "marginal-memory-per-pod"),
		)
		if err != nil {
			t.Fatalf("Failed to record memory metrics: %v", err)
		}
	}

	// Print nicely formatted summary
	t.Logf("==================================================")
	t.Logf("  BENCHMARK SUMMARY")
	t.Logf("==================================================")
	logNodeAllocatableResources(ctx, t, cluster)
	t.Logf("  Max Density:            %d pods", successCount)
	t.Logf("  Stop Reason:            %s", stopReason)
	if successCount > 0 {
		if marginalMem > 0 {
			avgMem := float64(marginalMem) / float64(successCount)
			t.Logf("  Marginal Memory Used:        %d bytes (%.3f GiB)", marginalMem, float64(marginalMem)/(1024*1024*1024))
			t.Logf("  Amortized Marginal Memory:   %.0f bytes (%.3f GiB)", avgMem, avgMem/(1024*1024*1024))
		} else {
			t.Logf("  Memory Usage:            N/A (metrics missing)")
		}
	}
	t.Logf("==================================================")
}

// startMemoryMonitor provisions a persistent unsandboxed pod on the test nodepool
// to periodically log host node memory statistics from /proc/meminfo.
func startMemoryMonitor(ctx context.Context, cluster *testcluster.TestCluster, namespace string) (*v13.Pod, error) {
	pod := &v13.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      "mem-monitor",
			Namespace: namespace,
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:    "monitor",
					Image:   "alpine:latest",
					Command: []string{"/bin/sh", "-c", "while true; do echo \"$(date +%s):$(grep MemTotal /proc/meminfo | awk '{print $2}'):$(grep MemAvailable /proc/meminfo | awk '{print $2}')\"; sleep 1; done"},
					Resources: v13.ResourceRequirements{
						Requests: v13.ResourceList{
							v13.ResourceCPU:    resource.MustParse("10m"),
							v13.ResourceMemory: resource.MustParse("32Mi"),
						},
						Limits: v13.ResourceList{
							v13.ResourceCPU:    resource.MustParse("100m"),
							v13.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
	pod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to configure monitor pod: %w", err)
	}
	pod.Spec.RuntimeClassName = nil // Run unsandboxed (runc) to read host /proc/meminfo
	// Tolerate gVisor node taint if running on a gVisor cluster.
	pod.Spec.Tolerations = append(pod.Spec.Tolerations, v13.Toleration{
		Key:      "sandbox.gke.io/runtime",
		Operator: v13.TolerationOpEqual,
		Value:    "gvisor",
		Effect:   v13.TaintEffectNoSchedule,
	})

	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor pod: %w", err)
	}

	if err := cluster.WaitForPodRunning(ctx, pod); err != nil {
		cluster.DeletePod(ctx, pod)
		return nil, fmt.Errorf("monitor pod failed to start running: %w", err)
	}

	return pod, nil
}

// getMarginalMemory reads the logs of the background monitor pod, extracts the
// MemAvailable values at startSec and endSec, and calculates the delta in bytes.
func getMarginalMemory(ctx context.Context, cluster *testcluster.TestCluster, monitorPod *v13.Pod, startSec, endSec int64) (int64, error) {
	logs, err := cluster.ReadPodLogs(ctx, monitorPod)
	if err != nil {
		return 0, err
	}

	var startAvail, endAvail int64
	var startFound, endFound bool

	// Parse log lines: "timestamp:total:available"
	for _, line := range strings.Split(logs, "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		ts, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}
		avail, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			continue
		}

		// Capture the first available sample at or after startSec
		if ts >= startSec && !startFound {
			startAvail = avail
			startFound = true
		}
		// Capture the last available sample at or before endSec
		if ts <= endSec {
			endAvail = avail
			endFound = true
		}
	}

	if !startFound || !endFound {
		return 0, fmt.Errorf("failed to find start or end memory samples in monitor logs")
	}

	// Return the delta in bytes (meminfo values are in KB)
	usedKb := startAvail - endAvail
	if usedKb < 0 {
		usedKb = 0 // Guard against noise
	}
	return usedKb * 1024, nil
}

func newOpenClawPod(namespace *testcluster.Namespace, name, image, hostname, subdomain string) *v13.Pod {
	pod := &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace.Namespace,
			Labels:    map[string]string{"app": "openclaw-benchmark"},
		},
		Spec: v13.PodSpec{
			Hostname:  hostname,
			Subdomain: subdomain,
			Containers: []v13.Container{
				{
					Name:    "gateway",
					Image:   image,
					Command: []string{"node", "/app/dist/index.js", "gateway", "run"},
					Ports: []v13.ContainerPort{
						{
							Name:          "gateway",
							ContainerPort: openclawPort,
						},
					},
					Env: []v13.EnvVar{
						{
							Name:  "HOME",
							Value: "/home/node",
						},
						{
							Name:  "OPENCLAW_CONFIG_DIR",
							Value: "/home/node/.openclaw",
						},
						{
							Name:  "NODE_ENV",
							Value: "production",
						},
						{
							Name: "OPENCLAW_GATEWAY_TOKEN",
							ValueFrom: &v13.EnvVarSource{
								SecretKeyRef: &v13.SecretKeySelector{
									LocalObjectReference: v13.LocalObjectReference{
										Name: "openclaw-secrets",
									},
									Key: "OPENCLAW_GATEWAY_TOKEN",
								},
							},
						},
					},
					VolumeMounts: []v13.VolumeMount{
						{
							Name:      "config-volume",
							MountPath: "/home/node/.openclaw/openclaw.json",
							SubPath:   "openclaw.json",
						},
						{
							Name:      "tmp-volume",
							MountPath: "/tmp",
						},
					},
					Resources: v13.ResourceRequirements{
						Requests: v13.ResourceList{
							v13.ResourceCPU:    resource.MustParse(*targetCPURequest),
							v13.ResourceMemory: resource.MustParse(*targetMemRequest),
						},
						Limits: v13.ResourceList{
							v13.ResourceCPU:    resource.MustParse(*targetCPULimit),
							v13.ResourceMemory: resource.MustParse(*targetMemLimit),
						},
					},
				},
			},
			Volumes: []v13.Volume{
				{
					Name: "config-volume",
					VolumeSource: v13.VolumeSource{
						ConfigMap: &v13.ConfigMapVolumeSource{
							LocalObjectReference: v13.LocalObjectReference{
								Name: "openclaw-config",
							},
						},
					},
				},
				{
					Name: "tmp-volume",
					VolumeSource: v13.VolumeSource{
						EmptyDir: &v13.EmptyDirVolumeSource{},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
	return pod
}

func newOpenClawService(namespace *testcluster.Namespace, name string, headless bool) *v13.Service {
	spec := v13.ServiceSpec{
		Selector: map[string]string{"app": "openclaw-benchmark"},
		Ports: []v13.ServicePort{
			{
				Name:       "gateway",
				Protocol:   v13.ProtocolTCP,
				Port:       openclawPort,
				TargetPort: intstr.FromInt(openclawPort),
			},
		},
	}
	if headless {
		spec.ClusterIP = "None"
	}
	return namespace.GetService(name, spec)
}

// logNodeAllocatableResources queries and logs the test node's allocatable capacity and running pods.
func logNodeAllocatableResources(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster) {
	err := cluster.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		nodes, err := client.CoreV1().Nodes().List(ctx, v1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", testcluster.NodePoolTypeKey, testcluster.TestRuntimeNodepoolName),
		})
		if err != nil {
			return err
		}
		if len(nodes.Items) == 0 {
			return fmt.Errorf("no nodes found in test nodepool")
		}
		node := nodes.Items[0]

		cpu := node.Status.Allocatable[v13.ResourceCPU]
		mem := node.Status.Allocatable[v13.ResourceMemory]
		pods := node.Status.Allocatable[v13.ResourcePods]

		t.Logf("  Node Allocatable:")
		t.Logf("    CPU:     %s", cpu.String())
		t.Logf("    Memory:  %s", mem.String())
		t.Logf("    Pods:    %s", pods.String())

		return nil
	})
	if err != nil {
		t.Logf("  Warning: Could not determine Node Allocatable resources: %v", err)
	}
}
