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

// Package redis holds the redis test where the runtime under test runs a redis server and the
// native runtime runs a client making requests against it.
package redis

import (
	"context"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	redisPort                    = 6379
	defaultRequestsPerConnection = 50000

	redisServerLabelKey   = "app.kubernetes.io/name"
	redisServerLabelValue = "redis-server"
	redisVolumeName       = "redis-data"
	redisDataDirectory    = "/redis-data"
	redisImageAMD         = k8s.ImageRepoPrefix + "benchmarks/redis_x86_64:latest"
	redisImageARM         = k8s.ImageRepoPrefix + "benchmarks/redis_aarch64:latest"
)

var (
	numConnections     = []int{1, 4, 32}
	latencyPercentiles = []int{50, 95, 99}
	operations         = []string{"GET", "MSET", "LRANGE_500"}
)

// BenchmarkRedis runs the Redis performance benchmark using redis-benchmark.
func BenchmarkRedis(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)

	persistentVol := benchmarkNS.GetPersistentVolume(redisVolumeName, "30Gi")
	persistentVol, err := cluster.CreatePersistentVolume(ctx, persistentVol)
	if err != nil {
		t.Fatalf("Failed to create persistent volume: %v", err)
	}
	defer cluster.DeletePersistentVolume(ctx, persistentVol)

	testCPUArch, err := cluster.RuntimeTestNodepoolArchitecture(ctx)
	if err != nil {
		t.Fatalf("Failed to get runtime test nodepool architecture: %v", err)
	}
	var image string
	switch testCPUArch {
	case testcluster.CPUArchitectureX86:
		image = redisImageAMD
	case testcluster.CPUArchitectureARM:
		image = redisImageARM
	default:
		t.Fatalf("Unsupported CPU architecture: %v", testCPUArch)
	}
	if image, err = k8sCtx.ResolveImage(ctx, image); err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	for _, test := range []struct {
		// Benchmark name
		name string
		// Suffix for the redis server, must be short to fit in pod name.
		suffix string
		// redis-server command-line.
		serverCommand []string
		// Volume to use for persistence, if any.
		volume *v13.PersistentVolumeClaim
	}{
		{
			name:   "Persistence",
			suffix: "persist",
			serverCommand: []string{
				"redis-server",
				"--dir", redisDataDirectory,
				// Default save settings per
				// https://redis.io/docs/management/config-file/
				"--save", "3600 1 300 100 60 10000",
			},
			volume: persistentVol,
		},
		{
			name:   "NoPersistence",
			suffix: "nopersist",
			serverCommand: []string{
				"redis-server",
				"--appendonly", "no",
				"--save", "",
			},
			volume: nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			endProfiling, err := profiling.MaybeSetup(ctx, t, k8sCtx, cluster, benchmarkNS)
			if err != nil {
				t.Fatalf("Failed to setup profiling: %v", err)
			}
			defer endProfiling()

			// Create a server on the runtime under test nodepool.
			server := newRedisPodWithPort(benchmarkNS, fmt.Sprintf("redis-%s", test.suffix), image, test.serverCommand, redisPort, test.volume)
			if server.ObjectMeta.Labels == nil {
				server.ObjectMeta.Labels = make(map[string]string)
			}
			server.ObjectMeta.Labels[redisServerLabelKey] = redisServerLabelValue
			server, err = cluster.ConfigurePodForRuntimeTestNodepool(ctx, server)
			if err != nil {
				t.Fatalf("ConfigurePodForRuntimeTestNodepool on cluster %q: %v", cluster.GetName(), err)
			}

			server, err = testcluster.SetContainerResources(server, "", testcluster.ContainerResourcesRequest{})
			if err != nil {
				t.Fatalf("SetContainerResources on cluster %q: %v", cluster.GetName(), err)
			}

			server, err = cluster.CreatePod(ctx, server)
			if err != nil {
				t.Fatalf("CreatePod on cluster %q: %v", cluster.GetName(), err)
			}
			defer cluster.DeletePod(ctx, server)

			if err := cluster.WaitForPodRunning(ctx, server); err != nil {
				t.Fatalf("WaitForPodRunning on cluster %q pod: %q: %v", cluster.GetName(), server.GetName(), err)
			}

			// create a service to service traffic to the pod.
			service := newRedisService(benchmarkNS, server.GetName())
			service, err = cluster.CreateService(ctx, service)
			if err != nil {
				t.Fatalf("CreateService on cluster %q: %v", cluster.GetName(), err)
			}
			defer cluster.DeleteService(ctx, service)
			if err := cluster.WaitForServiceReady(ctx, service); err != nil {
				t.Fatalf("WaitForServiceReady on cluster %q: %v", cluster.GetName(), err)
			}

			ip := testcluster.GetIPFromService(service)
			if ip == "" {
				t.Fatalf("did not get valid ip: %s", ip)
			}

			// run the 'redis-cli' command to ping the server and make sure it is up. The "ping" request comes
			// back with a "PONG" response. We repeat -r=5 times with a -i=1 second interval. If we
			// get one PONG back then the server is considered up.
			pingCmd := []string{"redis-cli", "-h", ip, "-r", "5", "-i", "1", "ping"}
			ensureUp := func() error {
				pinger := newRedisPod(benchmarkNS, fmt.Sprintf("rpinger-%s", test.suffix), image, pingCmd)
				pinger, err = cluster.ConfigurePodForClientNodepool(ctx, pinger)
				if err != nil {
					return fmt.Errorf("ConfigurePodForClientNodepool on cluster %q: pod: %q: %v", cluster.GetName(), pinger.GetName(), err)
				}

				pinger, err = cluster.CreatePod(ctx, pinger)
				if err != nil {
					return fmt.Errorf("CreatePod %q on cluster %q: %v", pinger.GetName(), cluster.GetName(), err)
				}
				defer cluster.DeletePod(ctx, pinger)

				waitCtx, waitCancel := context.WithTimeout(ctx, 30*time.Second)
				var podWaitSuffix string
				if err := cluster.WaitForPodCompleted(waitCtx, pinger); err != nil {
					podWaitSuffix = fmt.Sprintf(" (pod wait error: %v)", err)
				}
				waitCancel()

				rdr, err := cluster.GetLogReader(ctx, pinger, v13.PodLogOptions{})
				if err != nil {
					return fmt.Errorf("GetLogReader on cluster %q: %v%s", cluster.GetName(), err, podWaitSuffix)
				}
				out, err := io.ReadAll(rdr)
				if err != nil {
					return fmt.Errorf("failed to read from pod: %q: %v%s", pinger.GetName(), err, podWaitSuffix)
				}

				if !strings.Contains(string(out), "PONG") {
					return fmt.Errorf("mismatched output: wanted: PONG got: %q%s", string(out), podWaitSuffix)
				}

				return nil
			}
			var isUpErr error
			serverUpCtx, serverUpCancel := context.WithTimeout(ctx, 100*time.Second)
			defer serverUpCancel()
			for serverUpCtx.Err() == nil {
				if isUpErr = ensureUp(); isUpErr == nil {
					break
				}
			}
			if isUpErr != nil {
				t.Fatalf("%s at IP %s did not come up: %v", server.GetName(), ip, isUpErr)
			}

			for _, connections := range numConnections {
				t.Run(fmt.Sprintf("Connections_%d", connections), func(t *testing.T) {
					for _, operation := range operations {
						t.Run(operation, func(t *testing.T) {
							// Create a client for this client run w/ the specified number of connections.
							// Sadly the --csv mode only reports QPS, not latency. In order to report both,
							// we need to parse the human-readable version of the output.
							clientCmd := []string{
								"redis-benchmark",
								"-t", operation, // RPC to benchmark
								"-h", ip, // Redis server IP
								"-n", fmt.Sprintf("%d", defaultRequestsPerConnection*connections), // Number of total requests to do
								"-c", fmt.Sprintf("%d", connections), // Number of threads to spread them over.
								"-r", "1000", // Key space size (larger = more memory faults)
								"--precision", "4", // Floating-point precision for reporting latency (in ms)
							}
							client := newRedisPod(benchmarkNS, "client", image, clientCmd)
							client, err = cluster.ConfigurePodForClientNodepool(ctx, client)
							if err != nil {
								t.Fatalf("ConfigurePodForClientNodepool on cluster %q: pod: %q: %v", cluster.GetName(), client.GetName(), err)
							}

							client, err = cluster.CreatePod(ctx, client)
							if err != nil {
								t.Fatalf("CreatePod %q on cluster %q: %v", client.GetName(), cluster.GetName(), err)
							}
							defer cluster.DeletePod(ctx, client)

							if err := cluster.WaitForPodCompleted(ctx, client); err != nil {
								t.Fatalf("WaitForPodCompleted on cluster %q pod: %q: %v", cluster.GetName(), client.GetName(), err)
							}

							// get and parse the logs from the client to get the results
							rdr, err := cluster.GetLogReader(ctx, client, v13.PodLogOptions{})

							if err != nil {
								t.Fatalf("GetLogReader on cluster %q: %v", cluster.GetName(), err)
							}

							out, err := io.ReadAll(rdr)
							if err != nil {
								t.Fatalf("failed to read from pod: %q: %v", client.GetName(), err)
							}

							recorder, err := benchmetric.GetRecorder(ctx)
							if err != nil {
								t.Fatalf("Failed to initialize benchmark recorder: %v", err)
							}
							redisBenchmarkName := fmt.Sprintf("Redis/%s/%dClients/%s", test.name, connections, operation)
							metrics, err := getMeasurements(string(out), operation)
							if err != nil {
								// Redis uses '\r' to update its status by overwriting the current line.
								// If printed directly, this messes up the output.
								// To make that clear, we replace '\r' with a literal
								// backslash + 'r', and add a newline.
								humanReadableOut := strings.ReplaceAll(string(out), "\r", "\\r\n")
								t.Fatalf("failed to get metric for op %q: out:\n\n%s\n\nerr: %v", operation, humanReadableOut, err)
							}
							// We don't multiply `defaultRequestsPerConnection` by `connections` here
							// because the number of "samples" we're testing is the number of times we
							// can call an RPC from *that many connections* (which is part of the
							// benchmark name).
							// Adding 5x the number of connections does not make the sample size of this
							// benchmark go 5x higher.
							if err := recorder.RecordIters(ctx, redisBenchmarkName, defaultRequestsPerConnection, metrics...); err != nil {
								t.Fatalf("Failed to record benchmark data for op %q: %v", operation, err)
							}
						})
						if t.Failed() {
							break
						}
					}
				})
				if t.Failed() {
					break
				}
			}
		})
		if t.Failed() {
			break
		}
	}
}

// newRedisService gets a service to serve traffic to the redis server.
func newRedisService(namespace *testcluster.Namespace, containerName string) *v13.Service {
	name := fmt.Sprintf("redis-service-%d", time.Now().UnixNano())
	return namespace.GetService(name, v13.ServiceSpec{
		Selector: map[string]string{redisServerLabelKey: redisServerLabelValue},
		Ports: []v13.ServicePort{
			{
				Name:       name,
				Protocol:   v13.ProtocolTCP,
				Port:       redisPort,
				TargetPort: intstr.FromString(containerName),
			},
		},
	})
}

var (
	latencyPercentileRegex = regexp.MustCompile("^([-,.\\d]+)% <=? ([-,.\\d]+) milliseconds(?: \\(cumulative count .*\\))?$")
	latencyStartHeader     = "Latency by percentile distribution:"
	queriesPerSecondRegex  = regexp.MustCompile("^throughput summary: ([-,.\\d]+) requests per second$")
)

func stringToFloat64(s string) float64 {
	f, err := strconv.ParseFloat(strings.ReplaceAll(s, ",", ""), 64)
	if err != nil {
		panic(fmt.Sprintf("cannot convert float %q: %v", s, err))
	}
	return f
}

// getMeasurements parses the output of redis-benchmark to get the stats.
func getMeasurements(out, operation string) ([]benchmetric.MetricValue, error) {
	var currentOperation string
	var returned []benchmetric.MetricValue
	inLatencyBlock := false
	foundPercentiles := make(map[int]bool, len(latencyPercentiles))
	foundQPS := false
	lastPercentile := -1.0
	lastPercentileLatencyMs := math.NaN()
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// The human-readable output contains a bunch of data like
		// "OPERATION: number\r" which are used to update the result
		// interactively. Strip them out here.
		if strings.Contains(line, "\r") {
			line = line[strings.LastIndex(line, "\r")+1:]
		}
		if strings.HasPrefix(line, "====== ") {
			currentOperation = strings.SplitN(strings.Trim(line, "= "), " ", 2)[0]
		}
		if currentOperation != operation {
			continue
		}
		if line == latencyStartHeader {
			inLatencyBlock = true
			continue
		}
		if inLatencyBlock {
			latencyMatch := latencyPercentileRegex.FindStringSubmatch(line)
			if latencyMatch != nil {
				percentile := stringToFloat64(latencyMatch[1])
				if percentile < lastPercentile {
					continue
				}
				latencyMs := stringToFloat64(latencyMatch[2])
				if percentile == 0 {
					lastPercentile = 0
					lastPercentileLatencyMs = latencyMs
					continue
				}
				// Look for all percentiles in `wantPercentiles` that are in the range [lastPercentile,
				// percentile].
				var recordPercentiles []int
				for _, wantPercentile := range latencyPercentiles {
					if float64(wantPercentile) < lastPercentile {
						continue
					}
					if float64(wantPercentile) > percentile {
						continue
					}
					if foundPercentiles[wantPercentile] {
						continue
					}
					recordPercentiles = append(recordPercentiles, wantPercentile)
				}
				for _, recordPercentile := range recordPercentiles {
					// Linear interpolation of the latency value from within the latency range in the two
					// percentile values that we got.
					// For example, given p50=1.0ms and p70=2.0ms, we infer that p60=1.5ms.
					// This isn't bulletproof but it is better than rounding to either end of the bucket.
					rangeFraction := (float64(recordPercentile) - lastPercentile) / (percentile - lastPercentile)
					pctileLatency := rangeFraction*(latencyMs-lastPercentileLatencyMs) + lastPercentileLatencyMs
					returned = append(returned, benchmetric.SpecificDuration(time.Duration(pctileLatency*float64(time.Millisecond)), fmt.Sprintf("p%d", recordPercentile)))
					foundPercentiles[recordPercentile] = true
				}
				// Update values for next round.
				lastPercentile = percentile
				lastPercentileLatencyMs = latencyMs
			} else {
				inLatencyBlock = false
			}
			continue
		}
		qpsMatch := queriesPerSecondRegex.FindStringSubmatch(line)
		if qpsMatch != nil {
			if foundQPS {
				return nil, fmt.Errorf("found QPS value multiple times: %q", line)
			}
			foundQPS = true
			returned = append(returned, benchmetric.RequestsPerSecond(stringToFloat64(qpsMatch[1])))
		}
	}
	if !foundQPS || len(foundPercentiles) != len(latencyPercentiles) {
		return nil, fmt.Errorf("did not find the data we wanted: foundQPS=%v foundPercentiles=%v", foundQPS, foundPercentiles)
	}
	return returned, nil
}

// newRedisPodWithPort returns a redis pod template.
func newRedisPodWithPort(namespace *testcluster.Namespace, name, image string, cmd []string, port int32, pvc *v13.PersistentVolumeClaim) *v13.Pod {
	container := newRedisContainer(name, image, cmd)
	container.Ports = append(container.Ports, v13.ContainerPort{Name: name, ContainerPort: port})
	if pvc != nil {
		container.VolumeMounts = append(container.VolumeMounts, v13.VolumeMount{
			Name:      redisVolumeName,
			MountPath: redisDataDirectory,
		})
	}

	pod := namespace.NewPod(name)
	pod.Spec.Containers = []v13.Container{container}
	if pvc != nil {
		pod.Spec.Volumes = append(pod.Spec.Volumes, v13.Volume{
			Name: redisVolumeName,
			VolumeSource: v13.VolumeSource{
				PersistentVolumeClaim: &v13.PersistentVolumeClaimVolumeSource{
					ClaimName: pvc.GetName(),
				},
			},
		})
	}
	return pod
}

// newRedisPod returns a redis pod template.
func newRedisPod(namespace *testcluster.Namespace, name, image string, cmd []string) *v13.Pod {
	pod := namespace.NewPod(name)
	pod.Spec.Containers = []v13.Container{newRedisContainer(name, image, cmd)}
	return pod
}

// newRedisContainer returns a new redis container.
func newRedisContainer(name, image string, cmd []string) v13.Container {
	return v13.Container{
		Name:    name,
		Image:   image,
		Command: cmd,
	}
}
