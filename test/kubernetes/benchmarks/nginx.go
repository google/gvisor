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

package nginx

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/httpbench"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	nginxPort              = 80
	nginxBenchmarkDuration = 55 * time.Second
	nginxRequestTimeout    = 3 * time.Second
	nginxServingDir        = "/tmp/html"

	nginxServerLabelKey   = "app.kubernetes.io/name"
	nginxServerLabelValue = "nginx-server"
	nginxImageAMD         = k8s.ImageRepoPrefix + "benchmarks/nginx_x86_64:latest"
	nginxImageARM         = k8s.ImageRepoPrefix + "benchmarks/nginx_aarch64:latest"
)

var (
	// nginxCommand is the main server command.
	// The test expects that it contains the files to be served at /local,
	// and will serve files out of `nginxServingDir`.
	nginxCommand      = []string{"nginx", "-c", "/etc/nginx/nginx.conf"}
	nginxDocKibibytes = []int{1, 10240}
	threads           = []int{1, 8, 1000}
	targetQPS         = []int{1, 64, httpbench.InfiniteQPS}
	wantPercentiles   = []int{50, 95, 99}
)

// BenchmarkNginx runs a series of benchmarks against an nginx server.
func BenchmarkNginx(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)

	testCPUArch, err := cluster.RuntimeTestNodepoolArchitecture(ctx)
	if err != nil {
		t.Fatalf("Failed to get runtime test nodepool architecture: %v", err)
	}
	var nginxImage string
	switch testCPUArch {
	case testcluster.CPUArchitectureX86:
		nginxImage = nginxImageAMD
	case testcluster.CPUArchitectureARM:
		nginxImage = nginxImageARM
	default:
		t.Fatalf("Unsupported CPU architecture: %v", testCPUArch)
	}
	if nginxImage, err = k8sCtx.ResolveImage(ctx, nginxImage); err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}

	persistentVol, err := cluster.CreatePersistentVolume(ctx, benchmarkNS.GetPersistentVolume("nginx-data", "30Gi"))
	if err != nil {
		t.Fatalf("Failed to create persistent volume: %v", err)
	}
	defer cluster.DeletePersistentVolume(ctx, persistentVol)

	for _, test := range []struct {
		// Name of the test.
		name string
		// Suffix for pod names, must be short enough.
		suffix string
		// Volume to mount at /tmp/root.
		volume *v13.Volume
	}{
		{
			name:   "RootFS",
			suffix: "rootfs",
			volume: nil,
		},
		{
			name:   "EmptyDir",
			suffix: "emdir",
			volume: &v13.Volume{
				Name: "emptydir",
				VolumeSource: v13.VolumeSource{
					EmptyDir: &v13.EmptyDirVolumeSource{},
				},
			},
		},
		{
			name:   "PersistentVolume",
			suffix: "pvol",
			volume: &v13.Volume{
				Name: persistentVol.GetName(),
				VolumeSource: v13.VolumeSource{
					PersistentVolumeClaim: &v13.PersistentVolumeClaimVolumeSource{
						ClaimName: persistentVol.GetName(),
					},
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			endProfiling, err := profiling.MaybeSetup(ctx, t, k8sCtx, cluster, benchmarkNS)
			if err != nil {
				t.Fatalf("Failed to setup profiling: %v", err)
			}
			defer endProfiling()

			name := fmt.Sprintf("nginx-%s", test.suffix)

			server := newNginxServer(benchmarkNS, name, nginxImage, test.volume)
			server, err = cluster.ConfigurePodForRuntimeTestNodepool(ctx, server)
			if err != nil {
				t.Fatalf("Failed to configure pod for runtime nodepool: %v", err)
			}
			server, err = testcluster.SetContainerResources(server, "", testcluster.ContainerResourcesRequest{})
			if err != nil {
				t.Fatalf("Failed to set container resources: %v", err)
			}
			server, err = cluster.CreatePod(ctx, server)
			if err != nil {
				t.Fatalf("Failed to create pod: %v", err)
			}
			defer cluster.DeletePod(ctx, server)

			if err := cluster.WaitForPodRunning(ctx, server); err != nil {
				t.Fatalf("Failed to wait for pod: %v", err)
			}

			service := newNginxService(benchmarkNS, name)
			service, err = cluster.CreateService(ctx, service)
			if err != nil {
				t.Fatalf("Failed to create service: %v", err)
			}
			defer cluster.DeleteService(ctx, service)

			var rounds []httpbench.Round
			for _, numThreads := range threads {
				for _, qps := range targetQPS {
					if qps < numThreads {
						continue
					}
					var onlyReport []httpbench.MetricType
					// If we're testing at max QPS, only report throughput,
					// because all requests will time out.
					// Otherwise, only report latency, because the throughput
					// is exactly determined by the QPS target anyway.
					if qps == httpbench.InfiniteQPS {
						onlyReport = append(onlyReport, httpbench.RequestsPerSecond)
						onlyReport = append(onlyReport, httpbench.BytesPerSecond)
					} else {
						onlyReport = append(onlyReport, httpbench.Latency)
					}
					rounds = append(rounds, httpbench.Round{
						NumThreads: numThreads,
						TargetQPS:  qps,
						Duration:   nginxBenchmarkDuration,
						OnlyReport: onlyReport,
					})
				}
			}

			t.Run("0KiB", func(t *testing.T) {
				benchmark := &httpbench.HTTPBenchmark{
					Name:            fmt.Sprintf("nginx/%s/0KiB", test.name),
					Cluster:         cluster,
					Namespace:       benchmarkNS,
					Service:         service,
					Port:            nginxPort,
					Path:            "/index.html",
					Rounds:          rounds,
					Timeout:         nginxRequestTimeout,
					WantPercentiles: wantPercentiles,
				}
				benchmark.Run(ctx, t)
			})
			for _, docKibibytes := range nginxDocKibibytes {
				t.Run(fmt.Sprintf("%dKiB", docKibibytes), func(t *testing.T) {
					benchmark := &httpbench.HTTPBenchmark{
						Name:            fmt.Sprintf("nginx/%s/%dKiB", test.name, docKibibytes),
						Cluster:         cluster,
						Namespace:       benchmarkNS,
						Service:         service,
						Port:            nginxPort,
						Path:            fmt.Sprintf("/latin%dk.txt", docKibibytes),
						Rounds:          rounds,
						Timeout:         nginxRequestTimeout,
						WantPercentiles: wantPercentiles,
					}
					benchmark.Run(ctx, t)
				})
			}
		})
		if t.Failed() {
			break
		}
	}
}

func newNginxServer(namespace *testcluster.Namespace, name, image string, volume *v13.Volume) *v13.Pod {
	var volumes []v13.Volume
	var volumeMounts []v13.VolumeMount
	if volume != nil {
		volumes = []v13.Volume{*volume}
		volumeMounts = []v13.VolumeMount{{
			MountPath: nginxServingDir,
			Name:      volume.Name,
		}}
	}
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace.Namespace,
			Labels:    map[string]string{nginxServerLabelKey: nginxServerLabelValue},
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  name,
					Image: image,
					Command: []string{
						"sh",
						"-c",
						strings.Join([]string{
							strings.Join([]string{"mkdir", "-p", nginxServingDir}, " "),
							strings.Join([]string{
								"cp", "-r", "/local/*", fmt.Sprintf("%s/.", nginxServingDir),
							}, " "),
							strings.Join(nginxCommand, " "),
						}, "  && "),
					},
					VolumeMounts: volumeMounts,
					Ports: []v13.ContainerPort{
						{
							Name:          name,
							ContainerPort: nginxPort,
						},
					},
				},
			},
			Volumes:       volumes,
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

func newNginxService(namespace *testcluster.Namespace, name string) *v13.Service {
	return namespace.GetService(name, v13.ServiceSpec{
		Selector: map[string]string{nginxServerLabelKey: nginxServerLabelValue},
		Ports: []v13.ServicePort{
			{
				Name:       name,
				Protocol:   v13.ProtocolTCP,
				Port:       nginxPort,
				TargetPort: intstr.FromString(name),
			},
		},
	})
}
