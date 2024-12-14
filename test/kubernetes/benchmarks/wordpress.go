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

package wordpress

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/test/kubernetes/benchmarks/httpbench"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	wordpressImage             = "wordpress:6.2.0-php8.2-apache"
	mariaDBImage               = "mariadb:10.11.3-jammy"
	wordpressPort              = 80
	mariaDBPort                = 3306
	wordpressBenchmarkDuration = 55 * time.Second
	wordpressRequestTimeout    = 10 * time.Second
	wordpressLoginPage         = "/wp-login.php"
	mariaDBName                = "wpbench"
	mariaDBUser                = "wpuser"
	mariaDBPassword            = "wppassword"
	mariaDBRootPassword        = "hunter2"
	mariaDBVolumeName          = "wpdata"
	mariaDBVolumeDirectory     = "/var/lib/mysql"

	wordpressServerLabelKey   = "app.kubernetes.io/name"
	wordpressServerLabelValue = "wordpress"
	mariaDBServerLabelKey     = "app.kubernetes.io/name"
	mariaDBServerLabelValue   = "mariadb"
)

var (
	threads         = []int{1, 8, 1000}
	targetQPS       = []int{1, 64, httpbench.InfiniteQPS}
	wantPercentiles = []int{50, 95, 99}
)

// BenchmarkWordpress runs a benchmark of WordPress performance.
func BenchmarkWordpress(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
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

	// Create a persistent volume on which to store the database data.
	dbVolume := benchmarkNS.GetPersistentVolume(mariaDBVolumeName, "30Gi")
	dbVolume, err = cluster.CreatePersistentVolume(ctx, dbVolume)
	if err != nil {
		t.Fatalf("failed to create persistent volume: %v", err)
	}
	defer cluster.DeletePersistentVolume(ctx, dbVolume)

	databaseName := "mariadb"
	mariaDBImg, err := k8sCtx.ResolveImage(ctx, mariaDBImage)
	if err != nil {
		t.Fatalf("failed to resolve image: %v", err)
	}
	database := newMariaDBServer(benchmarkNS, databaseName, mariaDBImg, dbVolume)
	database, err = cluster.ConfigurePodForTertiaryNodepool(ctx, database)
	if err != nil {
		t.Fatalf("Failed to configure pod for tertiary nodepool: %v", err)
	}
	database, err = cluster.CreatePod(ctx, database)
	if err != nil {
		t.Fatalf("Failed to create pod: %v", err)
	}
	defer cluster.DeletePod(ctx, database)
	if err := cluster.WaitForPodRunning(ctx, database); err != nil {
		t.Fatalf("Failed to wait for pod: %v", err)
	}
	databaseService := newMariaDBService(benchmarkNS, databaseName)
	databaseService, err = cluster.CreateService(ctx, databaseService)
	if err != nil {
		t.Fatalf("Failed to create database service: %v", err)
	}
	defer cluster.DeleteService(ctx, databaseService)
	mariaDBIP := testcluster.GetIPFromService(databaseService)

	name := "wordpress"
	wordpressImg, err := k8sCtx.ResolveImage(ctx, wordpressImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	server := newWordpressServer(benchmarkNS, name, wordpressImg, mariaDBIP)
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

	service := newWordpressService(benchmarkNS, name)
	service, err = cluster.CreateService(ctx, service)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer cluster.DeleteService(ctx, service)
	wordpressIP := testcluster.GetIPFromService(service)

	// Install WordPress.
	installWordpressPod := newWordpressInstall(benchmarkNS, "install-wordpress", wordpressIP)
	installWordpressPod, err = cluster.ConfigurePodForClientNodepool(ctx, installWordpressPod)
	if err != nil {
		t.Fatalf("Failed to configure pod for client nodepool: %v", err)
	}
	installWordpressPod, err = cluster.CreatePod(ctx, installWordpressPod)
	if err != nil {
		t.Fatalf("Failed to create pod: %v", err)
	}
	defer cluster.DeletePod(ctx, installWordpressPod)
	if err := cluster.WaitForPodCompleted(ctx, installWordpressPod); err != nil {
		t.Fatalf("Failed to wait for pod: %v", err)
	}
	cluster.DeletePod(ctx, installWordpressPod)

	var rounds []httpbench.Round
	for _, numThreads := range threads {
		for _, qps := range targetQPS {
			if qps < numThreads {
				continue
			}
			onlyReport := []httpbench.MetricType{httpbench.RequestsPerSecond}
			// If we're testing at max QPS, don't report latency,
			// because all requests will hit the timeout.
			// Otherwise, only report latency, because the throughput
			// is exactly determined by the QPS target anyway.
			if qps != httpbench.InfiniteQPS {
				onlyReport = append(onlyReport, httpbench.Latency)
			}
			rounds = append(rounds, httpbench.Round{
				NumThreads: numThreads,
				TargetQPS:  qps,
				Duration:   wordpressBenchmarkDuration,
				OnlyReport: onlyReport,
			})
		}
	}
	benchmark := &httpbench.HTTPBenchmark{
		Name:            "wordpress",
		Cluster:         cluster,
		Namespace:       benchmarkNS,
		Service:         service,
		Port:            wordpressPort,
		Path:            wordpressLoginPage,
		Rounds:          rounds,
		Timeout:         wordpressRequestTimeout,
		WantPercentiles: wantPercentiles,
	}
	benchmark.Run(ctx, t)
}

func newMariaDBServer(namespace *testcluster.Namespace, name, image string, volume *v13.PersistentVolumeClaim) *v13.Pod {
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace.Namespace,
			Labels:    map[string]string{mariaDBServerLabelKey: mariaDBServerLabelValue},
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  name,
					Image: image,
					Ports: []v13.ContainerPort{
						{
							Name:          name,
							ContainerPort: mariaDBPort,
						},
					},
					Env: []v13.EnvVar{
						{
							Name:  "MARIADB_ROOT_PASSWORD",
							Value: mariaDBRootPassword,
						},
						{
							Name:  "MARIADB_DATABASE",
							Value: mariaDBName,
						},
						{
							Name:  "MARIADB_USER",
							Value: mariaDBUser,
						},
						{
							Name:  "MARIADB_PASSWORD",
							Value: mariaDBPassword,
						},
					},
					VolumeMounts: []v13.VolumeMount{{
						Name:      volume.GetName(),
						MountPath: mariaDBVolumeDirectory,
					}},
				},
			},
			Volumes: []v13.Volume{{
				Name: volume.GetName(),
				VolumeSource: v13.VolumeSource{
					PersistentVolumeClaim: &v13.PersistentVolumeClaimVolumeSource{
						ClaimName: volume.GetName(),
					},
				},
			}},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

func newMariaDBService(namespace *testcluster.Namespace, name string) *v13.Service {
	return namespace.GetService(name, v13.ServiceSpec{
		Selector: map[string]string{mariaDBServerLabelKey: mariaDBServerLabelValue},
		Ports: []v13.ServicePort{
			{
				Name:       name,
				Protocol:   v13.ProtocolTCP,
				Port:       mariaDBPort,
				TargetPort: intstr.FromString(name),
			},
		},
	})
}

func newWordpressServer(namespace *testcluster.Namespace, name, image, mariaDBHost string) *v13.Pod {
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace.Namespace,
			Labels:    map[string]string{wordpressServerLabelKey: wordpressServerLabelValue},
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  name,
					Image: image,
					Ports: []v13.ContainerPort{
						{
							Name:          name,
							ContainerPort: wordpressPort,
						},
					},
					Env: []v13.EnvVar{
						{
							Name:  "WORDPRESS_DB_HOST",
							Value: mariaDBHost,
						},
						{
							Name:  "WORDPRESS_DB_USER",
							Value: mariaDBUser,
						},
						{
							Name:  "WORDPRESS_DB_PASSWORD",
							Value: mariaDBPassword,
						},
						{
							Name:  "WORDPRESS_DB_NAME",
							Value: mariaDBName,
						},
						{
							Name:  "WORDPRESS_TABLE_PREFIX",
							Value: "wp_",
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

func newWordpressService(namespace *testcluster.Namespace, name string) *v13.Service {
	return namespace.GetService(name, v13.ServiceSpec{
		Selector: map[string]string{wordpressServerLabelKey: wordpressServerLabelValue},
		Ports: []v13.ServicePort{
			{
				Name:       name,
				Protocol:   v13.ProtocolTCP,
				Port:       wordpressPort,
				TargetPort: intstr.FromString(name),
			},
		},
	})
}

func newWordpressInstall(namespace *testcluster.Namespace, name, wpHost string) *v13.Pod {
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace.Namespace,
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  "install-wordpress",
					Image: "debian:latest",
					// This command installs WordPress through the web UI.
					// Source of the parameters:
					// https://github.com/GoogleCloudPlatform/click-to-deploy/blob/master/k8s/wordpress/chart/wordpress/templates/wordpress-configmap.yaml
					Command: []string{
						"sh", "-c",
						strings.Join([]string{
							"apt-get update -y </dev/null",
							"apt-get install -y curl </dev/null",
							strings.Join([]string{
								"curl",
								"--fail",
								"--retry", "20",
								"--retry-delay", "5",
								"--retry-connrefused",
								"--data-urlencode", "'weblog_title=WPBench'",
								"--data-urlencode", "'user_name=iamroot'",
								"--data-urlencode", "'admin_email=iamroot@example.com'",
								"--data-urlencode", fmt.Sprintf("'admin_password=%s'", mariaDBPassword),
								"--data-urlencode", fmt.Sprintf("'admin_password2=%s'", mariaDBPassword),
								"--data-urlencode", "'pw_weak=1'",
								fmt.Sprintf("'http://%s/wp-admin/install.php?step=2'", wpHost),
							}, " "),
						}, " && "),
					},
					Env: []v13.EnvVar{
						{
							Name:  "DEBIAN_FRONTEND",
							Value: "noninteractive",
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}
