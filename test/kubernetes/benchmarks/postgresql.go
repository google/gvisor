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

// Package postgresql benchmarks a PostgreSQL database.
package postgresql

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	postgresServerLabelKey   = "app.kubernetes.io/name"
	postgresServerLabelValue = "postgresql-server"
	postgresPort             = 5432
	postgresImage            = "postgres:15.3-alpine"
	postgresUser             = "benchman"
	postgresPassword         = "hunter2"
	postgresDatabase         = "benchpress"
	postgresVolumeDir        = "/var/lib/postgresql/data"
	postgresDataDir          = "/var/lib/postgresql/data/pgdata"
)

var (
	numConnections = []int{1, 2, 12, 64}
)

// BenchmarkPostgresPGBench runs a PostgreSQL pgbench test.
func BenchmarkPostgresPGBench(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
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
	persistentVol := benchmarkNS.GetPersistentVolume("pgdata", "30Gi")
	persistentVol, err = cluster.CreatePersistentVolume(ctx, persistentVol)
	if err != nil {
		t.Fatalf("failed to create persistent volume: %v", err)
	}
	defer cluster.DeletePersistentVolume(ctx, persistentVol)

	// Create a server on the runtime under test nodepool.
	image, err := k8sCtx.ResolveImage(ctx, postgresImage)
	if err != nil {
		t.Fatalf("failed to resolve image: %v", err)
	}
	server := newPostgresPod(benchmarkNS, "postgresql", image, nil, true /* withPort */, persistentVol)
	if server.ObjectMeta.Labels == nil {
		server.ObjectMeta.Labels = make(map[string]string)
	}
	server.ObjectMeta.Labels[postgresServerLabelKey] = postgresServerLabelValue
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

	// Create a service to service traffic to the pod.
	service := newPostgresService(benchmarkNS, server.GetName())
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

	// Run the 'pg_isready' command to ping the server and make sure it is up.
	ensureUp := func() error {
		pgIsReadyName := "pgisready"
		pgIsReady := newPostgresPod(benchmarkNS, pgIsReadyName, image, []string{
			"pg_isready",
			"--timeout=10",
			fmt.Sprintf("--host=%s", ip),
			fmt.Sprintf("--port=%d", postgresPort),
			fmt.Sprintf("--username=%s", postgresUser),
			fmt.Sprintf("--dbname=%s", postgresDatabase),
		}, false /* withPort */, nil /* pvc */)
		pgIsReady, err = cluster.ConfigurePodForClientNodepool(ctx, pgIsReady)
		if err != nil {
			return fmt.Errorf("ConfigurePodForClientNodepool on cluster %q: pod: %q: %v", cluster.GetName(), pgIsReadyName, err)
		}

		pgIsReady, err = cluster.CreatePod(ctx, pgIsReady)
		if err != nil {
			return fmt.Errorf("CreatePod %q on cluster %q: %v", pgIsReady.GetName(), cluster.GetName(), err)
		}
		defer cluster.DeletePod(ctx, pgIsReady)

		waitCtx, waitCancel := context.WithTimeout(ctx, 20*time.Second)
		defer waitCancel()
		if err := cluster.WaitForPodCompleted(waitCtx, pgIsReady); err != nil {
			return fmt.Errorf("WaitForPodCompleted on cluster %q pod: %q: %v", cluster.GetName(), pgIsReadyName, err)
		}

		return nil
	}
	var isUpErr error
	for i := 0; i < 5; i++ {
		if isUpErr = ensureUp(); isUpErr == nil {
			break
		}
	}
	if isUpErr != nil {
		t.Fatalf("postgresql did not come up: %v", isUpErr)
	}

	// pgbench has two steps: an "init step" which create and fills up a
	// database with stuff, and then a main phase which does queries on that
	// stuff.
	// The initialization only needs to be done once per database.
	initDatabase := func() error {
		initDBName := "initdb"
		initDB := newPostgresPod(benchmarkNS, initDBName, image, []string{
			"pgbench",
			"--initialize",
			fmt.Sprintf("--host=%s", ip),
			fmt.Sprintf("--port=%d", postgresPort),
			fmt.Sprintf("--username=%s", postgresUser),
			postgresDatabase,
		}, false /* withPort */, nil /* pvc */)
		initDB, err = cluster.ConfigurePodForClientNodepool(ctx, initDB)
		if err != nil {
			return fmt.Errorf("ConfigurePodForClientNodepool on cluster %q: pod: %q: %v", cluster.GetName(), initDBName, err)
		}

		initDB, err = cluster.CreatePod(ctx, initDB)
		if err != nil {
			return fmt.Errorf("CreatePod %q on cluster %q: %v", initDB.GetName(), cluster.GetName(), err)
		}
		defer cluster.DeletePod(ctx, initDB)

		waitCtx, waitCancel := context.WithTimeout(ctx, 20*time.Second)
		defer waitCancel()
		if err := cluster.WaitForPodCompleted(waitCtx, initDB); err != nil {
			return fmt.Errorf("WaitForPodCompleted on cluster %q pod: %q: %v", cluster.GetName(), initDBName, err)
		}
		return nil
	}
	if err := initDatabase(); err != nil {
		t.Fatalf("cannot initialize database: %v", err)
	}

	for _, connections := range numConnections {
		t.Run(fmt.Sprintf("%dClients", connections), func(t *testing.T) {
			clientCmd := []string{
				"pgbench",
				"--time=90", // In seconds
				"--report-per-command",
				fmt.Sprintf("--host=%s", ip),
				fmt.Sprintf("--port=%d", postgresPort),
				fmt.Sprintf("--username=%s", postgresUser),
				fmt.Sprintf("--client=%d", connections),
				fmt.Sprintf("--jobs=%d", connections),
				postgresDatabase,
			}
			client := newPostgresPod(benchmarkNS, "pgbench", image, clientCmd, false /* withPort */, nil /* pvc */)
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

			postgresBenchmarkName := fmt.Sprintf("PostgresPGBench/%dClients", connections)
			recorder, err := benchmetric.GetRecorder(ctx)
			if err != nil {
				t.Fatalf("Failed to initialize benchmark recorder: %v", err)
			}
			metrics, err := getMeasurements(string(out))
			if err != nil {
				t.Fatalf("failed to get metrics: out:\n\n%s\n\nerr: %v", string(out), err)
			}
			if err := recorder.Record(ctx, postgresBenchmarkName, metrics...); err != nil {
				t.Fatalf("Failed to record benchmark data: %v", err)
			}
		})
	}
}

// newPostgresService gets a service to serve traffic to the PostgreSQL server.
func newPostgresService(namespace *testcluster.Namespace, containerName string) *v13.Service {
	name := fmt.Sprintf("postgresql-service-%d", time.Now().UnixNano())
	return namespace.GetService(name, v13.ServiceSpec{
		Selector: map[string]string{postgresServerLabelKey: postgresServerLabelValue},
		Ports: []v13.ServicePort{
			{
				Name:       name,
				Protocol:   v13.ProtocolTCP,
				Port:       postgresPort,
				TargetPort: intstr.FromInt(postgresPort),
			},
		},
	})
}

func newPostgresPod(namespace *testcluster.Namespace, containerName, image string, argv []string, withPort bool, pvc *v13.PersistentVolumeClaim) *v13.Pod {
	pod := namespace.NewPod(containerName)
	container := v13.Container{
		Name:    containerName,
		Image:   image,
		Command: argv,
		Env: []v13.EnvVar{
			// Used by postgres server:
			{Name: "POSTGRES_USER", Value: postgresUser},
			{Name: "POSTGRES_PASSWORD", Value: postgresPassword},
			{Name: "POSTGRES_DB", Value: postgresDatabase},
			{Name: "PGDATA", Value: postgresDataDir},

			// Used by pgbench:
			{Name: "PGPASSWORD", Value: postgresPassword},
			{Name: "sslmode", Value: "disable"},
		},
	}
	if withPort {
		container.Ports = append(container.Ports, v13.ContainerPort{ContainerPort: postgresPort})
	}
	if pvc != nil {
		pod.Spec.Volumes = append(pod.Spec.Volumes, v13.Volume{
			Name: pvc.GetName(),
			VolumeSource: v13.VolumeSource{
				PersistentVolumeClaim: &v13.PersistentVolumeClaimVolumeSource{
					ClaimName: pvc.GetName(),
				},
			},
		})
		container.VolumeMounts = append(container.VolumeMounts, v13.VolumeMount{
			MountPath: postgresVolumeDir,
			Name:      pvc.GetName(),
		})
	}
	pod.Spec.Containers = append(pod.Spec.Containers, container)
	return pod
}

var (
	latencyRegex           = regexp.MustCompile("^latency average = ([-,.\\d]+ .?s)$")
	initialConnectionRegex = regexp.MustCompile("^initial connection time = ([-,.\\d]+ .?s)$")
	tpsRegex               = regexp.MustCompile("^tps = ([-,.\\d]+) \\(without initial connection time\\)$")
)

func stringToFloat64(s string) float64 {
	f, err := strconv.ParseFloat(strings.ReplaceAll(s, ",", ""), 64)
	if err != nil {
		panic(fmt.Sprintf("cannot convert float %q: %v", s, err))
	}
	return f
}

func stringToDuration(s string) time.Duration {
	parts := strings.SplitN(s, " ", 2)
	floatStr, unit := parts[0], parts[1]
	floatPart := stringToFloat64(floatStr)
	switch unit {
	case "s":
		return time.Duration(floatPart * float64(time.Second))
	case "ms":
		return time.Duration(floatPart * float64(time.Millisecond))
	case "us", "μs":
		return time.Duration(floatPart * float64(time.Microsecond))
	case "ns":
		return time.Duration(floatPart * float64(time.Nanosecond))
	default:
		panic(fmt.Sprintf("unknown time unit %q", unit))
	}
}

// getMeasurements parses the output of pgbench to get the stats.
func getMeasurements(out string) ([]benchmetric.MetricValue, error) {
	var foundLatency, foundInitialConnection, foundTPS benchmetric.MetricValue
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if latencyMatch := latencyRegex.FindStringSubmatch(line); latencyMatch != nil {
			if foundLatency != nil {
				return nil, fmt.Errorf("found duplicate latency data: %v vs %q", foundLatency, line)
			}
			foundLatency = benchmetric.SpecificDuration(stringToDuration(latencyMatch[1]), "avg")
		}
		if initialConnectionMatch := initialConnectionRegex.FindStringSubmatch(line); initialConnectionMatch != nil {
			if foundInitialConnection != nil {
				return nil, fmt.Errorf("found duplicate initial connection data: %v vs %q", foundInitialConnection, line)
			}
			foundInitialConnection = benchmetric.SpecificDuration(stringToDuration(initialConnectionMatch[1]), "init")
		}
		if tpsMatch := tpsRegex.FindStringSubmatch(line); tpsMatch != nil {
			if foundTPS != nil {
				return nil, fmt.Errorf("found duplicate TPS data: %v vs %q", foundTPS, line)
			}
			foundTPS = benchmetric.RequestsPerSecond(stringToFloat64(tpsMatch[1]))
		}
	}
	if foundLatency == nil || foundInitialConnection == nil || foundTPS == nil {
		return nil, fmt.Errorf("did not find the data we wanted: foundLatency=%v foundInitialConnection=%v foundTPS=%v", foundLatency, foundInitialConnection, foundTPS)
	}
	return []benchmetric.MetricValue{
		foundLatency,
		foundInitialConnection,
		foundTPS,
	}, nil
}
