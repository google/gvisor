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

// package gsutil_test is used to benchmark the speed of large (10GB)
// downloads. It is intended for comparing runsc with runc.
package gsutil_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	imageAMD      = "us-central1-docker.pkg.dev/gvisor-presubmit/gvisor-presubmit-images/benchmarks/gsutil_x86_64:7eba9c02d11172d4"
	imageARM      = "us-central1-docker.pkg.dev/gvisor-presubmit/gvisor-presubmit-images/benchmarks/gsutil_aarch64:7eba9c02d11172d4"
	bigfile       = "gs://gvisor-benchmark-testdata/bigrandomfile"
	containerName = "gsutil"
)

func TestGSUtil(t *testing.T) {
	ctx := context.Background()
	k8sCtx, err := k8sctx.Context(ctx)
	if err != nil {
		t.Fatalf("Failed to get kubernetes context: %v", err)
	}
	k8sCtx.ForEachCluster(ctx, t, func(cluster *testcluster.TestCluster) {
		t.Run("GSUtil", func(t *testing.T) {
			t.Parallel()
			doGSUtilTest(ctx, t, k8sCtx, cluster)
		})
	})
}

func doGSUtilTest(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)

	const name = "gsutil"

	// Create persistent volume.
	persistentVol := benchmarkNS.GetPersistentVolume(name, "15Gi")
	persistentVol, err := cluster.CreatePersistentVolume(ctx, persistentVol)
	if err != nil {
		t.Fatalf("Failed to create persistent volume: %v", err)
	}
	defer cluster.DeletePersistentVolume(ctx, persistentVol)

	image := imageAMD
	if cluster.RuntimeTestNodepoolIsARM() {
		image = imageARM
	}
	if image, err = k8sCtx.ResolveImage(ctx, image); err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}

	// Run tests with different volume types.
	// TODO(b/361182379): Use gsutil parallel sliced downloads as a test
	// dimension.
	for _, storage := range []struct {
		name   string
		volume *v13.Volume
	}{
		{
			name:   "RootFS",
			volume: nil,
		},
		{
			name: "EmptyDir",
			volume: &v13.Volume{
				Name: "emptydir",
				VolumeSource: v13.VolumeSource{
					EmptyDir: &v13.EmptyDirVolumeSource{},
				},
			},
		},
		{
			name: "PersistentVolume",
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
		t.Run(storage.name, func(t *testing.T) {
			for _, slicing := range []struct {
				name   string
				option string
			}{
				{
					name:   "slicing=false",
					option: `-o "GSUtil:sliced_object_download_threshold=0"`,
				},
				{
					// Slicing is enabled by default, so we
					// don't set any extra options.
					name: "slicing=true",
				},
			} {
				t.Run(slicing.name, func(t *testing.T) {
					// Setup profiling if requested by the user.
					endProfiling, err := profiling.MaybeSetup(ctx, t, cluster, benchmarkNS)
					if err != nil {
						t.Fatalf("Failed to setup profiling: %v", err)
					}
					defer endProfiling()

					// Create a pod that performs setup, then times
					// downloading.
					p := newGSUtilDevPod(benchmarkNS, name, image, storage.volume, slicing.option)
					p, err = cluster.ConfigurePodForRuntimeTestNodepool(p)
					if err != nil {
						t.Fatalf("Failed to configure pod for runtime: %v", err)
					}
					p, err = testcluster.MaybeSetContainerResources(p, containerName, testcluster.ContainerResourcesRequest{})
					if err != nil {
						t.Fatalf("Failed to set container resources: %v", err)
					}

					// GetTimedContainerDuration waits for the container to
					// finish.
					recorder, err := benchmetric.GetRecorder(ctx)
					if err != nil {
						t.Fatalf("Failed to initialize benchmark recorder: %v", err)
					}
					containerDuration, err := benchmetric.GetTimedContainerDuration(ctx, cluster, p, containerName)
					if err != nil {
						t.Fatalf("Failed to get container duration: %v", err)
					}
					if err := recorder.Record(ctx, fmt.Sprintf("GSUtil/%s/%s", storage.name, slicing.name), benchmetric.BenchmarkDuration(containerDuration)); err != nil {
						t.Fatalf("Failed to record benchmark data: %v", err)
					}
				})
			}
		})
	}
}

// newGSUtilPod creates a new gsutil dev pod spec for benchmarks.
func newGSUtilDevPod(namespace *testcluster.Namespace, name, image string, volume *v13.Volume, gsutilFlags string) *v13.Pod {
	const downloadDir = "/downloads"
	initCommand := []string{
		"sh",
		"-c",
		strings.Join([]string{"mkdir", "-p", downloadDir}, " "),
	}
	command := []string{
		"sh", "-c",
		fmt.Sprintf("gsutil %s cp %s %s && sync",
			gsutilFlags,
			bigfile,
			filepath.Join(downloadDir, "randombigfile"),
		),
	}
	var volumes []v13.Volume
	var volumeMounts []v13.VolumeMount
	if volume != nil {
		volumes = []v13.Volume{*volume}
		volumeMounts = []v13.VolumeMount{{
			MountPath: downloadDir,
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
		},
		Spec: v13.PodSpec{
			Volumes: volumes,
			Containers: []v13.Container{
				{
					Name:         containerName,
					Image:        image,
					Command:      benchmetric.CommandThenTimed(initCommand, "", command),
					VolumeMounts: volumeMounts,
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

func TestMain(m *testing.M) {
	k8sctx.TestMain(m, map[string]k8sctx.TestFunc{
		"TestGSUtil": TestGSUtil,
	})
}
