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

package ffmpeg_test

import (
	"context"
	"fmt"
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
	imageAMD            = "gcr.io/gvisor-presubmit/benchmarks/ffmpeg_x86_64:latest"
	imageARM            = "gcr.io/gvisor-presubmit/benchmarks/ffmpeg_aarch64:latest"
	ffmpegContainerName = "ffmpeg"
)

func TestFfmpeg(t *testing.T) {
	ctx := context.Background()
	k8sCtx, err := k8sctx.Context(ctx)
	if err != nil {
		t.Fatalf("Failed to get kubernetes context: %v", err)
	}
	k8sCtx.ForEachCluster(ctx, t, func(cluster *testcluster.TestCluster) {
		t.Run("ffmpeg", func(t *testing.T) {
			t.Parallel()
			doFfmpegTest(ctx, t, k8sCtx, cluster)
		})
	})
}

func doFfmpegTest(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)

	const name = "ffmpeg"

	// create persistent volume
	persistentVol := benchmarkNS.GetPersistentVolume(name, "30Gi")
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

	for _, test := range []struct {
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
		t.Run(test.name, func(t *testing.T) {
			endProfiling, err := profiling.MaybeSetup(ctx, t, cluster, benchmarkNS)
			if err != nil {
				t.Fatalf("Failed to setup profiling: %v", err)
			}
			defer endProfiling()

			p := newFfmpegDevPod(benchmarkNS, name, image, test.volume)
			p, err = cluster.ConfigurePodForRuntimeTestNodepool(p)
			if err != nil {
				t.Fatalf("Failed to configure pod for runtime: %v", err)
			}
			p, err = testcluster.MaybeSetContainerResources(p, ffmpegContainerName, testcluster.ContainerResourcesRequest{})
			if err != nil {
				t.Fatalf("Failed to set container resources: %v", err)
			}

			p, err = cluster.CreatePod(ctx, p)
			if err != nil {
				t.Fatalf("Failed to create pod: %v", err)
			}
			defer cluster.DeletePod(ctx, p)

			recorder, err := benchmetric.GetRecorder(ctx)
			if err != nil {
				t.Fatalf("Failed to initialize benchmark recorder: %v", err)
			}
			containerDuration, err := benchmetric.GetTimedContainerDuration(ctx, cluster, p, ffmpegContainerName)
			if err != nil {
				t.Fatalf("Failed to get container duration: %v", err)
			}
			if recorder.Record(ctx, fmt.Sprintf("FFMPEG/%s", test.name), benchmetric.BenchmarkDuration(containerDuration)); err != nil {
				t.Fatalf("Failed to record benchmark data: %v", err)
			}
		})
	}
}

// newFfmpegPod creates a new ffmpeg dev pod spec for benchmarks.
func newFfmpegDevPod(namespace *testcluster.Namespace, name, image string, volume *v13.Volume) *v13.Pod {
	const workdir = "/workdir"
	initCommand := []string{
		"sh",
		"-c",
		strings.Join([]string{
			"mkdir", "-p", workdir,
			"&&",
			"cp", "/media/video.mp4", fmt.Sprintf("%s/.", workdir),
		}, " "),
	}
	command := []string{
		"ffmpeg",
		"-i", "video.mp4",
		"-c:v", "libx264",
		"-preset", "veryslow",
		"output.mp4",
	}
	var volumes []v13.Volume
	var volumeMounts []v13.VolumeMount
	if volume != nil {
		volumes = []v13.Volume{*volume}
		volumeMounts = []v13.VolumeMount{{
			MountPath: workdir,
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
					Name:         ffmpegContainerName,
					Image:        image,
					Command:      benchmetric.CommandThenTimed(initCommand, workdir, command),
					VolumeMounts: volumeMounts,
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

func TestMain(m *testing.M) {
	k8sctx.TestMain(m, map[string]k8sctx.TestFunc{
		"TestFfmpeg": TestFfmpeg,
	})
}
