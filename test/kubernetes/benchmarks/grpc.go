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

package grpc

import (
	"context"
	"fmt"
	"path"
	"strings"
	"testing"

	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	imageAMD = k8s.ImageRepoPrefix + "benchmarks/build-grpc_x86_64:latest"
	imageARM = k8s.ImageRepoPrefix + "benchmarks/build-grpc_aarch64:latest"
)

// BuildGRPC runs the GRPC benchmark.
// This benchmark builds the gRPC library using bazel.
func BuildGRPC(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)

	const name = "grpc"

	persistentVol := benchmarkNS.GetPersistentVolume(name, "30Gi")
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
		image = imageAMD
	case testcluster.CPUArchitectureARM:
		image = imageARM
	default:
		t.Fatalf("Unsupported CPU architecture: %v", testCPUArch)
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
			endProfiling, err := profiling.MaybeSetup(ctx, t, k8sCtx, cluster, benchmarkNS)
			if err != nil {
				t.Fatalf("Failed to setup profiling: %v", err)
			}
			defer endProfiling()

			pod := newGRPCPod(benchmarkNS, name, image, test.volume)
			pod, err = cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
			if err != nil {
				t.Fatalf("Failed to set pod for test runtime: %v", err)
			}

			pod, err = testcluster.SetContainerResources(pod, "", testcluster.ContainerResourcesRequest{})
			if err != nil {
				t.Fatalf("Failed to set container resources: %v", err)
			}

			pod, err = cluster.CreatePod(ctx, pod)
			if err != nil {
				t.Fatalf("Failed to create pod: %v", err)
			}
			defer cluster.DeletePod(ctx, pod)

			recorder, err := benchmetric.GetRecorder(ctx)
			if err != nil {
				t.Fatalf("Failed to initialize benchmark recorder: %v", err)
			}
			containerDuration, err := benchmetric.GetTimedContainerDuration(ctx, cluster, pod, name)
			if err != nil {
				t.Fatalf("Failed to get container duration: %v", err)
			}
			if err := recorder.Record(ctx, fmt.Sprintf("gRPC/%s", test.name), benchmetric.BenchmarkDuration(containerDuration)); err != nil {
				t.Fatalf("Failed to record benchmark data: %v", err)
			}
		})
	}
}

func newGRPCPod(namespace *testcluster.Namespace, name, image string, volume *v13.Volume) *v13.Pod {
	const workdir = "/workdir"
	initCommand := []string{
		"sh",
		"-c",
		strings.Join([]string{
			"mkdir", "-p", workdir,
			"&&",
			"cp", "-r", "/grpc", fmt.Sprintf("%s/.", workdir),
		}, " "),
	}
	command := []string{"bazel", "build", ":grpc"}
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
					Name:         name,
					Image:        image,
					Command:      benchmetric.CommandThenTimed(initCommand, path.Join(workdir, "grpc"), command),
					VolumeMounts: volumeMounts,
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}
