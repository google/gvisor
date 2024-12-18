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

package tensorflow

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	imageAMD = k8s.ImageRepoPrefix + "benchmarks/tensorflow_x86_64:latest"
	imageARM = k8s.ImageRepoPrefix + "benchmarks/tensorflow_aarch64:latest"
)

var workloads = map[string]string{
	"Kmeans":               "2_BasicModels/kmeans.py",
	"LogisticRegression":   "2_BasicModels/logistic_regression.py",
	"NearestNeighbor":      "2_BasicModels/nearest_neighbor.py",
	"RandomForest":         "2_BasicModels/random_forest.py",
	"ConvolutionalNetwork": "3_NeuralNetworks/convolutional_network.py",
	"MultilayerPerceptron": "3_NeuralNetworks/multilayer_perceptron.py",
	"NeuralNetwork":        "3_NeuralNetworks/neural_network.py",
}

// RunTensorflowOnCPU runs the Tensorflow example workloads on CPU.
func RunTensorflowOnCPU(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
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

	const name = "tensorflow"
	recorder, err := benchmetric.GetRecorder(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize benchmark recorder: %v", err)
	}

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

	workloadPaths := make([]string, 0, len(workloads))
	workloadPathToName := make(map[string]string, len(workloads))
	for name, path := range workloads {
		workloadPaths = append(workloadPaths, path)
		workloadPathToName[path] = name
	}
	sort.Strings(workloadPaths)

	var total time.Duration
	for _, workloadPath := range workloadPaths {
		workloadName := workloadPathToName[workloadPath]
		t.Run(workloadName, func(t *testing.T) {
			pod := newTensorflowOnCPUPod(benchmarkNS, name, image, workloadPath)
			pod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
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

			containerDuration, err := benchmetric.GetTimedContainerDuration(ctx, cluster, pod, name)
			if err != nil {
				t.Fatalf("Failed to get container duration: %v", err)
			}
			if err := recorder.Record(ctx, fmt.Sprintf("TensorflowOnCPU/%s", workloadName), benchmetric.BenchmarkDuration(containerDuration)); err != nil {
				t.Fatalf("Failed to record benchmark data: %v", err)
			}
			total += containerDuration
		})
		if t.Failed() {
			break
		}
	}
	if !t.Failed() {
		if err := recorder.Record(ctx, "TensorflowOnCPU", benchmetric.BenchmarkDuration(total)); err != nil {
			t.Fatalf("Failed to record benchmark data: %v", err)
		}
	}
}

func newTensorflowOnCPUPod(namespace *testcluster.Namespace, name, image, workloadPath string) *v13.Pod {
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
					Name:       name,
					Image:      image,
					Command:    benchmetric.TimedCommand("python", workloadPath),
					WorkingDir: "/TensorFlow-Examples/examples",
					Env: []v13.EnvVar{
						{
							Name:  "PYTHONPATH",
							Value: "/TensorFlow-Examples/examples",
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}
