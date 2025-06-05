// Copyright 2025 The gVisor Authors.
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

// Package cudatest is a test that runs a CUDA workload on k8s clusters.
package cudatest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
)

var (
	// For some reason, nvidia removed nvidia-smi from the nvidia/cuda image.
	// So we use the nvidia/cuda:12.6.3-base-ubuntu22.04 image which has nvidia-smi.
	// This image is a few MB instead of GB.
	nvidiaSMIImage   = "nvidia/cuda:12.6.3-base-ubuntu22.04"
	cudaTestImage122 = k8s.ImageRepoPrefix + "gpu/cuda-tests_x86_64"
	cudaTestImage128 = k8s.ImageRepoPrefix + "gpu/cuda-tests-12-8_x86_64"

	testsToRun122 = []string{
		"0_Introduction/concurrentKernels",
		"0_Introduction/simpleStreams",
		"0_Introduction/clock_nvrtc",
		"0_Introduction/simpleTemplates_nvrtc",
		"1_Utilities/bandwidthTest",
		"2_Concepts_and_Techniques/inlinePTX_nvrtc",
		"3_CUDA_Features/simpleCudaGraphs",
		"4_CUDA_Libraries/freeImageInteropNPP",
		"4_CUDA_Libraries/histEqualizationNPP",
		"4_CUDA_Libraries/matrixMulCUBLAS",
		"4_CUDA_Libraries/nvJPEG_encoder",
		"5_Domain_Specific/p2pBandwidthLatencyTest",
		"6_Performance/LargeKernelParameter",
		"6_Performance/transpose",
		"7_libNVVM/uvmlite",
	}

	testsToRun128 = []string{
		"0_Introduction/simpleAttributes",
		"0_Introduction/simpleCUDA2GL",
		"0_Introduction/simpleP2P",
		"0_Introduction/simpleStreams",
		"0_Introduction/UnifiedMemoryStreams",
		"1_Utilities/topologyQuery",
		"2_Concepts_and_Techniques/inlinePTX_nvrtc",
		"2_Concepts_and_Techniques/threadMigration",
		"2_Concepts_and_Techniques/inlinePTX",
		"2_Concepts_and_Techniques/EGLStream_CUDA_Interop",
		"3_CUDA_Features/graphMemoryNodes",
		"4_CUDA_Libraries/nvJPEG_encoder",
		"4_CUDA_Libraries/conjugateGradientPrecond",
		"5_Domain_Specific/quasirandomGenerator_nvrtc",
	}
)

// RunCudaTest122 runs a CUDA workload on a GKE node.
func RunCudaTest122(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	doCudaTest(ctx, t, k8sCtx, cluster, cudaTestImage122, "12.2", testsToRun122)
}

// RunCudaTest128 runs a CUDA workload on a GKE node.
func RunCudaTest128(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	doCudaTest(ctx, t, k8sCtx, cluster, cudaTestImage128, "12.8", testsToRun128)
}

func doCudaTest(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster, image, minCudaVersion string, tests []string) {
	ns := cluster.Namespace("cuda-test")
	if err := ns.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer ns.Cleanup(ctx)

	cudaVersion, err := getCudaVersion(ctx, k8sCtx, cluster, ns)
	if err != nil {
		t.Fatalf("failed to get CUDA version: %v", err)
	}

	if !cudaVersion.IsAtLeast(dockerutil.MustParseCudaVersion(minCudaVersion)) {
		t.Skipf("CUDA version %s or above is required: got: %s", minCudaVersion, cudaVersion)
	}

	image, err = k8sCtx.ResolveImage(ctx, image)
	if err != nil {
		t.Fatalf("failed to resolve image %q: %v", image, err)
	}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			if err := runCudaTest(ctx, t, k8sCtx, cluster, ns, test, image); err != nil {
				t.Fatalf("failed to run CUDA test %q: %v", test, err)
			}
		})
	}
}

func getCudaVersion(ctx context.Context, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster, ns *testcluster.Namespace) (*dockerutil.CudaVersion, error) {
	pod := ns.NewAlpinePod(fmt.Sprintf("cuda-%d", time.Now().UnixNano()), nvidiaSMIImage, []string{"nvidia-smi"})
	pod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to set pod on cluster %q: %v", cluster.GetName(), err)
	}

	pod.Spec.RuntimeClassName = nil
	pod.Spec.Tolerations = append(pod.Spec.Tolerations, cluster.GetGVisorRuntimeToleration())
	pod, err = testcluster.SetContainerResources(pod, pod.Spec.Containers[0].Name, testcluster.ContainerResourcesRequest{GPU: true})
	if err != nil {
		return nil, fmt.Errorf("failed to set container resources on cluster %q: %v", cluster.GetName(), err)
	}
	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		return nil, fmt.Errorf("failed to create pod on cluster %q: %v", cluster.GetName(), err)
	}
	defer cluster.DeletePod(ctx, pod)
	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		return nil, fmt.Errorf("failed to wait for pod on cluster %q: %v", cluster.GetName(), err)
	}
	reader, err := cluster.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get log reader on cluster %q: %v", cluster.GetName(), err)
	}
	defer reader.Close()
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		return nil, fmt.Errorf("failed to read log on cluster %q: %v", cluster.GetName(), err)
	}
	return dockerutil.NewCudaVersionFromOutput(buf.String())
}

func runCudaTest(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster, ns *testcluster.Namespace, test, image string) error {
	pod := ns.NewAlpinePod(fmt.Sprintf("cuda-%d", time.Now().UnixNano()), image, []string{"/run_sample", test})
	pod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		return fmt.Errorf("failed to set pod on cluster %q: %v", cluster.GetName(), err)
	}
	pod, err = testcluster.SetContainerResources(pod, pod.Spec.Containers[0].Name, testcluster.ContainerResourcesRequest{GPU: true})
	if err != nil {
		return fmt.Errorf("failed to set container resources on cluster %q: %v", cluster.GetName(), err)
	}
	pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, v13.EnvVar{
		Name:  "NVIDIA_DRIVER_CAPABILITIES",
		Value: "all",
	})
	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		return fmt.Errorf("failed to create pod on cluster %q: %v", cluster.GetName(), err)
	}
	defer cluster.DeletePod(ctx, pod)
	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		return fmt.Errorf("failed to wait for pod on cluster %q: %v", cluster.GetName(), err)
	}
	reader, err := cluster.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		return fmt.Errorf("failed to get log reader on cluster %q: %v", cluster.GetName(), err)
	}
	defer reader.Close()
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		t.Logf("Test output:\n%s", buf.String())
		return fmt.Errorf("failed to read log on cluster %q: %v", cluster.GetName(), err)
	}

	if !strings.Contains(buf.String(), fmt.Sprintf("Test passed: %s", test)) {
		return fmt.Errorf("test failed: %s", buf.String())
	}

	return nil
}
