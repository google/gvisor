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

package stablediffusion

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/test/gpu/stablediffusion"
	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Container image for Stable Diffusion XL.
	stableDiffusionImage = k8s.ImageRepoPrefix + "gpu/stable-diffusion-xl:latest"
)

// kubernetesPodRunner implements `stablediffusion.ContainerRunner`.
type kubernetesPodRunner struct {
	cluster   *testcluster.TestCluster
	namespace *testcluster.Namespace
}

// Run implements `stablediffusion.ContainerRunner.Run`.
func (r *kubernetesPodRunner) Run(ctx context.Context, image string, argv []string) ([]byte, []byte, error) {
	// Build pod spec.
	const stableDiffusionXLPodName = "stable-diffusion-xl"
	stableDiffusionXLPod := &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      stableDiffusionXLPodName,
			Namespace: r.namespace.Namespace,
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  stableDiffusionXLPodName,
					Image: image,
					Args:  argv,
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
	stableDiffusionXLPod, err := r.cluster.ConfigurePodForRuntimeTestNodepool(ctx, stableDiffusionXLPod)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to configure pod: %v", err)
	}
	stableDiffusionXLPod, err = testcluster.SetContainerResources(stableDiffusionXLPod, "", testcluster.ContainerResourcesRequest{GPU: true})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set container resources: %v", err)
	}

	// Delete pod that may possibly exist from a previous iteration.
	// Ignore errors since it most likely doesn't exist.
	r.cluster.DeletePod(ctx, stableDiffusionXLPod)

	// Start new client pod and wait for it.
	stableDiffusionXLPod, err = r.cluster.CreatePod(ctx, stableDiffusionXLPod)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create stable diffusion XL pod: %v", err)
	}
	defer r.cluster.DeletePod(ctx, stableDiffusionXLPod)
	if err := r.cluster.WaitForPodCompleted(ctx, stableDiffusionXLPod); err != nil {
		logs, logsErr := r.cluster.ReadPodLogs(ctx, stableDiffusionXLPod)
		logs = strings.TrimSpace(logs)
		if logsErr != nil {
			return nil, nil, fmt.Errorf("failed to run Stable Diffusion XL (%w) and to read logs from the pod: %v", err, logsErr)
		}
		if logs == "" {
			return nil, nil, fmt.Errorf("failed to run Stable Diffusion XL: %w (pod logs are empty)", err)
		}
		return nil, nil, fmt.Errorf("failed to run Stable Diffusion XL: %w (pod logs: %v)", err, logs)
	}

	// All good, get logs.
	logs, err := r.cluster.ReadPodLogs(ctx, stableDiffusionXLPod)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read logs from pod %q: %v", stableDiffusionXLPod.GetName(), err)
	}
	return []byte(logs), nil, nil
}

// RunStableDiffusionXL runs Stable Diffusion XL benchmarks for a single cluster.
func RunStableDiffusionXL(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("cannot reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)
	reqWaitCtx, reqWaitCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer reqWaitCancel()
	if err := benchmarkNS.WaitForResources(reqWaitCtx, testcluster.ContainerResourcesRequest{GPU: true}); err != nil {
		t.Fatalf("failed to wait for resources: %v", err)
	}
	endProfiling, err := profiling.MaybeSetup(ctx, t, k8sCtx, cluster, benchmarkNS)
	if err != nil {
		t.Fatalf("Failed to setup profiling: %v", err)
	}
	defer endProfiling()

	imageName, err := k8sCtx.ResolveImage(ctx, stableDiffusionImage)
	if err != nil {
		t.Fatalf("failed to resolve image: %v", err)
	}
	xl := stablediffusion.NewXL(imageName, &kubernetesPodRunner{
		cluster:   cluster,
		namespace: benchmarkNS,
	})

	// The refiner model uses a lot of VRAM, and not all GPUs have enough of
	// that to make it work.
	// So we try each prompt without the refiner first. If it fails, then we
	// don't try the same prompt with the refiner, as there is no way it will
	// work. Similarly, if the benchmark does work without the refiner but
	// does not work with the refiner, then future prompts will all have their
	// refiner model attempt skipped.
	refinerFailed := false

	for _, test := range []struct {
		name          string
		query         string
		useRefiner    bool
		noiseFraction float64
		steps         int
	}{
		{
			name:          "BoringCorporateLogo",
			query:         `A boring flat corporate logo that says "gVisor"`,
			useRefiner:    true,
			noiseFraction: 0.9,
			steps:         32,
		},
		{
			name:          "Androids",
			query:         "Photorealistic image of two androids playing chess aboard a spaceship",
			useRefiner:    true,
			noiseFraction: 0.85,
			steps:         64,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			failedWithoutRefiner := false
			for _, useRefiner := range []bool{false, true} {
				t.Run(fmt.Sprintf("refiner=%t", useRefiner), func(t *testing.T) {
					if useRefiner {
						if failedWithoutRefiner {
							t.Skipf("benchmark failed without refiner; skipping benchmark with refiner")
						}
						if refinerFailed {
							t.Skipf("refiner failed in previous benchmark; skipping benchmark with refiner")
						}
					}
					testCtx, testCancel := context.WithTimeout(ctx, 50*time.Minute)
					defer testCancel()
					prompt := &stablediffusion.XLPrompt{
						Query:           test.query,
						AllowCPUOffload: false,
						NoiseFraction:   test.noiseFraction,
						Steps:           test.steps,
						Warm:            true,
						UseRefiner:      useRefiner,
					}
					image, err := xl.Generate(testCtx, prompt)
					if err != nil {
						if useRefiner {
							refinerFailed = true
							t.Skipf("Failed to generate image with Refiner; will skip future attempts to run any prompt with the refiner.")
						}
						failedWithoutRefiner = true
						t.Fatalf("Failed to generate images: %v", err)
					}
					ascii, err := image.ASCII()
					if err != nil {
						t.Fatalf("Failed to get ASCII: %v", err)
					}
					t.Logf("Generated image:\n\n%s\n", ascii)
					hash := fnv.New32()
					hash.Write([]byte(ascii))
					recorder, err := benchmetric.GetRecorder(ctx)
					if err != nil {
						t.Fatalf("Failed to initialize benchmark recorder: %v", err)
					}
					metrics := []benchmetric.MetricValue{
						benchmetric.BenchmarkDuration(image.TotalDuration()),
						benchmetric.SpecificDuration(image.ColdBaseDuration(), "base-cold"),
						benchmetric.SpecificDuration(image.WarmBaseDuration(), "base-warm"),
					}
					if coldRefinerDuration := image.ColdRefinerDuration(); coldRefinerDuration >= 0 {
						metrics = append(metrics, benchmetric.SpecificDuration(coldRefinerDuration, "refiner-cold"))
					}
					if warmRefinerDuration := image.WarmRefinerDuration(); warmRefinerDuration >= 0 {
						metrics = append(metrics, benchmetric.SpecificDuration(warmRefinerDuration, "refiner-warm"))
					}
					// The image-hash metric should never change; it is still useful to
					// report as a metric in order to detect instability across benchmark
					// runs.
					metrics = append(metrics, benchmetric.Checksum(hash, "image"))
					if err := recorder.Record(ctx, fmt.Sprintf("StableDiffusionXL/%s/refiner=%t/steps=%d", test.name, useRefiner, test.steps), metrics...); err != nil {
						t.Fatalf("Failed to record benchmark data: %v", err)
					}
				})
			}
		})
	}
}
