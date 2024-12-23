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

// Package pytorch contains benchmarks using the pytorch "torchbench" repo.
package pytorch

// These tests use pytorch's "torchbench" suite (https://github.com/pytorch/benchmark/tree/main).
// The Authors describe the benchmarks in this paper: https://arxiv.org/pdf/2304.14226.pdf
// The Authors list both the type of model and its profile (how GPU intensive).

// Note: The image for this test is about 7-8 GB as of writing. After you get your clusters up and
// running, start the test and make sure that the pods show the event of downloading the image. Then
// get a cup of coffee, chat with your co-workers for 5 min, and it will be about done 5 min after
// that. You'll only need to do this once for each cluster (in parallel).

import (
	"context"
	"fmt"
	"io"
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
)

// pytorchTestType is the method used, either training or evaluation, for the model.
type pytorchTestType string

const (
	train = pytorchTestType("train")
	eval  = pytorchTestType("eval")

	pytorchImage = k8s.ImageRepoPrefix + "gpu/pytorch_x86_64:latest"
)

type pytorchTest struct {
	module string
	test   pytorchTestType
}

// Sets of tests.
var (
	// FastNLPBert uses the fastNLP_Bert module, which is classified as a NLP Language Model.
	// fastNLP_Bert taxes the GPU heavily with low data movement. See Figure 2 on
	// page 5: https://arxiv.org/pdf/2304.14226.pdf
	//
	// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/fastNLP_Bert
	// Bert Blog Post: https://towardsdatascience.com/bert-explained-state-of-the-art-language-model-for-nlp-f8b21a9b6270
	// Paper: https://arxiv.org/abs/1810.04805
	FastNLPBert = []pytorchTest{
		{
			module: "fastNLP_Bert",
			test:   train,
		},
		{
			module: "fastNLP_Bert",
			test:   eval,
		},
	}

	// BigBird uses the hf_BigBird module, which is classified as a NLP Language Model.
	// hf_BigBird taxes the GPU moderately with low data movement. See Figure 2 on
	// page 5 (speech_tf): https://arxiv.org/pdf/2304.14226.pdf
	//
	// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/hf_BigBird
	// Paper: https://arxiv.org/abs/2007.14062
	BigBird = []pytorchTest{
		{
			module: "hf_BigBird",
			test:   train,
		},
		{
			module: "hf_BigBird",
			test:   eval,
		},
	}

	// SpeechTransformer uses the speech_transformer module classified as "Speech Recognition"
	// model. speech_transformer has a lot of idle time for the GPU. See Figure 2 on
	// page 5 (speech_tf): https://arxiv.org/pdf/2304.14226.pdf
	//
	// https://github.com/pytorch/benchmark/pull/374
	// Paper: https://arxiv.org/abs/1706.03762
	SpeechTransformer = []pytorchTest{
		{
			module: "speech_transformer",
			test:   train,
		},
		{
			module: "speech_transformer",
			test:   eval,
		},
	}

	// LearningToPaint uses the LearningToPaint module classified as "neural renderer in model-based
	// Deep Reinforcement Learning (DRL)".
	// Learning to paint has a lot of "data movement" and doesn't tax the GPU a lot. See Figure 2 on
	// page 5: https://arxiv.org/pdf/2304.14226.pdf
	//
	// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/LearningToPaint
	LearningToPaint = []pytorchTest{
		{
			module: "LearningToPaint",
			test:   train,
		},
		{
			module: "LearningToPaint",
			test:   eval,
		},
	}

	// MobileNetV2 uses the mobilenet_v2 module classified as "Computer Vision: Image Classification".
	// MobileNet has a lot of taxes the GPU. See Figure 2 on page 5: https://arxiv.org/pdf/2304.14226.pdf
	//
	// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/mobilenet_v2
	// Paper: https://paperswithcode.com/method/mobilenetv2
	MobileNetV2 = []pytorchTest{
		{
			module: "mobilenet_v2",
			test:   train,
		},
		{
			module: "mobilenet_v2",
			test:   eval,
		},
	}

	// AllTests is a map of test names to the tests.
	AllTests = map[string][]pytorchTest{
		"FastNLPBert":       FastNLPBert,
		"BigBird":           BigBird,
		"SpeechTransformer": SpeechTransformer,
		"LearningToPaint":   LearningToPaint,
		"MobileNetV2":       MobileNetV2,
	}
)

// Name returns the name of the test with the argument parameters included. It is formatted so
// that it can be used for the name of the pod.
func (p pytorchTest) Name() string {
	// Kubernetes pod names cannot contain "_".
	module := strings.ReplaceAll(strings.ToLower(p.module), "_", "-")
	return fmt.Sprintf("%s-%s", module, p.test)
}

var snakeCase = regexp.MustCompile("_.")

// BenchName returns the name of the test with the argument parameters included.
// It is formatted so that it can be used for benchstat output.
func (p pytorchTest) BenchName() string {
	// First letter of the module should be capitalized, as it will be
	// concatenated with "Benchmark" and it's useful to mark it as a different
	// word.
	// Some modules use a lowercase first letter, e.g. "fastNLP_Bert".
	moduleName := strings.ToUpper(p.module[:1]) + p.module[1:]
	// We also replace "snake_case" with "snakeCase". Sorry snakes.
	moduleName = snakeCase.ReplaceAllStringFunc(moduleName, func(s string) string {
		return strings.ToUpper(strings.TrimPrefix(s, "_"))
	})
	test := strings.ToUpper(string(p.test)[:1]) + string(p.test[1:])
	return fmt.Sprintf("%s/%s", moduleName, test)
}

func (p pytorchTest) toPod(namespace *testcluster.Namespace, image string) (*v13.Pod, error) {
	pod := namespace.NewPod(p.Name())
	pod.Spec = v13.PodSpec{
		RestartPolicy: v13.RestartPolicyNever,
		Containers: []v13.Container{
			{
				Name:    p.Name(),
				Image:   pytorchImage,
				Command: benchmetric.TimedCommand(p.command()...),
			},
		},
	}
	return pod, nil
}

func (p pytorchTest) command() []string {
	return []string{
		"sh",
		"-c",
		strings.Join([]string{
			"cd /pytorch-benchmark",
			fmt.Sprintf("python3 run.py %s --device cuda --test %s", p.module, p.test),
		}, " && "),
	}
}

// RunPytorch runs the given PyTorch tests sequentially on a single cluster.
func RunPytorch(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster, tests []pytorchTest) {
	t.Helper()
	for _, test := range tests {
		t.Run(test.Name(), func(t *testing.T) {
			doPytorchRun(ctx, t, k8sCtx, cluster, test)
		})
	}
}

// doPytorchRun runs a single PyTorch test.
func doPytorchRun(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster, params pytorchTest) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("Failed to reset namespace: %v", err)
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

	image, err := k8sCtx.ResolveImage(ctx, pytorchImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	pod, err := params.toPod(benchmarkNS, image)
	if err != nil {
		t.Fatalf("Failed to create pod: %v", err)
	}

	pod, err = cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to configure pod for test-nodepool: %v", err)
	}

	pod, err = testcluster.SetContainerResources(pod, "", testcluster.ContainerResourcesRequest{GPU: true})
	if err != nil {
		t.Fatalf("Failed to set container resources: %v", err)
	}

	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to create pod: %v", err)
	}
	defer cluster.DeletePod(ctx, pod)

	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		t.Fatalf("Failed to wait for pod to complete: %v", err)
	}

	rdr, err := cluster.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		t.Fatalf("GetLogReader on cluster %q pod %v: %v", cluster.GetName(), pod.GetName(), err)
	}

	out, err := io.ReadAll(rdr)
	if err != nil {
		t.Fatalf("failed to read from pod: %q: %v", pod.GetName(), err)
	}

	metrics, err := parseStandardOutput(string(out))
	if err != nil {
		t.Fatalf("parseStandardOutput: %v", err)
	}

	containerDuration, err := benchmetric.ParseTimedContainerOutput(string(out))
	if err != nil {
		t.Fatalf("Failed to get container duration: %v", err)
	}

	metrics = append(metrics, benchmetric.BenchmarkDuration(containerDuration))

	recorder, err := benchmetric.GetRecorder(ctx)
	if err != nil {
		t.Fatalf("Failed to initialize benchmark recorder: %v", err)
	}
	if err := recorder.Record(ctx, params.BenchName(), metrics...); err != nil {
		t.Fatalf("Failed to record benchmark data: %v", err)
	}
}

func parseStandardOutput(output string) ([]benchmetric.MetricValue, error) {
	gpuTimeMillis, err := parseGPUTime(output)
	if err != nil {
		return nil, fmt.Errorf("parseGPUTime: %v", err)
	}

	gpuPeakMemoryGB, err := parseGPUPeakMemoryGB(output)
	if err != nil {
		return nil, fmt.Errorf("parseGPUPeakMemory: %v", err)
	}

	cpuPeakMemoryGB, err := parseCPUPeakMemoryGB(output)
	if err != nil {
		return nil, fmt.Errorf("parseCPUPeakMemory: %v", err)
	}

	return []benchmetric.MetricValue{
		benchmetric.SpecificDuration(time.Duration(gpuTimeMillis)*time.Millisecond, "gpu-runtime"),
		benchmetric.SpecificBytes(gpuPeakMemoryGB*1024*1024*1024, "gpu-peak-memory"),
		benchmetric.SpecificBytes(cpuPeakMemoryGB*1024*1024*1024, "cpu-peak-memory"),
	}, nil
}

var gpuTimeRegex = regexp.MustCompile(`GPU\sTime\sper\sbatch:\s*(\d+\.\d+)\smilliseconds`)

func parseGPUTime(output string) (float64, error) {
	match := gpuTimeRegex.FindStringSubmatch(output)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed to find GPU Time: %s", output)
	}
	return strconv.ParseFloat(match[1], 64)
}

var gpuPeakMemoryRegex = regexp.MustCompile(`GPU\s0\sPeak\sMemory:\s*(\d+\.\d+)\sGB`)

func parseGPUPeakMemoryGB(output string) (float64, error) {
	match := gpuPeakMemoryRegex.FindStringSubmatch(output)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed to find GPU Peak Memory: %s", output)
	}
	return strconv.ParseFloat(match[1], 64)
}

var cpuPeakMemoryRegex = regexp.MustCompile(`CPU\sPeak\sMemory:\s*(\d+\.\d+)\sGB`)

func parseCPUPeakMemoryGB(output string) (float64, error) {
	match := cpuPeakMemoryRegex.FindStringSubmatch(output)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed to find CPU Peak Memory: %s", output)
	}
	return strconv.ParseFloat(match[1], 64)
}
