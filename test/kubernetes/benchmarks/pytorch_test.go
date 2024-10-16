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

// Package pytorch_test contains benchmarks using the pytorch "torchbench" repo.
package pytorch_test

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

	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"

	v13 "k8s.io/api/core/v1"
)

const (
	pytorchImage = "gcr.io/gvisor-presubmit/benchmarks/pytorch_x86_64:f6f280aeb1b07989"
)

// pytorchTestType is the method used, either training or evaluation, for the model.
type pytorchTestType string

const (
	train = pytorchTestType("train")
	eval  = pytorchTestType("eval")
)

type pytorchMode string

// pytorchMode is the pytorch mode used, either script mode (jit) or eager mode.
// See: https://towardsdatascience.com/pytorch-jit-and-torchscript-c2a77bac0fff
const (
	jit   = pytorchMode("jit")
	eager = pytorchMode("eager")
)

type pytorchTest struct {
	module string
	test   pytorchTestType
	mode   pytorchMode
}

// Name returns the name of the test with the argument parameters included. It is formatted so
// that it can be used for the name of the pod.
func (p pytorchTest) Name() string {
	// Kubernetes pod names cannot contain "_".
	module := strings.ReplaceAll(strings.ToLower(p.module), "_", "-")
	return fmt.Sprintf("%s-%s-%s", module, p.test, p.mode)
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
	var mode string
	switch p.mode {
	case eager:
		mode = "Eager"
	case jit:
		mode = "JIT"
	default:
		panic(fmt.Sprintf("Unknown mode: %v", p.mode))
	}
	return fmt.Sprintf("%s/%s/%s", moduleName, test, mode)
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
		"python",
		"run.py",
		p.module,
		"--device", "cuda",
		"--test", string(p.test),
		"--mode", string(p.mode),
	}
}

// TestFastNLPBert uses the fastNLP_Bert module, which is classified as a NLP Language Model.
// fastNLP_Bert taxes the GPU heavily with low data movement. See Figure 2 on
// page 5: https://arxiv.org/pdf/2304.14226.pdf
//
// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/fastNLP_Bert
// Bert Blog Post: https://towardsdatascience.com/bert-explained-state-of-the-art-language-model-for-nlp-f8b21a9b6270
// Paper: https://arxiv.org/abs/1810.04805
func TestFastNLPBert(t *testing.T) {
	ctx := context.Background()
	const module = "fastNLP_Bert"
	tests := []pytorchTest{
		{
			module: module,
			test:   train,
			mode:   eager,
		},
		{
			module: module,
			test:   eval,
			mode:   eager,
		},
	}
	runTests(ctx, t, tests)
}

// TestBigBird uses the hf_BigBird module, which is classified as a NLP Language Model.
// hf_BigBird taxes the GPU moderately with low data movement. See Figure 2 on
// page 5 (speech_tf): https://arxiv.org/pdf/2304.14226.pdf
//
// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/hf_BigBird
// Paper: https://arxiv.org/abs/2007.14062
func TestBigBird(t *testing.T) {
	ctx := context.Background()
	const module = "hf_BigBird"
	tests := []pytorchTest{
		{
			module: module,
			test:   train,
			mode:   eager,
		},
		{
			module: module,
			test:   eval,
			mode:   eager,
		},
	}
	runTests(ctx, t, tests)
}

// TestSpeechTransformer uses the speech_transformer module classified as "Speech Recognition"
// model. speech_transformer has a lot of idle time for the GPU. See Figure 2 on
// page 5 (speech_tf): https://arxiv.org/pdf/2304.14226.pdf
//
// https://github.com/pytorch/benchmark/pull/374
// Paper: https://arxiv.org/abs/1706.03762
func TestSpeechTransformer(t *testing.T) {
	ctx := context.Background()
	const module = "speech_transformer"
	tests := []pytorchTest{
		{
			module: module,
			test:   train,
			mode:   eager,
		},
		{
			module: module,
			test:   eval,
			mode:   eager,
		},
	}
	runTests(ctx, t, tests)
}

// TestLearningToPaint uses the LearningToPaint module classified as "neural renderer in model-based
// Deep Reinforcement Learning (DRL)".
// Learning to paint has a lot of "data movement" and doesn't tax the GPU a lot. See Figure 2 on
// page 5: https://arxiv.org/pdf/2304.14226.pdf
//
// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/LearningToPaint
func TestLearningToPaint(t *testing.T) {
	ctx := context.Background()
	const module = "LearningToPaint"
	tests := []pytorchTest{
		{
			module: module,
			test:   train,
			mode:   jit,
		},
		{
			module: module,
			test:   eval,
			mode:   jit,
		},
	}
	runTests(ctx, t, tests)
}

// TestMobileNetV2 uses the mobilenet_v2 module classified as "Computer Vision: Image Classification".
// MobileNet has a lot of taxes the GPU. See Figure 2 on page 5: https://arxiv.org/pdf/2304.14226.pdf
//
// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/mobilenet_v2
// Paper: https://paperswithcode.com/method/mobilenetv2
func TestMobileNetV2(t *testing.T) {
	ctx := context.Background()
	const module = "mobilenet_v2"
	tests := []pytorchTest{
		{
			module: module,
			test:   train,
			mode:   jit,
		},
		{
			module: module,
			test:   eval,
			mode:   jit,
		},
	}
	runTests(ctx, t, tests)
}

// TestBackgroundMatting uses the Background_Matting module classified as "Computer Vision: Pattern Recognition".
// BackgroundMatting has a lot of GPU idle time. See Figure 2 on page 5: https://arxiv.org/pdf/2304.14226.pdf
//
// https://github.com/pytorch/benchmark/tree/main/torchbenchmark/models/Background_Matting (see README)
func TestBackgroundMatting(t *testing.T) {
	ctx := context.Background()
	const module = "Background_Matting"
	tests := []pytorchTest{
		{
			module: module,
			test:   train,
			mode:   eager,
		},
		{
			module: module,
			test:   eval,
			mode:   eager,
		},
	}
	runTests(ctx, t, tests)
}

func runTests(ctx context.Context, t *testing.T, tests []pytorchTest) {
	k8sCtx, err := k8sctx.Context(ctx)
	if err != nil {
		t.Fatalf("Failed to get kubernetes context: %v", err)
	}
	k8sCtx.ForEachCluster(ctx, t, func(cluster *testcluster.TestCluster) {
		t.Run("PyTorch", func(t *testing.T) {
			t.Parallel()
			for _, p := range tests {
				t.Run(p.Name(), func(t *testing.T) {
					doPytorchRun(ctx, t, k8sCtx, cluster, p)
				})
			}
		})
	})
}

func doPytorchRun(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster, params pytorchTest) {
	benchmarkNS := cluster.Namespace(testcluster.NamespaceBenchmark)
	endProfiling, err := profiling.MaybeSetup(ctx, t, cluster, benchmarkNS)
	if err != nil {
		t.Fatalf("Failed to setup profiling: %v", err)
	}
	defer endProfiling()
	if err := benchmarkNS.Reset(ctx); err != nil {
		t.Fatalf("Failed to reset namespace: %v", err)
	}
	defer benchmarkNS.Cleanup(ctx)

	image, err := k8sCtx.ResolveImage(ctx, pytorchImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	pod, err := params.toPod(benchmarkNS, image)
	if err != nil {
		t.Fatalf("Failed to create pod: %v", err)
	}

	pod, err = cluster.ConfigurePodForRuntimeTestNodepool(pod)
	if err != nil {
		t.Fatalf("Failed to configure pod for test-nodepool: %v", err)
	}

	pod, err = testcluster.MaybeSetContainerResources(pod, pod.Name, testcluster.ContainerResourcesRequest{GPU: true})
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

var gpuTimeRegex = regexp.MustCompile(`GPU\sTime:\s*(\d+\.\d+)\smilliseconds`)

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

func TestMain(m *testing.M) {
	k8sctx.TestMain(m, map[string]k8sctx.TestFunc{
		"TestFastNLPBert":       TestFastNLPBert,
		"TestBigBird":           TestBigBird,
		"TestSpeechTransformer": TestSpeechTransformer,
		"TestLearningToPaint":   TestLearningToPaint,
		"TestMobileNetV2":       TestMobileNetV2,
		"TestBackgroundMatting": TestBackgroundMatting,
	})
}
