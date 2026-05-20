// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You maye may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package triton provides a benchmark for triton on Kubernetes.
package triton

import (
	"context"
	_ "embed"
	"fmt"
	"hash/fnv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/test/gpu/triton"
	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/utils"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// tritonPodServer implements `triton.Server`.
// It performs requests against the triton server pod.
type tritonPodServer struct {
	cluster     *testcluster.TestCluster
	clientImage string
	pod         *v13.Pod
	service     *v13.Service
}

// InstrumentedRequest implements `triton.Server.InstrumentedRequest`.
func (sps *tritonPodServer) InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error) {
	return sps.cluster.ExecRequestInClientPod(ctx, sps.service, sps.pod.ObjectMeta.Namespace, sps.clientImage, "triton-client", argvFn)
}

// Logs implements `triton.Server.Logs`.
func (sps *tritonPodServer) Logs(ctx context.Context) (string, error) {
	return sps.cluster.ReadPodLogs(ctx, sps.pod)
}

// atLeastNWords verifies that the response at least N words.
// If not, it raises the temperature.
func atLeastNWords(wantNWords int) func(prompt *triton.Prompt, response *triton.Response) (*triton.Prompt, error) {
	return func(prompt *triton.Prompt, response *triton.Response) (*triton.Prompt, error) {
		if err := utils.CheckAtLeastNWords(response.Text(), wantNWords); err != nil {
			return prompt.WithHotterModel(), err
		}
		return nil, nil
	}
}

// wantSubstring verifies that the response contains the given substring.
// If not, it raises the temperature.
func wantSubstring(substring string) func(prompt *triton.Prompt, response *triton.Response) (*triton.Prompt, error) {
	return func(prompt *triton.Prompt, response *triton.Response) (*triton.Prompt, error) {
		if !strings.Contains(strings.ToLower(response.Text()), strings.ToLower(substring)) {
			return prompt.WithHotterModel(), fmt.Errorf("response %q does not contain substring %q", response.Text(), substring)
		}
		return nil, nil
	}
}

// BenchmarkTriton runs triton benchmarks for a single cluster.
func BenchmarkTriton(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
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

	logWithTime := func(t *testing.T, format string, values ...any) {
		t.Logf("[%v] "+format, append([]any{time.Now().Format(time.TimeOnly)}, values...)...)
	}

	// Make sure we're running on the right architecture.
	testCPUArch, err := cluster.RuntimeTestNodepoolArchitecture(ctx)
	if err != nil {
		t.Fatalf("Failed to get runtime test nodepool architecture: %v", err)
	}

	if testCPUArch != testcluster.CPUArchitectureX86 {
		t.Fatalf("Unsupported CPU architecture: %v", testCPUArch)
	}

	// Run pod and service.
	serverImage, err := k8sCtx.ResolveImage(ctx, tritonBenchImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	tritonPod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, newTritonServerPod(benchmarkNS, serverImage))
	if err != nil {
		t.Fatalf("Failed to configure pod for runtime nodepool: %v", err)
	}
	tritonPod, err = testcluster.SetContainerResources(tritonPod, "", testcluster.ContainerResourcesRequest{GPU: true})
	if err != nil {
		t.Fatalf("Failed to set container resources: %v", err)
	}
	tritonPod, err = cluster.CreatePod(ctx, tritonPod)
	if err != nil {
		t.Fatalf("Failed to create triton pod: %v", err)
	}
	defer cluster.DeletePod(ctx, tritonPod)
	logWithTime(t, "Waiting for triton server pod to start, this may take a long time (tens of minutes) if this is the first time the image is being downloaded onto the node.")
	startCtx, startCtxCancel := context.WithTimeout(ctx, 90*time.Minute)
	if err := cluster.WaitForPodRunning(startCtx, tritonPod); err != nil {
		t.Fatalf("Failed to wait for triton server pod: %v", err)
	}
	startCtxCancel()
	logWithTime(t, "Triton server pod started on Kubernetes but not yet initialized.")
	tritonService := newTritonService(benchmarkNS)
	tritonService, err = cluster.CreateService(ctx, tritonService)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer cluster.DeleteService(ctx, tritonService)
	tritonClientImage, err := k8sCtx.ResolveImage(ctx, tritonBenchClientImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	tritonServer := &tritonPodServer{
		cluster:     cluster,
		clientImage: tritonClientImage,
		service:     tritonService,
		pod:         tritonPod,
	}
	llm, err := triton.New(ctx, tritonServer, t)
	if err != nil {
		t.Fatalf("Failed to create triton client against server pod: %v", err)
	}
	logWithTime(t, "Triton server ready.")

	// Define test cases.
	type testCase struct {
		// Name of the test.
		name string
		// Query for the triton server.
		query string
		// If set, run this function over the response to verify it.
		// The LLM is prompted repeatedly until this function returns a non-nil error.
		// This function may also return a non-nil prompt if it needs to modify the prompt
		// for the next attempt. This is useful to raise the model temperature.
		verifyResponse func(*triton.Prompt, *triton.Response) (*triton.Prompt, error)
	}
	testCases := []testCase{
		{
			name: "HelloWorld",
			query: `
				Can you echo me back: "Hello World!"
			`,
			verifyResponse: atLeastNWords(2),
		},
		{
			name: "StoryTeller",
			query: `
				Tell me a very long story about a cat, bird and dog."
			`,
			verifyResponse: atLeastNWords(32),
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			verifyFn := atLeastNWords(1)
			if test.verifyResponse != nil {
				verifyFn = test.verifyResponse
			}
			numAttempts := 0
			verifyFnCount := func(prompt *triton.Prompt, resp *triton.Response) (*triton.Prompt, error) {
				numAttempts++
				prompt.RaiseTemperature()
				return verifyFn(prompt, resp)
			}
			const testTimeout = 60 * time.Minute
			testCtx, testCancel := context.WithTimeout(ctx, testTimeout)
			defer testCancel()

			prompt := triton.ZeroTemperaturePrompt(test.query, 1024)
			resp, err := llm.PromptUntil(testCtx, prompt, verifyFnCount)
			if err != nil {
				t.Fatalf("cannot prompt: %v", err)
			}
			logWithTime(t, "Prompting with query:\n%s\n\nResponse:\n%s\n(end of response)", prompt.CleanQuery(), resp.Text())
			respHash := fnv.New32()
			respHash.Write([]byte(resp.Text()))
			recorder, err := benchmetric.GetRecorder(ctx)
			if err != nil {
				t.Fatalf("Failed to initialize benchmark recorder: %v", err)
			}
			err = recorder.Record(
				ctx,
				fmt.Sprintf("Triton/%s", test.name),
				benchmetric.BenchmarkDuration(time.Duration(resp.E2ELatency()*float64(time.Second))),
				benchmetric.SpecificDuration(resp.TimeToFirstToken(), "tok-first"),
				benchmetric.SpecificDuration(resp.TimeToLastToken(), "tok-last"),
				benchmetric.Rate(resp.OutputTokensPerSecond(), "tok"),
				benchmetric.Count(uint64(numAttempts), "prompt-attempts"),
				benchmetric.Count(uint64(resp.NumTokens()), "resp-tokens"),
				benchmetric.Checksum(respHash, "resp"),
			)
			if err != nil {
				t.Fatalf("Failed to record benchmark data: %v", err)
			}
		})
	}

	// Hack to force the test to wait until all sub-tests finish.
	// This is necessary to make sure the triton server does not get
	// deleted from the `defer` statements before the subtests above finish.
	var wg sync.WaitGroup
	wg.Add(1)
	t.Run("", func(t *testing.T) {
		wg.Done()
	})
	wg.Wait()
}

const (
	tritonServerLabelKey   = "app.kubernetes.io/name"
	tritonServerLabelValue = "triton-server"
	tritonPort             = 8000
	tritonPodName          = "triton-server"
	tritonServiceName      = "triton-service"
	tritonBenchImage       = k8s.ImageRepoPrefix + "gpu/triton_x86_64:latest"
	tritonBenchClientImage = k8s.ImageRepoPrefix + "gpu/ollama/client_x86_64:latest"
)

// newTritonServerPod returns the pod spec for a triton server.
func newTritonServerPod(namespace *testcluster.Namespace, image string) *v13.Pod {
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      tritonPodName,
			Namespace: namespace.Namespace,
			Labels:    map[string]string{tritonServerLabelKey: tritonServerLabelValue},
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  tritonPodName,
					Image: image,
					Ports: []v13.ContainerPort{
						{
							Name:          tritonServiceName,
							ContainerPort: tritonPort,
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

// newTritonService returns a service definition for the triton server pod.
func newTritonService(namespace *testcluster.Namespace) *v13.Service {
	return namespace.GetService(tritonServiceName, v13.ServiceSpec{
		Selector: map[string]string{tritonServerLabelKey: tritonServerLabelValue},
		Ports: []v13.ServicePort{
			{
				Name:       tritonServiceName,
				Protocol:   v13.ProtocolTCP,
				Port:       tritonPort,
				TargetPort: intstr.FromString(tritonServiceName),
			},
		},
	})
}
