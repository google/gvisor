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

// Package sglang provides a benchmark for sglang on Kubernetes.
package sglang

import (
	"context"
	_ "embed"
	"fmt"
	"hash/fnv"
	"io"
	"strings"
	"testing"
	"time"
	"unicode"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/test/gpu/sglang"
	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/benchmarks/profiling"
	"gvisor.dev/gvisor/test/kubernetes/benchmetric"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// sglangPodServer implements `sglang.Server`.
// It performs requests against the sglang server pod.
type sglangPodServer struct {
	cluster     *testcluster.TestCluster
	clientImage string
	pod         *v13.Pod
	service     *v13.Service
}

// readPodLogs reads logs from a pod.
func readPodLogs(ctx context.Context, cluster *testcluster.TestCluster, pod *v13.Pod) (string, error) {
	rdr, err := cluster.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		return "", fmt.Errorf("GetLogReader on cluster %q pod %q: %v", cluster.GetName(), pod.GetName(), err)
	}
	out, err := io.ReadAll(rdr)
	if err != nil {
		return "", fmt.Errorf("failed to read from pod %q: %v", pod.GetName(), err)
	}
	return string(out), nil
}

// InstrumentedRequest implements `sglang.Server.InstrumentedRequest`.
func (sps *sglangPodServer) InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error) {
	// Get server IP.
	if err := sps.cluster.WaitForServiceReady(ctx, sps.service); err != nil {
		return nil, fmt.Errorf("failed to wait for service: %v", err)
	}
	ip := testcluster.GetIPFromService(sps.service)
	if ip == "" {
		return nil, fmt.Errorf("did not get valid ip from service: %v", sps.service)
	}

	// Build client pod spec.
	const clientPodName = "sglang-client"
	argv := argvFn(fmt.Sprintf("http://%s:%d", ip, sps.service.Spec.Ports[0].Port))
	clientPod := &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      clientPodName,
			Namespace: sps.pod.ObjectMeta.Namespace,
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:    clientPodName,
					Image:   sps.clientImage,
					Command: argv,
					Resources: v13.ResourceRequirements{
						Requests: v13.ResourceList{
							v13.ResourceCPU: resource.MustParse("500m"),
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
	clientPod, err := sps.cluster.ConfigurePodForClientNodepool(ctx, clientPod)
	if err != nil {
		return nil, fmt.Errorf("failed to configure pod: %v", err)
	}

	// Delete pod that may possibly exist from a previous iteration.
	// Ignore errors since it most likely doesn't exist.
	sps.cluster.DeletePod(ctx, clientPod)

	// Start new client pod and wait for it.
	clientPod, err = sps.cluster.CreatePod(ctx, clientPod)
	if err != nil {
		return nil, fmt.Errorf("failed to create client pod: %v", err)
	}
	defer sps.cluster.DeletePod(ctx, clientPod)
	if err := sps.cluster.WaitForPodCompleted(ctx, clientPod); err != nil {
		logs, logsErr := readPodLogs(ctx, sps.cluster, clientPod)
		logs = strings.TrimSpace(logs)
		if logsErr != nil {
			return nil, fmt.Errorf("failed HTTP request (%v) and to read logs from the pod: %w", err, logsErr)
		}
		if logs == "" {
			return nil, fmt.Errorf("failed HTTP request: %w (pod logs are empty)", err)
		}
		return nil, fmt.Errorf("failed HTTP request: %w (pod logs: %v)", err, logs)
	}

	// All good, get logs.
	logs, err := readPodLogs(ctx, sps.cluster, clientPod)
	if err != nil {
		return nil, fmt.Errorf("failed to read logs from pod %q: %v", clientPod.GetName(), err)
	}
	return []byte(logs), nil
}

// Logs implements `sglang.Server.Logs`.
func (sps *sglangPodServer) Logs(ctx context.Context) (string, error) {
	return readPodLogs(ctx, sps.cluster, sps.pod)
}

// atLeastNWords verifies that the response at least N words.
// If not, it raises the temperature.
func atLeastNWords(wantNWords int) func(prompt *sglang.Prompt, response *sglang.Response) (*sglang.Prompt, error) {
	return func(prompt *sglang.Prompt, response *sglang.Response) (*sglang.Prompt, error) {
		responseText := strings.TrimSpace(response.Text())
		responseText = strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) {
				return r
			}
			return ' '
		}, responseText)
		numWords := 0
		for _, word := range strings.Split(responseText, " ") {
			if len(word) >= 0 {
				numWords++
			}
		}
		if numWords < wantNWords {
			return prompt.WithHotterModel(), fmt.Errorf("response %q is too short: had %d words, want at least %d", responseText, numWords, wantNWords)
		}
		return nil, nil
	}
}

// wantSubstring verifies that the response contains the given substring.
// If not, it raises the temperature.
func wantSubstring(substring string) func(prompt *sglang.Prompt, response *sglang.Response) (*sglang.Prompt, error) {
	return func(prompt *sglang.Prompt, response *sglang.Response) (*sglang.Prompt, error) {
		if !strings.Contains(strings.ToLower(response.Text()), strings.ToLower(substring)) {
			return prompt.WithHotterModel(), fmt.Errorf("response %q does not contain substring %q", response.Text(), substring)
		}
		return nil, nil
	}
}

// BenchmarkSGLang runs sglang benchmarks for a single cluster.
func BenchmarkSGLang(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
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
	serverImage, err := k8sCtx.ResolveImage(ctx, sglangBenchImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	sglangPod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, newSGLangServerPod(benchmarkNS, serverImage))
	if err != nil {
		t.Fatalf("Failed to configure pod for runtime nodepool: %v", err)
	}
	sglangPod, err = testcluster.SetContainerResources(sglangPod, "", testcluster.ContainerResourcesRequest{GPU: true})
	if err != nil {
		t.Fatalf("Failed to set container resources: %v", err)
	}
	sglangPod, err = cluster.CreatePod(ctx, sglangPod)
	if err != nil {
		t.Fatalf("Failed to create sglang pod: %v", err)
	}
	defer cluster.DeletePod(ctx, sglangPod)
	logWithTime(t, "Waiting for sglang server pod to start, this may take a long time (tens of minutes) if this is the first time the image is being downloaded onto the node.")
	startCtx, startCtxCancel := context.WithTimeout(ctx, 90*time.Minute)
	if err := cluster.WaitForPodRunning(startCtx, sglangPod); err != nil {
		t.Fatalf("Failed to wait for sglang server pod: %v", err)
	}
	startCtxCancel()
	logWithTime(t, "sglang server pod started on Kubernetes but not yet initialized.")
	sglangService := newSGLangService(benchmarkNS)
	sglangService, err = cluster.CreateService(ctx, sglangService)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer cluster.DeleteService(ctx, sglangService)
	sglangClientImage, err := k8sCtx.ResolveImage(ctx, sglangBenchClientImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	sglangServer := &sglangPodServer{
		cluster:     cluster,
		clientImage: sglangClientImage,
		service:     sglangService,
		pod:         sglangPod,
	}
	llm, err := sglang.New(ctx, sglangServer, t)
	if err != nil {
		t.Fatalf("Failed to create sglang client against server pod: %v", err)
	}
	logWithTime(t, "sglang server ready.")

	// Define test cases.
	type testCase struct {
		// Name of the test.
		name string
		// Query for the sglang server.
		query string
		// If set, run this function over the response to verify it.
		// The LLM is prompted repeatedly until this function returns a non-nil error.
		// This function may also return a non-nil prompt if it needs to modify the prompt
		// for the next attempt. This is useful to raise the model temperature.
		verifyResponse func(*sglang.Prompt, *sglang.Response) (*sglang.Prompt, error)
	}
	testCases := []testCase{
		{
			name: "HelloWorld",
			query: `
				Reply with the words: "Hello World!".
				Do not reply anything else.
			`,
			verifyResponse: wantSubstring("Hello World!"),
		},
		{
			name: "ExtractMeaning",
			query: `
				Consider the following text:

				"""
				We assembled on the vast green lawn outside as the reactors began
				to slowly wind down. The workers were solemn; the activists who had
				fought against the decommissioning seemed crushed. There was
				supposed to be a speech, but the spokeswoman had lost her notes.
				Outside, the protesters cheered.

				My eyes were drawn to the discarded anti-shutdown banners,
				endlessly reciting the facts.
				The statistics on mortality per trillion kWh (lowest of all energy sources).
				The lifespan of a reactor (70 more years, in our case).
				Minimal land footprint.
				Almost zero emissions.
				No intermittency.
				It became a jumble of words, a litany, almost a kind of glossolalia.
				As far as the protesters outside were concerned,
				it might as well be an alien tongue.

				One thing was clear to them, and that was enough:
				the technology inside this compound was deeply, inherently wrong. It was a sin.

				I could not help but think of that moment on August 6th, 1945,
				when the sky erupted above Shima Hospital.
				My imagination could never fully encompass it.
				How do you imagine more than seventy thousand people annihilated
				in an instant? An ancestor of mine was in that hospital; he went
				from being a doctor, a husband, a father, a pacifist stuck
				in a terrible war, to being a pile of bleached bones covered in rubble,
				all in a single second.
				Not by accident, but because of a choice someone made.
				Not because of a reactor, but because of a bomb.

				Just two days earlier, contradicting his campaign promises,
				the prime minister had suggested that the use of
				"tactical" weapons based on this technology would be an
				acceptable risk if the conflict continued.
				Very few seemed to find this particularly shocking or outrageous.

				They were afraid of reactors, but not of bombs.

				The spokeswoman gave up on finding her notes.
				It was starting to rain, and people were walking away.
				She grabbed the microphone.

				"By the time you regret this, it'll be too late," she said.
				"But honestly, I don't know if I care anymore. Maybe you have it coming."

				The spokeswoman sounded so bitter.
				The protesters didn't mean any harm.
				From their perspective, they were doing good.

				Collective action can change the world when it's deliberate
				and based in reason, but it can also become a mental trap,
				or a societal pressure valve.

				People always think they're doing good when they get
				collectively outraged. That doesn't make them right.

				The Flame will not harm you, Son of Man, if you wield it wisely.
				"""

				Summarize what happened in the above text.
				Then answer the following questions:
				What technology is involved?
				What are the protestors clamoring for?
				What does the spokeswoman mean?
				What does "The Flame" symbolize in the text?
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
			verifyFnCount := func(prompt *sglang.Prompt, resp *sglang.Response) (*sglang.Prompt, error) {
				numAttempts++
				return verifyFn(prompt, resp)
			}
			const testTimeout = 25 * time.Minute
			testCtx, testCancel := context.WithTimeout(ctx, testTimeout)
			defer testCancel()

			prompt := sglang.ZeroTemperaturePrompt(test.query)
			resp, err := llm.PromptUntil(testCtx, prompt, verifyFnCount)
			if err != nil {
				t.Fatalf("cannot prompt: %v", err)
			}
			if !resp.Done() {
				t.Fatalf("warm response did not finish: %v", resp)
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
				fmt.Sprintf("SGLang/%s", test.name),
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
	// This is necessary to make sure the sglang server does not get
	// deleted from the `defer` statements before the subtests above finish.
	var wg sync.WaitGroup
	wg.Add(1)
	t.Run("", func(t *testing.T) {
		wg.Done()
	})
	wg.Wait()
}

const (
	sglangServerLabelKey   = "app.kubernetes.io/name"
	sglangServerLabelValue = "sglang-server"
	sglangPort             = 30000
	sglangPodName          = "sglang-server"
	sglangServiceName      = "sglang-service"
	sglangBenchImage       = k8s.ImageRepoPrefix + "gpu/sglang_x86_64:latest"
	sglangBenchClientImage = k8s.ImageRepoPrefix + "gpu/sglang/client_x86_64:latest"
)

// newSGLangServerPod returns the pod spec for an sglang server.
func newSGLangServerPod(namespace *testcluster.Namespace, image string) *v13.Pod {
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      sglangPodName,
			Namespace: namespace.Namespace,
			Labels:    map[string]string{sglangServerLabelKey: sglangServerLabelValue},
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  sglangPodName,
					Image: image,
					Ports: []v13.ContainerPort{
						{
							Name:          sglangServiceName,
							ContainerPort: sglangPort,
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

// newSGLangService returns a service definition for the sglang server pod.
func newSGLangService(namespace *testcluster.Namespace) *v13.Service {
	return namespace.GetService(sglangServiceName, v13.ServiceSpec{
		Selector: map[string]string{sglangServerLabelKey: sglangServerLabelValue},
		Ports: []v13.ServicePort{
			{
				Name:       sglangServiceName,
				Protocol:   v13.ProtocolTCP,
				Port:       sglangPort,
				TargetPort: intstr.FromString(sglangServiceName),
			},
		},
	})
}
