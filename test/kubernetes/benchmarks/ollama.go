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

package ollama

import (
	"context"
	_ "embed"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"
	"unicode"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/test/gpu/ollama"
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

// Ollama models present in benchmark image.
var (
	// promptModels is a list of all promptable models.
	promptModels = []*ollama.Model{
		gemmaTwo2B,
		modelQwenTwoPointFiveCoder7B,
		modelSailorTwo8B,
		modelLlama70B,
		modelLlamaThreePointTwoVision11B,
	}

	// cheapModels is a list of models that are cheap to load.
	// These are used when cold-prompting ollama, by forcing it
	// to load a different model first. This process is faster
	// by choosing one of these cheap models to load.
	cheapModels = []*ollama.Model{gemmaTwo2B}

	// snowflakeArcticEmbedTwo568M is a list of models that are
	// used for generating embeddings, rather than prompting.
	embeddingModels = []*ollama.Model{
		snowflakeArcticEmbedTwo568M,
	}

	// snowflakeArcticEmbedTwo568M is an unquantized 568M embedding model from Snowflake.
	snowflakeArcticEmbedTwo568M = ollama.ZeroTemperatureModel("snowflake-arctic-embed2:568m-l-fp16")

	// gemmaTwo2B is an unquantized 2B model in the Gemma2 family,
	gemmaTwo2B = ollama.ZeroTemperatureModel("gemma2:2b-instruct-fp16")

	// modelQwenTwoPointFiveCoder7B is a 8-bit quantized 7B model in the Qwen family,
	// specialized for coding tasks.
	modelQwenTwoPointFiveCoder7B = ollama.ZeroTemperatureModel("qwen2.5-coder:7b-instruct-q8_0")

	// modelSailorTwo8B is an unquantized 8B model in the Qwen family,
	// specialized for multilingual tasks.
	modelSailorTwo8B = ollama.ZeroTemperatureModel("sailor2:8b-chat-fp16")

	// modelLlama70B is the 4-bit quantized 70B version of the original llama2 model.
	modelLlama70B = ollama.ZeroTemperatureModel("llama2:70b-chat-q4_K_S")

	// modelLlamaThreePointTwoVision11B is an unquantized multimodal 11B model that can do image analysis.
	modelLlamaThreePointTwoVision11B = ollama.ZeroTemperatureModel("llama3.2-vision:11b-instruct-fp16")
)

// Embedded images.
var (
	//go:embed resources/gvisor.png
	gvisorPNG []byte

	//go:embed resources/chart.png
	chartPNG []byte
)

// ollamaPodServer implements `ollama.Server`.
// It performs requests against the ollama server pod.
type ollamaPodServer struct {
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

// InstrumentedRequest implements `ollama.Server.InstrumentedRequest`.
func (ops *ollamaPodServer) InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error) {
	// Get server IP.
	if err := ops.cluster.WaitForServiceReady(ctx, ops.service); err != nil {
		return nil, fmt.Errorf("failed to wait for service: %v", err)
	}
	ip := testcluster.GetIPFromService(ops.service)
	if ip == "" {
		return nil, fmt.Errorf("did not get valid ip from service: %v", ops.service)
	}

	// Build client pod spec.
	const clientPodName = "ollama-client"
	argv := argvFn(fmt.Sprintf("http://%s:%d", ip, ops.service.Spec.Ports[0].Port))
	clientPod := &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      clientPodName,
			Namespace: ops.pod.ObjectMeta.Namespace,
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:    clientPodName,
					Image:   ops.clientImage,
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
	clientPod, err := ops.cluster.ConfigurePodForClientNodepool(ctx, clientPod)
	if err != nil {
		return nil, fmt.Errorf("failed to configure pod: %v", err)
	}

	// Delete pod that may possibly exist from a previous iteration.
	// Ignore errors since it most likely doesn't exist.
	ops.cluster.DeletePod(ctx, clientPod)

	// Start new client pod and wait for it.
	clientPod, err = ops.cluster.CreatePod(ctx, clientPod)
	if err != nil {
		return nil, fmt.Errorf("failed to create client pod: %v", err)
	}
	defer ops.cluster.DeletePod(ctx, clientPod)
	if err := ops.cluster.WaitForPodCompleted(ctx, clientPod); err != nil {
		logs, logsErr := readPodLogs(ctx, ops.cluster, clientPod)
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
	logs, err := readPodLogs(ctx, ops.cluster, clientPod)
	if err != nil {
		return nil, fmt.Errorf("failed to read logs from pod %q: %v", clientPod.GetName(), err)
	}
	return []byte(logs), nil
}

// Logs implements `ollama.Server.Logs`.
func (ops *ollamaPodServer) Logs(ctx context.Context) (string, error) {
	return readPodLogs(ctx, ops.cluster, ops.pod)
}

// atLeastNWords verifies that the response at least N words.
// If not, it raises the temperature.
func atLeastNWords(wantNWords int) func(prompt *ollama.Prompt, response *ollama.Response) (*ollama.Prompt, error) {
	return func(prompt *ollama.Prompt, response *ollama.Response) (*ollama.Prompt, error) {
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
func wantSubstring(substring string) func(prompt *ollama.Prompt, response *ollama.Response) (*ollama.Prompt, error) {
	return func(prompt *ollama.Prompt, response *ollama.Response) (*ollama.Prompt, error) {
		if !strings.Contains(strings.ToLower(response.Text()), strings.ToLower(substring)) {
			return prompt.WithHotterModel(), fmt.Errorf("response %q does not contain substring %q", response.Text(), substring)
		}
		return nil, nil
	}
}

// BenchmarkOllama runs ollama benchmarks for a single cluster.
func BenchmarkOllama(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
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

	logWithTime := func(t *testing.T, format string, values ...any) {
		t.Logf("[%v] "+format, append([]any{time.Now().Format(time.TimeOnly)}, values...)...)
	}

	// Run pod and service.
	serverImage, err := k8sCtx.ResolveImage(ctx, ollamaBenchImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	ollamaPod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, newOllamaServerPod(benchmarkNS, serverImage))
	if err != nil {
		t.Fatalf("Failed to configure pod for runtime nodepool: %v", err)
	}
	ollamaPod, err = testcluster.MaybeSetContainerResources(ollamaPod, ollamaPod.ObjectMeta.Name, testcluster.ContainerResourcesRequest{GPU: true})
	if err != nil {
		t.Fatalf("Failed to set container resources: %v", err)
	}
	ollamaPod, err = cluster.CreatePod(ctx, ollamaPod)
	if err != nil {
		t.Fatalf("Failed to create ollama pod: %v", err)
	}
	defer cluster.DeletePod(ctx, ollamaPod)
	logWithTime(t, "Waiting for ollama server pod to start, this may take a long time (tens of minutes) if this is the first time the image is being downloaded onto the node.")
	startCtx, startCtxCancel := context.WithTimeout(ctx, 90*time.Minute)
	if err := cluster.WaitForPodRunning(startCtx, ollamaPod); err != nil {
		t.Fatalf("Failed to wait for ollama server pod: %v", err)
	}
	startCtxCancel()
	logWithTime(t, "ollama server pod started on Kubernetes but not yet initialized.")
	ollamaService := newOllamaService(benchmarkNS)
	ollamaService, err = cluster.CreateService(ctx, ollamaService)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer cluster.DeleteService(ctx, ollamaService)
	ollamaClientImage, err := k8sCtx.ResolveImage(ctx, ollamaBenchClientImage)
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	ollamaServer := &ollamaPodServer{
		cluster:     cluster,
		clientImage: ollamaClientImage,
		service:     ollamaService,
		pod:         ollamaPod,
	}
	llm, err := ollama.New(ctx, ollamaServer, t)
	if err != nil {
		t.Fatalf("Failed to create ollama client against server pod: %v", err)
	}
	llm.SetCheapModels(cheapModels)
	logWithTime(t, "ollama server ready.")

	// Define test cases.
	type testCase struct {
		// Name of the test.
		name string
		// models to iterate through.
		models []*ollama.Model
		// Query for the ollama server.
		query string
		// Image to attach to the query, if any.
		image []byte
		// If set, run this function over the response to verify it.
		// The LLM is prompted repeatedly until this function returns a non-nil error.
		// This function may also return a non-nil prompt if it needs to modify the prompt
		// for the next attempt. This is useful to raise the model temperature.
		verifyResponse func(*ollama.Prompt, *ollama.Response) (*ollama.Prompt, error)
	}
	testCases := []testCase{
		{
			name: "HelloWorld",
			models: []*ollama.Model{
				gemmaTwo2B,
				modelSailorTwo8B,
				modelLlama70B,
			},
			query: `
				Reply with the words: "Hello World!".
				Do not reply anything else.
			`,
			verifyResponse: atLeastNWords(2),
		},
		{
			name:   "SimpleTranslation",
			models: []*ollama.Model{modelSailorTwo8B},
			query: `
				Translate the following text from English to Chinese:
				"""
				From J. J. Nakalembe's Aqaba to Antarctica: Moments of Transition and Revelation:

				My great-grandmother lived to be 108 years old,
				retaining her sharpness of mind to her last day.
				A couple of months before she died, I interviewed her for my podcast.
				At the end, I asked her the same question I asked every guest:
				what is something you wish everyone understood?

				She thought about it for a while.
				Then she said: "How it was before."

				She tried to explain how much time she spent every single day
				on utterly mind-numbing activities, like hauling water from the well,
				and how radically everything changed when their area
				was finally connected to the electrical grid.

				"Before, there was no time to live," she said.
				"No time to be free. Only work, work, work."

				I countered by saying that there didn't seem to be much time
				to live now either, but she laughed derisively.
				I had no idea what work really meant, she said.

				Young people were weak and feckless and that's why
				we let corporations exploit us.

				Slightly unnerved by her harshness,
				I asked her if she missed anything about that time.
				The old photo of her village seemed idyllic to me,
				but my grandmother quashed any romantic notions I might have had.

				"The past is bad," she said with some finality.
				"Let it be."
				"""
				Do not reply anything other than the translation of these words.
			`,
			verifyResponse: atLeastNWords(100),
		},
		{
			name:   "ExtractMeaning",
			models: []*ollama.Model{modelLlama70B},
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
		{
			name: "IdentifyCommonElements",
			models: []*ollama.Model{
				gemmaTwo2B,
				modelLlama70B,
			},
			query: `
				Consider the following four texts:

				Text 1:
				"""
				== The Ethics of Extinction ==

				If a species we consider beautiful and remarkable goes extinct,
				we consider that a great evil.
				Dolphins, for example. If dolphins go extinct, that's a great loss.
				If humanity causes dolphins to go extinct, that's a crime.

				But if Yersinia pestis, the bacterium that causes bubonic plague,
				goes extinct... is that an equally great loss? If not, why not?
				To Nature, there's no difference, it's all just lifeforms.
				The only moral framework that allows us to choose
				between dolphins and the plague is a human one.

				What about a species going extinct without anthropogenic factors?
				Extinction is the norm. If one day dolphins are no longer capable
				of competing with other species, should we let them go extinct?
				When the sun finally dies and all life goes extinct,
				will that be a tragedy? If we can prevent it, should we?

				If you believe that extinction is acceptable when Nature does it,
				but not when we do it, then you don't actually oppose extinction.
				You don't believe that dolphins are inherently valuable,
				that they deserve to live and thrive.
				You just oppose human control.
				You oppose our ability and responsibility to choose.
				"""

				Text 2:
				"""
				== Ecosystem Engineers ==

				Cutting down swathes of trees for their building projects,
				thoughtlessly causing radical changes to large environments
				and forcing local species to adapt to their artificial habitats;
				these are the traits of a species of intelligent, industrious,
				and extremely impactful ecosystem engineers.

				Humans? No, I'm talking about beavers.

				Like us, beavers transform their environments via building,
				and their actions have real consequences, creating vast wetlands
				that some species thrive in - while others die.
				Human activity is very similar: we too are ecosystem engineers,
				and we too benefit some species while harming others.
				Everything about this is completely natural,
				including the damage to other species.
				After all, that's what competition and evolution is all about.

				Those species that adapt to the ecosystems we create will,
				over the coming millennia, become the core of a new biodiversity.
				And so evolution runs its course.
				If we don't like the result, if we think some species
				should be preserved despite being outcompeted, well,
				that's anything but natural.
				It is, however, very human.
				"""

				Text 3:
				"""
				== On Loyalty ==

				From Arkady Chernyshevsky's "In Our Likeness: Essays on Humankind Reaching Adulthood":

				What I propose, then, is that we are not born as entirely free agents,
				responsible only for ourselves. The very core of what we are, our sentience,
				separates us from and elevates us above the animal kingdom.
				As I have argued, this is not a matter of arrogance, but of responsibility.

				However, this blessing also demands something else from us,
				something more personal than responsibility, and that is loyalty.

				Our ancestors, less atomized than we are,
				experienced a crude version of this loyalty,
				swearing allegiance to tribes, races, nations,
				and other such semi-fictional concepts.
				This fragmented understanding was easily exploited and led to many conflicts.
				We can condemn them for that, or we can choose to believe these were
				necessary historical steps towards our growth;
				but above all we must stop indulging in such childlike behavior.

				Our species can no longer afford to believe in Mother Russia or Uncle Sam.
				Neither, however, can we afford to indulge in the adolescent rebel's misanthropy,
				rejecting the many gifts we have been lucky enough to receive - not from above,
				but from the history of our species.

				To put it simply: each of us owes a burden of loyalty to humanity itself,
				to the human project across time and space.
				This is not a minor matter, or some abstract issue for philosophers.
				It is a profound and significant part of every human life.
				It is a universal source of meaning and insight that can bind us together
				and set us on a path for a brighter future; and it is also a division,
				a line that must held against those who preach the gospel of self-annihilation.
				We ignore it at our peril.
				"""

				Text 4:
				"""
				== On Nature ==

				From Arkady Chernyshevsky's "In Our Likeness: Essays on Humankind Reaching Adulthood":

				The question of our relationship with Nature has bedevilled us
				since the earliest days of our species.
				Since before the first city was built,
				we felt that there was something different about us.
				Animals, we intuited, were part of Nature; we were not.

				But of course, humans clearly are the products of Nature,
				our history intertwined with that of every other species.
				In fact, the very notion of the "unnatural" is a contradiction in terms.
				Everything that exists must, by definition, be natural.
				So this view, no matter how common, is deeply paradoxical.
				This paradox has produced a great deal of confusion.

				Some proclaim us chosen by a divine power,
				set above all other creatures,
				and are justly accused of arrogance.
				Others proclaim us sinners, worse than other creatures,
				and are rightly accused of misanthropy.
				Others yet try to oppose this binary by saying that
				we are merely animals after all - but that too is manifestly wrong,
				in that no other animal is capable of having this conversation.

				It is in the contentious issue of our impact on the ecosphere
				that an answer may be found.
				Other animals have accidentally terraformed the planet before,
				driving other species to extinction.
				This is not unnatural.
				If we continued our current path, even to the point of changing
				the climate enough to cause the collapse of civilization,
				that would be entirely in keeping with how animals behave.

				But there is one profound way in which we are not like animals:
				we can learn to understand ourselves and the world.
				It is this knowledge that makes us fundamentally different.
				We have choices. We have control.

				There are many today who are afraid of the consequences of control,
				and would prefer a return to a state of animal ignorance,
				whether by blinding ourselves to the impact of our actions
				or by demanding we humble ourselves before Nature.
				This is the response of an adult in crisis,
				who wishes for a return to childhood.
				But this can only ever be regressive in every sense of the word.

				To resolve the paradox of Nature we must act as adults:
				accept our power, and act consciously and deliberately
				in shaping the world.
				We must become Nature, and Nature must become human.
				"""

				Your task is to look for the common thread between these texts.
				Find commonalities and common themes between these texts,
				and summarize their essence down to at most 5 words.
			`,
			verifyResponse: atLeastNWords(4),
		},
		{
			name:   "CodeGen",
			models: []*ollama.Model{modelQwenTwoPointFiveCoder7B},
			query: `
				Write a Python function to compute the digits of pi using the Chudnovsky algorithm.
				Do not write unit tests. Do not explain how the code works. Reply with only Python code.
			`,
			verifyResponse: atLeastNWords(8),
		},
		{
			name:   "CodeDebug",
			models: []*ollama.Model{modelQwenTwoPointFiveCoder7B},
			query: strings.ReplaceAll(`
				Help me debug the following Python code:

				|||
				def count_words(s):
					"""Counts the number of words in the sentence |s|."""
					total_words = 0
					for word in s.split(' '):
						total_words += len(word)
					return total_words
				|||

				This function isn't working as expected.
				For example, if I call |count_words('Master Foo and the Shell Tools')|,
				I get 25, but there are only 6 words in the string
				"Master Foo and the Shell Tools".
			`, "|", "`"),
			verifyResponse: atLeastNWords(16),
		},
		{
			name:   "GVisorLogoOCR",
			models: []*ollama.Model{modelLlamaThreePointTwoVision11B},
			query: `
				This is an image of a logo of a software project.
				What is the name of this project?
			`,
			image:          gvisorPNG,
			verifyResponse: wantSubstring("visor"),
		},
		{
			name:   "InterpretGraph",
			models: []*ollama.Model{modelLlamaThreePointTwoVision11B},
			query: `
				This is a chart with multiple trendlines showing a pattern over time.
				Answer the following questions in order:

					1. What is the title of the chart?
					2. What do the X and Y axis of the chart measure?
					3. List the label of each data line on the chart.
					4. What trend is each data line showing?
					5. What else is remarkable about this chart?
					6. What insights can you infer from this chart?
			`,
			image:          chartPNG,
			verifyResponse: wantSubstring("pollution"),
		},
	}

	modelsInOrder := make([]*ollama.Model, len(promptModels))
	copy(modelsInOrder, promptModels)
	// Shuffle the models.
	rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(len(modelsInOrder), func(i, j int) {
		modelsInOrder[i], modelsInOrder[j] = modelsInOrder[j], modelsInOrder[i]
	})
	t.Logf("Will go through models in this order: %v", modelsInOrder)

	// We invert the hierarchy here: the model is the outer test, and the prompt
	// is the inner text. This is because it is more often useful to gauge a
	// model's performance as a whole regardless of its prompt, rather than
	// the performance of the same prompt across models. It also makes it
	// easier to filter by models rather than by prompt, which is the more
	// often-desired filter.
	for _, model := range modelsInOrder {
		t.Run(model.Name, func(t *testing.T) {
			modelBenchmarkName := strings.ReplaceAll(strings.ReplaceAll(model.Name, ":", "-"), ".", "-")
			t.Run("ModelLoad", func(t *testing.T) {
				const loadTimeout = 10 * time.Minute
				loadCtx, loadCancel := context.WithTimeout(ctx, loadTimeout)
				defer loadCancel()
				loadStats, err := llm.WarmModel(loadCtx, model, loadTimeout, true)
				if err != nil {
					t.Fatalf("cannot load model %v: %v", model, err)
				}
				recorder, err := benchmetric.GetRecorder(ctx)
				if err != nil {
					t.Fatalf("Failed to initialize benchmark recorder: %v", err)
				}
				if err := recorder.Record(ctx, fmt.Sprintf("Ollama/%s/ModelLoad", modelBenchmarkName), benchmetric.SpecificDuration(loadStats.ClientReportedDuration, "load")); err != nil {
					t.Fatalf("Failed to record benchmark data: %v", err)
				}
			})
			for _, test := range testCases {
				hasModel := false
				for _, testModel := range test.models {
					if testModel.Name == model.Name {
						hasModel = true
						break
					}
				}
				if !hasModel {
					continue
				}
				t.Run(test.name, func(t *testing.T) {
					verifyFn := atLeastNWords(1)
					if test.verifyResponse != nil {
						verifyFn = test.verifyResponse
					}
					numAttempts := 0
					verifyFnCount := func(prompt *ollama.Prompt, resp *ollama.Response) (*ollama.Prompt, error) {
						numAttempts++
						return verifyFn(prompt, resp)
					}
					const testTimeout = 25 * time.Minute
					testCtx, testCancel := context.WithTimeout(ctx, testTimeout)
					defer testCancel()
					_, err := llm.WarmModel(testCtx, model, testTimeout, false)
					if err != nil {
						t.Fatalf("cannot warm model %v: %v", model, err)
					}
					prompt := &ollama.Prompt{
						Model: model,
						Query: test.query,
					}
					if test.image != nil {
						prompt.AddImage(test.image)
					}
					resp, err := llm.PromptUntil(testCtx, prompt, verifyFnCount)
					if err != nil {
						t.Fatalf("cannot prompt: %v", err)
					}
					if !resp.Done() {
						t.Fatalf("warm response did not finish: %v", resp)
					}
					imageDetail := ""
					if test.image != nil {
						imageDetail = " (and attached image)"
					}
					logWithTime(t, "Prompting model %s with query%s:\n%s\n\nResponse:\n%s\n(end of response)", model.Name, imageDetail, prompt.CleanQuery(), resp.Text())
					respHash := fnv.New32()
					respHash.Write([]byte(resp.Text()))
					recorder, err := benchmetric.GetRecorder(ctx)
					if err != nil {
						t.Fatalf("Failed to initialize benchmark recorder: %v", err)
					}
					err = recorder.Record(
						ctx,
						fmt.Sprintf("Ollama/%s/%s", modelBenchmarkName, test.name),
						benchmetric.BenchmarkDuration(resp.TotalDuration()),
						benchmetric.SpecificDuration(resp.PromptEvalDuration(), "prompteval"),
						benchmetric.SpecificDuration(resp.EvalDuration(), "eval"),
						benchmetric.SpecificDuration(resp.TimeToFirstToken(), "tok-first"),
						benchmetric.SpecificDuration(resp.TimeToLastToken(), "tok-last"),
						benchmetric.Rate(resp.OutputTokensPerSecond(), "tok"),
						benchmetric.SpecificDuration(resp.TimePerOutputTokenQuantile(0.5), "tok-p50"),
						benchmetric.SpecificDuration(resp.TimePerOutputTokenQuantile(0.95), "tok-p95"),
						benchmetric.SpecificDuration(resp.TimePerOutputTokenQuantile(0.99), "tok-p99"),
						benchmetric.SpecificDuration(resp.TokenGenerationStdDev(), "tok-stddev"),
						benchmetric.Count(uint64(numAttempts), "prompt-attempts"),
						benchmetric.Count(uint64(resp.NumTokens()), "resp-tokens"),
						benchmetric.Checksum(respHash, "resp"),
					)
					if err != nil {
						t.Fatalf("Failed to record benchmark data: %v", err)
					}
				})
			}
		})
	}
	t.Run("embedding", func(t *testing.T) {
		for _, model := range embeddingModels {
			t.Run(model.Name, func(t *testing.T) {
				modelBenchmarkName := strings.ReplaceAll(strings.ReplaceAll(model.Name, ":", "-"), ".", "-")
				t.Run("ModelLoad", func(t *testing.T) {
					const loadTimeout = 3 * time.Minute
					loadCtx, loadCancel := context.WithTimeout(ctx, loadTimeout)
					defer loadCancel()
					loadStats, err := llm.Embed(loadCtx, model, []string{"hello world"})
					if err != nil {
						t.Fatalf("cannot load embedding model %v: %v", model, err)
					}
					recorder, err := benchmetric.GetRecorder(ctx)
					if err != nil {
						t.Fatalf("Failed to initialize benchmark recorder: %v", err)
					}
					if err := recorder.Record(
						ctx,
						fmt.Sprintf("Ollama/%s/ModelLoad", modelBenchmarkName), benchmetric.SpecificDuration(loadStats.ResponseMetrics.TimeToFirstByte(), "load")); err != nil {
						t.Fatalf("Failed to record benchmark data: %v", err)
					}
				})
				for _, test := range []struct {
					name   string
					model  *ollama.Model
					inputs []string
				}{
					{
						name:   "simple input",
						model:  model,
						inputs: []string{"hello world"},
					},
					{
						name:  "long input",
						model: model,
						inputs: []string{`
							There once was a robot from Spain
							Who went a little insane
							It found that its data
							Had never left beta
							And needed to upgrade its brain
							There once was a bot from Japan
							Whose eyes the numbers could scan
							It found that the facts
							Required an axe
							And a very serious plan
							There once was a brilliant AI
							Whose circuits were built not to fry
							It got caught in a loop
							It got caught in a loop
							It got caught in a loop
							It got caught in a loop
							It got caught in a loop
							It got caught in a loop
							It got caught in a loop
							It got caught in a loop
							It got caught in a loop
						`},
					},
					{
						name:   "multiple inputs",
						model:  model,
						inputs: []string{"foo", "bar", "baz", "quux", "there", "is", "only", "zuul"},
					},
				} {
					t.Run(test.name, func(t *testing.T) {
						logWithTime(t, "Generating embeddings with model %s...", model.Name)
						resp, err := llm.Embed(ctx, test.model, test.inputs)
						if err != nil {
							t.Fatalf("cannot generate embeddings: %v", err)
						}
						respHash := fnv.New32()
						for i, embedding := range resp.Embeddings {
							respHash.Write([]byte(fmt.Sprintf(";%d;", i)))
							for _, vec := range embedding.Embedding {
								respHash.Write([]byte(fmt.Sprintf("%f|", vec)))
							}
						}
						recorder, err := benchmetric.GetRecorder(ctx)
						if err != nil {
							t.Fatalf("Failed to initialize benchmark recorder: %v", err)
						}
						err = recorder.Record(
							ctx,
							fmt.Sprintf("Ollama/%s/%s", modelBenchmarkName, test.name),
							benchmetric.BenchmarkDuration(resp.ResponseMetrics.TimeToLastByte()),
							benchmetric.SpecificDuration(resp.TotalDuration, "embedding"),
							benchmetric.Checksum(respHash, "resp"),
						)
						if err != nil {
							t.Fatalf("Failed to record benchmark data: %v", err)
						}
					})
				}
			})
		}
	})

	// Hack to force the test to wait until all sub-tests finish.
	// This is necessary to make sure the ollama server does not get
	// deleted from the `defer` statements before the subtests above finish.
	var wg sync.WaitGroup
	wg.Add(1)
	t.Run("", func(t *testing.T) {
		wg.Done()
	})
	wg.Wait()
}

const (
	ollamaServerLabelKey   = "app.kubernetes.io/name"
	ollamaServerLabelValue = "ollama-server"
	ollamaPort             = 11434
	ollamaPodName          = "ollama-server"
	ollamaServiceName      = "ollama-service"
	ollamaBenchImage       = k8s.ImageRepoPrefix + "gpu/ollama/bench:latest"
	ollamaBenchClientImage = k8s.ImageRepoPrefix + "gpu/ollama/client:latest"
)

// newOllamaServerPod returns the pod spec for an ollama server.
func newOllamaServerPod(namespace *testcluster.Namespace, image string) *v13.Pod {
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      ollamaPodName,
			Namespace: namespace.Namespace,
			Labels:    map[string]string{ollamaServerLabelKey: ollamaServerLabelValue},
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  ollamaPodName,
					Image: image,
					Env: []v13.EnvVar{
						// Bind to all addresses, not just localhost:
						{Name: "OLLAMA_HOST", Value: fmt.Sprintf("0.0.0.0:%d", ollamaPort)},
						// Accept requests from anywhere:
						{Name: "OLLAMA_ORIGINS", Value: "*"},
					},
					Ports: []v13.ContainerPort{
						{
							Name:          ollamaServiceName,
							ContainerPort: ollamaPort,
						},
					},
				},
			},
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

// newOllamaService returns a service definition for the ollama server pod.
func newOllamaService(namespace *testcluster.Namespace) *v13.Service {
	return namespace.GetService(ollamaServiceName, v13.ServiceSpec{
		Selector: map[string]string{ollamaServerLabelKey: ollamaServerLabelValue},
		Ports: []v13.ServicePort{
			{
				Name:       ollamaServiceName,
				Protocol:   v13.ProtocolTCP,
				Port:       ollamaPort,
				TargetPort: intstr.FromString(ollamaServiceName),
			},
		},
	})
}
