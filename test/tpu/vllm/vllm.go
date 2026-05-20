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

// Package vllm provides a vLLM API client for testing.
package vllm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/llmutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// Port is the port used by the vllm server.
	Port = 8000

	// curtQuery is a query that should result in a very curt response.
	curtQuery = `Please reply with the single word: "Hello". Do not reply with any other word.`
)

// VLLM is a vllm client.
type VLLM struct {
	// server is used to perform requests against the server.
	server llmutil.Server

	// logger is used to log.
	logger testutil.Logger
}

// New starts a new VLLM server in the given container,
// then waits for it to serve and returns the client.
func New(ctx context.Context, server llmutil.Server, logger testutil.Logger) (*VLLM, error) {
	started := time.Now()
	llm := &VLLM{
		logger: logger,
		server: server,
	}

	// Wait until serving.
	if err := llm.WaitUntilServing(ctx); err != nil {
		return nil, llm.withServerLogsErr(ctx, fmt.Errorf("vllm did not come up for serving: %w", err))
	}
	logger.Logf("vLLM serving API requests after %v", time.Since(started))

	// Run a warmup query to force the model to load.
	_, err := llm.WarmModel(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not warmup the model: %w", err)
	}
	logger.Logf("Loaded vllm model. (%v since container start)", time.Since(started))

	logger.Logf("vLLM successfully initialized in a total of %v", time.Since(started))
	return llm, nil
}

// ModelLoadStats holds metrics about the model loading process.
type ModelLoadStats struct {
	// ClientReportedDuration is the duration to load the model as perceived
	// by the client, measured by HTTP client metrics.
	ClientReportedDuration time.Duration
}

// WarmModel pre-warms a model in memory.
func (llm *VLLM) WarmModel(ctx context.Context) (*ModelLoadStats, error) {
	prompt := ZeroTemperaturePrompt(curtQuery)
	prompt.MaxTokens = 1
	resp, err := llm.Prompt(ctx, prompt)
	if err != nil {
		return nil, llm.withServerLogsErr(ctx, fmt.Errorf("warmup prompt (%s) failed: %w", prompt.Text, err))
	}
	return &ModelLoadStats{
		ClientReportedDuration: resp.metrics.TimeToFirstByte(),
	}, nil
}

// NewDocker returns a new VLLM client talking to a vLLM server that runs
// in a local Docker container.
func NewDocker(ctx context.Context, cont *dockerutil.Container, logger testutil.Logger) (*VLLM, error) {
	// We use privileged for TPUs.
	opts := dockerutil.RunOpts{
		Image:      "tpu/vllm",
		Privileged: true,
	}
	started := time.Now()
	if err := cont.Spawn(ctx, opts); err != nil {
		return nil, fmt.Errorf("could not start vllm: %v", err)
	}
	logger.Logf("vLLM container started after %v", time.Since(started))
	ds := &llmutil.DockerServer{
		Container:   cont,
		Logger:      logger,
		Port:        Port,
		ClientImage: "gpu/ollama/client",
	}
	return New(ctx, ds, logger)
}

func (llm *VLLM) instrumentedRequest(ctx context.Context, method, endpoint, header string, data []byte) ([]byte, error) {
	argvFn := func(hostPort string) []string {
		argv := []string{
			"httpclient",
			fmt.Sprintf("--method=%s", method),
			fmt.Sprintf("--url=%s%s", hostPort, endpoint),
			"--strip_prefix=data: ",
		}
		if header != "" {
			argv = append(argv, fmt.Sprintf("--header=%s", header))
		}
		if data != nil {
			argv = append(argv, fmt.Sprintf("--post_base64=%s", base64.StdEncoding.EncodeToString(data)))
		}
		return argv
	}
	return llm.server.InstrumentedRequest(ctx, argvFn)
}

// WaitUntilServing waits until vllm is serving.
func (llm *VLLM) WaitUntilServing(ctx context.Context) error {
	for ctx.Err() == nil {
		out, err := llm.instrumentedRequest(ctx, "GET", "/health", "Content-Type: application/json", nil)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		if strings.Contains(string(out), "uvicorn") {
			return nil
		}
		llm.logger.Logf("vLLM health check output: %q", string(out))
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("vllm did not respond: %w", ctx.Err())
}

// Prompt is a vllm prompt.
type Prompt struct {
	Model       string  `json:"model"`
	Text        string  `json:"prompt"`
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
	Stream      bool    `json:"stream"`
}

// ZeroTemperaturePrompt returns a minimal Prompt.
func ZeroTemperaturePrompt(text string) *Prompt {
	return &Prompt{
		Model:       "Qwen/Qwen2.5-1.5B-Instruct",
		Text:        text,
		MaxTokens:   100,
		Temperature: 0.0,
		Stream:      true,
	}
}

// RaiseTemperature increases the temperature of the prompt.
func (p *Prompt) RaiseTemperature() {
	p.Temperature = min(1.0, p.Temperature*2+0.1)
}

// Response represents a response to a query.
type Response struct {
	Choices []struct {
		Text         string  `json:"text"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

// FullResponse aggregates streamed responses.
type FullResponse struct {
	objects []*Response
	metrics llmutil.ResponseMetrics
}

// Text returns the concatenated text from all responses.
func (r *FullResponse) Text() string {
	var sb strings.Builder
	for _, obj := range r.objects {
		if len(obj.Choices) > 0 {
			sb.WriteString(obj.Choices[0].Text)
		}
	}
	return sb.String()
}

// Done returns whether the response was completely generated.
func (r *FullResponse) Done() bool {
	return r.FinishReason() != ""
}

// FinishReason returns the reason the model stopped generating or an empty string.
// End of request looks like as follows:
// data: {"id":"cmpl-a1fcb98a99df0198","object":"text_completion","created":1776445044,"model":"Qwen/Qwen2.5-1.5B-Instruct","choices":[{"index":0,"text":" performance","logprobs":null,"finish_reason":null,"stop_reason":null,"prompt_token_ids":null,"token_ids":null}],"usage":null}
// data: {"id":"cmpl-a1fcb98a99df0198","object":"text_completion","created":1776445044,"model":"Qwen/Qwen2.5-1.5B-Instruct","choices":[{"index":0,"text":" and","logprobs":null,"finish_reason":"length","stop_reason":null,"prompt_token_ids":null,"token_ids":null}],"usage":null}
// data: [DONE]
func (r *FullResponse) FinishReason() string {
	if len(r.objects) == 0 {
		return ""
	}
	// The finish reason is expected to be in the last object of the stream.
	lastObj := r.objects[len(r.objects)-1]
	for _, choice := range lastObj.Choices {
		if choice.FinishReason != nil {
			return *choice.FinishReason
		}
	}
	return ""
}

// NumTokens returns the number of tokens in the response.
func (r *FullResponse) NumTokens() int {
	fmt.Println("NumTokens: ", len(r.objects))
	return len(r.objects)
}

// TimeToFirstToken returns the time it took between the request starting
// and the first token being received by the client.
func (r *FullResponse) TimeToFirstToken() time.Duration {
	if !r.Done() {
		fmt.Println("TimeToFirstToken: not done")
		return -1
	}
	fmt.Println("TimeToFirstToken: ", r.metrics.FirstByteRead.Sub(r.metrics.RequestSent))
	return r.metrics.FirstByteRead.Sub(r.metrics.RequestSent)
}

// TimeToLastToken returns the time it took between the request starting
// and the last token being received by the client.
func (r *FullResponse) TimeToLastToken() time.Duration {
	if !r.Done() {
		fmt.Println("TimeToLastToken: not done")
		return -1
	}
	fmt.Println("TimeToLastToken: ", r.metrics.LastByteRead.Sub(r.metrics.RequestSent))
	return r.metrics.LastByteRead.Sub(r.metrics.RequestSent)
}

// E2ELatency returns the elapsed time from request sent to last byte read in seconds.
func (r *FullResponse) E2ELatency() float64 {
	if !r.Done() {
		fmt.Println("E2ELatency: not done")
		return 0
	}
	fmt.Println("E2ELatency: ", r.metrics.LastByteRead.Sub(r.metrics.RequestSent).Seconds())
	return r.metrics.LastByteRead.Sub(r.metrics.RequestSent).Seconds()
}

// OutputTokensPerSecond computes the average number of output tokens
// generated per second.
func (r *FullResponse) OutputTokensPerSecond() float64 {
	latency := r.E2ELatency()
	if latency <= 0 {
		return -1
	}
	fmt.Println("OutputTokensPerSecond: ", float64(len(r.objects))/latency)
	return float64(len(r.objects)) / latency
}

// Prompt returns the result of prompting.
func (llm *VLLM) Prompt(ctx context.Context, prompt *Prompt) (*FullResponse, error) {
	data, err := json.Marshal(prompt)
	if err != nil {
		return nil, err
	}
	out, err := llm.instrumentedRequest(ctx, "POST", "/v1/completions", "Content-Type: application/json", data)
	if err != nil {
		return nil, err
	}
	resp, err := llmutil.MakeAPIResponse[Response](out)
	if err != nil {
		return nil, err
	}
	return &FullResponse{objects: resp.Objects, metrics: resp.Metrics}, nil
}

// withServerLogsErr adds server logs to err.
func (llm *VLLM) withServerLogsErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	serverLogs, _ := llm.server.Logs(ctx)
	if serverLogs != "" {
		return fmt.Errorf("%w; vllm server logs:\n%v", err, serverLogs)
	}
	return err
}

// PromptUntil repeatedly issues a prompt until iterate returns nil.
func (llm *VLLM) PromptUntil(ctx context.Context, prompt *Prompt, iterate func(*Prompt, *FullResponse) (*Prompt, error)) (*FullResponse, error) {
	for ctx.Err() == nil {
		response, err := llm.Prompt(ctx, prompt)
		if err != nil {
			return nil, err
		}
		newPrompt, err := iterate(prompt, response)
		if err == nil {
			return response, nil
		}
		if newPrompt != nil {
			prompt = newPrompt
		}
	}
	return nil, ctx.Err()
}
