// Copyright 2023 The gVisor Authors.
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

// Package ollama provides an Ollama API client.
package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// Port is the port used by the ollama server.
	Port = 11434

	// curtQuery is a query that should result in a very curt response.
	curtQuery = `Please reply with the single word: "Hello". Do not reply with any other word.`
)

// Ollama is an ollama client.
type Ollama struct {
	container *dockerutil.Container
	logger    testutil.Logger

	// ModelNames is the list of available model names.
	ModelNames []string

	// HasGPU is set depending on whether the LLM has GPU access.
	// ollama supports running both on CPU and GPU, and detects this
	// by spawning nvidia-smi.
	HasGPU bool
}

// New starts a new Ollama server in the given container,
// then waits for it to serve and returns the client.
func New(ctx context.Context, cont *dockerutil.Container, logger testutil.Logger) (*Ollama, error) {
	opts := dockerutil.GPURunOpts()
	opts.Image = "gpu/ollama"
	if err := cont.Spawn(ctx, opts); err != nil {
		return nil, fmt.Errorf("could not start ollama: %v", err)
	}
	llm := &Ollama{
		container: cont,
		logger:    logger,
	}

	// Wait until serving.
	if err := llm.WaitUntilServing(ctx); err != nil {
		return nil, fmt.Errorf("ollama did not come up for serving: %w", err)
	}

	// Get list of model names.
	modelNames, err := llm.listModelNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not list model names: %w", err)
	}
	if len(modelNames) == 0 {
		return nil, errors.New("no models available")
	}
	llm.ModelNames = modelNames

	// Load the first model.
	// This is necessary to force ollama to load a model, without which
	// we cannot detect if it is using the GPU or not.
	_, err = llm.Prompt(ctx, &Prompt{
		Model: &Model{Name: llm.ModelNames[0]},
		Query: curtQuery,
	})
	if err != nil {
		return nil, fmt.Errorf("could not load first model %q: %w", llm.ModelNames[0], err)
	}

	// Now go over the logs and check if the GPU was used.
	logs, err := llm.container.Logs(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get logs: %w", err)
	}
	switch {
	case strings.Contains(logs, "check that you have installed GPU drivers"):
		llm.HasGPU = false
	case strings.Contains(logs, "VRAM available"):
		llm.HasGPU = true
	default:
		return nil, fmt.Errorf("cannot determine whether ollama is using GPU from logs:\n%s", logs)
	}
	return llm, nil
}

// request makes an HTTP request to the ollama API.
func (llm *Ollama) request(ctx context.Context, endpoint string, data []byte) ([]byte, error) {
	if endpoint != "" && !strings.HasPrefix(endpoint, "/") {
		return nil, fmt.Errorf("endpoint must be empty or start with '/', got %q", endpoint)
	}
	cmd := []string{"wget", "-qO-"}
	if data != nil {
		cmd = append(cmd, "--post-data", string(data))
	}
	cmd = append(cmd, fmt.Sprintf("http://llm:%d%s", Port, endpoint))
	out, err := dockerutil.MakeContainer(ctx, llm.logger).Run(ctx, dockerutil.RunOpts{
		Image: "basic/busybox",
		Links: []string{llm.container.MakeLink("llm")},
	}, cmd...)
	return []byte(out), err
}

// jsonGet performs a JSON HTTP GET request.
func jsonGet[Out any](ctx context.Context, llm *Ollama, endpoint string) (Out, error) {
	var resp Out
	out, err := llm.request(ctx, endpoint, nil)
	if err != nil {
		return resp, fmt.Errorf("GET %q failed: %w", endpoint, err)
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return resp, fmt.Errorf("malformed JSON response %q: %w", string(out), err)
	}
	return resp, nil
}

// jsonPost performs a JSON HTTP POST request.
func jsonPost[In, Out any](ctx context.Context, llm *Ollama, endpoint string, input In) (Out, error) {
	var resp Out
	query, err := json.Marshal(input)
	if err != nil {
		return resp, fmt.Errorf("could not marshal input %v: %w", input, err)
	}
	out, err := llm.request(ctx, endpoint, query)
	if err != nil {
		return resp, fmt.Errorf("POST %q(%v) failed: %w", endpoint, input, err)
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return resp, fmt.Errorf("malformed JSON response %q: %w", string(out), err)
	}
	return resp, nil
}

// listModelNames lists the available model names.
func (llm *Ollama) listModelNames(ctx context.Context) ([]string, error) {
	type model struct {
		Name       string `json:"name"`
		ModifiedAt string `json:"modified_at"`
		Size       int    `json:"size"`
	}
	type modelsList struct {
		Models []model `json:"models"`
	}
	models, err := jsonGet[modelsList](ctx, llm, "/api/tags")
	if err != nil {
		return nil, err
	}
	modelNames := make([]string, len(models.Models))
	for i, m := range models.Models {
		modelNames[i] = m.Name
	}
	return modelNames, nil
}

// WaitUntilServing waits until ollama is serving, or the context expires.
func (llm *Ollama) WaitUntilServing(ctx context.Context) error {
	for ctx.Err() == nil {
		out, err := llm.request(ctx, "/", nil)
		if err != nil {
			continue
		}
		if string(out) == "Ollama is running" {
			return nil
		}
	}
	return fmt.Errorf("ollama did not respond: %w", ctx.Err())
}

// Model encodes a model and options for it.
type Model struct {
	// Name is the name of the ollama model, e.g. "codellama:7b".
	Name string

	// Options maps parameter names to JSON-compatible values.
	Options map[string]any
}

// String returns the model's name.
func (m *Model) String() string {
	return m.Name
}

// modelTemperatureOption is the temperature option that most models have
// which controls how free they are from deviating from their most-likely
// token chain.
const modelTemperatureOption = "temperature"

// RaiseTemperature increases the "temperature" option of the model,
// if any.
func (m *Model) RaiseTemperature() {
	temp, ok := m.Options[modelTemperatureOption]
	if !ok {
		temp = float64(0.0)
	}
	if m.Options == nil {
		m.Options = map[string]any{}
	}
	m.Options[modelTemperatureOption] = min(1.0, temp.(float64)*2+.025)
}

// ZeroTemperatureModel returns a Model with the given name and an initial
// temperature setting of zero. This setting allows for consistent settings.
func ZeroTemperatureModel(name string) *Model {
	return &Model{
		Name: name,
		Options: map[string]any{
			modelTemperatureOption: 0.0,
		},
	}
}

// Prompt is an ollama prompt.
type Prompt struct {
	// Model is the model to query.
	Model *Model

	// Query is the prompt string.
	Query string

	// Context is the conversational context to follow up on, if any.
	// This is returned from `Response`.
	Context ConversationContext
}

// String returns a human-friendly string representing this prompt.
func (p *Prompt) String() string {
	return fmt.Sprintf("[%v] %s", p.Model, p.Query)
}

// PromptJSON encodes the JSON data for a query.
type PromptJSON struct {
	Model   string              `json:"model"`
	Prompt  string              `json:"prompt"`
	Stream  bool                `json:"stream"`
	Context ConversationContext `json:"context"`
	Options map[string]any      `json:"options"`
}

// json encodes this prompt to the JSON format expected by Ollama.
func (p *Prompt) json() PromptJSON {
	return PromptJSON{
		Model:   p.Model.Name,
		Prompt:  p.Query,
		Stream:  false,
		Context: p.Context,
		Options: p.Model.Options,
	}
}

// ResponseJSON is the JSON-format response from ollama about a prompt in
// non-streamed mode.
type ResponseJSON struct {
	Model           string              `json:"model"`
	Response        string              `json:"response"`
	Done            bool                `json:"done"`
	TotalNanos      int                 `json:"total_duration"`
	LoadNanos       int                 `json:"load_duration"`
	EvalCount       int                 `json:"eval_count"`
	EvalNanos       int                 `json:"eval_duration"`
	PromptEvalCount int                 `json:"prompt_eval_count"`
	PromptEvalNanos int                 `json:"prompt_eval_duration"`
	Context         ConversationContext `json:"context"`
}

// Response represents a response to a query from Ollama.
type Response struct {
	data ResponseJSON
}

// Done returns whether the response was completely generated.
func (r *Response) Done() bool {
	return r.data.Done
}

// String returns the response text, if it is done.
func (r *Response) String() string {
	if !r.data.Done {
		if r.data.Response != "" {
			return fmt.Sprintf("%s <NOT DONE>", r.data.Response)
		}
		return "<NOT DONE>"
	}
	return r.data.Response
}

// Text returns the body of the response, if it is done.
func (r *Response) Text() string {
	return r.data.Response
}

// TotalDuration returns the total response generation time.
func (r *Response) TotalDuration() time.Duration {
	return time.Duration(r.data.TotalNanos) * time.Nanosecond
}

// LoadDuration returns the load response generation time.
func (r *Response) LoadDuration() time.Duration {
	return time.Duration(r.data.LoadNanos) * time.Nanosecond
}

// EvalDuration returns the response evaluation time.
func (r *Response) EvalDuration() time.Duration {
	return time.Duration(r.data.EvalNanos) * time.Nanosecond
}

// PromptEvalDuration returns the prompt evaluation time.
func (r *Response) PromptEvalDuration() time.Duration {
	return time.Duration(r.data.PromptEvalNanos) * time.Nanosecond
}

// TokensPerSecond computes the number of tokens generated per second.
func (r *Response) TokensPerSecond() float64 {
	if !r.data.Done || r.EvalDuration() == 0 {
		return 0
	}
	return float64(r.data.EvalCount) / r.EvalDuration().Seconds()
}

// ConversationContext represents a conversational context.
// It is returned by a response and may be passed to a follow-up prompt.
type ConversationContext []int

// Prompt returns the result of prompting the given `model` with `prompt`.
func (llm *Ollama) Prompt(ctx context.Context, prompt *Prompt) (*Response, error) {
	resp, err := jsonPost[PromptJSON, ResponseJSON](ctx, llm, "/api/generate", prompt.json())
	if err != nil {
		return nil, err
	}
	return &Response{data: resp}, nil
}

// PromptUntil repeatedly issues a prompt until `iterate` returns a nil error.
// `iterate` may optionally return an updated `Prompt` which will be used to
// follow up.
// This is useful to work around the flakiness of LLMs in tests.
func (llm *Ollama) PromptUntil(ctx context.Context, prompt *Prompt, iterate func(*Prompt, *Response) (*Prompt, error)) (*Response, error) {
	var lastResponse *Response
	var lastError error
	attempts := 0
	for ctx.Err() == nil {
		response, err := llm.Prompt(ctx, prompt)
		if err != nil {
			return nil, fmt.Errorf("prompt request failed: %w", err)
		}
		attempts++
		newPrompt, err := iterate(prompt, response)
		if err == nil {
			return response, nil
		}
		if newPrompt != nil {
			prompt = newPrompt
		}
		lastResponse = response
		lastError = err
	}
	return nil, fmt.Errorf("response %q (attempt #%d with prompt %v) did not match predicate: %v", lastResponse, attempts, prompt, lastError)
}
