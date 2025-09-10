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

// Package sglang provides an SGLang API client.
package sglang

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// Port is the port used by the sglang server.
	Port = 30000

	// curtQuery is a query that should result in a very curt response.
	curtQuery = `Please reply with the single word: "Hello". Do not reply with any other word.`
)

// SGLang is an sglang client.
type SGLang struct {
	// server is used to perform requests against the server.
	server Server

	// logger is used to log.
	logger testutil.Logger
}

// Server performs requests against an sglang server.
type Server interface {
	// InstrumentedRequest performs an instrumented HTTP request against the
	// sglang server, using the `gpu/sglang_client` sglang image.
	// `argvFn` takes in a `protocol://host:port` string and returns a
	// command-line to use for making an instrumented HTTP request against the
	// sglang server.
	// InstrumentedRequest should return the logs from the request container.
	InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error)

	// Logs retrieves logs from the server.
	Logs(ctx context.Context) (string, error)
}

// New starts a new SGLang server in the given container,
// then waits for it to serve and returns the client.
func New(ctx context.Context, server Server, logger testutil.Logger) (*SGLang, error) {
	started := time.Now()
	llm := &SGLang{
		logger: logger,
		server: server,
	}

	// Wait until serving.
	if err := llm.WaitUntilServing(ctx); err != nil {
		return nil, fmt.Errorf("sglang did not come up for serving: %w", err)
	}
	logger.Logf("SGLang serving API requests after %v", time.Since(started))

	// Run a warmup query to force the model to load.
	_, err := llm.WarmModel(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not warmup the model: %w", err)
	}
	logger.Logf("Loaded sglang model. (%v since container start)", time.Since(started))

	logger.Logf("SGLang successfully initialized in a total of %v", time.Since(started))
	return llm, nil
}

// ModelLoadStats holds metrics about the model loading process.
type ModelLoadStats struct {
	// ClientReportedDuration is the duration to load the model as perceived
	// by the client, measured by HTTP client metrics.
	ClientReportedDuration time.Duration
}

// WarmModel pre-warms a model in memory and keeps it warm for `keepWarmFor`.
// If `unloadFirst` is true, another model will be loaded before loading the
// requested model. This ensures that the model was loaded from a cold state.
func (llm *SGLang) WarmModel(ctx context.Context) (*ModelLoadStats, error) {
	prompt := ZeroTemperaturePrompt(curtQuery)
	prompt.SetMaxNewTokens(1)
	resp, err := llm.Prompt(ctx, prompt)
	if err != nil {
		return nil, llm.withServerLogsErr(ctx, fmt.Errorf("warmup prompt (%s) failed: %w", prompt.Text, err))
	}
	return &ModelLoadStats{
		ClientReportedDuration: resp.metrics.TimeToFirstByte(),
	}, nil
}

// dockerServer implements `Server`. It interfaces with an sglang server
// running in a local Docker container.
type dockerServer struct {
	container *dockerutil.Container
	logger    testutil.Logger
}

// NewDocker returns a new SGLang client talking to an SGLang server that runs
// in a local Docker container.
func NewDocker(ctx context.Context, cont *dockerutil.Container, logger testutil.Logger) (*SGLang, error) {
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to get GPU run options: %w", err)
	}
	opts.Image = "gpu/sglang"
	started := time.Now()
	if err := cont.Spawn(ctx, opts); err != nil {
		return nil, fmt.Errorf("could not start sglang: %v", err)
	}
	logger.Logf("SGLang container started after %v", time.Since(started))
	ds := &dockerServer{
		container: cont,
		logger:    logger,
	}
	return New(ctx, ds, logger)
}

// InstrumentedRequest implements `Server.InstrumentedRequest`.
func (ds *dockerServer) InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error) {
	const sglangHost = "llm"
	cmd := argvFn(fmt.Sprintf("http://%s:%d", sglangHost, Port))
	out, err := dockerutil.MakeContainer(ctx, ds.logger).Run(ctx, dockerutil.RunOpts{
		Image: "gpu/sglang/client",
		Links: []string{ds.container.MakeLink(sglangHost)},
	}, cmd...)
	if err != nil {
		if out != "" {
			return []byte(out), fmt.Errorf("command %q failed (%w): %v", strings.Join(cmd, " "), err, out)
		}
		return nil, fmt.Errorf("could not run command %q: %w", strings.Join(cmd, " "), err)
	}
	return []byte(out), nil
}

// Logs implements `Server.Logs`.
func (ds *dockerServer) Logs(ctx context.Context) (string, error) {
	return ds.container.Logs(ctx)
}

// ResponseMetrics are HTTP request metrics from an sglang API query.
// These is the same JSON struct as defined in
// `images/gpu/sglang/client/client.go`.
type ResponseMetrics struct {
	// ProgramStarted is the time when the program started.
	ProgramStarted time.Time `json:"program_started"`
	// RequestSent is the time when the HTTP request was sent.
	RequestSent time.Time `json:"request_sent"`
	// ResponseReceived is the time when the HTTP response headers were received.
	ResponseReceived time.Time `json:"response_received"`
	// FirstByteRead is the time when the first HTTP response body byte was read.
	FirstByteRead time.Time `json:"first_byte_read"`
	// LastByteRead is the time when the last HTTP response body byte was read.
	LastByteRead time.Time `json:"last_byte_read"`
}

// TimeToFirstByte returns the duration it took between the request being sent
// and the first byte of the response being read.
func (rm *ResponseMetrics) TimeToFirstByte() time.Duration {
	return rm.FirstByteRead.Sub(rm.RequestSent)
}

// TimeToLastByte returns the duration it took between the request being sent
// and the last byte of the response being read.
func (rm *ResponseMetrics) TimeToLastByte() time.Duration {
	return rm.LastByteRead.Sub(rm.RequestSent)
}

// apiResponse represents a JSON response from the sglang API.
type apiResponse[T any] struct {
	// Objects is the list of JSON objects in the response.
	Objects []*T
	// Metrics contains HTTP response metrics.
	Metrics ResponseMetrics
}

// Obj returns the first object in the response, if there is a singular
// object in the response.
func (ar *apiResponse[T]) Obj() (*T, error) {
	if len(ar.Objects) == 0 {
		return nil, fmt.Errorf("no objects in response")
	}
	if len(ar.Objects) > 1 {
		return nil, fmt.Errorf("multiple objects in response")
	}
	return ar.Objects[0], nil
}

// makeAPIResponse decodes a raw response from an instrumented HTTP request
// into an `apiResponse` with deserialized JSON objects.
func makeAPIResponse[T any](rawResponse []byte) (*apiResponse[T], error) {
	var respBytes bytes.Buffer
	var resp apiResponse[T]
	for _, line := range strings.Split(string(rawResponse), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colonIndex := strings.Index(line, ":")
		if colonIndex == -1 {
			return nil, fmt.Errorf("malformed line: %q", line)
		}
		data := strings.TrimSpace(line[colonIndex+1:])
		switch line[:colonIndex] {
		case "FATAL":
			return nil, fmt.Errorf("request failed: %s", data)
		case "REQHEADER", "RESPHEADER":
			// Do nothing with these.
		case "BODY":
			unquoted, err := strconv.Unquote(data)
			if err != nil {
				return nil, fmt.Errorf("malformed body line: %q", data)
			}
			// Last token in the response is "[DONE]" which is not JSON.
			if strings.TrimSpace(unquoted) == "[DONE]" {
				break
			}
			respBytes.WriteString(unquoted)
		case "STATS":
			if err := json.Unmarshal([]byte(data), &resp.Metrics); err != nil {
				return nil, fmt.Errorf("malformed stats line: %q", data)
			}
		default:
			return nil, fmt.Errorf("malformed line: %q", line)
		}
	}
	decoder := json.NewDecoder(&respBytes)
	for {
		var obj T
		err := decoder.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed JSON response: %w", err)
		}
		resp.Objects = append(resp.Objects, &obj)
	}
	if len(resp.Objects) == 0 {
		return nil, fmt.Errorf("response is empty")
	}
	leftoverBytes, err := io.ReadAll(decoder.Buffered())
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("could not read leftover bytes: %w", err)
	}
	if leftover := strings.TrimSpace(string(leftoverBytes)); leftover != "" {
		return nil, fmt.Errorf("unprocessed bytes in response: %q", leftover)
	}
	return &resp, nil
}

// instrumentedRequest makes an HTTP request to the sglang API.
// It returns the raw bytestream from the instrumented request logs.
func (llm *SGLang) instrumentedRequest(ctx context.Context, method, endpoint string, data []byte) ([]byte, error) {
	if endpoint != "" && !strings.HasPrefix(endpoint, "/") {
		return nil, fmt.Errorf("endpoint must be empty or start with '/', got %q", endpoint)
	}
	argvFn := func(hostPort string) []string {
		argv := []string{
			"httpclient",
			fmt.Sprintf("--method=%s", method),
			fmt.Sprintf("--url=%s%s", hostPort, endpoint),
		}
		if data != nil {
			argv = append(argv, fmt.Sprintf("--post_base64=%s", base64.StdEncoding.EncodeToString(data)))
		}
		if ctxDeadline, hasDeadline := ctx.Deadline(); hasDeadline {
			argv = append(argv, fmt.Sprintf("--timeout=%v", time.Until(ctxDeadline)))
		}
		return argv
	}
	rawResponse, err := llm.server.InstrumentedRequest(ctx, argvFn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	return rawResponse, nil
}

// jsonGet performs a JSON HTTP GET request.
func jsonGet[Out any](ctx context.Context, llm *SGLang, endpoint string) (*apiResponse[Out], error) {
	out, err := llm.instrumentedRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("GET %q failed: %w", endpoint, err)
	}
	return makeAPIResponse[Out](out)
}

// jsonPost performs a JSON HTTP POST request.
func jsonPost[In, Out any](ctx context.Context, llm *SGLang, endpoint string, input In) (*apiResponse[Out], error) {
	query, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("could not marshal input %v: %w", input, err)
	}
	out, err := llm.instrumentedRequest(ctx, "POST", endpoint, query)
	if err != nil {
		return nil, fmt.Errorf("POST %q %v failed: %w", endpoint, string(query), err)
	}

	return makeAPIResponse[Out](out)
}

// WaitUntilServing waits until sglang is serving, or the context expires.
func (llm *SGLang) WaitUntilServing(ctx context.Context) error {
	for ctx.Err() == nil {
		out, err := llm.instrumentedRequest(ctx, "GET", "/health", nil)
		if err != nil {
			continue
		}
		if strings.Contains(string(out), "uvicorn") {
			return nil
		}
	}
	return fmt.Errorf("sglang did not respond: %w", ctx.Err())
}

// temperatureOption is the temperature option that most models have
// which controls how free they are from deviating from their most-likely
// token chain.
const temperatureOption = "temperature"
const maxNewTokensOption = "max_new_tokens"

// RaiseTemperature increases the "temperature" option of the model,
// if any.
func (p *Prompt) RaiseTemperature() {
	temp, ok := p.Options[temperatureOption]
	if !ok {
		temp = float64(0.0)
	}
	if p.Options == nil {
		p.Options = map[string]any{}
	}
	p.Options[temperatureOption] = min(1.0, temp.(float64)*2+.025)
}

// Copy returns a copy of the prompt.
func (p *Prompt) Copy() *Prompt {
	promptCopy := *p
	promptCopy.Options = make(map[string]any, len(p.Options))
	for k, v := range p.Options {
		promptCopy.Options[k] = v
	}
	return &promptCopy
}

// SetTemperature sets the "temperature" option of the prompt to the given
// value.
func (p *Prompt) SetTemperature(temperature float64) {
	if p.Options == nil {
		p.Options = map[string]any{}
	}
	p.Options[temperatureOption] = temperature
}

// SetMaxNewTokens sets the "max_new_tokens" option of the prompt to the given
// value.
func (p *Prompt) SetMaxNewTokens(maxNewTokens int) {
	if p.Options == nil {
		p.Options = map[string]any{}
	}
	p.Options[maxNewTokensOption] = maxNewTokens
}

// ZeroTemperaturePrompt returns a Prompt with the given text and an initial
// temperature setting of zero. This setting allows for consistent settings.
func ZeroTemperaturePrompt(text string) *Prompt {
	return &Prompt{
		Text: text,
		Options: map[string]any{
			temperatureOption: 0.0,
		},
	}
}

// Prompt is an sglang prompt.
type Prompt struct {

	// Text is the prompt string.
	// Common leading whitespace will be removed.
	Text string

	// images is a set of attached images.
	// Use AddImage to add an image.
	images [][]byte

	// Options maps parameter names to JSON-compatible values.
	Options map[string]any
}

// AddImage attaches an image to the prompt.
// Returns itself for chainability.
func (p *Prompt) AddImage(data []byte) *Prompt {
	p.images = append(p.images, data)
	return p
}

// CleanQuery removes common whitespace from query lines, and all
// leading/ending whitespace-only lines.
// It is useful to be able to specify query string as indented strings
// without breaking visual continuity in Go code.
// For example (where dots are spaces):
//
// """\n
// ..The Quick Brown Fox\n
// ..Jumps Over\n
// ....The Lazy Dog\n
// ."""
//
// becomes:
// Jumps Over\n
// ..The Lazy Dog"""
func (p *Prompt) CleanQuery() string {
	lines := strings.Split(p.Text, "\n")

	// Trim lines at the beginning and end that are only whitespace.
	trimmedLines := make([]string, 0, len(lines))
	startedNonWhitespace := false
	var block []string
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if !startedNonWhitespace && trimmedLine != "" {
			startedNonWhitespace = true
		}
		if startedNonWhitespace {
			block = append(block, line)
		}
		if trimmedLine != "" {
			trimmedLines = append(trimmedLines, block...)
			block = block[:0]
		}
	}

	// Find longest common whitespace prefix.
	if len(trimmedLines) == 0 {
		return ""
	}
	trimmedFirstLine := strings.TrimSpace(trimmedLines[0])
	common := []rune(trimmedLines[0][:strings.Index(trimmedLines[0], trimmedFirstLine)])
	for ; len(common) > 0; common = common[:len(common)-1] {
		allMatch := true
		for _, line := range trimmedLines[1:] {
			if strings.TrimSpace(line) == "" {
				continue // Ignore whitespace-only or empty lines.
			}
			if !strings.HasPrefix(line, string(common)) {
				allMatch = false
				break
			}
		}
		if allMatch {
			break
		}
	}

	// Remove it.
	if len(common) > 0 {
		for i, line := range trimmedLines {
			trimmedLines[i] = strings.TrimPrefix(line, string(common))
		}
	}

	return strings.Join(trimmedLines, "\n")
}

// WithHotterModel returns a copy of this prompt with the same model having
// a higher temperature.
func (p *Prompt) WithHotterModel() *Prompt {
	promptCopy := p.Copy()
	promptCopy.RaiseTemperature()
	return promptCopy
}

// Request defines the structure for the JSON payload.
// https://docs.sglang.ai/basic_usage/sampling_params.html
type promptJSON struct {
	Prompt  string         `json:"text,omitempty"`
	Options map[string]any `json:"sampling_params"`
	Images  []string       `json:"image_data"`
	Stream  bool           `json:"stream"`
}

// json encodes this prompt to the JSON format expected by SGLang.
func (p *Prompt) json() promptJSON {
	images := make([]string, len(p.images))
	for i, image := range p.images {
		images[i] = base64.StdEncoding.EncodeToString(image)
	}
	return promptJSON{
		Prompt:  p.CleanQuery(),
		Images:  images,
		Stream:  true,
		Options: p.Options,
	}
}

// MetaInfo contains the meta information about the response.
// Every token has a meta info.
type MetaInfo struct {
	// E2ELatency only exists in the last token.
	E2ELatency float64 `json:"e2e_latency"`
}

// responseJSON is the JSON-format response from sglang about a prompt.
// Note that in `streamed` mode, the `Response` field contains a single token.
// To recover the whole response, all `Response` fields must be concatenated
// until the last `responseJSON`, identified as such by the `Done` field.
type responseJSON struct {
	Text     string   `json:"text"`
	MetaInfo MetaInfo `json:"meta_info"`
}

// Response represents a response to a query from SGLang.
type Response struct {
	data    []*responseJSON
	metrics ResponseMetrics
}

// Done returns whether the response was completely generated.
func (r *Response) Done() bool {
	if len(r.data) == 0 {
		return false
	}
	return r.data[len(r.data)-1].MetaInfo.E2ELatency > 0
}

// NumTokens returns the number of tokens in the response.
func (r *Response) NumTokens() int {
	return len(r.data)
}

// String returns the response text, if it is done.
func (r *Response) String() string {
	if len(r.data) == 0 {
		return "<EMPTY>"
	}
	response := r.data[len(r.data)-1]
	if response.MetaInfo.E2ELatency > 0 {
		return response.Text
	}
	return "<NOT DONE>"
}

// Text returns the body of the response, if it is done.
func (r *Response) Text() string {
	if !r.Done() {
		return ""
	}
	return r.String()
}

// withServerLogsErr adds server logs to `err` if possible.
func (llm *SGLang) withServerLogsErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w (+ context err: %v)", err, ctx.Err())
	}
	serverLogs, logsErr := llm.server.Logs(ctx)
	if logsErr != nil {
		return fmt.Errorf("%w (could not get server logs: %v)", err, logsErr)
	}
	if serverLogs != "" {
		return fmt.Errorf("%w; sglang server logs:\n%v\n(end of sglang server logs)", err, serverLogs)
	}
	return fmt.Errorf("%w (server logs are empty)", err)
}

// Prompt returns the result of prompting the given `model` with `prompt`.
func (llm *SGLang) Prompt(ctx context.Context, prompt *Prompt) (*Response, error) {
	resp, err := jsonPost[promptJSON, responseJSON](ctx, llm, "/generate", prompt.json())
	if err != nil {
		return nil, llm.withServerLogsErr(ctx, fmt.Errorf("prompt (%q) request failed: %w", prompt.CleanQuery(), err))
	}
	return &Response{data: resp.Objects, metrics: resp.Metrics}, nil
}

// PromptUntil repeatedly issues a prompt until `iterate` returns a nil error.
// `iterate` may optionally return an updated `Prompt` which will be used to
// follow up. This is useful to work around the flakiness of LLMs in tests.
func (llm *SGLang) PromptUntil(ctx context.Context, prompt *Prompt, iterate func(*Prompt, *Response) (*Prompt, error)) (*Response, error) {
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
