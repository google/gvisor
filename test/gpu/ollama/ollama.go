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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
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
	// server is used to perform requests against the server.
	server Server

	// logger is used to log.
	logger testutil.Logger

	// ModelNames is the list of available model names.
	ModelNames []string

	// cheapModels is a list of models that are known to be cheap.
	// A caller may set this to make forcefully unloading a model quicker.
	cheapModels []*Model

	// HasGPU is set depending on whether the LLM has GPU access.
	// ollama supports running both on CPU and GPU, and detects this
	// by spawning nvidia-smi.
	HasGPU bool
}

// Server performs requests against an ollama server.
type Server interface {
	// InstrumentedRequest performs an instrumented HTTP request against the
	// ollama server, using the `gpu/ollama_client` ollama image.
	// `argvFn` takes in a `protocol://host:port` string and returns a
	// command-line to use for making an instrumented HTTP request against the
	// ollama server.
	// InstrumentedRequest should return the logs from the request container.
	InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error)

	// Logs retrieves logs from the server.
	Logs(ctx context.Context) (string, error)
}

// New starts a new Ollama server in the given container,
// then waits for it to serve and returns the client.
func New(ctx context.Context, server Server, logger testutil.Logger) (*Ollama, error) {
	started := time.Now()
	llm := &Ollama{
		logger: logger,
		server: server,
	}

	// Wait until serving.
	if err := llm.WaitUntilServing(ctx); err != nil {
		return nil, fmt.Errorf("ollama did not come up for serving: %w", err)
	}
	logger.Logf("Ollama serving API requests after %v", time.Since(started))

	// Get list of model names.
	modelNames, err := llm.listModelNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not list model names: %w", err)
	}
	if len(modelNames) == 0 {
		return nil, errors.New("no models available")
	}
	llm.ModelNames = modelNames
	logger.Logf("Available ollama model names: %v (loaded %v since container start)", modelNames, time.Since(started))

	// Load the first model.
	// This is necessary to force ollama to load a model, without which
	// we cannot detect if it is using the GPU or not.
	// This may fail during the process of loading the first model, so we keep
	// iterating for a while.
	_, err = llm.WarmModel(ctx, &Model{Name: llm.ModelNames[0]}, 1*time.Millisecond, false)
	if err != nil {
		return nil, fmt.Errorf("could not load first model %q: %w", llm.ModelNames[0], err)
	}
	logger.Logf("Loaded first ollama model %q (%v since container start)", llm.ModelNames[0], time.Since(started))

	// Now go over the logs and check if the GPU was used.
	logs, err := llm.server.Logs(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get logs: %w", err)
	}
	switch {
	case strings.Contains(logs, "library=cpu"):
		llm.HasGPU = false
	case strings.Contains(logs, "library=cuda"):
		llm.HasGPU = true
	default:
		return nil, fmt.Errorf("cannot determine whether ollama is using GPU from logs:\n%s", logs)
	}
	logger.Logf("Ollama successfully initialized in a total of %v", time.Since(started))
	return llm, nil
}

// SetCheapModels can be used to inform this Ollama client as to the list of
// models it can use that are known to be cheap.
// This is useful when forcefully unloading models by swapping them with
// another one, to ensure that the one it is being swapped with is small.
// Therefore, there should be at least two models specified here.
func (llm *Ollama) SetCheapModels(cheapModels []*Model) {
	llm.cheapModels = cheapModels
}

// dockerServer implements `Server`. It interfaces with an ollama server
// running in a local Docker container.
type dockerServer struct {
	container *dockerutil.Container
	logger    testutil.Logger
}

// NewDocker returns a new Ollama client talking to an Ollama server that runs
// in a local Docker container.
func NewDocker(ctx context.Context, cont *dockerutil.Container, logger testutil.Logger) (*Ollama, error) {
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to get GPU run options: %w", err)
	}
	opts.Image = "gpu/ollama"
	started := time.Now()
	if err := cont.Spawn(ctx, opts); err != nil {
		return nil, fmt.Errorf("could not start ollama: %v", err)
	}
	logger.Logf("Ollama container started after %v", time.Since(started))
	ds := &dockerServer{
		container: cont,
		logger:    logger,
	}
	return New(ctx, ds, logger)
}

// InstrumentedRequest implements `Server.InstrumentedRequest`.
func (ds *dockerServer) InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error) {
	const ollamaHost = "llm"
	cmd := argvFn(fmt.Sprintf("http://%s:%d", ollamaHost, Port))
	out, err := dockerutil.MakeContainer(ctx, ds.logger).Run(ctx, dockerutil.RunOpts{
		Image: "gpu/ollama/client",
		Links: []string{ds.container.MakeLink(ollamaHost)},
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

// ResponseMetrics are HTTP request metrics from an ollama API query.
// These is the same JSON struct as defined in
// `images/gpu/ollama/client/client.go`.
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

// apiResponse represents a JSON response from the ollama API.
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

// instrumentedRequest makes an HTTP request to the ollama API.
// It returns the raw bytestream from the instrumented request logs.
func (llm *Ollama) instrumentedRequest(ctx context.Context, method, endpoint string, data []byte) ([]byte, error) {
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
func jsonGet[Out any](ctx context.Context, llm *Ollama, endpoint string) (*apiResponse[Out], error) {
	out, err := llm.instrumentedRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("GET %q failed: %w", endpoint, err)
	}
	return makeAPIResponse[Out](out)
}

// jsonPost performs a JSON HTTP POST request.
func jsonPost[In, Out any](ctx context.Context, llm *Ollama, endpoint string, input In) (*apiResponse[Out], error) {
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
	modelsResp, err := jsonGet[modelsList](ctx, llm, "/api/tags")
	if err != nil {
		return nil, err
	}
	models, err := modelsResp.Obj()
	if err != nil {
		return nil, fmt.Errorf("malformed model tags response: %w", err)
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
		out, err := llm.instrumentedRequest(ctx, "GET", "/", nil)
		if err != nil {
			continue
		}
		if strings.Contains(string(out), "Ollama is running") {
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

// Copy returns a copy of the model.
func (m *Model) Copy() *Model {
	modelCopy := *m
	modelCopy.Options = make(map[string]any, len(m.Options))
	for k, v := range m.Options {
		modelCopy.Options[k] = v
	}
	return &modelCopy
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

	// If set, keep the model alive in memory for the given duration after this
	// prompt is answered. A zero duration will use the ollama default (a few
	// minutes). Note that model unloading is asynchronous, so the model will
	// not be fully unloaded after only `KeepModelAlive` beyond prompt response.
	KeepModelAlive time.Duration

	// Query is the prompt string.
	// Common leading whitespace will be removed.
	Query string

	// images is a set of attached images.
	// Use AddImage to add an image.
	images [][]byte

	// Context is the conversational context to follow up on, if any.
	// This is returned from `Response`.
	Context ConversationContext
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
//
// ""The Quick Brown Fox\n
// Jumps Over\n
// ..The Lazy Dog"""
func (p *Prompt) CleanQuery() string {
	lines := strings.Split(p.Query, "\n")

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

// String returns a human-friendly string representing this prompt.
func (p *Prompt) String() string {
	return fmt.Sprintf("[%v] %s", p.Model, p.CleanQuery())
}

// WithHotterModel returns a copy of this prompt with the same model having
// a higher temperature.
func (p *Prompt) WithHotterModel() *Prompt {
	promptCopy := *p
	promptCopy.Model = p.Model.Copy()
	promptCopy.Model.RaiseTemperature()
	return &promptCopy
}

// promptJSON encodes the JSON data for a query.
type promptJSON struct {
	Model     string              `json:"model"`
	Prompt    string              `json:"prompt,omitempty"`
	Images    []string            `json:"images"`
	Stream    bool                `json:"stream"`
	Context   ConversationContext `json:"context"`
	Options   map[string]any      `json:"options"`
	KeepAlive string              `json:"keep_alive,omitempty"`
}

// json encodes this prompt to the JSON format expected by Ollama.
func (p *Prompt) json() promptJSON {
	keepAlive := ""
	if p.KeepModelAlive != 0 {
		keepAlive = p.KeepModelAlive.String()
	}
	images := make([]string, len(p.images))
	for i, image := range p.images {
		images[i] = base64.StdEncoding.EncodeToString(image)
	}
	return promptJSON{
		Model:     p.Model.Name,
		Prompt:    p.CleanQuery(),
		Images:    images,
		Stream:    true,
		Context:   p.Context,
		Options:   p.Model.Options,
		KeepAlive: keepAlive,
	}
}

// responseJSON is the JSON-format response from ollama about a prompt.
// Note that in `streamed` mode, the `Response` field contains a single token.
// To recover the whole response, all `Response` fields must be concatenated
// until the last `responseJSON`, identified as such by the `Done` field.
type responseJSON struct {
	Model           string              `json:"model"`
	CreatedAt       time.Time           `json:"created_at"`
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
	data    []*responseJSON
	metrics ResponseMetrics
}

// Done returns whether the response was completely generated.
func (r *Response) Done() bool {
	if len(r.data) == 0 {
		return false
	}
	return r.data[len(r.data)-1].Done
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
	var fullResponse strings.Builder
	gotDone := false
	for i, token := range r.data {
		fullResponse.WriteString(token.Response)
		if token.Done {
			if i != len(r.data)-1 {
				fullResponse.WriteString("<CORRUPT>")
			}
			gotDone = true
			break
		}
	}
	if !gotDone {
		return "<NOT DONE>"
	}
	return fullResponse.String()
}

// Text returns the body of the response, if it is done.
func (r *Response) Text() string {
	if !r.Done() {
		return ""
	}
	return r.String()
}

// TimeToFirstToken returns the time it took between the request starting
// and the first token being received by the client.
func (r *Response) TimeToFirstToken() time.Duration {
	if !r.Done() {
		return -1
	}
	return r.metrics.FirstByteRead.Sub(r.metrics.RequestSent)
}

// TimeToLastToken returns the time it took between the request starting
// and the last token being received by the client.
func (r *Response) TimeToLastToken() time.Duration {
	if !r.Done() {
		return -1
	}
	return r.metrics.LastByteRead.Sub(r.metrics.RequestSent)
}

// tokenIntervals returns the time between each token generation.
func (r *Response) tokenIntervals() []time.Duration {
	if !r.Done() || len(r.data) < 2 {
		return nil
	}
	intervals := make([]time.Duration, len(r.data)-1)
	for i := 0; i < len(r.data)-1; i++ {
		intervals[i] = r.data[i+1].CreatedAt.Sub(r.data[i].CreatedAt)
	}
	return intervals
}

// OutputTokensPerSecond computes the average number of output tokens
// generated per second.
func (r *Response) OutputTokensPerSecond() float64 {
	if !r.Done() || r.EvalDuration() == 0 {
		return -1
	}
	return float64(r.data[len(r.data)-1].EvalCount) / float64(r.EvalDuration().Seconds())
}

// TimePerOutputTokenAverage computes the average time to generate an output
// token.
func (r *Response) TimePerOutputTokenAverage() time.Duration {
	if !r.Done() {
		return -1
	}
	intervals := r.tokenIntervals()
	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}
	return sum / time.Duration(len(intervals))
}

// TimePerOutputTokenQuantile computes a quantile of the time it takes to
// generate an output token.
func (r *Response) TimePerOutputTokenQuantile(quantile float64) time.Duration {
	if quantile < 0.0 || quantile > 1.0 {
		panic("quantile must be between 0.0 and 1.0 inclusively")
	}
	if !r.Done() || r.EvalDuration() == 0 {
		return -1
	}
	intervals := r.tokenIntervals()
	sort.Slice(intervals, func(i, j int) bool { return intervals[i] < intervals[j] })
	return intervals[int(quantile*float64(len(intervals)-1))]
}

// TokenGenerationStdDev returns the standard deviation of the time between
// token generations.
func (r *Response) TokenGenerationStdDev() time.Duration {
	intervals := r.tokenIntervals()
	if len(intervals) == 0 {
		return -1
	}
	if len(intervals) == 1 {
		return 0
	}

	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}
	mean := sum / time.Duration(len(intervals))
	variance := 0.0
	for _, interval := range intervals {
		intervalMinusMean := float64((interval - mean).Nanoseconds())
		variance += intervalMinusMean * intervalMinusMean
	}
	variance = variance / float64(len(intervals)-1)
	return time.Duration(math.Sqrt(variance)) * time.Nanosecond
}

// TotalDuration returns the total response generation time.
func (r *Response) TotalDuration() time.Duration {
	if !r.Done() {
		return time.Duration(0)
	}
	return time.Duration(r.data[len(r.data)-1].TotalNanos) * time.Nanosecond
}

// LoadDuration returns the load response generation time as reported
// by the ollama server.
func (r *Response) LoadDuration() time.Duration {
	if !r.Done() {
		return time.Duration(0)
	}
	return time.Duration(r.data[len(r.data)-1].LoadNanos) * time.Nanosecond
}

// EvalDuration returns the response evaluation time.
func (r *Response) EvalDuration() time.Duration {
	if !r.Done() {
		return time.Duration(0)
	}
	return time.Duration(r.data[len(r.data)-1].EvalNanos) * time.Nanosecond
}

// PromptEvalDuration returns the prompt evaluation time.
func (r *Response) PromptEvalDuration() time.Duration {
	if !r.Done() {
		return time.Duration(0)
	}
	return time.Duration(r.data[len(r.data)-1].PromptEvalNanos) * time.Nanosecond
}

// ConversationContext represents a conversational context.
// It is returned by a response and may be passed to a follow-up prompt.
type ConversationContext []int

// withServerLogsErr adds server logs to `err` if possible.
func (llm *Ollama) withServerLogsErr(ctx context.Context, err error) error {
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
		return fmt.Errorf("%w; ollama server logs:\n%v\n(end of ollama server logs)", err, serverLogs)
	}
	return fmt.Errorf("%w (server logs are empty)", err)
}

// getReplacementModel picks an available model other than `model`.
// It tries to find a one that is marked cheap if possible.
func (llm *Ollama) getReplacementModel(model *Model) (*Model, error) {
	for _, cheapModel := range llm.cheapModels {
		if cheapModel.Name != model.Name {
			return cheapModel, nil
		}
	}
	for _, otherModelName := range llm.ModelNames {
		if otherModelName != model.Name {
			return ZeroTemperatureModel(otherModelName), nil
		}
	}
	return nil, fmt.Errorf("cannot find a replacement model to load instead of %q (available: %v; cheap: %v)", model.Name, llm.ModelNames, llm.cheapModels)
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
func (llm *Ollama) WarmModel(ctx context.Context, model *Model, keepWarmFor time.Duration, unloadFirst bool) (*ModelLoadStats, error) {
	if keepWarmFor <= 0 {
		return nil, fmt.Errorf("keepWarmFor must be strictly positive, got %v", keepWarmFor)
	}
	if unloadFirst {
		replacementModel, err := llm.getReplacementModel(model)
		if err != nil {
			return nil, fmt.Errorf("cannot find a replacement model to load instead of %q to forcefully unload it: %w", model.Name, err)
		}
		unloadCtx, unloadCancel := context.WithTimeout(ctx, 3*time.Minute)
		_, err = llm.Prompt(unloadCtx, &Prompt{Model: replacementModel, KeepModelAlive: 1 * time.Millisecond})
		unloadCancel()
		if err != nil {
			return nil, llm.withServerLogsErr(ctx, fmt.Errorf("unload prompt for replacement model %s failed: %w", replacementModel.Name, err))
		}
		select { // Wait for the model to get unloaded. Unfortunately there isn't a great way to do this but to sleep.
		case <-time.After(20 * time.Second):
		case <-ctx.Done():
		}
	}
	resp, err := llm.Prompt(ctx, &Prompt{Model: model, KeepModelAlive: keepWarmFor})
	if err != nil {
		return nil, llm.withServerLogsErr(ctx, fmt.Errorf("warmup prompt for model %s failed: %w", model.Name, err))
	}
	return &ModelLoadStats{
		ClientReportedDuration: resp.metrics.TimeToFirstByte(),
	}, nil
}

// Prompt returns the result of prompting the given `model` with `prompt`.
func (llm *Ollama) Prompt(ctx context.Context, prompt *Prompt) (*Response, error) {
	resp, err := jsonPost[promptJSON, responseJSON](ctx, llm, "/api/generate", prompt.json())
	if err != nil {
		return nil, llm.withServerLogsErr(ctx, fmt.Errorf("prompt (%s %q) request failed: %w", prompt.Model.Name, prompt.CleanQuery(), err))
	}
	return &Response{data: resp.Objects, metrics: resp.Metrics}, nil
}

// PromptUntil repeatedly issues a prompt until `iterate` returns a nil error.
// `iterate` may optionally return an updated `Prompt` which will be used to
// follow up. This is useful to work around the flakiness of LLMs in tests.
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

// Embedding holds the result of running an embedding model on a single input.
type Embedding struct {
	Input     string
	Embedding []float64
}

// EmbeddingResponse represents the result of running an embedding model
// on a set of inputs.
type EmbeddingResponse struct {
	// Model is the model used to generate the embeddings.
	Model *Model

	// Embeddings is the list of embeddings generated for the given inputs.
	Embeddings []Embedding

	// TotalDuration is the total duration of the embedding request as
	// measured by the server, not the client.
	TotalDuration time.Duration

	// LoadDuration is the duration of the embedding model load time as measured
	// by the server, not the client.
	LoadDuration time.Duration

	// PromptEvalCount is the number of prompt evaluations performed by the
	// server.
	PromptEvalCount int

	// ResponseMetrics contains HTTP response metrics as perceived by the
	// client.
	ResponseMetrics ResponseMetrics
}

// Embed generates embeddings for each of the given inputs.
func (llm *Ollama) Embed(ctx context.Context, model *Model, inputs []string) (*EmbeddingResponse, error) {
	// embeddingRequestJSON is the JSON format of an embedding request.
	type embeddingRequestJSON struct {
		Model string   `json:"model"`
		Input []string `json:"input"`
	}

	// embeddingResponseJSON is the JSON format of an embedding response.
	type embeddingResponseJSON struct {
		Model           string      `json:"model"`
		Embeddings      [][]float64 `json:"embeddings"`
		TotalDuration   int64       `json:"total_duration"`
		LoadDuration    int64       `json:"load_duration"`
		PromptEvalCount int         `json:"prompt_eval_count"`
	}

	resp, err := jsonPost[embeddingRequestJSON, embeddingResponseJSON](ctx, llm, "/api/embed", embeddingRequestJSON{Model: model.Name, Input: inputs})
	if err != nil {
		return nil, llm.withServerLogsErr(ctx, fmt.Errorf("embedding request failed: %w", err))
	}
	obj, err := resp.Obj()
	if err != nil {
		return nil, fmt.Errorf("malformed embedding response: %w", err)
	}
	if len(obj.Embeddings) != len(inputs) {
		return nil, fmt.Errorf("embedding response has %d embeddings, but %d inputs were provided", len(obj.Embeddings), len(inputs))
	}
	embeddings := make([]Embedding, len(inputs))
	for i, embedding := range obj.Embeddings {
		embeddings[i] = Embedding{
			Input:     inputs[i],
			Embedding: embedding,
		}
	}
	return &EmbeddingResponse{
		Model:           model,
		Embeddings:      embeddings,
		TotalDuration:   time.Duration(obj.TotalDuration) * time.Nanosecond,
		LoadDuration:    time.Duration(obj.LoadDuration) * time.Nanosecond,
		PromptEvalCount: obj.PromptEvalCount,
		ResponseMetrics: resp.Metrics,
	}, nil
}
