// Copyright 2026 The gVisor Authors.
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

// Package llmutil provides common utilities for LLM container testing.
package llmutil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// ResponseMetrics are HTTP request metrics from an LLM API query.
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

// APIResponse represents a response from an LLM API.
type APIResponse[T any] struct {
	// Objects is the list of JSON objects in the response.
	Objects []*T
	// Metrics contains HTTP response metrics.
	Metrics ResponseMetrics
}

// Obj returns the first object in the response, if there is a singular
// object in the response.
func (ar *APIResponse[T]) Obj() (*T, error) {
	if len(ar.Objects) == 0 {
		return nil, fmt.Errorf("no objects in response")
	}
	if len(ar.Objects) > 1 {
		return nil, fmt.Errorf("multiple objects in response")
	}
	return ar.Objects[0], nil
}

// MakeAPIResponse decodes a raw response from an instrumented HTTP request.
func MakeAPIResponse[T any](rawResponse []byte) (*APIResponse[T], error) {
	var respBytes strings.Builder
	var resp APIResponse[T]
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
		case "RESPSTATUS":
			if !strings.Contains(data, "200 OK") {
				return nil, fmt.Errorf("HTTP error: %s", data)
			}
		case "REQHEADER", "RESPHEADER":
			// Do nothing.
		case "BODY":
			unquoted, err := strconv.Unquote(data)
			if err != nil {
				return nil, fmt.Errorf("malformed body line: %q", data)
			}
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
	decoder := json.NewDecoder(strings.NewReader(respBytes.String()))
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
	return &resp, nil
}

// Server performs requests against a generic LLM server.
type Server interface {
	// InstrumentedRequest performs an instrumented HTTP request against the
	// server, using the client image.
	InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error)

	// Logs retrieves logs from the server.
	Logs(ctx context.Context) (string, error)
}

// DockerServer implements an LLM server interface via a local Docker container.
type DockerServer struct {
	Container   *dockerutil.Container
	Logger      testutil.Logger
	Port        int
	ClientImage string
}

// InstrumentedRequest performs an instrumented HTTP request against the server.
func (ds *DockerServer) InstrumentedRequest(ctx context.Context, argvFn func(hostPort string) []string) ([]byte, error) {
	const host = "llm"
	cmd := argvFn(fmt.Sprintf("http://%s:%d", host, ds.Port))
	out, err := dockerutil.MakeContainer(ctx, ds.Logger).Run(ctx, dockerutil.RunOpts{
		Image: ds.ClientImage,
		Links: []string{ds.Container.MakeLink(host)},
	}, cmd...)
	if err != nil {
		if out != "" {
			return []byte(out), fmt.Errorf("command %q failed (%w): %v", strings.Join(cmd, " "), err, out)
		}
		return nil, fmt.Errorf("could not run command %q: %w", strings.Join(cmd, " "), err)
	}
	return []byte(out), nil
}

// Logs retrieves logs from the server container.
func (ds *DockerServer) Logs(ctx context.Context) (string, error) {
	return ds.Container.Logs(ctx)
}
