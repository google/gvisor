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

// Package compatibility provides shared helpers for gVisor application
// compatibility tests.
package compatibility

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// WriteConfigFile writes content to a file named name in a fresh temporary
// directory and returns the file's absolute path.
func WriteConfigFile(t *testing.T, name, content string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "compat-config")
	if err != nil {
		t.Fatalf("failed to create temp config dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file %s: %v", name, err)
	}
	return p
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// Poll repeatedly calls cond until it returns nil, failing the test (via
// t.Fatalf) if it has not succeeded within timeout. It waits interval between
// attempts.
//
// This is the preferred way to wait for a stack to become ready: poll for a
// readiness signal (a health endpoint, an accepted connection, etc).
//
// desc is a short human-readable description of what is being waited for, used in
// the timeout message (e.g. "gitea API to be ready").
func Poll(ctx context.Context, t *testing.T, desc string, timeout, interval time.Duration, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if lastErr = cond(); lastErr == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s: %v", timeout, desc, lastErr)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled while waiting for %s: %v (last error: %v)", desc, ctx.Err(), lastErr)
		case <-time.After(interval):
		}
	}
}

// Request describes an HTTP request issued by a compatibility test.
type Request struct {
	Method      string // defaults to GET.
	URL         string
	Body        string
	ContentType string
	Host        string // overrides the Host header if non-empty.
	Username    string // enables HTTP basic auth if non-empty.
	Password    string
	Headers     map[string]string
	// Timeout overrides the default client timeout for this request.
	// Zero uses the default from httpClient.
	Timeout time.Duration
}

func (r Request) method() string {
	if r.Method == "" {
		return http.MethodGet
	}
	return r.Method
}

// Do issues the request and returns the response status code and body. A
// transport-level failure is returned as an error; an HTTP error status is
// not an error.
func (r Request) Do() (int, string, error) {
	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}
	req, err := http.NewRequest(r.method(), r.URL, body)
	if err != nil {
		return 0, "", err
	}
	if r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	if r.Host != "" {
		req.Host = r.Host
	}
	if r.Username != "" {
		req.SetBasicAuth(r.Username, r.Password)
	}
	client := httpClient
	if r.Timeout > 0 {
		client = &http.Client{Timeout: r.Timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("reading body of %s %s: %w", r.method(), r.URL, err)
	}
	return resp.StatusCode, string(respBody), nil
}

// DoOrFatal issues the request, failing the test on a transport error or if the
// status code is not wantStatus, and returns the response body.
func (r Request) DoOrFatal(t *testing.T, wantStatus int) string {
	t.Helper()
	status, body, err := r.Do()
	if err != nil {
		t.Fatalf("%s %s failed: %v", r.method(), r.URL, err)
	}
	if status != wantStatus {
		t.Fatalf("%s %s: got status %d, want %d; body: %s", r.method(), r.URL, status, wantStatus, body)
	}
	return body
}

// Get is a convenience wrapper for a plain GET.
func Get(url string) (int, string, error) {
	return Request{URL: url}.Do()
}
