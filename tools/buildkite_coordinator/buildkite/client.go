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

// Package buildkite is a thin client for the Buildkite Agent API, which hosts the
// Stacks API. It authenticates with a cluster agent token.
package buildkite

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// endpoint is the Buildkite Agent API endpoint.
const endpoint = "https://agent.buildkite.com/v3"

// Client is a Buildkite Agent API client.
//
// Safe for concurrent use.
type Client struct {
	agentToken string
	client     *http.Client
}

// NewClient returns a client that authenticates with the given agent token.
func NewClient(agentToken []byte) *Client {
	return &Client{
		agentToken: string(agentToken),
		client:     &http.Client{Timeout: 60 * time.Second},
	}
}

// call makes a request to the Buildkite Agent API, authenticated with the
// agent token, and decodes the JSON response into out if it is non-nil.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.agentToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("failed to decode response to %s %s: %w", method, path, err)
		}
	}
	return nil
}
