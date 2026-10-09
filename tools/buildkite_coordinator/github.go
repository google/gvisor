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

package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/go-github/v84/github"
)

const (
	githubOwner = "google"
	githubRepo  = "gvisor"
)

type authorID uint64

func parseAuthorID(s string) (authorID, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	return authorID(v), err
}

// githubClient is a GitHub API client.
//
// Safe for concurrent use.
type githubClient struct {
	client *github.Client
}

// newGitHubClient returns a client that authenticates with the given token.
func newGitHubClient(token []byte) *githubClient {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	return &githubClient{client: github.NewClient(httpClient).WithAuthToken(string(token))}
}

// prAuthor returns the GitHub user ID of the account that opened the given pull
// request.
//
// On success, the returned ID is guaranteed to be non-zero.
func (g *githubClient) prAuthor(ctx context.Context, prNumber int) (authorID, error) {
	ctx = context.WithValue(ctx, github.SleepUntilPrimaryRateLimitResetWhenRateLimited, true)
	pr, _, err := g.client.PullRequests.Get(ctx, githubOwner, githubRepo, prNumber)
	if err != nil {
		return 0, fmt.Errorf("failed to get pull request %d: %w", prNumber, err)
	}
	id := pr.GetUser().GetID()
	if id <= 0 {
		return 0, fmt.Errorf("pull request %d has no or invalid author", prNumber)
	}
	return authorID(id), nil
}
