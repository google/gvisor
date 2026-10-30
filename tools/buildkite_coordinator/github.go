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
	"strings"
	"time"

	"github.com/google/go-github/v84/github"
)

type authorID uint64

func parseAuthorID(s string) (authorID, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	return authorID(v), err
}

// githubRepository identifies a GitHub repository.
type githubRepository struct {
	owner string
	name  string
}

// parseGitHubRepository parses a repository of the form github.com/OWNER/NAME.
func parseGitHubRepository(s string) (githubRepository, error) {
	path, ok := strings.CutPrefix(s, "github.com/")
	if !ok {
		return githubRepository{}, fmt.Errorf("repository %q does not start with github.com/", s)
	}
	owner, name, ok := strings.Cut(path, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return githubRepository{}, fmt.Errorf("repository %q is not of the form github.com/OWNER/NAME", s)
	}
	return githubRepository{owner: owner, name: name}, nil
}

// String implements fmt.Stringer.
func (r githubRepository) String() string {
	return "github.com/" + r.owner + "/" + r.name
}

// githubClient is a GitHub API client for a repository.
//
// Safe for concurrent use.
type githubClient struct {
	client *github.Client
	repo   githubRepository
}

// newGitHubClient returns a client for the given repository that authenticates
// with the given token.
func newGitHubClient(token []byte, repo githubRepository) *githubClient {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	return &githubClient{
		client: github.NewClient(httpClient).WithAuthToken(string(token)),
		repo:   repo,
	}
}

// prAuthor returns the GitHub user ID of the account that opened the given pull
// request.
//
// On success, the returned ID is guaranteed to be non-zero.
func (g *githubClient) prAuthor(ctx context.Context, prNumber int) (authorID, error) {
	ctx = context.WithValue(ctx, github.SleepUntilPrimaryRateLimitResetWhenRateLimited, true)
	pr, _, err := g.client.PullRequests.Get(ctx, g.repo.owner, g.repo.name, prNumber)
	if err != nil {
		return 0, fmt.Errorf("failed to get pull request %d: %w", prNumber, err)
	}
	id := pr.GetUser().GetID()
	if id <= 0 {
		return 0, fmt.Errorf("pull request %d has no or invalid author", prNumber)
	}
	return authorID(id), nil
}

// fileContents returns the contents of the file at the given path on the
// repository's default branch.
func (g *githubClient) fileContents(ctx context.Context, path string) ([]byte, error) {
	ctx = context.WithValue(ctx, github.SleepUntilPrimaryRateLimitResetWhenRateLimited, true)
	file, _, _, err := g.client.Repositories.GetContents(ctx, g.repo.owner, g.repo.name, path, nil)
	if err != nil {
		return nil, fmt.Errorf("getting %q in %v: %w", path, g.repo, err)
	}
	if file == nil {
		return nil, fmt.Errorf("%q in %v is not a file", path, g.repo)
	}
	content, err := file.GetContent()
	if err != nil {
		return nil, fmt.Errorf("decoding %q in %v: %w", path, g.repo, err)
	}
	return []byte(content), nil
}
