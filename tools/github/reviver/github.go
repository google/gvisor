// Copyright 2019 The gVisor Authors.
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

package reviver

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/github"
)

// GitHubBugger implements Bugger interface for github issues.
type GitHubBugger struct {
	owner  string
	repo   string
	dryRun bool

	client *github.Client
	issues map[int]*github.Issue
}

// NewGitHubBugger creates a new GitHubBugger.
func NewGitHubBugger(client *github.Client, owner, repo string, dryRun bool) (*GitHubBugger, error) {
	b := &GitHubBugger{
		owner:  owner,
		repo:   repo,
		dryRun: dryRun,
		issues: map[int]*github.Issue{},
		client: client,
	}
	if err := b.load(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *GitHubBugger) load() error {
	err := processAllPages(func(listOpts github.ListOptions) (*github.Response, error) {
		opts := &github.IssueListByRepoOptions{State: "open", ListOptions: listOpts}
		tmps, resp, err := b.client.Issues.ListByRepo(context.Background(), b.owner, b.repo, opts)
		if err != nil {
			return resp, err
		}
		for _, issue := range tmps {
			b.issues[issue.GetNumber()] = issue
		}
		return resp, nil
	})
	if err != nil {
		return err
	}

	fmt.Printf("Loaded %d issues from github.com/%s/%s\n", len(b.issues), b.owner, b.repo)
	return nil
}

// Activate implements Bugger.Activate.
func (b *GitHubBugger) Activate(todo *Todo) (bool, error) {
	id, err := parseIssueNo(todo.Issue)
	if err != nil {
		return true, err
	}
	if id <= 0 {
		return false, nil
	}

	// Check against active issues cache.
	if _, ok := b.issues[id]; ok {
		fmt.Printf("%q is active: OK\n", todo.Issue)
		return true, nil
	}

	fmt.Printf("%q is not active: reopening issue %d\n", todo.Issue, id)

	// Format comment with TODO locations and search link.
	comment := strings.Builder{}
	fmt.Fprintln(&comment, "There are TODOs still referencing this issue:")
	for _, l := range todo.Locations {
		fmt.Fprintf(&comment,
			"1. [%s:%d](https://github.com/%s/%s/blob/HEAD/%s#%d): %s\n",
			l.File, l.Line, b.owner, b.repo, l.File, l.Line, l.Comment)
	}
	fmt.Fprintf(&comment,
		"\n\nSearch [TODO](https://github.com/%s/%s/search?q=%%22%s%%22)", b.owner, b.repo, todo.Issue)

	if b.dryRun {
		fmt.Printf("[dry-run: skipping change to issue %d]\n%s\n=======================\n", id, comment.String())
		return true, nil
	}

	ctx := context.Background()
	req := &github.IssueRequest{State: github.String("open")}
	_, _, err = b.client.Issues.Edit(ctx, b.owner, b.repo, id, req)
	if err != nil {
		return true, fmt.Errorf("failed to reactivate issue %d: %v", id, err)
	}

	_, _, err = b.client.Issues.AddLabelsToIssue(ctx, b.owner, b.repo, id, []string{"revived"})
	if err != nil {
		return true, fmt.Errorf("failed to set label on issue %d: %v", id, err)
	}

	cmt := &github.IssueComment{
		Body:      github.String(comment.String()),
		Reactions: &github.Reactions{Confused: github.Int(1)},
	}
	if _, _, err := b.client.Issues.CreateComment(ctx, b.owner, b.repo, id, cmt); err != nil {
		return true, fmt.Errorf("failed to add comment to issue %d: %v", id, err)
	}

	return true, nil
}

var issuePrefixes = []string{
	"gvisor.dev/issue/",
	"gvisor.dev/issues/",
}

// parseIssueNo parses the issue number out of the issue url.
//
// 0 is returned if url does not correspond to an issue.
func parseIssueNo(url string) (int, error) {
	// First check if I can handle the TODO.
	var idStr string
	for _, p := range issuePrefixes {
		if str := strings.TrimPrefix(url, p); len(str) < len(url) {
			idStr = str
			break
		}
	}
	if len(idStr) == 0 {
		return 0, nil
	}

	id, err := strconv.ParseInt(strings.TrimRight(idStr, "/"), 10, 64)
	if err != nil {
		return 0, err
	}
	return int(id), nil
}

func processAllPages(fn func(github.ListOptions) (*github.Response, error)) error {
	opts := github.ListOptions{PerPage: 1000}
	for {
		resp, err := fn(opts)
		if err != nil {
			if rateErr, ok := err.(*github.RateLimitError); ok {
				duration := rateErr.Rate.Reset.Sub(time.Now())
				if duration > 5*time.Minute {
					return fmt.Errorf("Rate limited for too long: %v", duration)
				}
				fmt.Printf("Rate limited, sleeping for: %v\n", duration)
				time.Sleep(duration)
				continue
			}
			return err
		}
		if resp.NextPage == 0 {
			return nil
		}
		opts.Page = resp.NextPage
	}
}
