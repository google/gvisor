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

// Package nogo provides nogo-related utilities.
package nogo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/github"
	"gvisor.dev/gvisor/tools/nogo"
)

// FindingsPoster is a simple wrapper around the GitHub api.
type FindingsPoster struct {
	owner     string
	repo      string
	commit    string
	dryRun    bool
	startTime time.Time

	findings map[nogo.Finding]struct{}
	client   *github.Client
}

// NewFindingsPoster returns a object that can post findings.
func NewFindingsPoster(client *github.Client, owner, repo, commit string, dryRun bool) *FindingsPoster {
	return &FindingsPoster{
		owner:     owner,
		repo:      repo,
		commit:    commit,
		dryRun:    dryRun,
		startTime: time.Now(),
		findings:  make(map[nogo.Finding]struct{}),
		client:    client,
	}
}

// Walk walks the given path tree for findings files.
func (p *FindingsPoster) Walk(paths []string) error {
	for _, path := range paths {
		if err := filepath.Walk(path, func(filename string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// Skip any directories or files not ending in .findings.
			if !strings.HasSuffix(filename, ".findings") || info.IsDir() {
				return nil
			}
			findings, err := nogo.ExtractFindingsFromFile(filename)
			if err != nil {
				return err
			}
			// Add all findings to the list. We use a map to ensure
			// that each finding is unique.
			for _, finding := range findings {
				p.findings[finding] = struct{}{}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// Post posts all results to the GitHub API as a check run.
func (p *FindingsPoster) Post() error {
	// Just show results?
	if p.dryRun {
		for finding := range p.findings {
			// Pretty print, so that this is useful for debugging.
			fmt.Printf("%s: (%s+%d) %s\n", finding.Category, finding.Position.Filename, finding.Position.Line, finding.Message)
		}
		return nil
	}

	// Construct the message.
	title := "nogo"
	count := len(p.findings)
	status := "completed"
	conclusion := "success"
	if count > 0 {
		conclusion = "failure" // Contains errors.
	}
	summary := fmt.Sprintf("%d findings.", count)
	opts := github.CreateCheckRunOptions{
		Name:        title,
		HeadSHA:     p.commit,
		Status:      &status,
		Conclusion:  &conclusion,
		StartedAt:   &github.Timestamp{p.startTime},
		CompletedAt: &github.Timestamp{time.Now()},
		Output: &github.CheckRunOutput{
			Title:            &title,
			Summary:          &summary,
			AnnotationsCount: &count,
		},
	}
	annotationLevel := "failure" // Always.
	for finding := range p.findings {
		title := string(finding.Category)
		opts.Output.Annotations = append(opts.Output.Annotations, &github.CheckRunAnnotation{
			Path:            &finding.Position.Filename,
			StartLine:       &finding.Position.Line,
			EndLine:         &finding.Position.Line,
			Message:         &finding.Message,
			Title:           &title,
			AnnotationLevel: &annotationLevel,
		})
	}

	// Post to GitHub.
	_, _, err := p.client.Checks.CreateCheckRun(context.Background(), p.owner, p.repo, opts)
	return err
}
