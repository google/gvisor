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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"cloud.google.com/go/compute/metadata"
)

// config is the coordinator's configuration.
type config struct {
	// port is the port to listen on. Cloud Run sets $PORT.
	port string

	// stackKey is the key of the stack used to register in Buildkite.
	stackKey string

	// queues is the set of Buildkite queues the coordinator serves.
	queues map[string]struct{}

	// trustedAuthors is the set of GitHub logins whose pull requests are
	// trusted.
	//
	// TODO: we should eventually fetch this from governance/maintainers.yaml.
	trustedAuthors map[authorID]struct{}

	// bkTokenProject and bkTokenSecret identify the Secret Manager secret that
	// holds the Buildkite agent token.
	bkTokenProject string
	bkTokenSecret  string

	// githubTokenProject and githubTokenSecret identify the Secret Manager secret
	// that holds the GitHub token.
	githubTokenProject string
	githubTokenSecret  string

	// project is the project the coordinator runs in. Agent VMs must be in
	// this project.
	project string

	// agentServiceAccount is the email of the service account that agent VMs
	// must run as.
	agentServiceAccount string
}

// loadConfig reads the configuration from the environment and the metadata
// server.
func loadConfig(ctx context.Context) (config, error) {
	projectID, err := metadata.ProjectIDWithContext(ctx)
	if err != nil {
		return config{}, fmt.Errorf("failed to get project ID from metadata server: %w", err)
	}
	agentServiceAccount := os.Getenv("AGENT_SERVICE_ACCOUNT")
	if agentServiceAccount == "" {
		return config{}, fmt.Errorf("AGENT_SERVICE_ACCOUNT is not set")
	}
	queues := envSet("BUILDKITE_QUEUES")
	if len(queues) == 0 {
		return config{}, fmt.Errorf("BUILDKITE_QUEUES is not set")
	}
	trustedAuthorsRaw := envSet("TRUSTED_AUTHORS")
	trustedAuthors := make(map[authorID]struct{})
	for author := range trustedAuthorsRaw {
		id, err := parseAuthorID(author)
		if err != nil {
			return config{}, fmt.Errorf("TRUSTED_AUTHORS: failed to parse author GitHub user ID %v: %w", author, err)
		}
		trustedAuthors[id] = struct{}{}
	}
	stackKeyPrefix := envOr("STACK_KEY_PREFIX", "bk-test-stack")
	idHash, err := instanceIDHash(ctx)
	if err != nil {
		return config{}, fmt.Errorf("failed to compute instance ID hash: %w", err)
	}
	stackKey := stackKeyPrefix + "-" + idHash[:16]
	return config{
		port:                envOr("PORT", "8080"),
		stackKey:            stackKey,
		queues:              queues,
		trustedAuthors:      trustedAuthors,
		bkTokenProject:      envOr("BUILDKITE_TOKEN_PROJECT", "gvisor-kokoro-testing"),
		bkTokenSecret:       envOr("BUILDKITE_TOKEN_SECRET", "buildkite-default-token"),
		githubTokenProject:  envOr("GITHUB_TOKEN_PROJECT", "gvisor-kokoro-testing"),
		githubTokenSecret:   envOr("GITHUB_TOKEN_SECRET", "github-default-token"),
		project:             projectID,
		agentServiceAccount: agentServiceAccount,
	}, nil
}

// instanceIDHash returns the sha256 hash of the Cloud Run instance's ID.
func instanceIDHash(ctx context.Context) (string, error) {
	instanceID, err := metadata.GetWithContext(ctx, "instance/id")
	if err != nil {
		return "", fmt.Errorf("failed to get instance ID from metadata server: %w", err)
	}
	sum := sha256.Sum256([]byte(instanceID))
	key := hex.EncodeToString(sum[:])
	return key, nil
}

// serviceURL returns the coordinator's Cloud Run URL, which has
// the form https://SERVICE-PROJECT_NUMBER.REGION.run.app.
func serviceURL(ctx context.Context) (string, error) {
	service := os.Getenv("K_SERVICE")
	if service == "" {
		return "", fmt.Errorf("K_SERVICE is not set")
	}
	// Of the form "projects/PROJECT_NUMBER/regions/REGION".
	region, err := metadata.GetWithContext(ctx, "instance/region")
	if err != nil {
		return "", fmt.Errorf("failed to get region from metadata server: %w", err)
	}
	parts := strings.Split(region, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != "regions" {
		return "", fmt.Errorf("unexpected region from metadata server: %q", region)
	}
	return fmt.Sprintf("https://%s-%s.%s.run.app", service, parts[1], parts[3]), nil
}

// envOr returns the value of the environment variable key, or def if unset.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envSet returns the comma-separated values of the environment variable key as
// a set.
func envSet(key string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, v := range strings.Split(os.Getenv(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			set[v] = struct{}{}
		}
	}
	return set
}
