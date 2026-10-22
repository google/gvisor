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
	"sync"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/auth/credentials/downscope"
	"cloud.google.com/go/auth/credentials/impersonate"
	"cloud.google.com/go/compute/metadata"
)

const (
	// BucketTokenLifetime is how long bucket tokens last.
	BucketTokenLifetime = time.Hour

	// cloudPlatformScope is the OAuth scope that covers all Google Cloud APIs.
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

// BucketTokenController issues bucket tokens: access tokens that only grant certain
// roles on objects under a prefix in a Cloud Storage bucket.
//
// Tokens are cached by prefix.
//
// Safe for concurrent use.
type BucketTokenController struct {
	// The following fields are immutable.
	bucket               string
	availablePermissions []string
	serviceAccount       string
	creds                *auth.Credentials

	// mu protects tokens.
	mu     sync.Mutex
	tokens map[string]*auth.Token
}

// NewBucketTokenController returns a BucketTokenController that issues tokens for the given
// bucket granting the specified roles.
func NewBucketTokenController(ctx context.Context, bucket string, roles []string) (*BucketTokenController, error) {
	serviceAccount, err := metadata.EmailWithContext(ctx, "default")
	if err != nil {
		return nil, fmt.Errorf("failed to get service account from metadata server: %w", err)
	}
	creds, err := credentials.DetectDefault(&credentials.DetectOptions{
		Scopes: []string{cloudPlatformScope},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect default credentials: %w", err)
	}
	availablePermissions := make([]string, len(roles))
	for i, role := range roles {
		availablePermissions[i] = "inRole:" + role
	}
	return &BucketTokenController{
		bucket:               bucket,
		availablePermissions: availablePermissions,
		serviceAccount:       serviceAccount,
		creds:                creds,
		tokens:               make(map[string]*auth.Token),
	}, nil
}

// GetToken returns a token scoped to objects under prefix. The returned token will last at
// least minLifetime, however if a longer-lasting cached token was found, it may last
// longer.
//
// If minLifetime is longer than BucketTokenLifetime, it will be clamped to BucketTokenLifetime.
func (b *BucketTokenController) GetToken(ctx context.Context, prefix string, minLifetime time.Duration) (*auth.Token, error) {
	now := time.Now()

	b.mu.Lock()
	// Evict expired tokens to ensure we don't accumulate old builds' tokens
	for p, token := range b.tokens {
		if token.Expiry.Before(now) {
			delete(b.tokens, p)
		}
	}
	token, ok := b.tokens[prefix]
	b.mu.Unlock()

	if ok && !token.Expiry.Before(now.Add(minLifetime)) {
		return token, nil
	}

	token, err := b.generate(ctx, prefix)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[prefix] = token
	return token, nil
}

// generate generates a new token for the objects whose names start with
// prefix.
func (b *BucketTokenController) generate(ctx context.Context, prefix string) (*auth.Token, error) {
	// Generate a fresh access token for the coordinator's service account
	// to downscope from.
	root, err := newImpersonatedCredentials(ctx, &impersonate.CredentialsOptions{
		TargetPrincipal: b.serviceAccount,
		Scopes:          []string{cloudPlatformScope},
		Lifetime:        BucketTokenLifetime,
		Credentials:     b.creds,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create impersonated credentials: %w", err)
	}

	creds, err := downscope.NewCredentials(&downscope.Options{
		Credentials: root,
		Rules: []downscope.AccessBoundaryRule{{
			AvailableResource:    "//storage.googleapis.com/projects/_/buckets/" + b.bucket,
			AvailablePermissions: b.availablePermissions,
			Condition: &downscope.AvailabilityCondition{
				Expression: fmt.Sprintf("resource.name.startsWith(%q)", "projects/_/buckets/"+b.bucket+"/objects/"+prefix),
			},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure downscoping: %w", err)
	}
	token, err := creds.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate downscoped token: %w", err)
	}
	return token, nil
}

// artifactRoles are the roles that agents get on their build's artifacts.
var artifactRoles = []string{"roles/storage.objectCreator", "roles/storage.objectViewer"}

// artifactPrefix returns the prefix of the given build's artifacts in the
// artifact bucket.
//
// See BUILDKITE_ARTIFACT_UPLOAD_DESTINATION in startup.sh.
func artifactPrefix(build BuildUUID) string {
	return string(build) + "/"
}
