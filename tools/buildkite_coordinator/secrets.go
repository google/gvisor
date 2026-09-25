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
	"encoding/base64"
	"fmt"
	"log"
	"time"

	secretmanager "google.golang.org/api/secretmanager/v1"
)

const (
	secretAttempts   = 5
	secretRetryDelay = 5 * time.Second
)

// accessSecret returns the payload of the given secret.
//
// Failures are retried up to 5 times.
func accessSecret(ctx context.Context, project, secret string) ([]byte, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", project, secret)

	svc, err := secretmanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	for attempt := 1; ; attempt++ {
		result, err := svc.Projects.Secrets.Versions.Access(name).Context(ctx).Do()
		if err == nil {
			// The REST API returns the payload base64-encoded.
			return base64.StdEncoding.DecodeString(result.Payload.Data)
		}
		if attempt == secretAttempts {
			return nil, fmt.Errorf("failed to access secret version %s: %w", name, err)
		}
		log.Printf("Failed to access secret version %s (attempt %d/%d), retrying in %v: %v",
			name, attempt, secretAttempts, secretRetryDelay, err)
		time.Sleep(secretRetryDelay)
	}
}
