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

//go:build !false
// +build !false

package container

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestCompatibilityTestingDirCordoned verifies that the compatibility_testing
// directory is never committed to or present on non-testing branches (e.g. master).
func TestCompatibilityTestingDirCordoned(t *testing.T) {
	branch := currentGitBranch(t)
	if branch == "fscheckpoint-compat-testing" || branch == "origin/fscheckpoint-compat-testing" {
		return
	}
	for _, dir := range []string{"compatibility_testing", "../../compatibility_testing"} {
		if _, err := os.Stat(dir); err == nil {
			t.Fatalf("Directory %q found on branch %q; historical snapshots must only exist on fscheckpoint-compat-testing.", dir, branch)
		}
	}
}

func currentGitBranch(t *testing.T) string {
	if b := os.Getenv("BUILDKITE_BRANCH"); b != "" {
		return b
	}
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	out, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}
