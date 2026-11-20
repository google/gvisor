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
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// TestCompatibilityTestingDirCordoned verifies that the compatibility_testing
// directory is never committed to or present on non-testing branches (e.g. master).
func TestCompatibilityTestingDirCordoned(t *testing.T) {
	branch := currentGitBranch(t)
	if strings.HasSuffix(branch, "fscheckpoint-compat-testing") {
		return
	}
	for _, dir := range compatibilityTestingCandidateDirs() {
		if _, err := os.Stat(dir); err == nil {
			t.Fatalf("Directory %q found on branch %q; historical snapshots must only exist on fscheckpoint-compat-testing.", dir, branch)
		}
	}
}

func compatibilityTestingCandidateDirs() []string {
	var dirs []string
	if dir, err := testutil.FindFile("compatibility_testing"); err == nil {
		if abs, err := filepath.Abs(dir); err == nil {
			dirs = append(dirs, abs)
		}
	}
	if ws := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); ws != "" {
		if abs, err := filepath.Abs(filepath.Join(ws, "compatibility_testing")); err == nil {
			dirs = append(dirs, abs)
		}
	}
	if out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output(); err == nil {
		if top := strings.TrimSpace(string(out)); top != "" {
			if abs, err := filepath.Abs(filepath.Join(top, "compatibility_testing")); err == nil {
				dirs = append(dirs, abs)
			}
		}
	}
	return dirs
}

func currentGitBranch(t *testing.T) string {
	for _, env := range []string{"BUILDKITE_BRANCH", "GITHUB_REF_NAME", "GITHUB_HEAD_REF"} {
		if b := os.Getenv(env); b != "" {
			return b
		}
	}
	if out, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
		if b := strings.TrimSpace(string(out)); b != "" && b != "HEAD" {
			return b
		}
	}
	if out, err := exec.Command("git", "branch", "-a", "--contains", "HEAD").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			b := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "*"))
			if strings.HasSuffix(b, "fscheckpoint-compat-testing") {
				return b
			}
		}
	}
	return ""
}
