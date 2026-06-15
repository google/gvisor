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

package bwrap

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestEnvVars(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	rootDir := t.TempDir()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}

	hostEnvVar := "BWRAP_TEST_ENV_VAR"
	hostEnvVal := "BWRAP_TEST_ENV_VALUE"

	baseEnv := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
	}

	tests := []struct {
		name      string
		bwrapArgs []string
		wantEnv   []string
	}{
		{
			name: "SetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--setenv", "FOO", "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: append(baseEnv, hostEnvVar+"="+hostEnvVal, "FOO=bar"),
		},
		{
			name: "ResetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--setenv", hostEnvVar, "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: append(baseEnv, hostEnvVar+"=bar"),
		},
		{
			name: "ClearEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--clearenv",
				"--setenv", "FOO", "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: []string{"PWD=" + cwd, "FOO=bar", "HOME=/root"},
		},
		{
			name: "UnsetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--unsetenv", hostEnvVar,
				"--",
				"/usr/bin/env",
			},
			wantEnv: baseEnv,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := filepath.Join(rootDir, tc.name)
			if err := os.MkdirAll(runRootDir, 0755); err != nil {
				t.Fatalf("creating root dir: %v", err)
			}

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)
			cmd.Env = append(baseEnv, hostEnvVar+"="+hostEnvVal)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			actualEnv := strings.Split(strings.TrimSpace(stdout.String()), "\n")

			// 2. Sort both slices alphabetically so order is 100% ignored!
			slices.Sort(tc.wantEnv)
			slices.Sort(actualEnv)

			if diff := cmp.Diff(tc.wantEnv, actualEnv); diff != "" {
				t.Errorf("runsc bwrap env mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUserAndGroup(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	rootDir := t.TempDir()

	tests := []struct {
		name      string
		bwrapArgs []string
		wantUID   string
		wantGID   string
	}{
		{
			name: "DefaultUser",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-u",
			},
			wantUID: fmt.Sprintf("%d", os.Getuid()),
		},
		{
			name: "CustomUID",
			bwrapArgs: []string{
				"--unshare-user",
				"--uid", "12345",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-u",
			},
			wantUID: "12345",
		},
		{
			name: "CustomGID",
			bwrapArgs: []string{
				"--unshare-user",
				"--gid", "54321",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-g",
			},
			wantGID: "54321",
		},
		{
			name: "CustomUIDAndGID",
			bwrapArgs: []string{
				"--unshare-user",
				"--uid", "12345",
				"--gid", "54321",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id",
			},
			wantUID: "uid=12345",
			wantGID: "gid=54321",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := filepath.Join(rootDir, tc.name)
			if err := os.MkdirAll(runRootDir, 0755); err != nil {
				t.Fatalf("creating root dir: %v", err)
			}

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Run(); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantUID != "" && !strings.Contains(output, tc.wantUID) {
				t.Errorf("output = %q, want UID %q", output, tc.wantUID)
			}
			if tc.wantGID != "" && !strings.Contains(output, tc.wantGID) {
				t.Errorf("output = %q, want GID %q", output, tc.wantGID)
			}
		})
	}
}

// TODO: b/518882196 - Support joining existing user namespaces.
func TestUserns(t *testing.T) {
	t.Skip("Skipping userns joining due to runsc doesn't support joining existing user namespaces")
}

func TestHostname(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	rootDir := t.TempDir()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "Hostname",
			bwrapArgs: []string{
				"--hostname", "test-host",
				"--ro-bind", "/", "/",
				"--",
				"/bin/hostname",
			},
			wantOutput: "test-host",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := filepath.Join(rootDir, tc.name)
			if err := os.MkdirAll(runRootDir, 0755); err != nil {
				t.Fatalf("creating root dir: %v", err)
			}

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}
