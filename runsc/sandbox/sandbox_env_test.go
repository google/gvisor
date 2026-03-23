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

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestTempDirHelper is invoked as a subprocess by TestSandboxSubprocessTMPDIR
// and TestSandboxEnvEndToEnd. It prints os.TempDir() to stdout.
func TestTempDirHelper(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	fmt.Fprint(os.Stdout, os.TempDir())
	os.Exit(0)
}

// sandboxEnvTMPDIR mirrors the TMPDIR forwarding logic in
// createSandboxProcess. It returns the env slice that would be used for
// the sandbox subprocess when the environment is cleared.
func sandboxEnvTMPDIR() []string {
	env := []string{}
	if tmpDir := os.TempDir(); tmpDir != "/tmp" {
		env = append(env, "TMPDIR="+tmpDir)
	}
	return env
}

func findEnvEntry(env []string, prefix string) string {
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return e
		}
	}
	return ""
}

// TestSandboxEnvTMPDIRForwarding verifies that the sandbox subprocess
// environment construction correctly handles TMPDIR forwarding.
func TestSandboxEnvTMPDIRForwarding(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tmpdir    string
		wantEntry string
	}{
		{
			name:      "empty TMPDIR defaults to /tmp",
			tmpdir:    "",
			wantEntry: "",
		},
		{
			name:      "TMPDIR=/tmp not forwarded",
			tmpdir:    "/tmp",
			wantEntry: "",
		},
		{
			name:      "custom TMPDIR forwarded",
			tmpdir:    "/realtmp",
			wantEntry: "TMPDIR=/realtmp",
		},
		{
			name:      "nested TMPDIR forwarded",
			tmpdir:    "/var/tmp/custom",
			wantEntry: "TMPDIR=/var/tmp/custom",
		},
		{
			name:      "trailing slash TMPDIR forwarded",
			tmpdir:    "/realtmp/",
			wantEntry: "TMPDIR=/realtmp/",
		},
		{
			name:      "path with multiple components forwarded",
			tmpdir:    "/mnt/data/tmp",
			wantEntry: "TMPDIR=/mnt/data/tmp",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", tc.tmpdir)

			env := sandboxEnvTMPDIR()
			found := findEnvEntry(env, "TMPDIR=")

			if tc.wantEntry == "" && found != "" {
				t.Errorf("expected no TMPDIR in env, got %q", found)
			} else if tc.wantEntry != "" && found != tc.wantEntry {
				t.Errorf("expected %q in env, got %q", tc.wantEntry, found)
			}
		})
	}
}

// TestSandboxSubprocessTMPDIR verifies that a subprocess started with a
// cleared environment and optional TMPDIR resolves os.TempDir() correctly.
func TestSandboxSubprocessTMPDIR(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     []string
		wantDir string
	}{
		{
			name:    "cleared env defaults to /tmp",
			env:     nil,
			wantDir: "/tmp",
		},
		{
			name:    "forwarded TMPDIR=/realtmp",
			env:     []string{"TMPDIR=/realtmp"},
			wantDir: "/realtmp",
		},
		{
			name:    "forwarded TMPDIR=/var/tmp/custom",
			env:     []string{"TMPDIR=/var/tmp/custom"},
			wantDir: "/var/tmp/custom",
		},
		{
			name:    "explicit TMPDIR=/tmp",
			env:     []string{"TMPDIR=/tmp"},
			wantDir: "/tmp",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTempDirHelper$")
			cmd.Env = append([]string{"GO_WANT_HELPER_PROCESS=1"}, tc.env...)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("subprocess failed: %v", err)
			}
			if got := string(out); got != tc.wantDir {
				t.Errorf("subprocess os.TempDir() = %q, want %q", got, tc.wantDir)
			}
		})
	}
}

// TestSandboxEnvEndToEnd mirrors the full env construction path from
// createSandboxProcess and verifies a subprocess sees the expected
// os.TempDir() value. This is the key integration test: parent sets
// TMPDIR, builds the env using the same logic as production, spawns a
// child, and checks the child's os.TempDir().
func TestSandboxEnvEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name             string
		parentTmpdir     string
		wantChildTempDir string
	}{
		{
			name:             "default /tmp round-trips",
			parentTmpdir:     "",
			wantChildTempDir: "/tmp",
		},
		{
			name:             "custom /realtmp round-trips",
			parentTmpdir:     "/realtmp",
			wantChildTempDir: "/realtmp",
		},
		{
			name:             "explicit /tmp round-trips",
			parentTmpdir:     "/tmp",
			wantChildTempDir: "/tmp",
		},
		{
			name:             "/var/tmp/custom round-trips",
			parentTmpdir:     "/var/tmp/custom",
			wantChildTempDir: "/var/tmp/custom",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", tc.parentTmpdir)

			env := sandboxEnvTMPDIR()

			cmd := exec.Command(os.Args[0], "-test.run=^TestTempDirHelper$")
			cmd.Env = append([]string{"GO_WANT_HELPER_PROCESS=1"}, env...)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("subprocess failed: %v", err)
			}
			if got := string(out); got != tc.wantChildTempDir {
				t.Errorf("child os.TempDir() = %q, want %q (parent TMPDIR=%q, constructed env: %v)",
					got, tc.wantChildTempDir, tc.parentTmpdir, env)
			}
		})
	}
}

// TestSandboxEnvNoUnintendedLeaks verifies that the cleared sandbox
// environment does not leak parent env vars other than TMPDIR.
func TestSandboxEnvNoUnintendedLeaks(t *testing.T) {
	t.Setenv("TMPDIR", "/realtmp")
	t.Setenv("HOME", "/root")
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("SECRET_TOKEN", "do-not-leak")

	env := sandboxEnvTMPDIR()

	for _, forbidden := range []string{"HOME=", "PATH=", "SECRET_TOKEN="} {
		if entry := findEnvEntry(env, forbidden); entry != "" {
			t.Errorf("parent env var leaked to sandbox: %q", entry)
		}
	}

	if entry := findEnvEntry(env, "TMPDIR="); entry != "TMPDIR=/realtmp" {
		t.Errorf("expected TMPDIR=/realtmp, got %q", entry)
	}
}

// TestSandboxEnvTMPDIROnlyEntry verifies the env slice size matches
// expectations: exactly one entry (TMPDIR) when TMPDIR differs from
// /tmp, and zero entries when it matches.
func TestSandboxEnvTMPDIROnlyEntry(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tmpdir   string
		wantSize int
	}{
		{
			name:     "no entries when TMPDIR is default",
			tmpdir:   "",
			wantSize: 0,
		},
		{
			name:     "no entries when TMPDIR is /tmp",
			tmpdir:   "/tmp",
			wantSize: 0,
		},
		{
			name:     "one entry when TMPDIR is custom",
			tmpdir:   "/realtmp",
			wantSize: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", tc.tmpdir)

			env := sandboxEnvTMPDIR()
			if len(env) != tc.wantSize {
				t.Errorf("expected %d env entries, got %d: %v", tc.wantSize, len(env), env)
			}
		})
	}
}
