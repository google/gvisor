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

package specutils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/runsc/config"
)

// writeFile creates a file named name in dir with the given permissions and
// returns its path.
func writeFile(t *testing.T, dir, name string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), perm); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", p, err)
	}
	// Apply perm explicitly, since os.WriteFile is subject to the umask.
	if err := os.Chmod(p, perm); err != nil {
		t.Fatalf("os.Chmod(%q, %v): %v", p, perm, err)
	}
	return p
}

func TestFindNVIDIAContainerCLI(t *testing.T) {
	dir := t.TempDir()
	executable := writeFile(t, dir, "nvidia-container-cli-custom", 0755)
	notExecutable := writeFile(t, dir, "not-executable", 0644)

	for _, tc := range []struct {
		name    string
		cliPath string
		want    string
		wantErr string
	}{
		{
			name:    "configured executable",
			cliPath: executable,
			want:    executable,
		},
		{
			name:    "configured path does not exist",
			cliPath: filepath.Join(dir, "missing"),
			wantErr: "no such file or directory",
		},
		{
			name:    "configured path is not executable",
			cliPath: notExecutable,
			wantErr: "not an executable regular file",
		},
		{
			name:    "configured path is a directory",
			cliPath: dir,
			wantErr: "not an executable regular file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &config.Config{NVProxyContainerCLIPath: tc.cliPath}
			got, err := FindNVIDIAContainerCLI(conf)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("FindNVIDIAContainerCLI() = %q, %v; want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FindNVIDIAContainerCLI() failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("FindNVIDIAContainerCLI() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFindNVIDIAContainerCLIInPath(t *testing.T) {
	dir := t.TempDir()
	want := writeFile(t, dir, nvidiaContainerCLI, 0755)
	t.Setenv("PATH", dir)

	got, err := FindNVIDIAContainerCLI(&config.Config{})
	if err != nil {
		t.Fatalf("FindNVIDIAContainerCLI() failed: %v", err)
	}
	if got != want {
		t.Errorf("FindNVIDIAContainerCLI() = %q, want %q", got, want)
	}
}

func TestFindNVIDIAContainerCLINotInPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	got, err := FindNVIDIAContainerCLI(&config.Config{})
	if err == nil {
		t.Fatalf("FindNVIDIAContainerCLI() = %q, want error", got)
	}
	if want := "--nvproxy-container-cli-path"; !strings.Contains(err.Error(), want) {
		t.Errorf("FindNVIDIAContainerCLI() error = %v, want it to mention %q", err, want)
	}
}
