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

package nvconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetHostSettingsFrom(t *testing.T) {
	const wantParams = "ModifyDeviceFiles: 1\nImexChannelCount: 4\n"
	const wantVersion = "NVRM version: NVIDIA UNIX x86_64 Kernel Module  610.57.04\n"

	for _, tc := range []struct {
		name        string
		setup       func(t *testing.T, dir string)
		wantVersion string
	}{
		{
			name: "with_version",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, "version"), []byte(wantVersion), 0644); err != nil {
					t.Fatalf("os.WriteFile(version) failed: %v", err)
				}
			},
			wantVersion: wantVersion,
		},
		{
			name:        "without_version",
			setup:       func(t *testing.T, dir string) {},
			wantVersion: "",
		},
		{
			name: "unreadable_version",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(dir, "version"), 0755); err != nil {
					t.Fatalf("os.Mkdir(version) failed: %v", err)
				}
			},
			wantVersion: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "params"), []byte(wantParams), 0644); err != nil {
				t.Fatalf("os.WriteFile(params) failed: %v", err)
			}
			tc.setup(t, dir)

			got, err := getHostSettingsFrom(dir, HostSettingsOptions{})
			if err != nil {
				t.Fatalf("getHostSettingsFrom() failed: %v", err)
			}
			if got.ProcDriverNvidiaParams != wantParams {
				t.Errorf("ProcDriverNvidiaParams = %q, want %q", got.ProcDriverNvidiaParams, wantParams)
			}
			if got.ProcDriverNvidiaVersion != tc.wantVersion {
				t.Errorf("ProcDriverNvidiaVersion = %q, want %q", got.ProcDriverNvidiaVersion, tc.wantVersion)
			}
		})
	}
}

func TestReadFileIfExists(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	const want = "hello\n"
	if err := os.WriteFile(existing, []byte(want), 0644); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	got, err := readFileIfExists(existing)
	if err != nil {
		t.Fatalf("readFileIfExists(%q) failed: %v", existing, err)
	}
	if got != want {
		t.Errorf("readFileIfExists(%q) = %q, want %q", existing, got, want)
	}

	missing := filepath.Join(dir, "missing")
	got, err = readFileIfExists(missing)
	if err != nil {
		t.Fatalf("readFileIfExists(%q) failed: %v", missing, err)
	}
	if got != "" {
		t.Errorf("readFileIfExists(%q) = %q, want empty", missing, got)
	}

	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatalf("os.Mkdir() failed: %v", err)
	}
	got, err = readFileIfExists(subdir)
	if err == nil {
		t.Errorf("readFileIfExists(%q) succeeded with %q, want error", subdir, got)
	}
}
