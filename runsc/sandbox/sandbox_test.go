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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsRunning(t *testing.T) {
	var s Sandbox
	// Pid == 0 should not be running.
	running, err := s.IsRunning()
	if err != nil {
		t.Fatalf("IsRunning() error = %v, want nil", err)
	}
	if running {
		t.Errorf("IsRunning() = true for pid 0, want false")
	}

	// Current process should be running.
	s.Pid.Store(os.Getpid())
	running, err = s.IsRunning()
	if err != nil {
		t.Fatalf("IsRunning() error = %v, want nil", err)
	}
	if !running {
		t.Errorf("IsRunning() = false for current process, want true")
	}

	// Spawn a child process that exits immediately and becomes a zombie until reaped.
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed: %v", err)
	}
	childPid := cmd.Process.Pid
	s.Pid.Store(childPid)

	// Wait until child enters zombie state ('Z').
	deadline := time.Now().Add(5 * time.Second)
	for {
		statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", childPid))
		if err == nil && strings.Contains(string(statBytes), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Wait()
			t.Fatalf("timed out waiting for child pid %d to become zombie", childPid)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Zombie process must NOT be reported as running.
	running, err = s.IsRunning()
	if err != nil {
		_ = cmd.Wait()
		t.Fatalf("IsRunning() on zombie error = %v, want nil", err)
	}
	if running {
		t.Errorf("IsRunning() = true for zombie process %d, want false", childPid)
	}

	// Reap the zombie process.
	_ = cmd.Wait()
	running, err = s.IsRunning()
	if err != nil {
		t.Fatalf("IsRunning() on reaped process error = %v, want nil", err)
	}
	if running {
		t.Errorf("IsRunning() = true for reaped process %d, want false", childPid)
	}
}

func TestGetGCSURIFromImagePath(t *testing.T) {
	tmpDir := t.TempDir()

	testCases := []struct {
		name      string
		content   string
		writeOpts bool
		want      string
	}{
		{
			name:      "missing file",
			writeOpts: false,
			want:      "",
		},
		{
			name:      "invalid json",
			content:   "not valid json",
			writeOpts: true,
			want:      "",
		},
		{
			name:      "empty bucket",
			content:   `{"bucket": ""}`,
			writeOpts: true,
			want:      "",
		},
		{
			name:      "bucket only",
			content:   `{"bucket": "my-test-bucket"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket",
		},
		{
			name:      "bucket with object prefix",
			content:   `{"bucket": "my-test-bucket", "object_prefix": "snapshots/test/"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket/snapshots/test/",
		},
		{
			name:      "bucket with leading slash in object prefix",
			content:   `{"bucket": "my-test-bucket", "object_prefix": "/snapshots/test/"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket/snapshots/test/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			subDir := filepath.Join(tmpDir, tc.name)
			if err := os.MkdirAll(subDir, 0755); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}
			if tc.writeOpts {
				optsPath := filepath.Join(subDir, checkpointGCSOptsFileName)
				if err := os.WriteFile(optsPath, []byte(tc.content), 0644); err != nil {
					t.Fatalf("failed to write %s: %v", optsPath, err)
				}
			}
			got := getGCSURIFromImagePath(subDir)
			if got != tc.want {
				t.Errorf("getGCSURIFromImagePath(%q) = %q, want %q", subDir, got, tc.want)
			}
		})
	}
}
