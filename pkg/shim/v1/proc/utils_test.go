// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proc

import (
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestGetLastRuntimeErrorNoFDLeak verifies that getLastRuntimeError closes the
// log file it opens. It runs on every failed runsc command, so a leak here
// exhausts the fd table of a long-lived shim.
func TestGetLastRuntimeErrorNoFDLeak(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "log.json")
	content := `{"level":"info","msg":"starting","time":"2026-01-01T00:00:00Z"}
{"level":"error","msg":"something failed","time":"2026-01-01T00:00:01Z"}
`
	if err := os.WriteFile(logPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	r := &runsccmd.Runsc{Log: logPath}

	// Prime lazy initialization before sampling the fd count.
	if _, err := getLastRuntimeError(r); err != nil {
		t.Fatalf("getLastRuntimeError: %v", err)
	}

	before := openFDs(t)
	const iterations = 64
	for i := 0; i < iterations; i++ {
		msg, err := getLastRuntimeError(r)
		if err != nil {
			t.Fatalf("getLastRuntimeError: %v", err)
		}
		if want := "something failed"; msg != want {
			t.Fatalf("getLastRuntimeError() = %q, want %q", msg, want)
		}
	}
	after := openFDs(t)

	// Slack for unrelated runtime activity; a per-call leak adds ~iterations.
	if after-before > iterations/2 {
		t.Errorf("open fds grew from %d to %d over %d calls; log file is not being closed", before, after, iterations)
	}
}

// TestGetLastRuntimeErrorNoLog verifies the empty-log short circuit.
func TestGetLastRuntimeErrorNoLog(t *testing.T) {
	msg, err := getLastRuntimeError(&runsccmd.Runsc{})
	if err != nil {
		t.Fatalf("getLastRuntimeError: %v", err)
	}
	if msg != "" {
		t.Errorf("getLastRuntimeError() = %q, want empty", msg)
	}
}
