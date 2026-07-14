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

//go:build linux

package runsccmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runc "github.com/containerd/go-runc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestRunscStatsUsesDirectProvider(t *testing.T) {
	want := &runc.Stats{}
	r := &Runsc{
		Command: filepath.Join(t.TempDir(), "missing-runsc"),
		Root:    "/run/runsc",
		stats: func(_ context.Context, root, id string) (*runc.Stats, error) {
			if root != "/run/runsc" || id != "cid-1" {
				t.Fatalf("stats provider got root=%q id=%q", root, id)
			}
			return want, nil
		},
	}

	got, err := r.Stats(t.Context(), "cid-1")
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got != want {
		t.Fatalf("Stats returned %p, want %p", got, want)
	}
}

func TestRunscStatsFallsBackToCLI(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-runsc")
	event, err := json.Marshal(runc.Event{Type: "stats", Stats: &runc.Stats{}})
	if err != nil {
		t.Fatal(err)
	}
	scriptBody := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q\n", string(event))
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Runsc{
		Command: script,
		Root:    filepath.Join(dir, "root"),
		stats: func(context.Context, string, string) (*runc.Stats, error) {
			return nil, fmt.Errorf("direct stats unavailable")
		},
	}

	if _, err := r.Stats(t.Context(), "cid-1"); err != nil {
		t.Fatalf("Stats: %v", err)
	}
}

func TestLoadDirectStatsClient(t *testing.T) {
	root := t.TempDir()
	id := "cid-1"
	sandboxID := "sandbox-1"
	socketPath := filepath.Join(root, "runsc-"+sandboxID+".sock")
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	state := statsContainerState{
		ID: id,
		Sandbox: &statsSandboxState{
			ID:                sandboxID,
			PID:               os.Getpid(),
			ControlSocketPath: filepath.Join(root, "old", "runsc.sock"),
		},
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	stateBase := filepath.Join(root, id+"_sandbox:"+sandboxID)
	if err := os.WriteFile(stateBase+".state", stateJSON, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateBase+".lock", nil, 0o640); err != nil {
		t.Fatal(err)
	}

	direct, err := loadDirectStatsClient(root, id)
	if err != nil {
		t.Fatalf("loadDirectStatsClient: %v", err)
	}
	if direct.controlSocketPath != socketPath {
		t.Fatalf("control socket path = %q, want %q", direct.controlSocketPath, socketPath)
	}
	if direct.cgroup == nil {
		t.Fatal("cgroup is nil")
	}
}

func TestPopulateStatsCPU(t *testing.T) {
	for _, tc := range []struct {
		name           string
		containerUsage map[string]uint64
		cgroupUsage    uint64
		want           uint64
	}{
		{
			name:           "scales selected container",
			containerUsage: map[string]uint64{"cid-1": 20, "cid-2": 30},
			cgroupUsage:    100,
			want:           40,
		},
		{
			name:           "splits cgroup usage when sentry usage is zero",
			containerUsage: map[string]uint64{"cid-1": 0, "cid-2": 0},
			cgroupUsage:    100,
			want:           50,
		},
		{
			name:           "uses sentry usage when cgroup usage is zero",
			containerUsage: map[string]uint64{"cid-1": 20, "cid-2": 30},
			want:           20,
		},
		{
			name:        "reports zero without containers",
			cgroupUsage: 100,
			want:        0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := &runc.Stats{}
			populateStatsCPU(stats, "cid-1", tc.containerUsage, tc.cgroupUsage)
			if got := stats.Cpu.Usage.Total; got != tc.want {
				t.Fatalf("CPU usage total = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestRunscUpdateCLI verifies Update runs the OCI update flow: JSON resources on
// stdin and "update --resources - <id>" in argv (same contract as go-runc).
func TestRunscUpdateCLI(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args.txt")
	stdinLog := filepath.Join(dir, "stdin.txt")
	script := filepath.Join(dir, "fake-runsc")
	scriptBody := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >%q
cat >%q
exit 0
`, argsLog, stdinLog)
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}

	limit := int64(4096)
	wantRes := &specs.LinuxResources{
		Memory: &specs.LinuxMemory{Limit: &limit},
	}

	r := &Runsc{
		Command: script,
		Root:    filepath.Join(dir, "root"),
	}
	if err := r.Update(ctx, "cid-1", wantRes); err != nil {
		t.Fatalf("Update: %v", err)
	}

	rawArgs, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Fields(string(rawArgs))
	var joined strings.Builder
	for _, a := range args {
		joined.WriteString(a)
		joined.WriteByte(' ')
	}
	s := joined.String()
	// go-runc may pass "--resources -"; we use "--resources=-" (same stdin contract).
	if !strings.Contains(s, "update ") || !strings.Contains(s, "--resources") || !strings.Contains(s, "cid-1") {
		t.Fatalf("argv missing expected update flags: %q", string(rawArgs))
	}

	rawStdin, err := os.ReadFile(stdinLog)
	if err != nil {
		t.Fatal(err)
	}
	var got specs.LinuxResources
	if err := json.Unmarshal(rawStdin, &got); err != nil {
		t.Fatalf("stdin JSON: %v", err)
	}
	if got.Memory == nil || got.Memory.Limit == nil || *got.Memory.Limit != limit {
		t.Fatalf("stdin resources: got %+v, want memory limit %d", got.Memory, limit)
	}
}
