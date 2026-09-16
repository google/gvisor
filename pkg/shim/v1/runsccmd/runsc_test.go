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
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

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

// TestCmdOutputDoesNotAliasPooledBuffer verifies that cmdOutput copies its
// output before returning. Its buffers come from a sync.Pool and are released
// on return, so an alias would be overwritten by the next runsc invocation
// while the caller is still unmarshaling it.
func TestCmdOutputDoesNotAliasPooledBuffer(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-runsc")
	const want = "original output"
	scriptBody := fmt.Sprintf("#!/bin/sh\nprintf '%%s' %q\n", want)
	if err := os.WriteFile(script, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}

	r := &Runsc{Command: script, Root: filepath.Join(dir, "root")}
	out, _, err := cmdOutput(r.command(t.Context(), "state", "cid-1"), true)
	if err != nil {
		t.Fatalf("cmdOutput: %v", err)
	}
	if string(out) != want {
		t.Fatalf("cmdOutput() = %q, want %q", out, want)
	}

	// Scribble over the pooled buffers, as a subsequent command would.
	for i := 0; i < 8; i++ {
		b := getBuf()
		b.WriteString(strings.Repeat("X", len(want)*4))
		putBuf(b)
	}

	if string(out) != want {
		t.Errorf("cmdOutput() result was corrupted to %q; it aliases a pooled buffer", out)
	}
}

// TestCmdOutputSeparateStderr verifies the non-combined path also copies.
func TestCmdOutputSeparateStderr(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-runsc")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'out'\nprintf 'err' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	r := &Runsc{Command: script, Root: filepath.Join(dir, "root")}
	stdout, stderr, err := cmdOutput(r.command(t.Context(), "state", "cid-1"), false)
	if err != nil {
		t.Fatalf("cmdOutput: %v", err)
	}

	for i := 0; i < 8; i++ {
		b := getBuf()
		b.WriteString(strings.Repeat("X", 64))
		putBuf(b)
	}

	if string(stdout) != "out" {
		t.Errorf("stdout = %q, want %q", stdout, "out")
	}
	if string(stderr) != "err" {
		t.Errorf("stderr = %q, want %q", stderr, "err")
	}
}

// TestCommandWaitDelayUnblocksWait covers a runsc that dies while a child still
// holds the pipe cmdOutput gave it. Without WaitDelay, Wait stays blocked on
// that fd and the caller keeps the container lock.
func TestCommandWaitDelayUnblocksWait(t *testing.T) {
	old := waitDelay
	waitDelay = 200 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })

	fake := filepath.Join(t.TempDir(), "fake-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nsleep 60 &\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to write fake runsc: %v", err)
	}

	r := &Runsc{Command: fake}
	start := time.Now()
	if _, _, err := cmdOutput(r.command(context.Background()), false); err == nil {
		t.Fatal("cmdOutput reported success for a command whose pipes never closed")
	}
	// Below waitDelay means the command failed at startup and never exercised
	// the delay. Above the child lifetime means Wait sat on the inherited fd.
	elapsed := time.Since(start)
	if elapsed < 200*time.Millisecond || elapsed > 30*time.Second {
		t.Fatalf("cmdOutput returned after %v, want between waitDelay and the child lifetime", elapsed)
	}
}
