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
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/stdio"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

// newWedgedInit returns an Init whose runsc never answers.
func newWedgedInit(t *testing.T) *Init {
	t.Helper()
	old := runscTimeout
	runscTimeout = 500 * time.Millisecond
	t.Cleanup(func() { runscTimeout = old })
	fake := filepath.Join(t.TempDir(), "fake-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec >/dev/null 2>&1\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatalf("failed to write fake runsc: %v", err)
	}
	return New("test", &runsccmd.Runsc{Command: fake}, stdio.Stdio{})
}

func expectBounded(t *testing.T, name string, start time.Time) {
	t.Helper()
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("%s returned after %v, want under 10s", name, elapsed)
	}
}

func TestKillAllWedgedRunscReturnsAndSparesSandbox(t *testing.T) {
	// The fake sandbox holds the write end, so EOF here means it died. Checking
	// the pid with signal 0 would also succeed for an unreaped zombie.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()

	sandbox := exec.Command("sleep", "60")
	sandbox.ExtraFiles = []*os.File{w}
	if err := sandbox.Start(); err != nil {
		t.Fatalf("failed to start fake sandbox: %v", err)
	}
	w.Close()
	defer func() {
		sandbox.Process.Kill()
		sandbox.Wait()
	}()

	p := newWedgedInit(t)
	p.pid = sandbox.Process.Pid

	start := time.Now()
	p.KillAll(context.Background())
	expectBounded(t, "KillAll", start)

	r.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var b [1]byte
	if _, err := r.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("fake sandbox did not survive KillAll (read returned %v); the shim must not escalate past runsc kill", err)
	}
}

func TestStatsWedgedRunscTimesOut(t *testing.T) {
	p := newWedgedInit(t)
	start := time.Now()
	if _, err := p.Stats(context.Background(), "test"); err == nil {
		t.Fatal("Stats succeeded against a wedged runsc")
	}
	expectBounded(t, "Stats", start)
}

func TestStatusWedgedRunscTimesOut(t *testing.T) {
	p := newWedgedInit(t)
	start := time.Now()
	if _, err := p.Status(context.Background()); err == nil {
		t.Fatal("Status succeeded against a wedged runsc")
	}
	expectBounded(t, "Status", start)
}

func TestKillWedgedRunscTimesOut(t *testing.T) {
	p := newWedgedInit(t)
	start := time.Now()
	if err := p.kill(context.Background(), uint32(unix.SIGTERM), false); err == nil {
		t.Fatal("kill succeeded against a wedged runsc")
	}
	expectBounded(t, "kill", start)
}
