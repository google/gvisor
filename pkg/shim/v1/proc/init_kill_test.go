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
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/stdio"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

func newWedgedInit(t *testing.T) *Init {
	t.Helper()
	fake := filepath.Join(t.TempDir(), "fake-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec >/dev/null 2>&1\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatalf("failed to write fake runsc: %v", err)
	}
	return New("test", &runsccmd.Runsc{Command: fake}, stdio.Stdio{})
}

func TestKillAllTimeoutKillsSandboxProcess(t *testing.T) {
	oldTimeout := killTimeout
	killTimeout = 500 * time.Millisecond
	defer func() { killTimeout = oldTimeout }()

	sandbox := exec.Command("sleep", "60")
	if err := sandbox.Start(); err != nil {
		t.Fatalf("failed to start fake sandbox: %v", err)
	}
	defer sandbox.Process.Kill()
	waitCh := make(chan error, 1)
	go func() { waitCh <- sandbox.Wait() }()

	p := newWedgedInit(t)
	p.pid = sandbox.Process.Pid

	start := time.Now()
	p.KillAll(context.Background())
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("KillAll returned after %v, want under 10s", elapsed)
	}

	select {
	case <-waitCh:
		if ws, ok := sandbox.ProcessState.Sys().(syscall.WaitStatus); !ok || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("sandbox exited with %v, want SIGKILL", sandbox.ProcessState)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sandbox process still alive after KillAll timed out")
	}
}

func TestKillAllCanceledContextDoesNotKillSandbox(t *testing.T) {
	oldTimeout := killTimeout
	killTimeout = 500 * time.Millisecond
	defer func() { killTimeout = oldTimeout }()

	sandbox := exec.Command("sleep", "60")
	if err := sandbox.Start(); err != nil {
		t.Fatalf("failed to start fake sandbox: %v", err)
	}
	defer sandbox.Wait()
	defer sandbox.Process.Kill()

	p := newWedgedInit(t)
	p.pid = sandbox.Process.Pid

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.KillAll(ctx)

	if err := unix.Kill(sandbox.Process.Pid, 0); err != nil {
		t.Fatal("sandbox process was killed on a caller-canceled context")
	}
}
