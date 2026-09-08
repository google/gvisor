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
	"sync"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/stdio"
	runc "github.com/containerd/go-runc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

// TestWaitTimeoutExpires verifies that waitTimeout gives up on a WaitGroup that
// is never released, instead of blocking forever as Init.delete used to.
func TestWaitTimeoutExpires(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1) // Never released, simulating a stuck io copy goroutine.

	start := time.Now()
	err := waitTimeout(context.Background(), &wg, 100*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Errorf("waitTimeout returned nil for a WaitGroup that was never released, want an error")
	}
	if elapsed > 5*time.Second {
		t.Errorf("waitTimeout took %v to give up, want it bounded near the 100ms timeout", elapsed)
	}
}

// TestWaitTimeoutCompletes verifies that waitTimeout returns promptly, and
// without error, once the WaitGroup is released.
func TestWaitTimeoutCompletes(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		wg.Done()
	}()

	if err := waitTimeout(context.Background(), &wg, 30*time.Second); err != nil {
		t.Errorf("waitTimeout returned %v for a WaitGroup that was released, want nil", err)
	}
}

// closeRecordingIO records whether Close was called.
type closeRecordingIO struct {
	runc.IO
	closed bool
}

func (f *closeRecordingIO) Close() error {
	f.closed = true
	return nil
}

// TestCreatedStateToStoppedClosesIO verifies that a container leaving "created"
// for "stopped" releases its stdio. It never ran, so closing is safe; leaving
// the pipes open means Init.delete's drain never observes EOF.
func TestCreatedStateToStoppedClosesIO(t *testing.T) {
	p := New("id", &runsccmd.Runsc{}, stdio.Stdio{})
	io := &closeRecordingIO{}
	p.io = io
	state := &createdState{p: p}
	p.initState = state

	state.transition(stopped)

	if !io.closed {
		t.Errorf("io was not closed on the created->stopped transition; the shim would keep the pipe write ends and Init.delete could never drain")
	}
	if _, ok := p.initState.(*stoppedState); !ok {
		t.Errorf("initState is %T after transitioning to stopped, want *stoppedState", p.initState)
	}
}

// TestCreatedStateToStoppedNilIO verifies the transition tolerates a nil io,
// which happens when the container was created with a terminal (Init.Create
// leaves p.io unset on that path).
func TestCreatedStateToStoppedNilIO(t *testing.T) {
	p := New("id", &runsccmd.Runsc{}, stdio.Stdio{})
	p.io = nil
	state := &createdState{p: p}
	p.initState = state

	// Must not panic.
	state.transition(stopped)

	if _, ok := p.initState.(*stoppedState); !ok {
		t.Errorf("initState is %T after transitioning to stopped, want *stoppedState", p.initState)
	}
}

// TestRunningStateToStoppedKeepsIO verifies that a container leaving "running"
// does NOT have its io closed here: it may still have output in flight, so
// Init.delete drains first and closes afterwards.
func TestRunningStateToStoppedKeepsIO(t *testing.T) {
	p := New("id", &runsccmd.Runsc{}, stdio.Stdio{})
	io := &closeRecordingIO{}
	p.io = io
	state := &runningState{p: p}
	p.initState = state

	state.transition(stopped)

	if io.closed {
		t.Errorf("io was closed on the running->stopped transition; buffered container output could be truncated")
	}
}
