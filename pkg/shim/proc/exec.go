// Copyright 2018 The containerd Authors.
// Copyright 2018 The gVisor Authors.
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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/containerd/console"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/fifo"
	runc "github.com/containerd/go-runc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"

	"gvisor.dev/gvisor/pkg/shim/runsc"
)

type execProcess struct {
	wg sync.WaitGroup

	execState execState

	mu          sync.Mutex
	id          string
	console     console.Console
	io          runc.IO
	status      int
	exited      time.Time
	pid         int
	internalPid int
	closers     []io.Closer
	stdin       io.Closer
	stdio       stdio.Stdio
	path        string
	spec        specs.Process

	parent    *Init
	waitBlock chan struct{}
}

func (e *execProcess) Wait() {
	<-e.waitBlock
}

func (e *execProcess) ID() string {
	return e.id
}

func (e *execProcess) Pid() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.pid
}

func (e *execProcess) ExitStatus() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

func (e *execProcess) ExitedAt() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exited
}

func (e *execProcess) SetExited(status int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.execState.SetExited(status)
}

func (e *execProcess) setExited(status int) {
	if !e.exited.IsZero() {
		log.L.Debugf("Exec: status already set to %d, ignoring status: %d", e.status, status)
		return
	}

	log.L.Debugf("Exec: setting status: %d", status)
	e.status = status
	e.exited = time.Now()
	e.parent.Platform.ShutdownConsole(context.Background(), e.console)
	close(e.waitBlock)
}

func (e *execProcess) Delete(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.execState.Delete(ctx)
}

func (e *execProcess) delete() {
	e.wg.Wait()
	if e.io != nil {
		for _, c := range e.closers {
			c.Close()
		}
		e.io.Close()
	}
}

func (e *execProcess) Resize(ws console.WinSize) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.execState.Resize(ws)
}

func (e *execProcess) resize(ws console.WinSize) error {
	if e.console == nil {
		return nil
	}
	return e.console.Resize(ws)
}

func (e *execProcess) Kill(ctx context.Context, sig uint32, _ bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.execState.Kill(ctx, sig, false)
}

func (e *execProcess) kill(ctx context.Context, sig uint32, _ bool) error {
	internalPid := e.internalPid
	if internalPid == 0 {
		return nil
	}

	opts := runsc.KillOpts{Pid: internalPid}
	if err := e.parent.runtime.Kill(ctx, e.parent.id, int(sig), &opts); err != nil {
		return fmt.Errorf("%s: %w", err.Error(), errdefs.ErrNotFound)
	}
	return nil
}

func (e *execProcess) Stdin() io.Closer {
	return e.stdin
}

func (e *execProcess) Stdio() stdio.Stdio {
	return e.stdio
}

func (e *execProcess) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.execState.Start(ctx)
}

func (e *execProcess) start(ctx context.Context) error {
	var socket *runc.Socket

	switch {
	case e.stdio.Terminal:
		s, err := runc.NewTempConsoleSocket()
		if err != nil {
			return fmt.Errorf("failed to create runc console socket: %w", err)
		}
		defer s.Close()
		socket = s

	case e.stdio.IsNull():
		io, err := runc.NewNullIO()
		if err != nil {
			return fmt.Errorf("creating new NULL IO: %w", err)
		}
		e.io = io

	default:
		io, err := runc.NewPipeIO(e.parent.IoUID, e.parent.IoGID, withConditionalIO(e.stdio))
		if err != nil {
			return fmt.Errorf("failed to create runc io pipes: %w", err)
		}
		e.io = io
	}

	opts := &runsc.ExecOpts{
		PidFile:         filepath.Join(e.path, fmt.Sprintf("%s.pid", e.id)),
		InternalPidFile: filepath.Join(e.path, fmt.Sprintf("%s-internal.pid", e.id)),
		IO:              e.io,
		Detach:          true,
	}
	defer func() {
		_ = os.Remove(opts.PidFile)
		_ = os.Remove(opts.InternalPidFile)
	}()
	if socket != nil {
		opts.ConsoleSocket = socket
	}

	eventCh := e.parent.Monitor.Subscribe()
	cu := cleanup.Make(func() {
		e.parent.Monitor.Unsubscribe(eventCh)
	})
	defer cu.Clean()

	if err := e.parent.runtime.Exec(ctx, e.parent.id, e.spec, opts); err != nil {
		close(e.waitBlock)
		return e.parent.runtimeError(err, "OCI runtime exec failed")
	}
	if e.stdio.Stdin != "" {
		sc, err := fifo.OpenFifo(context.Background(), e.stdio.Stdin, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("failed to open stdin fifo %s: %w", e.stdio.Stdin, err)
		}
		e.closers = append(e.closers, sc)
		e.stdin = sc
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if socket != nil {
		console, err := socket.ReceiveMaster()
		if err != nil {
			return fmt.Errorf("failed to retrieve console master: %w", err)
		}
		if e.console, err = e.parent.Platform.CopyConsole(ctx, console, e.stdio.Stdin, e.stdio.Stdout, e.stdio.Stderr, &e.wg); err != nil {
			return fmt.Errorf("failed to start console copy: %w", err)
		}
	} else if !e.stdio.IsNull() {
		if err := copyPipes(ctx, e.io, e.stdio.Stdin, e.stdio.Stdout, e.stdio.Stderr, &e.wg); err != nil {
			return fmt.Errorf("failed to start io pipe copy: %w", err)
		}
	}

	pid, err := runc.ReadPidFile(opts.PidFile)
	if err != nil {
		return fmt.Errorf("failed to retrieve OCI runtime exec pid: %w", err)
	}
	e.pid = pid
	internalPid, err := runc.ReadPidFile(opts.InternalPidFile)
	if err != nil {
		return fmt.Errorf("failed to retrieve OCI runtime exec internal pid: %w", err)
	}
	e.internalPid = internalPid

	go func() {
		defer e.parent.Monitor.Unsubscribe(eventCh)
		for event := range eventCh {
			if event.Pid == e.pid {
				ExitCh <- Exit{
					Timestamp: event.Timestamp,
					ID:        e.id,
					Status:    event.Status,
				}
				break
			}
		}
	}()

	cu.Release() // cancel cleanup on success.
	return nil
}

func (e *execProcess) Status(context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// if we don't have a pid then the exec process has just been created
	if e.pid == 0 {
		return "created", nil
	}
	// This checks that `runsc exec` process is still running. This process has
	// the same lifetime as the process executing inside the container. So instead
	// of calling `runsc kill --pid`, just do a quick check that `runsc exec` is
	// still running.
	if err := unix.Kill(e.pid, 0); err != nil {
		// Can't signal the process, it must have exited.
		return "stopped", nil
	}
	return "running", nil
}
