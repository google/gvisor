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
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/console"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/process"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/fifo"
	runc "github.com/containerd/go-runc"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/shim/runsc"
)

// Init represents an initial process for a container.
type Init struct {
	wg        sync.WaitGroup
	initState initState

	// mu is used to ensure that `Start()` and `Exited()` calls return in
	// the right order when invoked in separate go routines.  This is the
	// case within the shim implementation as it makes use of the reaper
	// interface.
	mu sync.Mutex

	waitBlock chan struct{}

	WorkDir string

	id       string
	Bundle   string
	console  console.Console
	Platform stdio.Platform
	io       runc.IO
	runtime  *runsc.Runsc
	status   int
	exited   time.Time
	pid      int
	closers  []io.Closer
	stdin    io.Closer
	stdio    stdio.Stdio
	Rootfs   string
	IoUID    int
	IoGID    int
	Sandbox  bool
	UserLog  string
	Monitor  ProcessMonitor
}

// NewRunsc returns a new runsc instance for a process.
func NewRunsc(root, path, namespace, runtime string, config map[string]string) *runsc.Runsc {
	if root == "" {
		root = RunscRoot
	}
	return &runsc.Runsc{
		Command:      runtime,
		PdeathSignal: syscall.SIGKILL,
		Log:          filepath.Join(path, "log.json"),
		LogFormat:    runc.JSON,
		Root:         filepath.Join(root, namespace),
		Config:       config,
	}
}

// New returns a new init process.
func New(id string, runtime *runsc.Runsc, stdio stdio.Stdio) *Init {
	p := &Init{
		id:        id,
		runtime:   runtime,
		stdio:     stdio,
		status:    0,
		waitBlock: make(chan struct{}),
	}
	p.initState = &createdState{p: p}
	return p
}

// Create the process with the provided config.
func (p *Init) Create(ctx context.Context, r *CreateConfig) (err error) {
	var socket *runc.Socket
	if r.Terminal {
		if socket, err = runc.NewTempConsoleSocket(); err != nil {
			return fmt.Errorf("failed to create OCI runtime console socket: %w", err)
		}
		defer socket.Close()
	} else if hasNoIO(r) {
		if p.io, err = runc.NewNullIO(); err != nil {
			return fmt.Errorf("creating new NULL IO: %w", err)
		}
	} else {
		if p.io, err = runc.NewPipeIO(p.IoUID, p.IoGID, withConditionalIO(p.stdio)); err != nil {
			return fmt.Errorf("failed to create OCI runtime io pipes: %w", err)
		}
	}
	// pidFile is the file that will contain the sandbox pid.
	pidFile := filepath.Join(p.Bundle, "init.pid")
	opts := &runsc.CreateOpts{
		PidFile: pidFile,
	}
	if socket != nil {
		opts.ConsoleSocket = socket
	}
	if p.Sandbox {
		opts.IO = p.io
		// UserLog is only useful for sandbox.
		opts.UserLog = p.UserLog
	}
	if err := p.runtime.Create(ctx, r.ID, r.Bundle, opts); err != nil {
		return p.runtimeError(err, "OCI runtime create failed")
	}
	if r.Stdin != "" {
		sc, err := fifo.OpenFifo(context.Background(), r.Stdin, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("failed to open stdin fifo %s: %w", r.Stdin, err)
		}
		p.stdin = sc
		p.closers = append(p.closers, sc)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if socket != nil {
		console, err := socket.ReceiveMaster()
		if err != nil {
			return fmt.Errorf("failed to retrieve console master: %w", err)
		}
		console, err = p.Platform.CopyConsole(ctx, console, r.Stdin, r.Stdout, r.Stderr, &p.wg)
		if err != nil {
			return fmt.Errorf("failed to start console copy: %w", err)
		}
		p.console = console
	} else if !hasNoIO(r) {
		if err := copyPipes(ctx, p.io, r.Stdin, r.Stdout, r.Stderr, &p.wg); err != nil {
			return fmt.Errorf("failed to start io pipe copy: %w", err)
		}
	}
	pid, err := runc.ReadPidFile(pidFile)
	if err != nil {
		return fmt.Errorf("failed to retrieve OCI runtime container pid: %w", err)
	}
	p.pid = pid
	return nil
}

// Wait waits for the process to exit.
func (p *Init) Wait() {
	<-p.waitBlock
}

// ID returns the ID of the process.
func (p *Init) ID() string {
	return p.id
}

// Pid returns the PID of the process.
func (p *Init) Pid() int {
	return p.pid
}

// ExitStatus returns the exit status of the process.
func (p *Init) ExitStatus() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// ExitedAt returns the time when the process exited.
func (p *Init) ExitedAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exited
}

// Status returns the status of the process.
func (p *Init) Status(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, err := p.runtime.State(ctx, p.id)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return "stopped", nil
		}
		return "", p.runtimeError(err, "OCI runtime state failed")
	}
	return p.convertStatus(c.Status), nil
}

// Start starts the init process.
func (p *Init) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Start(ctx)
}

func (p *Init) start(ctx context.Context) error {
	var cio runc.IO
	if !p.Sandbox {
		cio = p.io
	}
	if err := p.runtime.Start(ctx, p.id, cio); err != nil {
		return p.runtimeError(err, "OCI runtime start failed")
	}
	go func() {
		status, err := p.runtime.Wait(context.Background(), p.id)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("Failed to wait for container %q", p.id)
			// TODO(random-liu): Handle runsc kill error.
			if err := p.killAll(ctx); err != nil {
				log.G(ctx).WithError(err).Errorf("Failed to kill container %q", p.id)
			}
			status = internalErrorCode
		}
		ExitCh <- Exit{
			Timestamp: time.Now(),
			ID:        p.id,
			Status:    status,
		}
	}()
	return nil
}

// SetExited set the exit stauts of the init process.
func (p *Init) SetExited(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.initState.SetExited(status)
}

func (p *Init) setExited(status int) {
	p.exited = time.Now()
	p.status = status
	p.Platform.ShutdownConsole(context.Background(), p.console)
	close(p.waitBlock)
}

// Delete deletes the init process.
func (p *Init) Delete(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Delete(ctx)
}

func (p *Init) delete(ctx context.Context) error {
	p.killAll(ctx)
	p.wg.Wait()
	err := p.runtime.Delete(ctx, p.id, nil)
	// ignore errors if a runtime has already deleted the process
	// but we still hold metadata and pipes
	//
	// this is common during a checkpoint, runc will delete the container state
	// after a checkpoint and the container will no longer exist within runc
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			err = nil
		} else {
			err = p.runtimeError(err, "failed to delete task")
		}
	}
	if p.io != nil {
		for _, c := range p.closers {
			c.Close()
		}
		p.io.Close()
	}
	if err2 := mount.UnmountAll(p.Rootfs, 0); err2 != nil {
		log.G(ctx).WithError(err2).Warn("failed to cleanup rootfs mount")
		if err == nil {
			err = fmt.Errorf("failed rootfs umount: %w", err2)
		}
	}
	return err
}

// Resize resizes the init processes console.
func (p *Init) Resize(ws console.WinSize) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.console == nil {
		return nil
	}
	return p.console.Resize(ws)
}

func (p *Init) resize(ws console.WinSize) error {
	if p.console == nil {
		return nil
	}
	return p.console.Resize(ws)
}

// Kill kills the init process.
func (p *Init) Kill(ctx context.Context, signal uint32, all bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Kill(ctx, signal, all)
}

func (p *Init) kill(context context.Context, signal uint32, all bool) error {
	var (
		killErr error
		backoff = 100 * time.Millisecond
	)
	timeout := 1 * time.Second
	for start := time.Now(); time.Now().Sub(start) < timeout; {
		c, err := p.runtime.State(context, p.id)
		if err != nil {
			if strings.Contains(err.Error(), "does not exist") {
				return fmt.Errorf("no such process: %w", errdefs.ErrNotFound)
			}
			return p.runtimeError(err, "OCI runtime state failed")
		}
		// For runsc, signal only works when container is running state.
		// If the container is not in running state, directly return
		// "no such process"
		if p.convertStatus(c.Status) == "stopped" {
			return fmt.Errorf("no such process: %w", errdefs.ErrNotFound)
		}
		killErr = p.runtime.Kill(context, p.id, int(signal), &runsc.KillOpts{
			All: all,
		})
		if killErr == nil {
			return nil
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	return p.runtimeError(killErr, "kill timeout")
}

// KillAll kills all processes belonging to the init process.
func (p *Init) KillAll(context context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.killAll(context)
}

func (p *Init) killAll(context context.Context) error {
	p.runtime.Kill(context, p.id, int(syscall.SIGKILL), &runsc.KillOpts{
		All: true,
	})
	// Ignore error handling for `runsc kill --all` for now.
	// * If it doesn't return error, it is good;
	// * If it returns error, consider the container has already stopped.
	// TODO: Fix `runsc kill --all` error handling.
	return nil
}

// Stdin returns the stdin of the process.
func (p *Init) Stdin() io.Closer {
	return p.stdin
}

// Runtime returns the OCI runtime configured for the init process.
func (p *Init) Runtime() *runsc.Runsc {
	return p.runtime
}

// Exec returns a new child process.
func (p *Init) Exec(ctx context.Context, path string, r *ExecConfig) (process.Process, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Exec(ctx, path, r)
}

// exec returns a new exec'd process.
func (p *Init) exec(path string, r *ExecConfig) (process.Process, error) {
	// process exec request
	var spec specs.Process
	if err := json.Unmarshal(r.Spec.Value, &spec); err != nil {
		return nil, err
	}
	spec.Terminal = r.Terminal

	e := &execProcess{
		id:     r.ID,
		path:   path,
		parent: p,
		spec:   spec,
		stdio: stdio.Stdio{
			Stdin:    r.Stdin,
			Stdout:   r.Stdout,
			Stderr:   r.Stderr,
			Terminal: r.Terminal,
		},
		waitBlock: make(chan struct{}),
	}
	e.execState = &execCreatedState{p: e}
	return e, nil
}

// Stdio returns the stdio of the process.
func (p *Init) Stdio() stdio.Stdio {
	return p.stdio
}

func (p *Init) runtimeError(rErr error, msg string) error {
	if rErr == nil {
		return nil
	}

	rMsg, err := getLastRuntimeError(p.runtime)
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w (unable to retrieve OCI runtime error: %v)", msg, rErr, err)
	case rMsg == "":
		return fmt.Errorf("%s: %w", msg, rErr)
	default:
		return fmt.Errorf("%s: %s", msg, rMsg)
	}
}

func (p *Init) convertStatus(status string) string {
	if status == "created" && !p.Sandbox && p.status == internalErrorCode {
		// Treat start failure state for non-root container as stopped.
		return "stopped"
	}
	return status
}

func withConditionalIO(c stdio.Stdio) runc.IOOpt {
	return func(o *runc.IOOption) {
		o.OpenStdin = c.Stdin != ""
		o.OpenStdout = c.Stdout != ""
		o.OpenStderr = c.Stderr != ""
	}
}
