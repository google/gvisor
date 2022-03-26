// Copyright 2020 The gVisor Authors.
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

package dockerutil

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/stdcopy"
)

// ExecOpts holds arguments for Exec calls.
type ExecOpts struct {
	// Env are additional environment variables.
	Env []string

	// Privileged enables privileged mode.
	Privileged bool

	// User is the user to use.
	User string

	// Enables Tty and stdin for the created process.
	UseTTY bool

	// WorkDir is the working directory of the process.
	WorkDir string
}

// Exec creates a process inside the container.
func (c *Container) Exec(ctx context.Context, opts ExecOpts, args ...string) (string, error) {
	p, err := c.doExec(ctx, opts, args)
	if err != nil {
		return "", err
	}
	done := make(chan struct{})
	var (
		out    string
		outErr error
	)
	// Read logs from another go-routine to be sure that it doesn't block on
	// writing into standard file descriptors.
	go func() {
		out, outErr = p.Logs()
		close(done)
	}()

	if exitStatus, err := p.WaitExitStatus(ctx); err != nil {
		return "", err
	} else if exitStatus != 0 {
		<-done
		return out, fmt.Errorf("process terminated with status: %d", exitStatus)
	}

	<-done
	return out, outErr
}

// ExecProcess creates a process inside the container and returns a process struct
// for the caller to use.
func (c *Container) ExecProcess(ctx context.Context, opts ExecOpts, args ...string) (Process, error) {
	return c.doExec(ctx, opts, args)
}

func (c *Container) doExec(ctx context.Context, r ExecOpts, args []string) (Process, error) {
	config := c.execConfig(r, args)
	resp, err := c.client.ContainerExecCreate(ctx, c.id, config)
	if err != nil {
		return Process{}, fmt.Errorf("exec create failed with err: %v", err)
	}

	hijack, err := c.client.ContainerExecAttach(ctx, resp.ID, types.ExecStartCheck{})
	if err != nil {
		return Process{}, fmt.Errorf("exec attach failed with err: %v", err)
	}

	return Process{
		container: c,
		execid:    resp.ID,
		conn:      hijack,
	}, nil
}

func (c *Container) execConfig(r ExecOpts, cmd []string) types.ExecConfig {
	env := append(r.Env, fmt.Sprintf("RUNSC_TEST_NAME=%s", c.Name))
	return types.ExecConfig{
		AttachStdin:  r.UseTTY,
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          cmd,
		Privileged:   r.Privileged,
		WorkingDir:   r.WorkDir,
		Env:          env,
		Tty:          r.UseTTY,
		User:         r.User,
	}

}

// Process represents a containerized process.
type Process struct {
	container *Container
	execid    string
	conn      types.HijackedResponse
}

// Write writes buf to the process's stdin.
func (p *Process) Write(timeout time.Duration, buf []byte) (int, error) {
	p.conn.Conn.SetDeadline(time.Now().Add(timeout))
	return p.conn.Conn.Write(buf)
}

// Read returns process's stdout and stderr.
func (p *Process) Read() (string, string, error) {
	var stdout, stderr bytes.Buffer
	if err := p.read(&stdout, &stderr); err != nil {
		return "", "", err
	}
	return stdout.String(), stderr.String(), nil
}

// Logs returns combined stdout/stderr from the process.
func (p *Process) Logs() (string, error) {
	var out bytes.Buffer
	if err := p.read(&out, &out); err != nil {
		return "", err
	}
	return out.String(), nil
}

func (p *Process) read(stdout, stderr *bytes.Buffer) error {
	_, err := stdcopy.StdCopy(stdout, stderr, p.conn.Reader)
	return err
}

// ExitCode returns the process's exit code.
func (p *Process) ExitCode(ctx context.Context) (int, error) {
	_, exitCode, err := p.runningExitCode(ctx)
	return exitCode, err
}

// IsRunning checks if the process is running.
func (p *Process) IsRunning(ctx context.Context) (bool, error) {
	running, _, err := p.runningExitCode(ctx)
	return running, err
}

// WaitExitStatus until process completes and returns exit status.
func (p *Process) WaitExitStatus(ctx context.Context) (int, error) {
	waitChan := make(chan (int))
	errChan := make(chan (error))

	go func() {
		for {
			running, exitcode, err := p.runningExitCode(ctx)
			if err != nil {
				errChan <- fmt.Errorf("error waiting process %s: container %v", p.execid, p.container.Name)
			}
			if !running {
				waitChan <- exitcode
			}
			time.Sleep(time.Millisecond * 500)
		}
	}()

	select {
	case ws := <-waitChan:
		return ws, nil
	case err := <-errChan:
		return -1, err
	}
}

// runningExitCode collects if the process is running and the exit code.
// The exit code is only valid if the process has exited.
func (p *Process) runningExitCode(ctx context.Context) (bool, int, error) {
	// If execid is not empty, this is a execed process.
	if p.execid != "" {
		status, err := p.container.client.ContainerExecInspect(ctx, p.execid)
		return status.Running, status.ExitCode, err
	}
	// else this is the root process.
	status, err := p.container.Status(ctx)
	return status.Running, status.ExitCode, err
}
