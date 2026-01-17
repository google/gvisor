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

package runsc

import (
	"context"
	"fmt"
	"sync"

	"github.com/containerd/console"
	"github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
)

// Container for operating on a runsc container and its processes
type Container struct {
	mu sync.Mutex

	// ID of the container
	ID string

	// Bundle path
	Bundle string

	// task is the main process that is running the container.
	task *proc.Init

	// processes maps ExecId to processes running through exec.
	//
	// +checklocks:mu
	processes map[string]extension.Process
}

// Pid of the main process of a container
func (c *Container) Pid() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.task.Pid()
}

// All processes in the container.
func (c *Container) All() []extension.Process {
	c.mu.Lock()
	defer c.mu.Unlock()

	o := make([]extension.Process, 0, len(c.processes)+1)
	for _, p := range c.processes {
		o = append(o, p)
	}
	if c.task != nil {
		o = append(o, c.task)
	}
	return o
}

// ExecdProcesses added to the container.
func (c *Container) ExecdProcesses() []extension.Process {
	c.mu.Lock()
	defer c.mu.Unlock()

	o := make([]extension.Process, 0, len(c.processes))
	for _, p := range c.processes {
		o = append(o, p)
	}
	return o
}

// Process returns the process by id.
// If id is empty, return the init process.
func (c *Container) Process(id string) (extension.Process, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == "" {
		if c.task == nil {
			return nil, fmt.Errorf("container must be created: %w", errdefs.ErrFailedPrecondition)
		}
		return c.task, nil
	}
	p, ok := c.processes[id]
	if !ok {
		return nil, fmt.Errorf("process does not exist %s: %w", id, errdefs.ErrNotFound)
	}
	return p, nil
}

// ProcessAdd adds a process to the container.
func (c *Container) ProcessAdd(p extension.Process) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processes[p.ID()] = p
}

// ProcessRemove removes the process by id from the container.
func (c *Container) ProcessRemove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.processes, id)
}

// Start a container process.
func (c *Container) Start(ctx context.Context, r *task.StartRequest) (extension.Process, error) {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// Delete the container or a process by id
func (c *Container) Delete(ctx context.Context, r *task.DeleteRequest) (extension.Process, error) {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Delete(ctx); err != nil {
		return nil, err
	}
	// When ExecID is empty, it removes the init task in the container.
	if r.ExecID != "" {
		c.ProcessRemove(r.ExecID)
	}
	return p, nil
}

// Exec starts an additional process in the container.
func (c *Container) Exec(ctx context.Context, r *task.ExecProcessRequest) (extension.Process, error) {
	if c.task == nil {
		return nil, fmt.Errorf("container must be created")
	}
	p, err := c.task.Exec(ctx, c.Bundle, &proc.ExecConfig{
		ID:       r.ExecID,
		Terminal: r.Terminal,
		Stdin:    r.Stdin,
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
		Spec:     r.Spec,
	})
	if err != nil {
		return nil, err
	}
	c.ProcessAdd(p)
	return p, nil
}

// ResizePty of a process
func (c *Container) ResizePty(ctx context.Context, r *task.ResizePtyRequest) error {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return err
	}
	ws := console.WinSize{
		Width:  uint16(r.Width),
		Height: uint16(r.Height),
	}
	return p.Resize(ws)
}

// Pause the container.
func (c *Container) Pause(ctx context.Context, r *task.PauseRequest) error {
	if c.task == nil {
		log.L.Debugf("Pause error, id: %s: container not created", r.ID)
		return fmt.Errorf("container must be created")
	}
	return c.task.Runtime().Pause(ctx, r.ID)
}

// Resume the container.
func (c *Container) Resume(ctx context.Context, r *task.ResumeRequest) error {
	if c.task == nil {
		log.L.Debugf("Resume error, id: %s: container not created", r.ID)
		return fmt.Errorf("container must be created")
	}
	return c.task.Runtime().Resume(ctx, r.ID)
}

// Kill a process with the provided signal
func (c *Container) Kill(ctx context.Context, r *task.KillRequest) error {
	p, err := c.Process(r.ExecID)
	if err != nil {
		log.L.Debugf("Kill failed: %v", err)
		return err
	}
	return p.Kill(ctx, r.Signal, r.All)
}

// CloseIO of a process.
func (c *Container) CloseIO(ctx context.Context, r *task.CloseIORequest) error {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return err
	}
	if stdin := p.Stdin(); stdin != nil {
		if err := stdin.Close(); err != nil {
			return fmt.Errorf("close stdin: %w", err)
		}
	}
	return nil
}

// Restore a process in the container.
func (c *Container) Restore(ctx context.Context, r *extension.RestoreRequest) (extension.Process, error) {
	p, err := c.Process(r.Start.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Restore(ctx, &r.Conf); err != nil {
		return nil, err
	}
	// TODO: Set the cgroup and oom notifications on restore.
	// https://github.com/google/gvisor-containerd-shim/issues/58
	return p, nil
}
