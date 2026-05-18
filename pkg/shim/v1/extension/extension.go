// Copyright 2024 The gVisor Authors.
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

// Package extension provides an extension to the shim.
package extension

import (
	"context"
	"io"
	"time"

	"github.com/containerd/console"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/v2/pkg/stdio"
	hibernatepb "gvisor.dev/gvisor/pkg/shim/v1/runsc/hibernate_go_proto"
)

// NewExtension registers an extension constructor. It may return nil, nil to indicate that the
// extension should not handle this task request. Returning an error will fail the task request.
var NewExtension func(ctx context.Context, next TaskServiceExt, req *task.CreateTaskRequest) (TaskServiceExt, error)

// NewPodExtension registers an extension constructor which is used when grouping is enabled.
// It may return nil, nil to indicate that the extension should not handle this task request.
// Returning an error will fail the task request.
var NewPodExtension func(ctx context.Context, next TaskServiceExt, req *task.CreateTaskRequest) (TaskServiceExt, error)

// FSRestoreConfig is the configuration for a FS restore request.
type FSRestoreConfig struct {
	ImagePath string
	Direct    bool
}

// RestoreConfig is the configuration for a restore request.
type RestoreConfig struct {
	ImagePath  string
	Direct     bool
	Background bool
}

// Process is the interface representing a process inside the container.
type Process interface {
	// ID returns the id for the process
	ID() string
	// Pid returns the pid for the process
	Pid() int
	// ExitStatus returns the exit status
	ExitStatus() int
	// ExitedAt is the time the process exited
	ExitedAt() time.Time
	// Stdin returns the process STDIN
	Stdin() io.Closer
	// Stdio returns io information for the container
	Stdio() stdio.Stdio
	// Status returns the process status
	Status(context.Context) (string, error)
	// Wait blocks until the process has exited
	Wait()
	// Resize resizes the process console
	Resize(ws console.WinSize) error
	// Start execution of the process
	Start(context.Context) error
	// Delete deletes the process and its resources
	Delete(context.Context) error
	// Kill kills the process
	Kill(context.Context, uint32, bool) error
	// SetExited sets the exit status for the process
	SetExited(status int)
	// Restore restores the container from a snapshot.
	Restore(context.Context, *RestoreConfig) error
}

// CreateWithFSRestoreRequest is a request to create a container and restore
// its filesystem from a snapshot.
type CreateWithFSRestoreRequest struct {
	Create *task.CreateTaskRequest
	Conf   FSRestoreConfig
}

// RestoreRequest is a request to restore a container. It extends
// task.StartRequest with restore functionality.
type RestoreRequest struct {
	Start *task.StartRequest
	Conf  RestoreConfig
}

// TaskServiceExt extends TaskRequest with extra functionality required by the shim.
type TaskServiceExt interface {
	task.TaskService
	CreateWithFSRestore(ctx context.Context, req *CreateWithFSRestoreRequest) (*task.CreateTaskResponse, error)
	Restore(ctx context.Context, req *RestoreRequest) (*task.StartResponse, error)
	Hide(ctx context.Context, req *hibernatepb.HideRequest, resp *hibernatepb.HideResponse) error
	Unhide(ctx context.Context, req *hibernatepb.UnhideRequest, resp *hibernatepb.UnhideResponse) error
}
