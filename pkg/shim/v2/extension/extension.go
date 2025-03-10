// Copyright 2025 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/shim"

	task "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/v2/cmd/containerd-shim-runc-v2/process"
)

// NewExtension registers an extension constructor. It may return nil, nil to indicate that the
// extension should not handle this task request. Returning an error will fail the task request.
var NewExtension func(ctx context.Context, next TaskServiceExt, req *task.CreateTaskRequest) (TaskServiceExt, error)

// RestoreRequest is a request to restore a container. It extends
// task.StartRequest with restore functionality.
type RestoreRequest struct {
	Start task.StartRequest
	Conf  shim.RestoreConfig
}

// Process extends process.Process with extra restore functionality.
type Process interface {
	process.Process
	// Restore restores the container from a snapshot.
	Restore(context.Context, *shim.RestoreConfig) error
}

// TaskServiceExt extends TaskRequest with extra functionality required by the shim.
type TaskServiceExt interface {
	task.TTRPCTaskService
	Cleanup(ctx context.Context) (*task.DeleteResponse, error)
	Restore(ctx context.Context, req *RestoreRequest) (*task.StartResponse, error)
}
