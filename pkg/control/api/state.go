// Copyright 2026 The gVisor Authors.
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

package api

import (
	"time"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/urpc"
)

// DefaultSaveRestoreExecTimeout is the default timeout for the save/restore
// binary.
const DefaultSaveRestoreExecTimeout = 10 * time.Minute

// SaveOpts contains options for the Save RPC call.
type SaveOpts struct {
	// Key is used to enable state integrity check.
	Key []byte `json:"key"`

	// Metadata is the set of metadata to prepend to the state file.
	Metadata map[string]string `json:"metadata"`

	// AppMFExcludeCommittedZeroPages is the value of
	// pgalloc.SaveOpts.ExcludeCommittedZeroPages for the application memory
	// file.
	AppMFExcludeCommittedZeroPages bool `json:"app_mf_exclude_committed_zero_pages"`

	// HavePagesFile indicates whether the pages file and its corresponding
	// metadata file is provided.
	HavePagesFile bool `json:"have_pages_file"`

	// FilePayload contains the following:
	// 1. checkpoint state file.
	// 2. optional checkpoint pages metadata file.
	// 3. optional checkpoint pages file.
	urpc.FilePayload

	// Resume indicates if the sandbox process should continue running
	// after checkpointing.
	Resume bool

	// ExecOpts contains options for executing a binary during save/restore.
	ExecOpts SaveRestoreExecOpts

	// If UseCheckpointGofer is true, the first and only file in FilePayload is
	// a Unix domain socket connected to a URPC server implementing
	// stateipc.AsyncFileServer and providing checkpoint files.
	UseCheckpointGofer bool `json:"use_checkpoint_gofer"`

	// CudaCheckpointPath is the path to the cuda-checkpoint binary.
	CudaCheckpointPath string `json:"cuda_checkpoint_path"`

	// CudaCheckpointSequential indicates whether cuda-checkpoint should be run
	// sequentially (rather than in parallel).
	CudaCheckpointSequential bool `json:"cuda_checkpoint_sequential"`

	// SplitFSCheckpointPaths is the list of paths to include in the filesystem
	// for split checkpoint. If non-empty, split filesystem checkpoint is enabled.
	// For capturing all of tmpfs, the ResourceID Path should be "all-tmpfs".
	SplitFSCheckpointPaths []checkpoint.ResourceID `json:"split_fs_checkpoint_paths"`

	// RunscVersion is the runsc binary version.
	RunscVersion string `json:"runsc_version"`
}

// SaveRestoreExecOpts contains options for executing a binary
// during save/restore.
type SaveRestoreExecOpts struct {
	// Argv is the argv of the save/restore binary split by spaces.
	// The first element is the path to the binary.
	Argv string

	// Timeout is the timeout for waiting for the save/restore binary.
	Timeout time.Duration

	// ContainerID is the ID of the container that the save/restore binary executes in.
	ContainerID string
}
