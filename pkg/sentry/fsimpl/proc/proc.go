// Copyright 2019 The gVisor Authors.
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

// Package proc implements a partial in-memory file system for procfs.
package proc

import (
	"sync"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// FilesystemType implements vfs.FilesystemType.
// TODO(b/138862512): Implement the interface.
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	vfsfs vfs.Filesystem

	// TODO(b/138862512): Remove this and implement the interface.
	vfs.FilesystemImpl

	// mu serializes changes to the Dentry tree.
	mu sync.RWMutex

	nextInoMinusOne uint64 // accessed using atomic memory operations

	// k is the Kernel containing this proc node.
	k *kernel.Kernel

	// pidns is the PID namespace of the task that mounted the proc filesystem
	// that this node represents.
	pidns *kernel.PIDNamespace

	// cgroupControllers is a map of controller name to directory in the
	// cgroup hierarchy. These controllers are immutable and will be listed
	// in /proc/pid/cgroup if not nil.
	cgroupControllers map[string]string
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// All filesystem state is in-memory.
	return nil
}
