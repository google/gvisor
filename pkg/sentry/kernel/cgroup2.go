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

package kernel

import (
	"math"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// Cgroup2Ctrl represents a supported cgroup v2 controller.
type Cgroup2Ctrl int

const (
	// Cgroup2CPU represents the CPU controller.
	Cgroup2CPU Cgroup2Ctrl = iota
	// Cgroup2Memory represents the memory controller.
	Cgroup2Memory
	// Cgroup2PIDs represents the pids controller.
	Cgroup2PIDs
	// Cgroup2CPUSet represents the cpuset controller.
	Cgroup2CPUSet
	// Cgroup2NumControllers is the total number of cgroup v2 controllers currently supported.
	Cgroup2NumControllers
)

// Cgroup2 is an interface representing a cgroup v2 node.
type Cgroup2 interface {
	// Path returns the root-relative path of the cgroup.
	// Used by procfs.
	Path() string

	// The following are used by clone() and CreateProcess().
	// CanEnter checks if a task can enter the cgroup.
	CanEnter(ctx context.Context, t *Task) (func(), func(), error)

	// Exit removes a task from a cgroup.
	// Called by exiting tasks.
	Exit(ctx context.Context, t *Task)

	// Called by clone() to check permissions for CLONE_CGROUP_INTO.
	CanCloneInto(ctx context.Context, creds *auth.Credentials) error

	// KillSeq returns the kill sequence number of the cgroup.
	// It helps prevent fork()s racing with cgroup.kill.
	KillSeq() uint64

	// IsFrozen returns whether the cgroup is effectively frozen (it or any
	// ancestor has cgroup.freeze set). It lets a task forked into a frozen
	// subtree start frozen.
	IsFrozen() bool
}

// Cgroup2FS is the public interface to cgroup2fs.
type Cgroup2FS interface {
	// EverMounted returns true if the filesystem has ever been mounted.
	EverMounted() bool

	// RootCgroup returns the root cgroup v2 node.
	RootCgroup() Cgroup2

	// LockTree locks the cgroup2fs tree for writing.
	LockTree()
	// UnlockTree is the inverse of LockTree.
	UnlockTree()
	// RLockTree locks the cgroup2fs tree for reading.
	RLockTree()
	// RUnlockTree is the inverse of RLockTree.
	RUnlockTree()

	// StealControllerLocked transfers ownership of the controller
	// away from the v2 hierarchy if a v1 hierarchy mounts it.
	StealControllerLocked(ctx context.Context, cType Cgroup2Ctrl) error
	// ReturnControllerLocked returns ownership of the controller
	// to the v2 hierarchy when a v1 hierarchy unmounts it.
	ReturnControllerLocked(ctx context.Context, cType Cgroup2Ctrl)
}

// Cgroup2FS returns the cgroup v2 filesystem singleton.
func (k *Kernel) Cgroup2FS() Cgroup2FS {
	return k.cgroupRegistry.v2fs.Impl().(Cgroup2FS)
}

// SetCgroup2 sets the cgroup v2 node for the task t.
func (t *Task) SetCgroup2(node Cgroup2) {
	t.cgroup2Mu.Lock()
	defer t.cgroup2Mu.Unlock()
	t.cgroup2 = node
}

// Cgroup2 returns t's cgroup v2 node.
func (t *Task) Cgroup2() Cgroup2 {
	t.cgroup2Mu.Lock()
	defer t.cgroup2Mu.Unlock()
	return t.cgroup2
}

// getCgroup2NodeFromFD returns the cgroup v2 node associated with the cgroupFD.
// If the cgroupFD is not valid, returns an error.
func (t *Task) getCgroup2NodeFromFD(cgroupFD uint64) (Cgroup2, error) {
	if cgroupFD > math.MaxInt32 {
		return nil, linuxerr.EINVAL
	}
	cgroupFile := t.GetFile(int32(cgroupFD))
	if cgroupFile == nil {
		return nil, linuxerr.EBADF
	}
	defer cgroupFile.DecRef(t)

	d, ok := cgroupFile.VirtualDentry().Dentry().Impl().(*kernfs.Dentry)
	if !ok {
		return nil, linuxerr.EBADF
	}
	if cgroupFile.VirtualDentry().Dentry().IsDead() {
		return nil, linuxerr.ENOENT
	}
	c, ok := d.Inode().(Cgroup2)
	if !ok {
		return nil, linuxerr.EBADF
	}

	return c, nil
}

// GetCgroup2Entry returns the cgroup v2 entry if cgroup v2 is mounted.
func (t *Task) GetCgroup2Entry() *TaskCgroupEntry {
	var path string
	if c := t.Cgroup2(); c != nil {
		path = c.Path()
	}
	if path == "" {
		path = "/"
	}
	return &TaskCgroupEntry{
		HierarchyID: 0,
		Controllers: "",
		Path:        path,
	}
}
