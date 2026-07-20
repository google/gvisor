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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/nsfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
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

	// ReadControl implements background accessible reading for cgroup v2 control files.
	ReadControl(ctx context.Context, name string) (string, error)

	// WriteControl implements background accessible writing for cgroup v2 control files.
	WriteControl(ctx context.Context, name string, val string) error

	// PathFrom returns the path of the cgroup relative to nsRoot, following
	// Linux's cgroup_path_ns() semantics: the result always starts with '/',
	// and contains leading "/.." components if the cgroup is not a descendant
	// of nsRoot. Used by procfs for cgroup namespace path virtualization.
	PathFrom(nsRoot Cgroup2) string

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

	// Deleted returns true if the cgroup has been deleted.
	Deleted() bool
}

// Cgroup2FS is the public interface to cgroup2fs.
type Cgroup2FS interface {
	// EverMounted returns true if the filesystem has ever been mounted.
	EverMounted() bool

	// RootCgroup returns the root cgroup v2 node.
	RootCgroup() Cgroup2

	// FindCgroup returns the cgroup v2 node at the specified root-relative path.
	FindCgroup(ctx context.Context, path string) (Cgroup2, error)

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

// GetCgroup2Entry returns the cgroup v2 entry if cgroup v2 is mounted. The
// cgroup path is expressed relative to the root of readerNS, the cgroup
// namespace of the task reading the entry. If readerNS is nil (e.g. for
// background contexts), the absolute path is used.
func (t *Task) GetCgroup2Entry(readerNS *CgroupNamespace) *TaskCgroupEntry {
	var path string
	if c := t.Cgroup2(); c != nil {
		if readerNS != nil {
			path = c.PathFrom(readerNS.Root())
		} else {
			path = c.Path()
		}
		if c.Deleted() {
			path += " (deleted)"
		}
	}
	if path == "" {
		path = "/"
	}
	return &TaskCgroupEntry{
		HierarchyID: 0,
		Path:        path,
	}
}

// CgroupNamespace represents a cgroup namespace. A cgroup namespace
// virtualizes the view of a task's cgroups: paths in /proc/<pid>/cgroup are
// shown relative to the namespace root, and cgroup2 mounts created from
// within the namespace are rooted at the namespace root.
//
// +stateify savable
type CgroupNamespace struct {
	// root is the cgroup2 node this namespace is rooted at. It was the
	// creating task's cgroup at the time the namespace was created, and does
	// not change even if that task subsequently migrates. Immutable.
	root Cgroup2

	// userns is the user namespace that owns this cgroup namespace. Immutable.
	userns *auth.UserNamespace

	// mu protects inode.
	mu sync.Mutex `state:"nosave"`

	// inode is the nsfs inode backing /proc/<pid>/ns/cgroup for this
	// namespace. It also holds this namespace's reference count.
	// +checklocks:mu
	inode *nsfs.Inode
}

// newCgroupNamespace creates a new cgroup namespace rooted at root and owned
// by userns.
func newCgroupNamespace(root Cgroup2, userns *auth.UserNamespace) *CgroupNamespace {
	return &CgroupNamespace{
		root:   root,
		userns: userns,
	}
}

// Root returns the cgroup2 node this namespace is rooted at.
func (ns *CgroupNamespace) Root() Cgroup2 {
	return ns.root
}

// UserNamespace returns the user namespace that owns this cgroup namespace.
func (ns *CgroupNamespace) UserNamespace() *auth.UserNamespace {
	return ns.userns
}

// Type implements vfs.Namespace.Type.
func (ns *CgroupNamespace) Type() string {
	return "cgroup"
}

// Destroy implements vfs.Namespace.Destroy.
func (ns *CgroupNamespace) Destroy(ctx context.Context) {}

// SetInode sets the nsfs inode of the cgroup namespace.
func (ns *CgroupNamespace) SetInode(inode *nsfs.Inode) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.inode = inode
}

// GetInode returns the nsfs inode associated with the cgroup namespace.
func (ns *CgroupNamespace) GetInode() *nsfs.Inode {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return ns.inode
}

// IncRef increments the namespace's reference count.
func (ns *CgroupNamespace) IncRef() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.inode.IncRef()
}

// DecRef decrements the namespace's reference count.
func (ns *CgroupNamespace) DecRef(ctx context.Context) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.inode.DecRef(ctx)
}

// CgroupNamespace returns the task's cgroup namespace.
func (t *Task) CgroupNamespace() *CgroupNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cgroupns
}

// GetCgroupNamespace takes a reference on the task's cgroup namespace and
// returns it. It returns nil if the task has exited.
func (t *Task) GetCgroupNamespace() *CgroupNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cgroupns != nil {
		t.cgroupns.IncRef()
	}
	return t.cgroupns
}
