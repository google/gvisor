// Copyright 2018 The gVisor Authors.
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
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/mqfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/nsfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/mq"
	"gvisor.dev/gvisor/pkg/sentry/kernel/msgqueue"
	"gvisor.dev/gvisor/pkg/sentry/kernel/semaphore"
	"gvisor.dev/gvisor/pkg/sentry/kernel/shm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// IPCNamespace represents an IPC namespace.
//
// +stateify savable
type IPCNamespace struct {
	inode *nsfs.Inode

	// User namespace which owns this IPC namespace. Immutable.
	userNS *auth.UserNamespace

	// System V utilities.
	queues     *msgqueue.Registry
	semaphores *semaphore.Registry
	shms       *shm.Registry

	// posixQueues is a POSIX message queue registry.
	//
	// posixQueues is somewhat equivalent to Linux's ipc_namespace.mq_mnt.
	// Unlike SysV utilities, mq.Registry is not map-based, but is backed by
	// a virtual filesystem.
	posixQueues *mq.Registry
}

// NewIPCNamespace creates a new IPC namespace.
func NewIPCNamespace(userNS *auth.UserNamespace) *IPCNamespace {
	ns := &IPCNamespace{
		userNS:     userNS,
		queues:     msgqueue.NewRegistry(userNS),
		semaphores: semaphore.NewRegistry(userNS),
		shms:       shm.NewRegistry(userNS),
	}
	return ns
}

// Type implements nsfs.Namespace.Type.
func (i *IPCNamespace) Type() string {
	return "ipc"
}

// Destroy implements nsfs.Namespace.Destroy.
func (i *IPCNamespace) Destroy(ctx context.Context) {
	i.shms.Release(ctx)
	if i.posixQueues != nil {
		i.posixQueues.Destroy(ctx)
	}
}

// SetInode sets the nsfs `inode` to the IPC namespace.
func (i *IPCNamespace) SetInode(inode *nsfs.Inode) {
	i.inode = inode
}

// GetInode returns the nsfs inode associated with the IPC namespace.
func (i *IPCNamespace) GetInode() *nsfs.Inode {
	return i.inode
}

// UserNamespace returns the user namespace associated with the namespace.
func (i *IPCNamespace) UserNamespace() *auth.UserNamespace {
	return i.userNS
}

// MsgqueueRegistry returns the message queue registry for this namespace.
func (i *IPCNamespace) MsgqueueRegistry() *msgqueue.Registry {
	return i.queues
}

// SemaphoreRegistry returns the semaphore set registry for this namespace.
func (i *IPCNamespace) SemaphoreRegistry() *semaphore.Registry {
	return i.semaphores
}

// ShmRegistry returns the shm segment registry for this namespace.
func (i *IPCNamespace) ShmRegistry() *shm.Registry {
	return i.shms
}

// InitPosixQueues creates a new POSIX queue registry, and returns an error if
// the registry was previously initialized.
func (i *IPCNamespace) InitPosixQueues(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) error {
	if i.posixQueues != nil {
		return fmt.Errorf("IPCNamespace.InitPosixQueues: already initialized")
	}

	impl, err := mqfs.NewRegistryImpl(ctx, vfsObj, creds)
	if err != nil {
		return err
	}
	i.posixQueues = mq.NewRegistry(i.userNS, impl)
	return nil
}

// PosixQueues returns the posix message queue registry for this namespace.
//
// Precondition: i.InitPosixQueues must have been called.
func (i *IPCNamespace) PosixQueues() *mq.Registry {
	return i.posixQueues
}

// IncRef increments the Namespace's refcount.
func (i *IPCNamespace) IncRef() {
	i.inode.IncRef()
}

// DecRef decrements the namespace's refcount.
func (i *IPCNamespace) DecRef(ctx context.Context) {
	i.inode.DecRef(ctx)
}

// IPCNamespace returns the task's IPC namespace.
func (t *Task) IPCNamespace() *IPCNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ipcns
}

// GetIPCNamespace takes a reference on the task IPC namespace and
// returns it. It will return nil if the task isn't alive.
func (t *Task) GetIPCNamespace() *IPCNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ipcns != nil {
		t.ipcns.IncRef()
	}
	return t.ipcns
}
