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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/msgqueue"
	"gvisor.dev/gvisor/pkg/sentry/kernel/semaphore"
	"gvisor.dev/gvisor/pkg/sentry/kernel/shm"
)

// IPCNamespace represents an IPC namespace.
//
// +stateify savable
type IPCNamespace struct {
	IPCNamespaceRefs

	// User namespace which owns this IPC namespace. Immutable.
	userNS *auth.UserNamespace

	queues     *msgqueue.Registry
	semaphores *semaphore.Registry
	shms       *shm.Registry
}

// NewIPCNamespace creates a new IPC namespace.
func NewIPCNamespace(userNS *auth.UserNamespace) *IPCNamespace {
	ns := &IPCNamespace{
		userNS:     userNS,
		queues:     msgqueue.NewRegistry(userNS),
		semaphores: semaphore.NewRegistry(userNS),
		shms:       shm.NewRegistry(userNS),
	}
	ns.InitRefs()
	return ns
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

// DecRef implements refsvfs2.RefCounter.DecRef.
func (i *IPCNamespace) DecRef(ctx context.Context) {
	i.IPCNamespaceRefs.DecRef(func() {
		i.shms.Release(ctx)
	})
}

// IPCNamespace returns the task's IPC namespace.
func (t *Task) IPCNamespace() *IPCNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ipcns
}
