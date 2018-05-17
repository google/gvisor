// Copyright 2018 Google Inc.
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/semaphore"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/shm"
)

// IPCNamespace represents an IPC namespace.
type IPCNamespace struct {
	// User namespace which owns this IPC namespace. Immutable.
	userNS *auth.UserNamespace

	semaphores *semaphore.Registry
	shms       *shm.Registry
}

// NewIPCNamespace creates a new IPC namespace.
func NewIPCNamespace(userNS *auth.UserNamespace) *IPCNamespace {
	return &IPCNamespace{
		userNS:     userNS,
		semaphores: semaphore.NewRegistry(),
		shms:       shm.NewRegistry(userNS),
	}
}

// SemaphoreRegistry returns the semanphore set registry for this namespace.
func (i *IPCNamespace) SemaphoreRegistry() *semaphore.Registry {
	return i.semaphores
}

// ShmRegistry returns the shm segment registry for this namespace.
func (i *IPCNamespace) ShmRegistry() *shm.Registry {
	return i.shms
}

// IPCNamespace returns the task's IPC namespace.
func (t *Task) IPCNamespace() *IPCNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ipcns
}
