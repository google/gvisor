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
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/semaphore"
)

// IPCNamespace represents an IPC namespace.
type IPCNamespace struct {
	semaphores *semaphore.Registry
}

// NewIPCNamespace creates a new IPC namespace.
func NewIPCNamespace() *IPCNamespace {
	return &IPCNamespace{
		semaphores: semaphore.NewRegistry(),
	}
}

// SemaphoreRegistry returns the semanphore set registry for this namespace.
func (i *IPCNamespace) SemaphoreRegistry() *semaphore.Registry {
	return i.semaphores
}

// IPCNamespace returns the task's IPC namespace.
func (t *Task) IPCNamespace() *IPCNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ipcns
}
