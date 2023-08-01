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
	"gvisor.dev/gvisor/pkg/sentry/inet"
)

// IsNetworkNamespaced returns true if t is in a non-root network namespace.
func (t *Task) IsNetworkNamespaced() bool {
	return !t.netns.IsRoot()
}

// NetworkContext returns the network stack used by the task. NetworkContext
// may return nil if no network stack is available.
//
// TODO(gvisor.dev/issue/1833): Migrate callers of this method to
// NetworkNamespace().
func (t *Task) NetworkContext() inet.Stack {
	return t.netns.Stack()
}

// NetworkNamespace returns the network namespace observed by the task.
func (t *Task) NetworkNamespace() *inet.Namespace {
	return t.netns
}

// GetNetworkNamespace takes a reference on the task network namespace and
// returns it. It can return nil if the task isn't alive.
func (t *Task) GetNetworkNamespace() *inet.Namespace {
	// t.mu is required to be sure that the network namespace will not be
	// released.
	t.mu.Lock()
	netns := t.netns
	if netns != nil {
		netns.IncRef()
	}
	t.mu.Unlock()
	return netns
}
