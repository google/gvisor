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
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
)

// IsNetworkNamespaced returns true if t is in a non-root network namespace.
func (t *Task) IsNetworkNamespaced() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.netns
}

// NetworkContext returns the network stack used by the task. NetworkContext
// may return nil if no network stack is available.
func (t *Task) NetworkContext() inet.Stack {
	if t.IsNetworkNamespaced() {
		return nil
	}
	return t.k.networkStack
}
