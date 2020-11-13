// Copyright 2020 The gVisor Authors.
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

package tcpip

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// SocketOptions contains all the variables which store values for socket
// level options.
//
// +stateify savable
type SocketOptions struct {
	// mu protects fields below.
	mu               sync.Mutex `state:"nosave"`
	broadcastEnabled bool
}

// GetBroadcast gets value for SO_BROADCAST option.
func (so *SocketOptions) GetBroadcast() bool {
	so.mu.Lock()
	defer so.mu.Unlock()

	return so.broadcastEnabled
}

// SetBroadcast sets value for SO_BROADCAST option.
func (so *SocketOptions) SetBroadcast(v bool) {
	so.mu.Lock()
	defer so.mu.Unlock()

	so.broadcastEnabled = v
}
