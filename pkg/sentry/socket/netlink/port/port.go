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

// Package port provides port ID allocation for netlink sockets.
//
// A netlink port is any int32 value. Positive ports are typically equivalent
// to the PID of the binding process. If that port is unavailable, negative
// ports are searched to find a free port that will not conflict with other
// PIDS.
package port

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
)

// maxPorts is a sanity limit on the maximum number of ports to allocate per
// protocol.
const maxPorts = 10000

// Manager allocates netlink port IDs.
//
// +stateify savable
type Manager struct {
	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// ports contains a map of allocated ports for each protocol.
	ports map[int]map[int32]struct{}
}

// New creates a new Manager.
func New() *Manager {
	return &Manager{
		ports: make(map[int]map[int32]struct{}),
	}
}

// Allocate reserves a new port ID for protocol. hint will be taken if
// available.
func (m *Manager) Allocate(protocol int, hint int32) (int32, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	proto, ok := m.ports[protocol]
	if !ok {
		proto = make(map[int32]struct{})
		// Port 0 is reserved for the kernel.
		proto[0] = struct{}{}
		m.ports[protocol] = proto
	}

	if len(proto) >= maxPorts {
		return 0, false
	}

	if _, ok := proto[hint]; !ok {
		// Hint is available, reserve it.
		proto[hint] = struct{}{}
		return hint, true
	}

	// Search for any free port in [math.MinInt32, -4096). The positive
	// port space is left open for pid-based allocations. This behavior is
	// consistent with Linux.
	start := int32(math.MinInt32 + rand.Int63n(math.MaxInt32-4096+1))
	curr := start
	for {
		if _, ok := proto[curr]; !ok {
			proto[curr] = struct{}{}
			return curr, true
		}

		curr--
		if curr >= -4096 {
			curr = -4097
		}
		if curr == start {
			// Nothing found. We should always find a free port
			// because maxPorts < -4096 - MinInt32.
			panic(fmt.Sprintf("No free port found in %+v", proto))
		}
	}
}

// Release frees the specified port for protocol.
//
// Preconditions: port is already allocated.
func (m *Manager) Release(protocol int, port int32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	proto, ok := m.ports[protocol]
	if !ok {
		panic(fmt.Sprintf("Released port %d for protocol %d which has no allocations", port, protocol))
	}

	if _, ok := proto[port]; !ok {
		panic(fmt.Sprintf("Released port %d for protocol %d is not allocated", port, protocol))
	}

	delete(proto, port)
}
