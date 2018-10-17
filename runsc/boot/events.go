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

package boot

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
)

// Event struct for encoding the event data to JSON. Corresponds to runc's
// main.event struct.
type Event struct {
	Type string      `json:"type"`
	ID   string      `json:"id"`
	Data interface{} `json:"data,omitempty"`
}

// Stats is the runc specific stats structure for stability when encoding and
// decoding stats.
type Stats struct {
	Memory Memory `json:"memory"`
	Pids   Pids   `json:"pids"`
}

// Pids contains stats on processes.
type Pids struct {
	Current uint64 `json:"current,omitempty"`
	Limit   uint64 `json:"limit,omitempty"`
}

// MemoryEntry contains stats on a kind of memory.
type MemoryEntry struct {
	Limit   uint64 `json:"limit"`
	Usage   uint64 `json:"usage,omitempty"`
	Max     uint64 `json:"max,omitempty"`
	Failcnt uint64 `json:"failcnt"`
}

// Memory contains stats on memory.
type Memory struct {
	Cache     uint64            `json:"cache,omitempty"`
	Usage     MemoryEntry       `json:"usage,omitempty"`
	Swap      MemoryEntry       `json:"swap,omitempty"`
	Kernel    MemoryEntry       `json:"kernel,omitempty"`
	KernelTCP MemoryEntry       `json:"kernelTCP,omitempty"`
	Raw       map[string]uint64 `json:"raw,omitempty"`
}

// Event gets the events from the container.
func (cm *containerManager) Event(_ *struct{}, out *Event) error {
	stats := &Stats{}
	stats.populateMemory(cm.l.k)
	stats.populatePIDs(cm.l.k)
	*out = Event{Type: "stats", Data: stats}
	return nil
}

func (s *Stats) populateMemory(k *kernel.Kernel) {
	mem := k.Platform.Memory()
	mem.UpdateUsage()
	_, totalUsage := usage.MemoryAccounting.Copy()
	s.Memory.Usage = MemoryEntry{
		Usage: totalUsage,
	}
}

func (s *Stats) populatePIDs(k *kernel.Kernel) {
	s.Pids.Current = uint64(len(k.TaskSet().Root.ThreadGroups()))
}
