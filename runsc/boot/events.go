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

package boot

import (
	"errors"

	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// EventOut is the return type of the Event command.
type EventOut struct {
	Event Event `json:"event"`

	// ContainerUsage maps each container ID to its total CPU usage.
	ContainerUsage map[string]uint64 `json:"containerUsage"`
}

// Event struct for encoding the event data to JSON. Corresponds to runc's
// main.event struct.
type Event struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Data Stats  `json:"data"`
}

// Stats is the runc specific stats structure for stability when encoding and
// decoding stats.
type Stats struct {
	CPU    CPU    `json:"cpu"`
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

// CPU contains stats on the CPU.
type CPU struct {
	Usage CPUUsage `json:"usage"`
}

// CPUUsage contains stats on CPU usage.
type CPUUsage struct {
	Kernel uint64   `json:"kernel,omitempty"`
	User   uint64   `json:"user,omitempty"`
	Total  uint64   `json:"total,omitempty"`
	PerCPU []uint64 `json:"percpu,omitempty"`
}

// Event gets the events from the container.
func (cm *containerManager) Event(cid *string, out *EventOut) error {
	*out = EventOut{
		Event: Event{
			ID:   *cid,
			Type: "stats",
		},
	}

	// PIDs and check that container exists before going further.
	pids, err := cm.l.pidsCount(*cid)
	if err != nil {
		return err
	}
	out.Event.Data.Pids.Current = uint64(pids)

	// Memory usage.
	mem := cm.l.k.MemoryFile()
	_ = mem.UpdateUsage(nil) // best effort to update.
	_, totalUsage := usage.MemoryAccounting.Copy()
	switch containers := cm.l.containerCount(); containers {
	case 0:
		return errors.New("no container was found")

	case 1:
		// There is a single container, so total usage can only come from it.

	default:
		// In the multi-container case, reports 0 for the root (pause) container,
		// since it's small and idle. Then equally split the usage to the other
		// containers. At least the sum of all containers will correctly account
		// for the memory used by the sandbox.
		//
		// TODO(gvisor.dev/issue/172): Proper per-container accounting.
		if *cid == cm.l.sandboxID {
			totalUsage = 0
		} else {
			totalUsage /= uint64(containers - 1)
		}
	}

	out.Event.Data.Memory.Usage.Usage = totalUsage

	// CPU usage by container.
	out.ContainerUsage = control.ContainerUsage(cm.l.k)

	return nil
}
