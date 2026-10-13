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

package sentryapi

// NetworkInterface is the network statistics of the particular network interface
type NetworkInterface struct {
	// Name is the name of the network interface.
	Name      string
	RxBytes   uint64
	RxPackets uint64
	RxErrors  uint64
	RxDropped uint64
	TxBytes   uint64
	TxPackets uint64
	TxErrors  uint64
	TxDropped uint64
}

// ContMgrEvent gets stats about the container used by "runsc events".
const ContMgrEvent = "containerManager.Event"

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
	CPU               CPU                 `json:"cpu"`
	Memory            Memory              `json:"memory"`
	Pids              Pids                `json:"pids"`
	NetworkInterfaces []*NetworkInterface `json:"network_interfaces"`
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
