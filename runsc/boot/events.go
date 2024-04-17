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
	"fmt"
	"strconv"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

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

func (cm *containerManager) getUsageFromCgroups(file control.CgroupControlFile) (uint64, error) {
	var out control.CgroupsResults
	args := control.CgroupsReadArgs{
		Args: []control.CgroupsReadArg{
			{
				File: file,
			},
		},
	}
	cgroups := control.Cgroups{Kernel: cm.l.k}
	if err := cgroups.ReadControlFiles(&args, &out); err != nil {
		return 0, err
	}
	if len(out.Results) != 1 {
		return 0, fmt.Errorf("expected 1 result, got %d, raw: %+v", len(out.Results), out)
	}
	val, err := out.Results[0].Unpack()
	if err != nil {
		return 0, err
	}
	usage, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return 0, err
	}
	return usage, nil
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

	networkStats, err := cm.l.networkStats()
	if err != nil {
		return err
	}
	out.Event.Data.NetworkInterfaces = networkStats

	numContainers := cm.l.containerCount()
	if numContainers == 0 {
		return fmt.Errorf("no container was found")
	}

	// Memory usage.
	memFile := control.CgroupControlFile{"memory", "/" + *cid, "memory.usage_in_bytes"}
	memUsage, err := cm.getUsageFromCgroups(memFile)
	if err != nil {
		// Cgroups is not installed or there was an error to get usage
		// from the cgroups. Fall back to the old method of getting the
		// usage from the sentry.
		log.Warningf("could not get container memory usage from cgroups, error:  %v", err)

		mem := cm.l.k.MemoryFile()
		_ = mem.UpdateUsage(nil) // best effort to update.
		_, totalUsage := usage.MemoryAccounting.Copy()
		if numContainers == 1 {
			memUsage = totalUsage
		} else {
			// In the multi-container case, reports 0 for the root (pause)
			// container, since it's small and idle. Then equally split the
			// usage to the other containers. At least the sum of all
			// containers will correctly account for the memory used by the
			// sandbox.
			if *cid == cm.l.sandboxID {
				memUsage = 0
			} else {
				memUsage = totalUsage / uint64(numContainers-1)
			}
		}
	}
	out.Event.Data.Memory.Usage.Usage = memUsage

	// CPU usage by container.
	cpuacctFile := control.CgroupControlFile{"cpuacct", "/" + *cid, "cpuacct.usage"}
	if cpuUsage, err := cm.getUsageFromCgroups(cpuacctFile); err != nil {
		// Cgroups is not installed or there was an error to get usage
		// from the cgroups. Fall back to the old method of getting the
		// usage from the sentry and host cgroups.
		log.Warningf("could not get container cpu usage from cgroups, error:  %v", err)

		out.ContainerUsage = control.ContainerUsage(cm.l.k)
	} else {
		out.Event.Data.CPU.Usage.Total = cpuUsage
	}
	return nil
}
