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
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
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
	RootFs Rootfs `jsoon:"rootfs"`
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

// Rootfs contains data about filesystem usage.
type Rootfs struct {
	// The time at which these stats were updated.
	Time uint64 `json:"time"`
	// AvailableBytes represents the storage space available (bytes) for the filesystem.
	// +optional
	AvailableBytes uint64 `json:"availableBytes,omitempty"`
	// CapacityBytes represents the total capacity (bytes) of the filesystems underlying storage.
	// +optional
	CapacityBytes uint64 `json:"capacityBytes,omitempty"`
	// UsedBytes represents the bytes used for a specific task on the filesystem.
	// This may differ from the total bytes used on the filesystem and may not equal CapacityBytes - AvailableBytes.
	// e.g. For ContainerStats.Rootfs this is the bytes used by the container rootfs on the filesystem.
	// +optional
	UsedBytes uint64 `json:"usedBytes,omitempty"`
	// InodesFree represents the free inodes in the filesystem.
	// +optional
	InodesFree uint64 `json:"inodesFree,omitempty"`
	// Inodes represents the total inodes in the filesystem.
	// +optional
	Inodes uint64 `json:"inodes,omitempty"`
	// InodesUsed represents the inodes used by the filesystem
	// This may not equal Inodes - InodesFree because this filesystem may share inodes with other "filesystems"
	// e.g. For ContainerStats.Rootfs, this is the inodes used only by that container, and does not count inodes used by other containers.
	InodesUsed uint64 `json:"inodesUsed,omitempty"`
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
	_ = mem.UpdateUsage(0) // best effort to update.
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

	var fsstat linux.Statfs
	fsstat, err = cm.l.rootfsStat()
	if err != nil {
		return err
	}

	// Filesystem usage of the container.
	out.Event.Data.RootFs = Rootfs{
		Time:           uint64(time.Now().Unix()),
		Inodes:         fsstat.Files,
		InodesFree:     fsstat.FilesFree,
		InodesUsed:     fsstat.Files - fsstat.FilesFree,
		AvailableBytes: (fsstat.BlocksAvailable * uint64(fsstat.BlockSize)),
		CapacityBytes:  (fsstat.Blocks * uint64(fsstat.BlockSize)),
		UsedBytes:      ((fsstat.Blocks - fsstat.BlocksAvailable) * uint64(fsstat.BlockSize)),
	}

	return nil
}
