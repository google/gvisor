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
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
)

func (cm *containerManager) readControlFile(file control.CgroupControlFile) (string, error) {
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
		return "", err
	}
	if len(out.Results) != 1 {
		return "", fmt.Errorf("expected 1 result, got %d, raw: %+v", len(out.Results), out)
	}
	return out.Results[0].Unpack()
}

func (cm *containerManager) getUsageFromCgroups(file control.CgroupControlFile) (uint64, error) {
	val, err := cm.readControlFile(file)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(val, 10, 64)
}

// Event gets the events from the container.
func (cm *containerManager) Event(cid *string, out *sentryapi.EventOut) error {
	*out = sentryapi.EventOut{
		Event: sentryapi.Event{
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
	memFile := control.CgroupControlFile{
		Controller: "memory",
		Path:       "/" + *cid,
		Name:       "memory.usage_in_bytes",
	}
	if cm.l.k.Cgroup2FS().EverMounted() {
		memFile.Name = "memory.current"
	}
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
	out.ContainerUsage, err = cm.getCPUUsageFromCgroups()
	if err != nil {
		// Cgroups is not installed or there was an error to get usage
		// from the cgroups. Fall back to the old method of getting the
		// usage from the sentry and host cgroups.
		log.Warningf("could not get container cpu usage from cgroups, error:  %v", err)
		out.ContainerUsage = control.ContainerUsage(cm.l.k)
	}
	return nil
}

func (cm *containerManager) getCPUUsageFromCgroups() (map[string]uint64, error) {
	usage := make(map[string]uint64)

	cm.l.mu.Lock()
	defer cm.l.mu.Unlock()

	isV2 := cm.l.k.Cgroup2FS().EverMounted()
	for name, cid := range cm.l.containerIDs {
		// Before the introduction of cgroup v2, the container name, not the ID, was incorrectly used in
		// the cgroup path. For avoiding behavior changes when cgroup v1 is in use, we use the container
		// ID only for cgroup v2.
		id := name
		if isV2 {
			id = cid
		}
		file := control.CgroupControlFile{
			Controller: "cpuacct",
			Path:       "/" + id,
			Name:       "cpuacct.usage",
		}
		if isV2 {
			file.Controller = "cpu"
			file.Name = "cpu.stat"
		}
		valStr, err := cm.readControlFile(file)
		if err != nil {
			return nil, err
		}
		var cpuUsage uint64
		if isV2 {
			for _, line := range strings.Split(valStr, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "usage_usec ") {
					usec, err := strconv.ParseUint(strings.TrimPrefix(line, "usage_usec "), 10, 64)
					if err != nil {
						return nil, fmt.Errorf("parsing usage_usec in cpu.stat: %w", err)
					}
					cpuUsage = usec * 1000
					break
				}
			}
		} else {
			cpuUsage, err = strconv.ParseUint(valStr, 10, 64)
			if err != nil {
				return nil, err
			}
		}
		usage[id] = cpuUsage
	}
	return usage, nil
}
