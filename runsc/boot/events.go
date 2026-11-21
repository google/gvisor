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
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
)

func (cm *containerManager) readControlFile(file controlapi.CgroupControlFile) (string, error) {
	var out controlapi.CgroupsResults
	args := controlapi.CgroupsReadArgs{
		Args: []controlapi.CgroupsReadArg{
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

func (cm *containerManager) getUsageFromCgroups(file controlapi.CgroupControlFile) (uint64, error) {
	val, err := cm.readControlFile(file)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(val, 10, 64)
}

// Event gets the events from the container.
func (cm *containerManager) Event(args *sentryapi.EventArgs, out *sentryapi.EventOut) error {
	cid := &args.CID
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
	memFile := controlapi.CgroupControlFile{
		Controller: "memory",
		Path:       "/" + *cid,
		Name:       "memory.usage_in_bytes",
	}
	if cm.l.k.Cgroup2FS().EverMounted() {
		memFile.Name = "memory.current"
	}
	// Cgroup reads update filesystem refs that checkpoint serializes.
	cm.l.saveMu.Lock()
	memUsage, err := cm.getUsageFromCgroups(memFile)
	cm.l.saveMu.Unlock()
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

	return cm.cpuStats(args, out)
}

func (cm *containerManager) cpuStats(args *sentryapi.EventArgs, out *sentryapi.EventOut) error {
	// Keep the guest snapshot and host allocation in the same container
	// lifecycle window. Destroy retires CPU accounting under l.mu.
	for {
		cm.l.saveMu.Lock()
		if cm.l.mu.TryLock() {
			break
		}
		cm.l.saveMu.Unlock()
		// Destroy may wait for task exit under mu; leave saveMu available.
		cm.l.mu.Lock()
		_, err := cm.l.tryThreadGroupFromIDLocked(execID{cid: args.CID})
		cm.l.mu.Unlock()
		if err != nil {
			return err
		}
	}
	defer cm.l.saveMu.Unlock()
	_, err := cm.l.tryThreadGroupFromIDLocked(execID{cid: args.CID}) // +checklocksforce: mu.TryLock succeeded above.
	defer cm.l.mu.Unlock()
	if err != nil {
		return err
	}
	out.ContainerUsage, err = cm.getCPUUsageFromCgroupsLocked()
	source := "cgroup"
	if err != nil {
		// Cgroups is not installed or there was an error to get usage
		// from the cgroups. Fall back to the old method of getting the
		// usage from the sentry and host cgroups.
		log.Warningf("could not get container cpu usage from cgroups, error:  %v", err)
		out.ContainerUsage = control.ContainerUsage(cm.l.k)
		source = "sentry"
	}
	allocated := cm.l.k.AccountContainerCPU(out.ContainerUsage, source, args.HostCPU, args.HostValid, args.HostConfigured)
	out.Event.Data.CPU.Usage.Total = allocated[args.CID]
	return nil
}

// Requires l.mu across guest snapshot and allocation to exclude retirement.
// +checklocks:cm.l.mu
func (cm *containerManager) getCPUUsageFromCgroupsLocked() (map[string]uint64, error) {
	usage := make(map[string]uint64)
	var missing []string

	isV2 := cm.l.k.Cgroup2FS().EverMounted()
	for name, cid := range cm.l.containerIDs {
		// Destroy retires this CID but leaves its name and v1 cgroup behind.
		if _, active := cm.l.processes[execID{cid: cid}]; !active {
			continue
		}
		// Pause and other containers without a cgroup mount use task CPU.
		if !specHasCgroupMount(cm.l.containerSpecs[name]) {
			missing = append(missing, cid)
			continue
		}
		file := controlapi.CgroupControlFile{
			Controller: "cpuacct",
			Path:       "/" + cid,
			Name:       "cpuacct.usage",
		}
		if isV2 {
			file.Controller = "cpu"
			file.Name = "cpu.stat"
		}
		valStr, err := cm.readControlFile(file)
		if err != nil {
			// Keep the cgroup clock after a transient failure. Containers
			// without a prior cgroup sample use retained sentry CPU.
			log.Debugf("could not get container %q cpu usage from cgroups, retaining its previous cgroup sample or sentry usage: %v", cid, err)
			missing = append(missing, cid)
			continue
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
		usage[cid] = cpuUsage
	}
	return cm.l.k.ContainerCPUUsageWithFallback(usage, missing), nil
}
