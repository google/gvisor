// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sys

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// NUMANodeData contains the per-node sysfs attributes that NCCL reads from
// /sys/devices/system/node/node<N>/ to build the topology XML's <cpu> blocks
// (notably the affinity bitmap).
type NUMANodeData struct {
	// ID is the numeric node identifier, e.g. "0".
	ID string `json:"id"`
	// CPUMap is the hex bitmap from /sys/devices/system/node/nodeN/cpumap,
	// e.g. "00000000,00000000,00ffffff,ffffffff".
	CPUMap string `json:"cpumap"`
	// CPUList is the range list from /sys/devices/system/node/nodeN/cpulist,
	// e.g. "0-23,48-71".
	CPUList string `json:"cpulist"`
	// Distance is the space-separated NUMA distance vector from
	// /sys/devices/system/node/nodeN/distance, e.g. "10 20".
	Distance string `json:"distance,omitempty"`
}

// NUMAData holds all collected NUMA node attributes.
type NUMAData struct {
	// Nodes is sorted by numeric ID for deterministic sysfs output.
	Nodes []NUMANodeData `json:"nodes"`
	// Online, Possible, HasCPU, HasMemory, HasNormalMemory mirror the
	// corresponding /sys/devices/system/node/* aggregate files. They are
	// captured verbatim from the host so the sandbox sees the same node set
	// as the kernel does, including any oddities like sparsely numbered nodes.
	Online          string `json:"online,omitempty"`
	Possible        string `json:"possible,omitempty"`
	HasCPU          string `json:"has_cpu,omitempty"`
	HasMemory       string `json:"has_memory,omitempty"`
	HasNormalMemory string `json:"has_normal_memory,omitempty"`
}

// CollectNUMAData reads NUMA topology from /sys/devices/system/node/. Returns
// nil if the host doesn't expose a node hierarchy (single-NUMA systems
// without CONFIG_NUMA omit the tree entirely). Must be called before
// pivot_root while host sysfs is still accessible.
func CollectNUMAData() *NUMAData {
	nodePath := "/sys/devices/system/node"
	dents, err := os.ReadDir(nodePath)
	if err != nil {
		log.Infof("numa collect: %s not accessible: %v", nodePath, err)
		return nil
	}
	data := &NUMAData{
		Online:          readSysfsFile(path.Join(nodePath, "online")),
		Possible:        readSysfsFile(path.Join(nodePath, "possible")),
		HasCPU:          readSysfsFile(path.Join(nodePath, "has_cpu")),
		HasMemory:       readSysfsFile(path.Join(nodePath, "has_memory")),
		HasNormalMemory: readSysfsFile(path.Join(nodePath, "has_normal_memory")),
	}
	for _, d := range dents {
		name := d.Name()
		if !strings.HasPrefix(name, "node") {
			continue
		}
		idStr := strings.TrimPrefix(name, "node")
		if _, err := strconv.Atoi(idStr); err != nil {
			continue
		}
		dir := path.Join(nodePath, name)
		data.Nodes = append(data.Nodes, NUMANodeData{
			ID:       idStr,
			CPUMap:   readSysfsFile(path.Join(dir, "cpumap")),
			CPUList:  readSysfsFile(path.Join(dir, "cpulist")),
			Distance: readSysfsFile(path.Join(dir, "distance")),
		})
	}
	sort.Slice(data.Nodes, func(i, j int) bool {
		ai, _ := strconv.Atoi(data.Nodes[i].ID)
		aj, _ := strconv.Atoi(data.Nodes[j].ID)
		return ai < aj
	})
	if len(data.Nodes) == 0 {
		log.Infof("numa collect: no node directories under %s", nodePath)
		return nil
	}
	log.Infof("numa collect: collected %d node(s), online=%q", len(data.Nodes), data.Online)
	return data
}

// NUMADataPath is the path within the chroot where serialized NUMA data is
// stored between boot stages.
const NUMADataPath = "/var/lib/gvisor/numa_data.json"

// SerializeNUMAData writes the collected data as JSON to the given path.
func SerializeNUMAData(data *NUMAData, filePath string) error {
	if data == nil {
		return nil
	}
	if err := os.MkdirAll(path.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("MkdirAll %s: %w", path.Dir(filePath), err)
	}
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("json.Marshal: %w", err)
	}
	return os.WriteFile(filePath, b, 0644)
}

// DeserializeNUMAData reads serialized NUMA data from the given path. Returns
// nil if the file is absent or malformed; the sysfs tree then falls back to
// having no /sys/devices/system/node/ subtree, which matches gVisor's
// pre-existing behavior.
func DeserializeNUMAData(filePath string) *NUMAData {
	b, err := os.ReadFile(filePath)
	if err != nil {
		log.Infof("numa deserialize: %s: %v", filePath, err)
		return nil
	}
	var data NUMAData
	if err := json.Unmarshal(b, &data); err != nil {
		log.Warningf("numa deserialize: unmarshal %s: %v", filePath, err)
		return nil
	}
	log.Infof("numa deserialize: loaded %d node(s) from %s", len(data.Nodes), filePath)
	return &data
}

// newNUMASysfsEntries builds the kernfs subtree to mount at
// /sys/devices/system/node/. Returns nil if data is empty.
//
// Layout:
//
//	node/
//	    online              -> aggregate range list
//	    possible            -> aggregate range list
//	    has_cpu             -> aggregate range list
//	    has_memory          -> aggregate range list
//	    has_normal_memory   -> aggregate range list
//	    node<N>/
//	        cpumap          -> hex bitmap
//	        cpulist         -> range list
//	        distance        -> space-separated distance vector
func (fs *filesystem) newNUMASysfsEntries(ctx context.Context, creds *auth.Credentials, data *NUMAData) map[string]kernfs.Inode {
	if data == nil || len(data.Nodes) == 0 {
		return nil
	}
	children := make(map[string]kernfs.Inode)
	addAggregate := func(name, val string) {
		if val == "" {
			return
		}
		children[name] = fs.newStaticFile(ctx, creds, defaultSysMode, ensureNewline(val))
	}
	addAggregate("online", data.Online)
	addAggregate("possible", data.Possible)
	addAggregate("has_cpu", data.HasCPU)
	addAggregate("has_memory", data.HasMemory)
	addAggregate("has_normal_memory", data.HasNormalMemory)

	for _, n := range data.Nodes {
		nodeChildren := make(map[string]kernfs.Inode)
		if n.CPUMap != "" {
			nodeChildren["cpumap"] = fs.newStaticFile(ctx, creds, defaultSysMode, ensureNewline(n.CPUMap))
		}
		if n.CPUList != "" {
			nodeChildren["cpulist"] = fs.newStaticFile(ctx, creds, defaultSysMode, ensureNewline(n.CPUList))
		}
		if n.Distance != "" {
			nodeChildren["distance"] = fs.newStaticFile(ctx, creds, defaultSysMode, ensureNewline(n.Distance))
		}
		children["node"+n.ID] = fs.newDir(ctx, creds, defaultSysDirMode, nodeChildren)
	}
	log.Infof("numa sysfs: created %d node entries", len(data.Nodes))
	return children
}

// ensureNewline appends a trailing newline if not already present, matching
// the kernel's sysfs convention.
func ensureNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
