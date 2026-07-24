// Copyright 2026 The gVisor Authors.
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

// Package rdma hosts RDMA configuration and utilities shared between the
// sentry and runsc.
package rdma

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Path is the location inside the sandbox chroot where the serialized
// snapshot is stored. Needed to communicate this information across the boot
// process re-exec boundary.
const Path = "/var/lib/gvisor/rdma_sysfs.json"

// PCINode is one directory in the /sys/devices/pci... hierarchy (a root
// complex, bridge, or leaf function) with its static attribute files.
type PCINode struct {
	// Path is relative to /sys, e.g.
	// "devices/pci0000:07/0000:07:01.0/0000:0c:00.0".
	Path string `json:"path"`
	// Attrs maps attribute file name to contents (verbatim, including any
	// trailing newline).
	Attrs map[string]string `json:"attrs"`
}

// Port is the per-IB-port state. Attributes split into static (immutable
// for the sandbox lifetime, snapshotted) and live (served by reading the
// host file at access time through a bind mount; the RoCE GID table
// changes when netdevs move between namespaces and acquire addresses).
type Port struct {
	StaticAttrs map[string]string `json:"static_attrs"`
	LiveAttrs   []string          `json:"live_attrs"`
	// GIDNames are the entry names of the GID table (typically "0".."255").
	// The same names index gids/<n>, gid_attrs/types/<n> and
	// gid_attrs/ndevs/<n>, all served live.
	GIDNames       []string `json:"gid_names"`
	CounterNames   []string `json:"counter_names"`
	HWCounterNames []string `json:"hw_counter_names"`
}

// NetDev is a network device associated with an RDMA device, with its
// curated static attribute set.
type NetDev struct {
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs"`
}

// Device is one uverbs device and everything hanging off it.
type Device struct {
	// Uverbs is the device name, e.g. "uverbs0".
	Uverbs string `json:"uverbs"`
	// IBDev is the InfiniBand device name, e.g. "mlx5_0".
	IBDev string `json:"ibdev"`
	// LeafPCI is the PCI function directory, relative to /sys.
	LeafPCI string `json:"leaf_pci"`
	// Dev is the host "major:minor" of the uverbs char device.
	Dev        string `json:"dev"`
	ABIVersion string `json:"abi_version"`
	// IBAttrs are the static identity attributes of
	// /sys/class/infiniband/<ibdev>/ (node_guid, fw_ver, ...).
	IBAttrs map[string]string `json:"ib_attrs"`
	// Ports maps port number ("1") to its state.
	Ports map[string]Port `json:"ports"`
	// NetDevs are the netdevs bound to this ibdev via device/net/.
	NetDevs []NetDev `json:"netdevs"`
}

// NUMA is the /sys/devices/system/node subtree.
type NUMA struct {
	// Aggregate holds the top-level range files (online, possible, ...).
	Aggregate map[string]string `json:"aggregate"`
	// Nodes maps node ID ("0") to its attribute files.
	Nodes map[string]map[string]string `json:"nodes"`
}

// Snapshot is the host sysfs snapshot for RDMA device topology.
type Snapshot struct {
	VerbsABIVersion string `json:"verbs_abi_version"`
	// PCINodes contains every PCI directory in the closure: the leaves
	// (NICs, GPUs) and all their ancestor bridges/roots. Sorted by Path,
	// which places parents before children.
	PCINodes []PCINode `json:"pci_nodes"`
	Devices  []Device  `json:"devices"`
	NUMA     *NUMA     `json:"numa,omitempty"`
}

// safeName matches names we are willing to reproduce inside the sandbox or
// join into host paths. Kernel-generated sysfs names satisfy this; anything
// else is dropped at collection time so the construction side never handles
// a name containing a path separator or dot-dot.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:+-]*$`)

// SafeName reports whether name may be used as a sysfs entry name.
func SafeName(name string) bool {
	return name != "." && name != ".." && safeName.MatchString(name)
}

// bdfRE matches a PCI function directory name ("0000:0c:00.0").
var bdfRE = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)

// pciRootRE matches a PCI root complex directory name ("pci0000:07").
var pciRootRE = regexp.MustCompile(`^pci[0-9a-f]{4}:[0-9a-f]{2}$`)

// IsBDF reports whether name is a PCI function directory name.
func IsBDF(name string) bool { return bdfRE.MatchString(name) }

// Save serializes the snapshot to dst, creating parent directories.
func (s *Snapshot) Save(dst string) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating %q: %w", dir, err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshaling RDMA sysfs snapshot: %w", err)
	}
	return os.WriteFile(dst, b, 0644)
}

// Load deserializes a snapshot from src. Returns (nil, nil) if the file
// does not exist.
func Load(src string) (*Snapshot, error) {
	b, err := os.ReadFile(src)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("unmarshaling RDMA sysfs snapshot %q: %w", src, err)
	}
	return &s, nil
}
