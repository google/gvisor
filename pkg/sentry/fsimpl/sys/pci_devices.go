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
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// PCIDeviceAttr contains sysfs attributes for a single PCI device,
// including its position in the /sys/devices/pci*/ hierarchy.
type PCIDeviceAttr struct {
	// Address is the PCI BDF address, e.g. "0000:0f:00.0".
	Address string `json:"address"`
	// RealPath is the resolved sysfs path, e.g.
	// "/sys/devices/pci0000:07/0000:07:01.0/.../0000:0f:00.0".
	// NCCL uses this hierarchy to compute PCI distances between devices.
	RealPath        string `json:"realpath"`
	Class           string `json:"class"`
	Vendor          string `json:"vendor"`
	Device          string `json:"device"`
	SubsystemVendor string `json:"subsystem_vendor"`
	SubsystemDevice string `json:"subsystem_device"`
	NumaNode        string `json:"numa_node"`
	LocalCPUs       string `json:"local_cpus"`
	LocalCPUList    string `json:"local_cpulist"`
	MaxLinkSpeed    string `json:"max_link_speed"`
	MaxLinkWidth    string `json:"max_link_width"`
	// NCCL prefers current_link_* over max_link_* and only falls back to
	// max when current is missing or "Unknown". Capturing both lets the
	// virtual sysfs report the negotiated link, matching what NCCL would
	// see on the host.
	CurrentLinkSpeed string `json:"current_link_speed"`
	CurrentLinkWidth string `json:"current_link_width"`
}

// PCIDevicesData holds all collected PCI device attributes.
type PCIDevicesData struct {
	Devices []PCIDeviceAttr `json:"devices"`
}

// pciClassRelevant returns true if the PCI class code is one that NCCL
// needs for topology discovery.
//
// This allowlist is curated for NVIDIA GPU + Mellanox/InfiniBand setups. It
// covers both InfiniBand controllers (class 0c06) and InfiniBand network
// controllers (class 0207, reported by e.g. Crusoe B200 RDMA NICs and AWS
// EFA). Other RDMA-capable adapters (Intel Gaudi class 1200, Broadcom
// bnxt_re, Chelsio iWARP, etc.) are not currently surfaced to the sandbox.
// Extend this switch when adding support for additional accelerator/NIC
// families.
func pciClassRelevant(class string) bool {
	c, err := strconv.ParseInt(strings.TrimSpace(class), 0, 0)
	if err != nil {
		return false
	}
	// The last byte of the class string is the programming interface byte, which is too restrictive
	// for our class matching control. We ignore it by truncating the last byte.
	switch c >> 8 {
	case 0x0302, 0x0300: // GPU (3D controller, VGA)
		return true
	case 0x0200: // Ethernet controller (NIC)
		return true
	case 0x0c06: // InfiniBand controller
		return true
	case 0x0207: // InfiniBand network controller (e.g. Crusoe B200 RDMA NICs report 0x020700)
		return true
	case 0x0604: // PCI bridge
		return true
	}
	return false
}

// collectDeviceAttrs reads sysfs attributes from the given directory path.
func collectDeviceAttrs(addr, realPath, devDir string) PCIDeviceAttr {
	return PCIDeviceAttr{
		Address:          addr,
		RealPath:         realPath,
		Class:            readSysfsFile(path.Join(devDir, "class")),
		Vendor:           readSysfsFile(path.Join(devDir, "vendor")),
		Device:           readSysfsFile(path.Join(devDir, "device")),
		SubsystemVendor:  readSysfsFile(path.Join(devDir, "subsystem_vendor")),
		SubsystemDevice:  readSysfsFile(path.Join(devDir, "subsystem_device")),
		NumaNode:         readSysfsFile(path.Join(devDir, "numa_node")),
		LocalCPUs:        readSysfsFile(path.Join(devDir, "local_cpus")),
		LocalCPUList:     readSysfsFile(path.Join(devDir, "local_cpulist")),
		MaxLinkSpeed:     readSysfsFile(path.Join(devDir, "max_link_speed")),
		MaxLinkWidth:     readSysfsFile(path.Join(devDir, "max_link_width")),
		CurrentLinkSpeed: readSysfsFile(path.Join(devDir, "current_link_speed")),
		CurrentLinkWidth: readSysfsFile(path.Join(devDir, "current_link_width")),
	}
}

// CollectPCIDeviceData reads PCI device sysfs attributes for devices
// relevant to NCCL topology discovery, including all ancestor bridge
// devices in the PCI hierarchy. This must be called before pivot_root
// while the host sysfs is still accessible.
func CollectPCIDeviceData() *PCIDevicesData {
	pciPath := "/sys/bus/pci/devices"
	dents, err := os.ReadDir(pciPath)
	if err != nil {
		log.Infof("pci collect: %s not accessible: %v", pciPath, err)
		return nil
	}

	// First pass: find relevant leaf devices and resolve their real paths.
	type leafDev struct {
		addr     string
		realPath string
	}
	var leaves []leafDev
	for _, dent := range dents {
		devDir := path.Join(pciPath, dent.Name())
		class := readSysfsFile(path.Join(devDir, "class"))
		if class == "" || !pciClassRelevant(class) {
			continue
		}
		realPath, err := filepath.EvalSymlinks(devDir)
		if err != nil {
			// NCCL needs the resolved /sys/devices/pci... hierarchy to
			// compute PCI distances. The flat bus path is not usable as a
			// substitute, so skip rather than collect a broken RealPath.
			log.Warningf("pci collect: EvalSymlinks(%s): %v; skipping", devDir, err)
			continue
		}
		leaves = append(leaves, leafDev{addr: dent.Name(), realPath: realPath})
	}

	// Second pass: collect all unique paths in the ancestor chains.
	// NCCL walks UP the /sys/devices/pci*/ hierarchy to compute PCI
	// distances, so we need every bridge in the chain.
	collected := make(map[string]bool)
	data := &PCIDevicesData{}
	for _, leaf := range leaves {
		p := leaf.realPath
		for p != "" && strings.Contains(p, "/pci") {
			if collected[p] {
				break
			}
			collected[p] = true
			addr := filepath.Base(p)
			dev := collectDeviceAttrs(addr, p, p)
			data.Devices = append(data.Devices, dev)
			p = filepath.Dir(p)
		}
	}

	// Sort by path for deterministic output.
	sort.Slice(data.Devices, func(i, j int) bool {
		return data.Devices[i].RealPath < data.Devices[j].RealPath
	})

	log.Infof("pci collect: collected %d device(s) in hierarchy from %d leaf devices",
		len(data.Devices), len(leaves))
	return data
}

// PCIDevicesDataPath is the path within the chroot where serialized PCI
// device data is stored between boot stages.
const PCIDevicesDataPath = "/var/lib/gvisor/pci_devices_data.json"

// SerializePCIDevicesData writes the collected data as JSON to the given path.
func SerializePCIDevicesData(data *PCIDevicesData, filePath string) error {
	if data == nil {
		return nil
	}
	if err := os.MkdirAll(path.Dir(filePath), 0755); err != nil {
		return err
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, b, 0644)
}

// DeserializePCIDevicesData reads serialized PCI device data from the given path.
func DeserializePCIDevicesData(filePath string) *PCIDevicesData {
	b, err := os.ReadFile(filePath)
	if err != nil {
		log.Infof("pci deserialize: %s: %v", filePath, err)
		return nil
	}
	var data PCIDevicesData
	if err := json.Unmarshal(b, &data); err != nil {
		log.Warningf("pci deserialize: unmarshal %s: %v", filePath, err)
		return nil
	}
	log.Infof("pci deserialize: loaded %d device(s) from %s", len(data.Devices), filePath)
	return &data
}

// newPCIDevicesSysfsEntries builds the virtual sysfs tree for PCI device
// topology. It creates:
//   - /sys/devices/pci<ROOT>/<BRIDGE>/.../<DEV>/ nested hierarchy with
//     class, vendor, device, numa_node, local_cpulist, etc. at each level
//   - /sys/devices/pci<ROOT>/.../<PARENT>/pci_bus/<BUS>/ directories so
//     NCCL's "../../<DEV>" path resolution works
//   - /sys/class/pci_bus/<BUS> symlinks into the devices hierarchy
//   - /sys/bus/pci/devices/<ADDR> symlinks into the devices hierarchy
//
// NCCL discovers topology by:
//  1. Constructing "/sys/class/pci_bus/<BUS>/../../<BUS:DEV.FN>"
//  2. Calling realpath() which resolves through the symlink
//  3. Walking UP the resolved path reading "class" to find bridges
//  4. Using the hierarchy depth to compute PCI distance between devices
func (fs *filesystem) newPCIDevicesSysfsEntries(ctx context.Context, creds *auth.Credentials, data *PCIDevicesData) (devicesSub, pciBusSub, busPCIDevicesSub map[string]kernfs.Inode, pciSlotToRelPath map[string]string) {
	if data == nil || len(data.Devices) == 0 {
		return nil, nil, nil, nil
	}

	log.Infof("pci sysfs: building virtual sysfs for %d device(s)", len(data.Devices))

	// Build a nested map representing the /sys/devices/ tree.
	// Key: path relative to /sys/ (e.g., "devices/pci0000:07/0000:07:01.0")
	// Value: map of child name -> inode
	type dirNode struct {
		children map[string]*dirNode
		files    map[string]string // attribute files
		symlinks map[string]string // child symlink name -> target
	}
	root := &dirNode{children: make(map[string]*dirNode), files: make(map[string]string), symlinks: make(map[string]string)}

	getOrCreate := func(pathFromSys string) *dirNode {
		parts := strings.Split(pathFromSys, "/")
		cur := root
		for _, part := range parts {
			if part == "" {
				continue
			}
			if cur.children[part] == nil {
				cur.children[part] = &dirNode{
					children: make(map[string]*dirNode),
					files:    make(map[string]string),
					symlinks: make(map[string]string),
				}
			}
			cur = cur.children[part]
		}
		return cur
	}

	// pciBusEntries: bus number -> relative symlink target from /sys/class/pci_bus/<bus>
	pciBusSymlinks := make(map[string]string)
	// busPCIDevicesSymlinks: addr -> relative symlink target from /sys/bus/pci/devices/<addr>
	busPCIDevicesSymlinks := make(map[string]string)
	pciAddrToRelPath := make(map[string]string)

	for _, dev := range data.Devices {

		// dev.RealPath is e.g. "/sys/devices/pci0000:07/0000:07:01.0/0000:0f:00.0"
		// Convert to relative path from /sys/
		relPath := strings.TrimPrefix(dev.RealPath, "/sys/")
		if relPath == dev.RealPath {
			continue // not under /sys
		}
		pciAddrToRelPath[strings.ToLower(dev.Address)] = relPath
		node := getOrCreate(relPath)
		node.files["class"] = dev.Class
		node.files["vendor"] = dev.Vendor
		node.files["device"] = dev.Device
		node.files["subsystem_vendor"] = dev.SubsystemVendor
		node.files["subsystem_device"] = dev.SubsystemDevice
		node.files["numa_node"] = dev.NumaNode
		node.files["local_cpus"] = dev.LocalCPUs
		node.files["local_cpulist"] = dev.LocalCPUList
		node.files["max_link_speed"] = dev.MaxLinkSpeed
		node.files["max_link_width"] = dev.MaxLinkWidth
		node.files["current_link_speed"] = dev.CurrentLinkSpeed
		node.files["current_link_width"] = dev.CurrentLinkWidth

		// Create pci_bus entry for this device's secondary bus.
		// The bus number is the first two hex groups of the address (domain:bus).
		// E.g., for device "0000:0f:00.0", bus is "0000:0f".
		addr := dev.Address
		if len(addr) >= 7 && strings.Count(addr, ":") >= 2 {
			bus := addr[:7] // "0000:0f"
			// pci_bus/<bus> lives inside the PARENT device directory.
			parentRelPath := filepath.Dir(relPath)
			if parentRelPath != "." && parentRelPath != relPath {
				// Create pci_bus/<bus> subdir in parent
				pciBusNode := getOrCreate(parentRelPath + "/pci_bus/" + bus)
				_ = pciBusNode // just ensure it exists

				// Symlink: /sys/class/pci_bus/<bus> -> ../../devices/pci.../pci_bus/<bus>
				pciBusSymlinks[bus] = "../../" + parentRelPath + "/pci_bus/" + bus
			}

			// Symlink: /sys/bus/pci/devices/<addr> -> ../../../devices/pci.../<addr>
			busPCIDevicesSymlinks[addr] = "../../../" + relPath
		}
	}

	// Convert the tree to kernfs inodes.
	var buildDir func(node *dirNode) map[string]kernfs.Inode
	buildDir = func(node *dirNode) map[string]kernfs.Inode {
		entries := make(map[string]kernfs.Inode)
		for name, val := range node.files {
			if val != "" {
				entries[name] = fs.newStaticFile(ctx, creds, defaultSysMode, val+"\n")
			}
		}
		for name, target := range node.symlinks {
			entries[name] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), target)
		}
		for name, child := range node.children {
			entries[name] = fs.newDir(ctx, creds, defaultSysDirMode, buildDir(child))
		}
		return entries
	}

	// Build /sys/devices/ subtree (pci0000:XX roots)
	devicesSub = make(map[string]kernfs.Inode)
	for name, child := range root.children {
		if name == "devices" {
			for devName, devChild := range child.children {
				devicesSub[devName] = fs.newDir(ctx, creds, defaultSysDirMode, buildDir(devChild))
			}
		}
	}

	// Build /sys/class/pci_bus/ entries as symlinks
	pciBusSub = make(map[string]kernfs.Inode)
	for bus, target := range pciBusSymlinks {
		pciBusSub[bus] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), target)
	}

	// Build /sys/bus/pci/devices/ entries as symlinks
	busPCIDevicesSub = make(map[string]kernfs.Inode)
	for addr, target := range busPCIDevicesSymlinks {
		busPCIDevicesSub[addr] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), target)
	}

	log.Infof("pci sysfs: created %d device tree entries, %d pci_bus symlinks, %d bus/pci/devices symlinks",
		len(devicesSub), len(pciBusSub), len(busPCIDevicesSub))
	return devicesSub, pciBusSub, busPCIDevicesSub, pciAddrToRelPath
}
