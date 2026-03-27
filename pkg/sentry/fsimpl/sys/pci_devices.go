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
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// PCIDeviceAttr contains sysfs attributes for a single PCI device.
type PCIDeviceAttr struct {
	Address         string `json:"address"`
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
}

// PCIDevicesData holds all collected PCI device attributes.
type PCIDevicesData struct {
	Devices []PCIDeviceAttr `json:"devices"`
}

// pciClassRelevant returns true if the PCI class code is one that NCCL
// needs for topology discovery: GPUs, NICs, InfiniBand, PCI bridges,
// and NVSwitches.
func pciClassRelevant(class string) bool {
	// class is a hex string like "0x030200". We match on the top bytes.
	c := strings.TrimPrefix(class, "0x")
	if len(c) < 4 {
		return false
	}
	prefix := c[:4]
	switch {
	case prefix == "0302": // 3D controller (GPU)
		return true
	case prefix == "0300": // VGA controller (GPU)
		return true
	case prefix == "0200": // Ethernet controller (NIC)
		return true
	case prefix == "0c06": // InfiniBand controller
		return true
	case prefix == "0604": // PCI bridge
		return true
	case prefix == "0680": // NVSwitch (bridge device, NVIDIA)
		return true
	}
	return false
}

// CollectPCIDeviceData reads PCI device sysfs attributes for devices
// relevant to NCCL topology discovery: GPUs, NICs, PCI bridges, and
// NVSwitches. This must be called before pivot_root while the host
// sysfs is still accessible.
func CollectPCIDeviceData() *PCIDevicesData {
	pciPath := "/sys/bus/pci/devices"
	dents, err := os.ReadDir(pciPath)
	if err != nil {
		log.Infof("pci collect: %s not accessible: %v", pciPath, err)
		return nil
	}

	data := &PCIDevicesData{}
	for _, dent := range dents {
		devDir := path.Join(pciPath, dent.Name())
		class := readSysfsFile(path.Join(devDir, "class"))
		if class == "" || !pciClassRelevant(class) {
			continue
		}
		dev := PCIDeviceAttr{
			Address:         dent.Name(),
			Class:           class,
			Vendor:          readSysfsFile(path.Join(devDir, "vendor")),
			Device:          readSysfsFile(path.Join(devDir, "device")),
			SubsystemVendor: readSysfsFile(path.Join(devDir, "subsystem_vendor")),
			SubsystemDevice: readSysfsFile(path.Join(devDir, "subsystem_device")),
			NumaNode:        readSysfsFile(path.Join(devDir, "numa_node")),
			LocalCPUs:       readSysfsFile(path.Join(devDir, "local_cpus")),
			LocalCPUList:    readSysfsFile(path.Join(devDir, "local_cpulist")),
			MaxLinkSpeed:    readSysfsFile(path.Join(devDir, "max_link_speed")),
			MaxLinkWidth:    readSysfsFile(path.Join(devDir, "max_link_width")),
		}
		data.Devices = append(data.Devices, dev)
	}

	log.Infof("pci collect: collected %d device(s) from %d total PCI devices",
		len(data.Devices), len(dents))
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

// newPCIDevicesSysfsEntries creates /sys/bus/pci/devices/<addr>/ directories
// from pre-collected PCI device data. Each device directory contains static
// files for the attributes NCCL uses to build its topology graph.
func (fs *filesystem) newPCIDevicesSysfsEntries(ctx context.Context, creds *auth.Credentials, data *PCIDevicesData) map[string]kernfs.Inode {
	if data == nil || len(data.Devices) == 0 {
		return nil
	}
	log.Infof("pci sysfs: building virtual sysfs for %d device(s)", len(data.Devices))

	pciDevices := make(map[string]kernfs.Inode)
	addFile := func(m map[string]kernfs.Inode, name, val string) {
		if val != "" {
			m[name] = fs.newStaticFile(ctx, creds, defaultSysMode, val+"\n")
		}
	}

	for _, dev := range data.Devices {
		entries := make(map[string]kernfs.Inode)
		addFile(entries, "class", dev.Class)
		addFile(entries, "vendor", dev.Vendor)
		addFile(entries, "device", dev.Device)
		addFile(entries, "subsystem_vendor", dev.SubsystemVendor)
		addFile(entries, "subsystem_device", dev.SubsystemDevice)
		addFile(entries, "numa_node", dev.NumaNode)
		addFile(entries, "local_cpus", dev.LocalCPUs)
		addFile(entries, "local_cpulist", dev.LocalCPUList)
		addFile(entries, "max_link_speed", dev.MaxLinkSpeed)
		addFile(entries, "max_link_width", dev.MaxLinkWidth)
		devDir := fs.newDir(ctx, creds, defaultSysDirMode, entries)
		pciDevices[dev.Address] = devDir
		// CUDA reports PCI bus IDs with uppercase hex (e.g., 0000:0F:00.0)
		// while Linux sysfs uses lowercase (0000:0f:00.0). Register both
		// so NCCL can find the device regardless of case.
		upper := strings.ToUpper(dev.Address)
		if upper != dev.Address {
			pciDevices[upper] = devDir
		}
	}
	return pciDevices
}
