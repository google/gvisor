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
	"path/filepath"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// RDMAGIDEntry contains a single GID table entry and its RoCE type.
type RDMAGIDEntry struct {
	Index  string `json:"index"`
	GID    string `json:"gid"`
	Type   string `json:"type"`
	NetDev string `json:"net_dev,omitempty"`
}

// RDMAPortData contains sysfs attributes for one port.
type RDMAPortData struct {
	Number    string         `json:"number"`
	State     string         `json:"state"`
	PhysState string         `json:"phys_state"`
	LinkLayer string         `json:"link_layer"`
	Rate      string         `json:"rate"`
	LID       string         `json:"lid"`
	SMLID     string         `json:"sm_lid"`
	SMSL      string         `json:"sm_sl"`
	CapMask   string         `json:"cap_mask"`
	GIDs      []RDMAGIDEntry `json:"gids,omitempty"`
}

// RDMADeviceData contains sysfs data for a single RDMA uverbs device.
type RDMADeviceData struct {
	Name       string         `json:"name"`
	IBDev      string         `json:"ibdev"`
	ABIVersion string         `json:"abi_version"`
	Dev        string         `json:"dev"`
	NodeType   string         `json:"node_type"`
	NodeGUID   string         `json:"node_guid"`
	SysImgGUID string         `json:"sys_image_guid"`
	FWVer      string         `json:"fw_ver"`
	Modalias   string         `json:"modalias"`
	Ports      []RDMAPortData `json:"ports"`

	// PCI device attributes from /sys/class/infiniband/<ibdev>/device/.
	// NCCL reads these (especially PCI_SLOT_NAME from uevent) to match
	// NIC PCI bus IDs against GPU bus IDs in the topology XML.
	PCISlotName     string `json:"pci_slot_name,omitempty"`
	PCIDriver       string `json:"pci_driver,omitempty"`
	PCIClass        string `json:"pci_class,omitempty"`
	PCIVendor       string `json:"pci_vendor,omitempty"`
	PCIDevice       string `json:"pci_device,omitempty"`
	PCISubsysVendor string `json:"pci_subsys_vendor,omitempty"`
	PCISubsysDevice string `json:"pci_subsys_device,omitempty"`
	NUMANode        string `json:"numa_node,omitempty"`
	LocalCPUList    string `json:"local_cpulist,omitempty"`

	// DynMajor is the sentry-assigned dynamic major for this device.
	// Set at runtime during device registration, not serialized.
	DynMajor uint32 `json:"-"`
}

// RDMANetDeviceData contains the minimal sysfs attributes NCCL/libibverbs read
// from /sys/class/net/<name>/ when selecting and characterizing NICs.
type RDMANetDeviceData struct {
	Name       string `json:"name"`
	Type       string `json:"type,omitempty"`
	Address    string `json:"address,omitempty"`
	MTU        string `json:"mtu,omitempty"`
	DevID      string `json:"dev_id,omitempty"`
	DevPort    string `json:"dev_port,omitempty"`
	Speed      string `json:"speed,omitempty"`
	Duplex     string `json:"duplex,omitempty"`
	OperState  string `json:"operstate,omitempty"`
	DevicePath string `json:"device_path,omitempty"`
}

// RDMAData holds all collected RDMA sysfs data.
type RDMAData struct {
	VerbsABIVersion string              `json:"verbs_abi_version"`
	PeerMemVersion  string              `json:"peer_mem_version,omitempty"`
	Devices         []RDMADeviceData    `json:"devices"`
	NetDevices      []RDMANetDeviceData `json:"net_devices,omitempty"`
}

// CollectRDMADeviceData reads the specific sysfs files that libibverbs
// needs for device discovery. Only well-known paths are read — no
// recursive traversal, no symlink following into PCI device trees.
func CollectRDMADeviceData() *RDMAData {
	verbsPath := "/sys/class/infiniband_verbs"
	dents, err := os.ReadDir(verbsPath)
	if err != nil {
		log.Infof("rdma collect: %s not accessible: %v", verbsPath, err)
		return nil
	}
	data := &RDMAData{
		VerbsABIVersion: readSysfsFile(path.Join(verbsPath, "abi_version")),
	}

	peerMemPaths := []string{
		"/sys/module/nvidia_peermem/version",
		"/sys/kernel/mm/memory_peers/nv_mem/version",
		"/sys/kernel/mm/memory_peers/nv_mem_nc/version",
	}
	for _, p := range peerMemPaths {
		if v := readSysfsFile(p); v != "" {
			data.PeerMemVersion = v
			log.Infof("rdma collect: nvidia_peermem version=%q (from %s)", v, p)
			break
		}
	}

	netDevices := make(map[string]struct{})
	log.Infof("rdma collect: scanning %s (%d entries), verbs_abi=%q",
		verbsPath, len(dents), data.VerbsABIVersion)
	for _, dent := range dents {
		if !strings.HasPrefix(dent.Name(), "uverbs") {
			continue
		}
		devDir := path.Join(verbsPath, dent.Name())
		ibdev := readSysfsFile(path.Join(devDir, "ibdev"))
		if ibdev == "" {
			log.Warningf("rdma collect: %s has no ibdev, skipping", dent.Name())
			continue
		}
		ibDir := path.Join("/sys/class/infiniband", ibdev)
		deviceDir := path.Join(ibDir, "device")
		dev := RDMADeviceData{
			Name:            dent.Name(),
			IBDev:           ibdev,
			ABIVersion:      readSysfsFile(path.Join(devDir, "abi_version")),
			Dev:             readSysfsFile(path.Join(devDir, "dev")),
			NodeType:        readSysfsFile(path.Join(ibDir, "node_type")),
			NodeGUID:        readSysfsFile(path.Join(ibDir, "node_guid")),
			SysImgGUID:      readSysfsFile(path.Join(ibDir, "sys_image_guid")),
			FWVer:           readSysfsFile(path.Join(ibDir, "fw_ver")),
			Modalias:        readSysfsFile(path.Join(deviceDir, "modalias")),
			PCISlotName:     parseUeventValue(path.Join(deviceDir, "uevent"), "PCI_SLOT_NAME"),
			PCIDriver:       parseUeventValue(path.Join(deviceDir, "uevent"), "DRIVER"),
			PCIClass:        readSysfsFile(path.Join(deviceDir, "class")),
			PCIVendor:       readSysfsFile(path.Join(deviceDir, "vendor")),
			PCIDevice:       readSysfsFile(path.Join(deviceDir, "device")),
			PCISubsysVendor: readSysfsFile(path.Join(deviceDir, "subsystem_vendor")),
			PCISubsysDevice: readSysfsFile(path.Join(deviceDir, "subsystem_device")),
			NUMANode:        readSysfsFile(path.Join(deviceDir, "numa_node")),
			LocalCPUList:    readSysfsFile(path.Join(deviceDir, "local_cpulist")),
		}
		log.Infof("rdma collect: %s → ibdev=%s dev=%s node_type=%q fw_ver=%q pci=%s numa=%s",
			dent.Name(), ibdev, dev.Dev, dev.NodeType, dev.FWVer, dev.PCISlotName, dev.NUMANode)
		portsPath := path.Join(ibDir, "ports")
		portDents, err := os.ReadDir(portsPath)
		if err == nil {
			for _, portDent := range portDents {
				portDir := path.Join(portsPath, portDent.Name())
				pd := RDMAPortData{
					Number:    portDent.Name(),
					State:     readSysfsFile(path.Join(portDir, "state")),
					PhysState: readSysfsFile(path.Join(portDir, "phys_state")),
					LinkLayer: readSysfsFile(path.Join(portDir, "link_layer")),
					Rate:      readSysfsFile(path.Join(portDir, "rate")),
					LID:       readSysfsFile(path.Join(portDir, "lid")),
					SMLID:     readSysfsFile(path.Join(portDir, "sm_lid")),
					SMSL:      readSysfsFile(path.Join(portDir, "sm_sl")),
					CapMask:   readSysfsFile(path.Join(portDir, "cap_mask")),
				}
				gidsPath := path.Join(portDir, "gids")
				typesPath := path.Join(portDir, "gid_attrs", "types")
				ndevsPath := path.Join(portDir, "gid_attrs", "ndevs")
				gidDents, gerr := os.ReadDir(gidsPath)
				if gerr == nil {
					for _, gidDent := range gidDents {
						gidVal := readSysfsFile(path.Join(gidsPath, gidDent.Name()))
						typeVal := readSysfsFile(path.Join(typesPath, gidDent.Name()))
						ndevVal := readSysfsFile(path.Join(ndevsPath, gidDent.Name()))
						if gidVal == "" {
							continue
						}
						if typeVal == "" && pd.LinkLayer == "Ethernet" {
							typeVal = inferRoCEType(gidDent.Name())
						}
						pd.GIDs = append(pd.GIDs, RDMAGIDEntry{
							Index:  gidDent.Name(),
							GID:    gidVal,
							Type:   typeVal,
							NetDev: ndevVal,
						})
						if ndevVal != "" {
							netDevices[ndevVal] = struct{}{}
						}
					}
				}
				log.Infof("rdma collect:   port %s: state=%q link_layer=%q rate=%q gids=%d",
					pd.Number, pd.State, pd.LinkLayer, pd.Rate, len(pd.GIDs))
				dev.Ports = append(dev.Ports, pd)
			}
		}
		data.Devices = append(data.Devices, dev)
	}
	data.NetDevices = collectRDMANetDevices(netDevices)
	log.Infof("rdma collect: collected %d device(s)", len(data.Devices))
	return data
}

func collectRDMANetDevices(names map[string]struct{}) []RDMANetDeviceData {
	if len(names) == 0 {
		return nil
	}
	var netDevices []RDMANetDeviceData
	for name := range names {
		netDir := path.Join("/sys/class/net", name)
		devicePath, err := filepath.EvalSymlinks(path.Join(netDir, "device"))
		if err != nil {
			devicePath = ""
		}
		netDevices = append(netDevices, RDMANetDeviceData{
			Name:       name,
			Type:       readSysfsFile(path.Join(netDir, "type")),
			Address:    readSysfsFile(path.Join(netDir, "address")),
			MTU:        readSysfsFile(path.Join(netDir, "mtu")),
			DevID:      readSysfsFile(path.Join(netDir, "dev_id")),
			DevPort:    readSysfsFile(path.Join(netDir, "dev_port")),
			Speed:      readSysfsFile(path.Join(netDir, "speed")),
			Duplex:     readSysfsFile(path.Join(netDir, "duplex")),
			OperState:  readSysfsFile(path.Join(netDir, "operstate")),
			DevicePath: devicePath,
		})
	}
	return netDevices
}

// RDMADataPath is the path within the chroot where serialized RDMA data
// is stored between boot stages.
const RDMADataPath = "/var/lib/gvisor/rdma_data.json"

// SerializeRDMAData writes the collected data as JSON to the given path.
func SerializeRDMAData(data *RDMAData, filePath string) error {
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

// DeserializeRDMAData reads serialized RDMA data from the given path.
func DeserializeRDMAData(filePath string) *RDMAData {
	b, err := os.ReadFile(filePath)
	if err != nil {
		log.Infof("rdma deserialize: %s: %v", filePath, err)
		return nil
	}
	var data RDMAData
	if err := json.Unmarshal(b, &data); err != nil {
		log.Warningf("rdma deserialize: unmarshal %s: %v", filePath, err)
		return nil
	}
	log.Infof("rdma deserialize: loaded %d device(s) from %s (verbs_abi=%q)",
		len(data.Devices), filePath, data.VerbsABIVersion)
	for _, d := range data.Devices {
		log.Infof("rdma deserialize:   %s ibdev=%s dev=%s ports=%d",
			d.Name, d.IBDev, d.Dev, len(d.Ports))
		for _, p := range d.Ports {
			typesWithValues := 0
			for _, g := range p.GIDs {
				if g.Type != "" {
					typesWithValues++
				}
			}
			log.Infof("rdma deserialize:   %s port %s: %d gids, %d with types",
				d.IBDev, p.Number, len(p.GIDs), typesWithValues)
		}
	}
	return &data
}

// extractMinor returns the minor portion from a "major:minor" dev string.
func extractMinor(dev string) string {
	if idx := strings.IndexByte(dev, ':'); idx >= 0 {
		return dev[idx+1:]
	}
	return "0"
}

// ExtractMinorUint32 parses the minor portion from a sysfs "major:minor" dev
// string (e.g. "231:192") and returns it as a uint32. Returns (0, false) if
// the string is malformed.
func ExtractMinorUint32(dev string) (uint32, bool) {
	idx := strings.IndexByte(dev, ':')
	if idx < 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(dev[idx+1:], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// inferRoCEType returns the RoCE GID type based on GID table index.
// The sandbox's restricted sysfs mount masks gid_attrs/types/ content,
// so we infer from the well-known mlx5 kernel assignment:
//   - index 0: RoCE v1 (link-local MAC-derived)
//   - index 1+: RoCE v2
//
// NCCL reads types from sysfs but gets actual GID addresses via ioctl.
func inferRoCEType(gidIndex string) string {
	if gidIndex == "0" {
		return "IB/RoCE v1"
	}
	return "RoCE v2"
}

// parseUeventValue reads a uevent file and extracts the value for the given
// KEY (matched as "KEY="). Returns empty string if the file doesn't exist or
// has no matching line.
func parseUeventValue(ueventPath, key string) string {
	data, err := os.ReadFile(ueventPath)
	if err != nil {
		return ""
	}
	prefix := key + "="
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

func readSysfsFile(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// newRDMASysfsEntries creates /sys/class/infiniband_verbs/ and
// /sys/class/infiniband/ directories from pre-collected device data.
func (fs *filesystem) newRDMASysfsEntries(ctx context.Context, creds *auth.Credentials, data *RDMAData, pciSlotToRelPath map[string]string) (ibVerbsDir, ibDir map[string]kernfs.Inode) {
	if data == nil || len(data.Devices) == 0 {
		log.Infof("rdma sysfs: no RDMA data, skipping sysfs construction")
		return nil, nil
	}
	log.Infof("rdma sysfs: building virtual sysfs for %d device(s), verbs_abi=%q",
		len(data.Devices), data.VerbsABIVersion)
	ibVerbsDir = map[string]kernfs.Inode{}
	ibDir = map[string]kernfs.Inode{}
	addFile := func(m map[string]kernfs.Inode, name, val string) {
		if val != "" {
			m[name] = fs.newStaticFile(ctx, creds, defaultSysMode, val+"\n")
		}
	}
	addFile(ibVerbsDir, "abi_version", data.VerbsABIVersion)

	for _, dev := range data.Devices {
		verbsEntries := map[string]kernfs.Inode{}
		addFile(verbsEntries, "ibdev", dev.IBDev)
		addFile(verbsEntries, "abi_version", dev.ABIVersion)
		devVal := dev.Dev
		if dev.DynMajor != 0 {
			minor := extractMinor(dev.Dev)
			devVal = fmt.Sprintf("%d:%s", dev.DynMajor, minor)
			log.Infof("rdma sysfs: %s dev=%s (patched from host %s, dynMajor=%d)",
				dev.Name, devVal, dev.Dev, dev.DynMajor)
		} else {
			log.Infof("rdma sysfs: %s dev=%s (no dynMajor, using host value)", dev.Name, devVal)
		}
		addFile(verbsEntries, "dev", devVal)
		ibVerbsDir[dev.Name] = fs.newDir(ctx, creds, defaultSysDirMode, verbsEntries)

		if dev.IBDev == "" {
			continue
		}
		log.Infof("rdma sysfs: %s → ibdev=%s node_type=%q fw_ver=%q guid=%s ports=%d",
			dev.Name, dev.IBDev, dev.NodeType, dev.FWVer, dev.NodeGUID, len(dev.Ports))
		ibDevEntries := map[string]kernfs.Inode{}
		addFile(ibDevEntries, "node_type", dev.NodeType)
		addFile(ibDevEntries, "node_guid", dev.NodeGUID)
		addFile(ibDevEntries, "sys_image_guid", dev.SysImgGUID)
		addFile(ibDevEntries, "fw_ver", dev.FWVer)
		// Create the device/ entry. On real Linux this is a symlink from
		// /sys/class/infiniband/<ibdev>/device → /sys/devices/pci0000:XX/...
		// NCCL calls realpath() on this to find the PCI device path and
		// place NICs in the PCI topology tree for distance computation.
		// Without a proper symlink, NCCL falls back to "attach to first
		// CPU" and graph search fails with "Could not find NET with id N".
		if dev.PCISlotName != "" {
			if relPath, ok := pciSlotToRelPath[strings.ToLower(dev.PCISlotName)]; ok {
				// /sys/class/infiniband/<ibdev>/ is 3 levels deep from /sys/
				target := "../../../" + relPath
				ibDevEntries["device"] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), target)
				log.Infof("rdma sysfs: %s device → %s (symlink to PCI tree)", dev.IBDev, target)
			} else {
				log.Warningf("rdma sysfs: %s PCI_SLOT_NAME=%s has no matching PCI device; creating device/ as directory (degraded topology)", dev.IBDev, dev.PCISlotName)
				deviceEntries := map[string]kernfs.Inode{}
				addFile(deviceEntries, "modalias", dev.Modalias)
				addFile(deviceEntries, "class", dev.PCIClass)
				addFile(deviceEntries, "vendor", dev.PCIVendor)
				addFile(deviceEntries, "device", dev.PCIDevice)
				addFile(deviceEntries, "subsystem_vendor", dev.PCISubsysVendor)
				addFile(deviceEntries, "subsystem_device", dev.PCISubsysDevice)
				addFile(deviceEntries, "numa_node", dev.NUMANode)
				addFile(deviceEntries, "local_cpulist", dev.LocalCPUList)
				ibDevEntries["device"] = fs.newDir(ctx, creds, defaultSysDirMode, deviceEntries)
			}
		}
		if len(dev.Ports) > 0 {
			portsDir := map[string]kernfs.Inode{}
			for _, port := range dev.Ports {
				log.Infof("rdma sysfs:   port %s: state=%q link_layer=%q rate=%q",
					port.Number, port.State, port.LinkLayer, port.Rate)
				portEntries := map[string]kernfs.Inode{}
				addFile(portEntries, "state", port.State)
				addFile(portEntries, "phys_state", port.PhysState)
				addFile(portEntries, "link_layer", port.LinkLayer)
				addFile(portEntries, "rate", port.Rate)
				addFile(portEntries, "lid", port.LID)
				addFile(portEntries, "sm_lid", port.SMLID)
				addFile(portEntries, "sm_sl", port.SMSL)
				addFile(portEntries, "cap_mask", port.CapMask)
				if len(port.GIDs) > 0 {
					gidsEntries := map[string]kernfs.Inode{}
					typesEntries := map[string]kernfs.Inode{}
					ndevsEntries := map[string]kernfs.Inode{}
					for _, gid := range port.GIDs {
						addFile(gidsEntries, gid.Index, gid.GID)
						addFile(typesEntries, gid.Index, gid.Type)
						addFile(ndevsEntries, gid.Index, gid.NetDev)
					}
					log.Infof("rdma sysfs:   port %s: %d gids, gidsEntries=%d typesEntries=%d ndevsEntries=%d",
						port.Number, len(port.GIDs), len(gidsEntries), len(typesEntries), len(ndevsEntries))
					gidAttrsEntries := map[string]kernfs.Inode{
						"types": fs.newDir(ctx, creds, defaultSysDirMode, typesEntries),
					}
					if len(ndevsEntries) > 0 {
						gidAttrsEntries["ndevs"] = fs.newDir(ctx, creds, defaultSysDirMode, ndevsEntries)
					}
					portEntries["gids"] = fs.newDir(ctx, creds, defaultSysDirMode, gidsEntries)
					portEntries["gid_attrs"] = fs.newDir(ctx, creds, defaultSysDirMode, gidAttrsEntries)
				}
				portsDir[port.Number] = fs.newDir(ctx, creds, defaultSysDirMode, portEntries)
			}
			ibDevEntries["ports"] = fs.newDir(ctx, creds, defaultSysDirMode, portsDir)
		}
		ibDir[dev.IBDev] = fs.newDir(ctx, creds, defaultSysDirMode, ibDevEntries)
	}
	return ibVerbsDir, ibDir
}

func (fs *filesystem) newRDMANetClassEntries(ctx context.Context, creds *auth.Credentials, data *RDMAData) map[string]kernfs.Inode {
	if data == nil || len(data.NetDevices) == 0 {
		return nil
	}
	netDir := make(map[string]kernfs.Inode)
	addFile := func(m map[string]kernfs.Inode, name, val string) {
		if val != "" {
			m[name] = fs.newStaticFile(ctx, creds, defaultSysMode, val+"\n")
		}
	}
	for _, dev := range data.NetDevices {
		entries := make(map[string]kernfs.Inode)
		addFile(entries, "type", dev.Type)
		addFile(entries, "address", dev.Address)
		addFile(entries, "mtu", dev.MTU)
		addFile(entries, "dev_id", dev.DevID)
		addFile(entries, "dev_port", dev.DevPort)
		addFile(entries, "speed", dev.Speed)
		addFile(entries, "duplex", dev.Duplex)
		addFile(entries, "operstate", dev.OperState)
		if strings.HasPrefix(dev.DevicePath, "/sys/") {
			// /sys/class/net/<iface>/device is resolved relative to
			// /sys/class/net/<iface>, so we need three ".." components to
			// reach /sys before descending into devices/.
			target := "../../../" + strings.TrimPrefix(dev.DevicePath, "/sys/")
			entries["device"] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), target)
		}
		netDir[dev.Name] = fs.newDir(ctx, creds, defaultSysDirMode, entries)
	}
	log.Infof("rdma sysfs: built virtual /sys/class/net entries for %d device(s)", len(netDir))
	return netDir
}
