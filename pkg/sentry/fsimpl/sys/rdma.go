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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// RDMAPortData contains sysfs attributes for one port.
type RDMAPortData struct {
	Number    string `json:"number"`
	State     string `json:"state"`
	PhysState string `json:"phys_state"`
	LinkLayer string `json:"link_layer"`
	Rate      string `json:"rate"`
	LID       string `json:"lid"`
	SMLID     string `json:"sm_lid"`
	SMSL      string `json:"sm_sl"`
	CapMask   string `json:"cap_mask"`
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
}

// RDMAData holds all collected RDMA sysfs data.
type RDMAData struct {
	VerbsABIVersion string           `json:"verbs_abi_version"`
	Devices         []RDMADeviceData `json:"devices"`
}

// CollectRDMADeviceData reads the specific sysfs files that libibverbs
// needs for device discovery. Only well-known paths are read — no
// recursive traversal, no symlink following into PCI device trees.
func CollectRDMADeviceData() *RDMAData {
	verbsPath := "/sys/class/infiniband_verbs"
	dents, err := os.ReadDir(verbsPath)
	if err != nil {
		return nil
	}
	data := &RDMAData{
		VerbsABIVersion: readSysfsFile(path.Join(verbsPath, "abi_version")),
	}
	for _, dent := range dents {
		if !strings.HasPrefix(dent.Name(), "uverbs") {
			continue
		}
		devDir := path.Join(verbsPath, dent.Name())
		ibdev := readSysfsFile(path.Join(devDir, "ibdev"))
		if ibdev == "" {
			continue
		}
		ibDir := path.Join("/sys/class/infiniband", ibdev)
		dev := RDMADeviceData{
			Name:       dent.Name(),
			IBDev:      ibdev,
			ABIVersion: readSysfsFile(path.Join(devDir, "abi_version")),
			Dev:        readSysfsFile(path.Join(devDir, "dev")),
			NodeType:   readSysfsFile(path.Join(ibDir, "node_type")),
			NodeGUID:   readSysfsFile(path.Join(ibDir, "node_guid")),
			SysImgGUID: readSysfsFile(path.Join(ibDir, "sys_image_guid")),
			FWVer:      readSysfsFile(path.Join(ibDir, "fw_ver")),
			Modalias:   readSysfsFile(path.Join(ibDir, "device", "modalias")),
		}
		portsPath := path.Join(ibDir, "ports")
		portDents, err := os.ReadDir(portsPath)
		if err == nil {
			for _, portDent := range portDents {
				portDir := path.Join(portsPath, portDent.Name())
				dev.Ports = append(dev.Ports, RDMAPortData{
					Number:    portDent.Name(),
					State:     readSysfsFile(path.Join(portDir, "state")),
					PhysState: readSysfsFile(path.Join(portDir, "phys_state")),
					LinkLayer: readSysfsFile(path.Join(portDir, "link_layer")),
					Rate:      readSysfsFile(path.Join(portDir, "rate")),
					LID:       readSysfsFile(path.Join(portDir, "lid")),
					SMLID:     readSysfsFile(path.Join(portDir, "sm_lid")),
					SMSL:      readSysfsFile(path.Join(portDir, "sm_sl")),
					CapMask:   readSysfsFile(path.Join(portDir, "cap_mask")),
				})
			}
		}
		data.Devices = append(data.Devices, dev)
	}
	return data
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
		return nil
	}
	var data RDMAData
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}
	return &data
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
func (fs *filesystem) newRDMASysfsEntries(ctx context.Context, creds *auth.Credentials, data *RDMAData) (ibVerbsDir, ibDir map[string]kernfs.Inode) {
	if data == nil || len(data.Devices) == 0 {
		return nil, nil
	}
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
		addFile(verbsEntries, "dev", dev.Dev)
		ibVerbsDir[dev.Name] = fs.newDir(ctx, creds, defaultSysDirMode, verbsEntries)

		if dev.IBDev == "" {
			continue
		}
		ibDevEntries := map[string]kernfs.Inode{}
		addFile(ibDevEntries, "node_type", dev.NodeType)
		addFile(ibDevEntries, "node_guid", dev.NodeGUID)
		addFile(ibDevEntries, "sys_image_guid", dev.SysImgGUID)
		addFile(ibDevEntries, "fw_ver", dev.FWVer)
		if dev.Modalias != "" {
			ibDevEntries["device"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
				"modalias": fs.newStaticFile(ctx, creds, defaultSysMode, dev.Modalias+"\n"),
			})
		}
		if len(dev.Ports) > 0 {
			portsDir := map[string]kernfs.Inode{}
			for _, port := range dev.Ports {
				portEntries := map[string]kernfs.Inode{}
				addFile(portEntries, "state", port.State)
				addFile(portEntries, "phys_state", port.PhysState)
				addFile(portEntries, "link_layer", port.LinkLayer)
				addFile(portEntries, "rate", port.Rate)
				addFile(portEntries, "lid", port.LID)
				addFile(portEntries, "sm_lid", port.SMLID)
				addFile(portEntries, "sm_sl", port.SMSL)
				addFile(portEntries, "cap_mask", port.CapMask)
				portsDir[port.Number] = fs.newDir(ctx, creds, defaultSysDirMode, portEntries)
			}
			ibDevEntries["ports"] = fs.newDir(ctx, creds, defaultSysDirMode, portsDir)
		}
		ibDir[dev.IBDev] = fs.newDir(ctx, creds, defaultSysDirMode, ibDevEntries)
	}
	return ibVerbsDir, ibDir
}

