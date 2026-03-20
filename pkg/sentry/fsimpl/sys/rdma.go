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
	"os"
	"path"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// RDMADeviceData contains sysfs data for a single RDMA uverbs device,
// collected from the host before the sandbox chroot is entered.
type RDMADeviceData struct {
	// Name is the uverbs device name (e.g. "uverbs0").
	Name string
	// IBDev is the InfiniBand device name (e.g. "mlx5_0").
	IBDev string
	// ABIVersion is the uverbs ABI version (e.g. "1").
	ABIVersion string
	// Dev is the device major:minor (e.g. "231:192").
	Dev string
	// NodeType is the IB node type (e.g. "1: CA").
	NodeType string
	// NodeGUID is the node GUID.
	NodeGUID string
	// SysImageGUID is the system image GUID.
	SysImageGUID string
	// FWVer is the firmware version.
	FWVer string
	// Ports contains per-port data.
	Ports []RDMAPortData
}

// RDMAPortData contains sysfs data for a single port of an IB device.
type RDMAPortData struct {
	// Number is the port number (e.g. "1").
	Number string
	// State is the port state.
	State string
	// PhysState is the physical state.
	PhysState string
	// LinkLayer is the link layer type (e.g. "InfiniBand").
	LinkLayer string
	// Rate is the port rate.
	Rate string
	// LID is the local identifier.
	LID string
	// SMLID is the subnet manager LID.
	SMLID string
	// SMSL is the subnet manager SL.
	SMSL string
	// CapMask is the port capability mask.
	CapMask string
}

// CollectRDMADeviceData reads RDMA sysfs data from the host filesystem.
// This must be called before the sandbox chroot is entered.
func CollectRDMADeviceData() []RDMADeviceData {
	verbsPath := "/sys/class/infiniband_verbs"
	dents, err := os.ReadDir(verbsPath)
	if err != nil {
		return nil
	}

	var devices []RDMADeviceData
	for _, dent := range dents {
		if !strings.HasPrefix(dent.Name(), "uverbs") {
			continue
		}
		devDir := path.Join(verbsPath, dent.Name())
		ibdev := readSysfsFile(path.Join(devDir, "ibdev"))
		if ibdev == "" {
			continue
		}

		dev := RDMADeviceData{
			Name:       dent.Name(),
			IBDev:      ibdev,
			ABIVersion: readSysfsFile(path.Join(devDir, "abi_version")),
			Dev:        readSysfsFile(path.Join(devDir, "dev")),
		}

		// Read IB device attributes.
		ibDevDir := path.Join("/sys/class/infiniband", ibdev)
		dev.NodeType = readSysfsFile(path.Join(ibDevDir, "node_type"))
		dev.NodeGUID = readSysfsFile(path.Join(ibDevDir, "node_guid"))
		dev.SysImageGUID = readSysfsFile(path.Join(ibDevDir, "sys_image_guid"))
		dev.FWVer = readSysfsFile(path.Join(ibDevDir, "fw_ver"))

		// Read port data.
		portsPath := path.Join(ibDevDir, "ports")
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

		devices = append(devices, dev)
	}
	return devices
}

func readSysfsFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// newRDMASysfsEntries creates /sys/class/infiniband_verbs/ and
// /sys/class/infiniband/ directories from pre-collected device data.
func (fs *filesystem) newRDMASysfsEntries(ctx context.Context, creds *auth.Credentials, devices []RDMADeviceData) (ibVerbsDir, ibDir map[string]kernfs.Inode) {
	if len(devices) == 0 {
		return nil, nil
	}

	ibVerbsDir = map[string]kernfs.Inode{}
	ibDir = map[string]kernfs.Inode{}

	for _, dev := range devices {
		// /sys/class/infiniband_verbs/uverbsN/
		verbsEntries := map[string]kernfs.Inode{}
		if dev.IBDev != "" {
			verbsEntries["ibdev"] = fs.newStaticFile(ctx, creds, defaultSysMode, dev.IBDev+"\n")
		}
		if dev.ABIVersion != "" {
			verbsEntries["abi_version"] = fs.newStaticFile(ctx, creds, defaultSysMode, dev.ABIVersion+"\n")
		}
		if dev.Dev != "" {
			verbsEntries["dev"] = fs.newStaticFile(ctx, creds, defaultSysMode, dev.Dev+"\n")
		}
		ibVerbsDir[dev.Name] = fs.newDir(ctx, creds, defaultSysDirMode, verbsEntries)

		// /sys/class/infiniband/<ibdev>/
		if dev.IBDev != "" {
			ibDevEntries := map[string]kernfs.Inode{}
			addStaticIfSet := func(name, value string) {
				if value != "" {
					ibDevEntries[name] = fs.newStaticFile(ctx, creds, defaultSysMode, value+"\n")
				}
			}
			addStaticIfSet("node_type", dev.NodeType)
			addStaticIfSet("node_guid", dev.NodeGUID)
			addStaticIfSet("sys_image_guid", dev.SysImageGUID)
			addStaticIfSet("fw_ver", dev.FWVer)

			if len(dev.Ports) > 0 {
				portsDir := map[string]kernfs.Inode{}
				for _, port := range dev.Ports {
					portEntries := map[string]kernfs.Inode{}
					addPort := func(name, value string) {
						if value != "" {
							portEntries[name] = fs.newStaticFile(ctx, creds, defaultSysMode, value+"\n")
						}
					}
					addPort("state", port.State)
					addPort("phys_state", port.PhysState)
					addPort("link_layer", port.LinkLayer)
					addPort("rate", port.Rate)
					addPort("lid", port.LID)
					addPort("sm_lid", port.SMLID)
					addPort("sm_sl", port.SMSL)
					addPort("cap_mask", port.CapMask)
					portsDir[port.Number] = fs.newDir(ctx, creds, defaultSysDirMode, portEntries)
				}
				ibDevEntries["ports"] = fs.newDir(ctx, creds, defaultSysDirMode, portsDir)
			}

			ibDir[dev.IBDev] = fs.newDir(ctx, creds, defaultSysDirMode, ibDevEntries)
		}
	}
	return ibVerbsDir, ibDir
}

