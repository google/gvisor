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
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// RDMAGIDEntry contains a single GID table entry and its RoCE type.
type RDMAGIDEntry struct {
	Index string `json:"index"`
	GID   string `json:"gid"`
	Type  string `json:"type"`
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

	// DynMajor is the sentry-assigned dynamic major for this device.
	// Set at runtime during device registration, not serialized.
	DynMajor uint32 `json:"-"`
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
		log.Infof("rdma collect: %s not accessible: %v", verbsPath, err)
		return nil
	}
	data := &RDMAData{
		VerbsABIVersion: readSysfsFile(path.Join(verbsPath, "abi_version")),
	}
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
		log.Infof("rdma collect: %s → ibdev=%s dev=%s node_type=%q fw_ver=%q",
			dent.Name(), ibdev, dev.Dev, dev.NodeType, dev.FWVer)
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
				gidDents, gerr := os.ReadDir(gidsPath)
				if gerr == nil {
					for _, gidDent := range gidDents {
						gidVal := readSysfsFile(path.Join(gidsPath, gidDent.Name()))
						typeVal := readSysfsFile(path.Join(typesPath, gidDent.Name()))
						if gidVal == "" {
							continue
						}
						if typeVal == "" && pd.LinkLayer == "Ethernet" {
							typeVal = inferRoCEType(gidVal)
						}
						pd.GIDs = append(pd.GIDs, RDMAGIDEntry{
							Index: gidDent.Name(),
							GID:   gidVal,
							Type:  typeVal,
						})
					}
				}
				log.Infof("rdma collect:   port %s: state=%q link_layer=%q rate=%q gids=%d",
					pd.Number, pd.State, pd.LinkLayer, pd.Rate, len(pd.GIDs))
				dev.Ports = append(dev.Ports, pd)
			}
		}
		data.Devices = append(data.Devices, dev)
	}
	log.Infof("rdma collect: collected %d device(s)", len(data.Devices))
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

const allZeroGID = "0000:0000:0000:0000:0000:0000:0000:0000"

// inferRoCEType guesses the RoCE GID type when the host sysfs
// gid_attrs/types/ files are not readable (e.g. restricted sysfs mount).
// For mlx5 Ethernet (RoCE) devices the kernel assigns:
//   - link-local GIDs (fe80::) → RoCE v1
//   - all other non-zero GIDs  → RoCE v2
func inferRoCEType(gid string) string {
	if gid == allZeroGID || gid == "" {
		return ""
	}
	if strings.HasPrefix(gid, "fe80:") {
		return "IB/RoCE v1"
	}
	return "RoCE v2"
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
		if dev.Modalias != "" {
			ibDevEntries["device"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
				"modalias": fs.newStaticFile(ctx, creds, defaultSysMode, dev.Modalias+"\n"),
			})
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
					for _, gid := range port.GIDs {
						addFile(gidsEntries, gid.Index, gid.GID)
						addFile(typesEntries, gid.Index, gid.Type)
					}
					log.Infof("rdma sysfs:   port %s: %d gids, gidsEntries=%d typesEntries=%d",
						port.Number, len(port.GIDs), len(gidsEntries), len(typesEntries))
					portEntries["gids"] = fs.newDir(ctx, creds, defaultSysDirMode, gidsEntries)
					portEntries["gid_attrs"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
						"types": fs.newDir(ctx, creds, defaultSysDirMode, typesEntries),
					})
				}
				portsDir[port.Number] = fs.newDir(ctx, creds, defaultSysDirMode, portEntries)
			}
			ibDevEntries["ports"] = fs.newDir(ctx, creds, defaultSysDirMode, portsDir)
		}
		ibDir[dev.IBDev] = fs.newDir(ctx, creds, defaultSysDirMode, ibDevEntries)
	}
	return ibVerbsDir, ibDir
}

