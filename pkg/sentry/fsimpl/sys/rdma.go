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

// SysfsDir is a generic recursive representation of a sysfs directory tree.
type SysfsDir struct {
	Files map[string]string
	Dirs  map[string]*SysfsDir
}

// RDMADeviceData contains sysfs data for a single RDMA uverbs device,
// collected from the host before the sandbox chroot is entered.
type RDMADeviceData struct {
	// Name is the uverbs device name (e.g. "uverbs0").
	Name string
	// IBDev is the InfiniBand device name (e.g. "mlx5_0").
	IBDev string
	// Verbs is the full tree under /sys/class/infiniband_verbs/<name>/.
	Verbs *SysfsDir
	// IB is the full tree under /sys/class/infiniband/<ibdev>/.
	IB *SysfsDir
}

// RDMAData holds all collected RDMA sysfs data.
type RDMAData struct {
	// VerbsABIVersion is the global /sys/class/infiniband_verbs/abi_version.
	VerbsABIVersion string
	// Devices contains per-uverbs-device data.
	Devices []RDMADeviceData
}

func collectSysfsDir(dirPath string) *SysfsDir {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil
	}
	d := &SysfsDir{
		Files: map[string]string{},
		Dirs:  map[string]*SysfsDir{},
	}
	for _, entry := range entries {
		child := path.Join(dirPath, entry.Name())
		if entry.IsDir() {
			if sub := collectSysfsDir(child); sub != nil {
				d.Dirs[entry.Name()] = sub
			}
			continue
		}
		data, err := os.ReadFile(child)
		if err != nil {
			continue
		}
		d.Files[entry.Name()] = strings.TrimSpace(string(data))
	}
	return d
}

// CollectRDMADeviceData reads RDMA sysfs data from the host filesystem.
// It must be called after rdmaProxyUpdateChroot has copied the host sysfs
// files into the chroot (or before the chroot when host sysfs is accessible).
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
		verbs := collectSysfsDir(devDir)
		if verbs == nil {
			continue
		}
		ibdev := verbs.Files["ibdev"]
		if ibdev == "" {
			continue
		}
		data.Devices = append(data.Devices, RDMADeviceData{
			Name:  dent.Name(),
			IBDev: ibdev,
			Verbs: verbs,
			IB:    collectSysfsDir(path.Join("/sys/class/infiniband", ibdev)),
		})
	}
	return data
}

func readSysfsFile(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (fs *filesystem) sysfsDirToInodes(ctx context.Context, creds *auth.Credentials, d *SysfsDir) map[string]kernfs.Inode {
	if d == nil {
		return nil
	}
	entries := map[string]kernfs.Inode{}
	for name, content := range d.Files {
		entries[name] = fs.newStaticFile(ctx, creds, defaultSysMode, content+"\n")
	}
	for name, sub := range d.Dirs {
		entries[name] = fs.newDir(ctx, creds, defaultSysDirMode, fs.sysfsDirToInodes(ctx, creds, sub))
	}
	return entries
}

// newRDMASysfsEntries creates /sys/class/infiniband_verbs/ and
// /sys/class/infiniband/ directories from pre-collected device data.
func (fs *filesystem) newRDMASysfsEntries(ctx context.Context, creds *auth.Credentials, data *RDMAData) (ibVerbsDir, ibDir map[string]kernfs.Inode) {
	if data == nil || len(data.Devices) == 0 {
		return nil, nil
	}
	ibVerbsDir = map[string]kernfs.Inode{}
	ibDir = map[string]kernfs.Inode{}
	if data.VerbsABIVersion != "" {
		ibVerbsDir["abi_version"] = fs.newStaticFile(ctx, creds, defaultSysMode, data.VerbsABIVersion+"\n")
	}
	for _, dev := range data.Devices {
		ibVerbsDir[dev.Name] = fs.newDir(ctx, creds, defaultSysDirMode, fs.sysfsDirToInodes(ctx, creds, dev.Verbs))
		if dev.IBDev != "" && dev.IB != nil {
			ibDir[dev.IBDev] = fs.newDir(ctx, creds, defaultSysDirMode, fs.sysfsDirToInodes(ctx, creds, dev.IB))
		}
	}
	return ibVerbsDir, ibDir
}

