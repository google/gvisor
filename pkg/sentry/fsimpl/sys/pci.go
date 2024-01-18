// Copyright 2023 The gVisor Authors.
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
	"errors"
	"fmt"
	"path"
	regex "regexp"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

const (
	pciMainBusDevicePath = "/sys/devices/pci0000:00"
	accelDevice          = "accel"
	vfioDevice           = "vfio-dev"
)

var (
	// Matches PCI device addresses in the main domain.
	pciDeviceRegex = regex.MustCompile(`0000:([a-fA-F0-9]{2}|[a-fA-F0-9]{4}):[a-fA-F0-9]{2}\.[a-fA-F0-9]{1,2}`)
	// Matches the directories for the main bus (i.e. pci000:00),
	// individual devices (e.g. 00:00:04.0), accel (TPU v4), and vfio (TPU v5)
	sysDevicesDirRegex = regex.MustCompile(`pci0000:00|accel|vfio|(0000:([a-fA-F0-9]{2}|[a-fA-F0-9]{4}):[a-fA-F0-9]{2}\.[a-fA-F0-9]{1,2})`)
	// Files allowlisted for host passthrough. These files are read-only.
	sysDevicesFiles = map[string]any{
		"vendor": nil, "device": nil, "subsystem_vendor": nil, "subsystem_device": nil,
		"revision": nil, "class": nil, "numa_node": nil,
		"resource": nil, "pci_address": nil, "dev": nil, "driver_version": nil,
		"reset_count": nil, "write_open_count": nil, "status": nil,
		"is_device_owned": nil, "device_owner": nil, "framework_version": nil,
		"user_mem_ranges": nil, "interrupt_counts": nil, "chip_model": nil,
		"bar_offsets": nil, "bar_sizes": nil, "resource0": nil, "resource1": nil,
		"resource2": nil, "resource3": nil, "resource4": nil, "resource5": nil,
	}
)

// Creates TPU devices' symlinks under /sys/class/. TPU device types that are
// not present on host will be ignored.
//
// TPU v4 symlinks are created at /sys/class/accel/accel#.
// TPU v5 symlinks go to /sys/class/vfio-dev/vfio#.
func (fs *filesystem) newDeviceClassDir(ctx context.Context, creds *auth.Credentials, tpuDeviceTypes []string, pciMainBusDevicePath string) (map[string]map[string]kernfs.Inode, error) {
	dirs := map[string]map[string]kernfs.Inode{}
	pciDents, err := hostDirEntries(pciMainBusDevicePath)
	if err != nil {
		return nil, err
	}
	for _, pciDent := range pciDents {
		for _, tpuDeviceType := range tpuDeviceTypes {
			subPath := path.Join(pciMainBusDevicePath, pciDent, tpuDeviceType)
			dirs[tpuDeviceType] = map[string]kernfs.Inode{}
			deviceDents, err := hostDirEntries(subPath)
			if err != nil {
				// Skips the path that doesn't exist.
				if err == unix.ENOENT {
					continue
				}
				return nil, err
			}
			if numOfDeviceDents := len(deviceDents); numOfDeviceDents != 1 {
				return nil, fmt.Errorf("exactly one entry is expected at %v while there are %d", subPath, numOfDeviceDents)
			}
			dirs[tpuDeviceType][deviceDents[0]] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), fmt.Sprintf("../../devices/pci0000:00/%s/%s/%s", pciDent, tpuDeviceType, deviceDents[0]))
		}
	}
	if len(dirs) == 0 {
		return nil, errors.New("no TPU device sysfile is found")
	}
	return dirs, nil
}

// Create /sys/bus/pci/devices symlinks.
func (fs *filesystem) newBusPCIDevicesDir(ctx context.Context, creds *auth.Credentials, pciMainBusDevicePath string) (map[string]kernfs.Inode, error) {
	pciDevicesDir := map[string]kernfs.Inode{}
	pciDents, err := hostDirEntries(pciMainBusDevicePath)
	if err != nil {
		return nil, err
	}
	for _, pciDent := range pciDents {
		pciDevicesDir[pciDent] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), fmt.Sprintf("../../../devices/pci0000:00/%s", pciDent))
	}

	return pciDevicesDir, nil
}

// Recursively build out sysfs directories according to the allowlisted files,
// directories, and symlinks defined in this package.
func (fs *filesystem) mirrorPCIBusDeviceDir(ctx context.Context, creds *auth.Credentials, dir string, iommuGroups map[string]string) (map[string]kernfs.Inode, error) {
	subs := map[string]kernfs.Inode{}
	dents, err := hostDirEntries(dir)
	if err != nil {
		return nil, err
	}
	for _, dent := range dents {
		dentPath := path.Join(dir, dent)
		dentMode, err := hostFileMode(dentPath)
		if err != nil {
			return nil, err
		}
		switch dentMode {
		case unix.S_IFDIR:
			if match := sysDevicesDirRegex.MatchString(dent); !match {
				continue
			}
			contents, err := fs.mirrorPCIBusDeviceDir(ctx, creds, dentPath, iommuGroups)
			if err != nil {
				return nil, err
			}
			subs[dent] = fs.newDir(ctx, creds, defaultSysMode, contents)
		case unix.S_IFREG:
			if _, ok := sysDevicesFiles[dent]; ok {
				subs[dent] = fs.newHostFile(ctx, creds, defaultSysMode, dentPath)
			}
		case unix.S_IFLNK:
			linkContent := ""
			switch {
			case pciDeviceRegex.MatchString(dent) || dent == "device":
				pciDeviceName, err := pciDeviceName(dir)
				if err != nil {
					return nil, err
				}
				// Both the device and PCI address entries are links to the original PCI
				// device directory that's at the same place earlier in the dir tree.
				linkContent = fmt.Sprintf("../../../%s", pciDeviceName)
			case dent == "iommu_group":
				pciDeviceName, err := pciDeviceName(dir)
				if err != nil {
					return nil, err
				}
				iommuGroupNum, exist := iommuGroups[pciDeviceName]
				if !exist {
					return nil, fmt.Errorf("no IOMMU group is found for device %v", pciDeviceName)
				}
				linkContent = fmt.Sprintf("../../../kernel/iommu_groups/%s", iommuGroupNum)
			default:
				continue
			}
			subs[dent] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linkContent)
		}
	}
	return subs, nil
}

// Infer a PCI device's name from its path.
func pciDeviceName(pciDevicePath string) (string, error) {
	pciDeviceName := pciDeviceRegex.FindString(pciDevicePath)
	if pciDeviceName == "" {
		return "", fmt.Errorf("no valid device name for the device path at %v", pciDevicePath)
	}
	return pciDeviceName, nil
}

func hostFileMode(path string) (uint32, error) {
	fd, err := unix.Openat(-1, path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_PATH, 0)
	if err != nil {
		return 0, err
	}
	stat := unix.Stat_t{}
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, err
	}
	return stat.Mode & unix.S_IFMT, nil
}

func hostDirEntries(path string) ([]string, error) {
	fd, err := unix.Openat(-1, path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return fsutil.DirentNames(fd)
}
