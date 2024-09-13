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
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

const (
	accelDevice        = "accel"
	vfioDevice         = "vfio-dev"
	sysDevicesMainPath = "/sys/devices"
)

var (
	// pciBusRegex matches PCI bus addresses.
	pciBusRegex = regex.MustCompile(`pci0000:[[:xdigit:]]{2}`)
	// Matches PCI device addresses.
	pciDeviceRegex = regex.MustCompile(`0000:([[:xdigit:]]{2}|[[:xdigit:]]{4}):[[:xdigit:]]{2}\.[[:xdigit:]]{1,2}`)
	// Matches the directories for the main bus (i.e. pci000:00),
	// individual devices (e.g. 00:00:04.0), accel (TPU v4), and vfio (TPU v5)
	sysDevicesDirRegex = regex.MustCompile(`pci0000:[[:xdigit:]]{2}|accel|vfio|vfio-dev|(0000:([[:xdigit:]]{2}|[[:xdigit:]]{4}):[[:xdigit:]]{2}\.[[:xdigit:]]{1,2})`)
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
		"enable": nil,
	}

	pciAddressLength = 13
)

// pciDevicePaths returns the paths of all PCI devices on the host in a
// /sys/devices directory.
func pciDevicePaths(sysDevicesPath string) (map[string]string, error) {
	sysDevicesDents, err := hostDirEntries(sysDevicesPath)
	if err != nil {
		return nil, err
	}
	pciPaths := map[string]string{}
	for _, busDent := range sysDevicesDents {
		if pciBusRegex.MatchString(busDent) {
			if err := walkPCIDeviceTopology(busDent, sysDevicesPath, pciPaths); err != nil {
				return nil, err
			}
		}
	}
	return pciPaths, nil
}

// walkPCIDeviceTopology recursively walks the PCI device topology and returns
// a map from PCI device name to its path starting from the PCI bus directory.
func walkPCIDeviceTopology(pciPath, sysDevicesPath string, devices map[string]string) error {
	dents, err := hostDirEntries(path.Join(sysDevicesPath, pciPath))
	if err != nil {
		return err
	}
	for _, dent := range dents {
		if pciDeviceRegex.MatchString(dent) && len(dent) <= pciAddressLength {
			dentPath := path.Join(pciPath, dent)
			devices[dent] = dentPath
			if err := walkPCIDeviceTopology(dentPath, sysDevicesPath, devices); err != nil {
				return err
			}
		}
	}
	return nil
}

// Creates TPU devices' symlinks under /sys/class/. TPU device types that are
// not present on host will be ignored.
//
// TPU v4 symlinks are created at /sys/class/accel/accel#.
// TPU v5 symlinks go to /sys/class/vfio-dev/vfio#.
func (fs *filesystem) newDeviceClassDir(ctx context.Context, creds *auth.Credentials, tpuDeviceTypes []string, sysDevicesPath string, pciPaths map[string]string) (map[string]map[string]kernfs.Inode, error) {
	dirs := map[string]map[string]kernfs.Inode{}
	for _, tpuDeviceType := range tpuDeviceTypes {
		dirs[tpuDeviceType] = map[string]kernfs.Inode{}
	}
	for _, pciPath := range pciPaths {
		for _, tpuDeviceType := range tpuDeviceTypes {
			subPath := path.Join(sysDevicesPath, pciPath, tpuDeviceType)
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

			dirs[tpuDeviceType][deviceDents[0]] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), fmt.Sprintf("../../devices/%s/%s/%s", pciPath, tpuDeviceType, deviceDents[0]))
		}
	}
	if len(dirs) == 0 {
		return nil, errors.New("no TPU device sysfile is found")
	}
	return dirs, nil
}

// Create /sys/bus/pci/devices symlinks.
func (fs *filesystem) newBusPCIDevicesDir(ctx context.Context, creds *auth.Credentials, pciPaths map[string]string) (map[string]kernfs.Inode, error) {
	pciDevicesDir := map[string]kernfs.Inode{}
	for pciDevice, pciPath := range pciPaths {
		pciDevicesDir[pciDevice] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), fmt.Sprintf("../../../devices/%s", pciPath))
	}
	return pciDevicesDir, nil
}

// Recursively build out sysfs directories according to the allowlisted files,
// directories, and symlinks defined in this package.
func (fs *filesystem) mirrorSysDevicesDir(ctx context.Context, creds *auth.Credentials, dir string, iommuGroups, pciPaths map[string]string) (map[string]kernfs.Inode, error) {
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
			contents, err := fs.mirrorSysDevicesDir(ctx, creds, dentPath, iommuGroups, pciPaths)
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
				// Remove the bus prefix.
				pciPath := pciBusRegex.ReplaceAllString(pciPaths[pciDeviceName], "")
				// Both the device and PCI address entries are links to the original PCI
				// device directory that's at the same place earlier in the dir tree.
				linkContent = path.Join("../../../", pciPath)
			case dent == "iommu_group":
				pciDeviceName, err := pciDeviceName(dir)
				if err != nil {
					return nil, err
				}
				iommuGroupNum, exist := iommuGroups[pciDeviceName]
				if !exist {
					return nil, fmt.Errorf("no IOMMU group is found for device %v", pciDeviceName)
				}
				// A PCI device path looks something like pci0000:00/0000:00:04.0. To
				// get to the /sys directory, we need to go up as many directories as
				// are in the pciPath plus one more for the "devices" directory.
				pciPathComponents := strings.Split(pciPaths[pciDeviceName], "/")
				upDirs := strings.Repeat("../", len(pciPathComponents)+1)
				linkContent = fmt.Sprintf("%skernel/iommu_groups/%s", upDirs, iommuGroupNum)
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
	pciDeviceNames := pciDeviceRegex.FindAllString(pciDevicePath, -1)
	if len(pciDeviceNames) == 0 {
		return "", fmt.Errorf("no valid device name for the device path at %v", pciDevicePath)
	}
	return pciDeviceNames[len(pciDeviceNames)-1], nil
}

func hostFileMode(path string) (uint32, error) {
	fd, err := unix.Openat(-1, path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_PATH, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
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
