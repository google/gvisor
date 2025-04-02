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
	"sort"
	"strconv"
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

// pciAddress represents a PCI device address. It has the address format
// 0000:00:04.0.
type pciAddress struct {
	bus      uint8
	device   uint8
	function uint8
}

// pciAddressFromString parses a PCI device address string into a pciAddress
// struct. It assumes the address is on the host's main bus (i.e. 0000:*).
func pciAddressFromString(pciAddressString string) (pciAddress, error) {
	pciAddressString = strings.TrimPrefix(pciAddressString, "0000:")
	parts := strings.SplitN(pciAddressString, ":", 2)
	if len(parts) != 2 {
		return pciAddress{}, fmt.Errorf("invalid PCI address: %s", pciAddressString)
	}
	bus, err := strconv.ParseUint(parts[0], 16, 8)
	if err != nil {
		return pciAddress{}, fmt.Errorf("invalid PCI bus: %s", parts[0])
	}
	subparts := strings.SplitN(parts[1], ".", 2)
	if len(subparts) != 2 {
		return pciAddress{}, fmt.Errorf("invalid PCI device address: %s", parts[1])
	}
	device, err := strconv.ParseUint(subparts[0], 16, 8)
	if err != nil {
		return pciAddress{}, fmt.Errorf("invalid PCI device number: %s", parts[1])
	}
	fn, err := strconv.ParseUint(subparts[1], 16, 8)
	if err != nil {
		return pciAddress{}, fmt.Errorf("invalid PCI function number: %s", parts[2])
	}
	return pciAddress{bus: uint8(bus), device: uint8(device), function: uint8(fn)}, nil
}

func (a pciAddress) String() string {
	return fmt.Sprintf("0000:%02x:%02x.%d", a.bus, a.device, a.function)
}

func (a pciAddress) Empty() bool {
	return a.bus == 0 && a.device == 0 && a.function == 0
}

type pciAddressSet []pciAddress

func (s pciAddressSet) Len() int {
	return len(s)
}

func (s pciAddressSet) Less(i, j int) bool {
	if s[i].bus != s[j].bus {
		return s[i].bus < s[j].bus
	}
	if s[i].device != s[j].device {
		return s[i].device < s[j].device
	}
	return s[i].function < s[j].function
}

func (s pciAddressSet) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// pciDeviceInfo contains information about a PCI device, including the path to
// it on the host (not including the /sys/devices prefix), its physical and
// virtual function addresses, and its IOMMU group number.
type pciDeviceInfo struct {
	path       string
	iommuGroup int
	physfn     pciAddress
	virtfn     pciAddressSet
}

// pciDeviceInfos returns the information about all PCI devices on the host in a
// /sys/devices directory in the form of a map from PCI device name (e.g.
// 0000:00:04.0) to information about the PCI device.
func pciDeviceInfos(sysDevicesPath, iommuGroupsPath string) (map[string]*pciDeviceInfo, error) {
	sysDevicesDents, err := hostDirEntries(sysDevicesPath)
	if err != nil {
		return nil, err
	}
	pciInfos := map[string]*pciDeviceInfo{}
	for _, busDent := range sysDevicesDents {
		if pciBusRegex.MatchString(busDent) {
			if err := walkPCIDeviceTopology(busDent, sysDevicesPath, pciInfos); err != nil {
				return nil, err
			}
		}
	}
	// Sort the virtual function addresses for each PCI device so they can be
	// retrieved in the correct order when mirroring host symlinks.
	for _, pciPath := range pciInfos {
		sort.Sort(pciPath.virtfn)
	}
	if err := pciDeviceIOMMUGroups(iommuGroupsPath, pciInfos); err != nil {
		return nil, err
	}
	return pciInfos, nil
}

// walkPCIDeviceTopology recursively walks the PCI device topology and returns
// a map from PCI device name (e.g. 0000:00:04.0) to information about the PCI
// device.
func walkPCIDeviceTopology(pciPath, sysDevicesPath string, devices map[string]*pciDeviceInfo) error {
	currentPCIDir := path.Base(pciPath)
	if pciDeviceRegex.MatchString(currentPCIDir) && len(currentPCIDir) <= pciAddressLength {
		if _, ok := devices[currentPCIDir]; !ok {
			devices[currentPCIDir] = &pciDeviceInfo{}
		}
	}

	pciDirChildren, err := hostDirEntries(path.Join(sysDevicesPath, pciPath))
	if err != nil {
		return err
	}
	// A parent PCI device directory includes children that are both PCI devices
	// and other directories. We only care about the PCI devices, so we skip the
	// directories. These child devices contain both virtual and physical
	// functions, which we need to track.
	//
	// Example:
	// .../pci0000:00/0000:00:41.0/0000:00:41.0/physfn -> ../0000:00:42.0
	// .../pci0000:00/0000:00:41.0/0000:00:41.1/physfn -> ../0000:00:42.0
	// .../pci0000:00/0000:00:41.0/0000:00:42.0/virtfn0 -> ../0000:00:41.0
	// .../pci0000:00/0000:00:41.0/0000:00:42.0/virtfn1 -> ../0000:00:41.1
	for _, pciDirChild := range pciDirChildren {
		if pciDeviceRegex.MatchString(pciDirChild) && len(pciDirChild) <= pciAddressLength {
			pciDirChildAddr, err := pciAddressFromString(pciDirChild)
			if err != nil {
				return err
			}
			pciDirChildPath := path.Join(pciPath, pciDirChild)
			pciDirChildEntries, err := hostDirEntries(path.Join(sysDevicesPath, pciDirChildPath))
			if err != nil {
				return err
			}
			for _, entry := range pciDirChildEntries {
				// The "physfn" and "virtfn" entries are links to the physical and
				// virtual function addresses of other devices in the same parent
				// directory. If a child PCI device has virtfn entries, it means that
				// it is the physical function for the parent device. If the child PCI
				// device has a physfn entry, it means that it is one of many virtual
				// functions for the parent device.
				//
				// virtfn entries are numbered from 0, starting with the smallest
				// address in bus-device-function order.
				//
				// There's only one physfn entry per device, so if we've already found
				// one, we can skip.
				if entry == "physfn" {
					devices[currentPCIDir].virtfn = append(devices[currentPCIDir].virtfn, pciDirChildAddr)
					break
				} else if strings.Contains(entry, "virtfn") {
					devices[currentPCIDir].physfn = pciDirChildAddr
					break
				}
			}

			devices[pciDirChild] = &pciDeviceInfo{path: pciDirChildPath}
			if err := walkPCIDeviceTopology(pciDirChildPath, sysDevicesPath, devices); err != nil {
				return err
			}
		}
	}
	return nil
}

func pciDeviceIOMMUGroups(iommuGroupsPath string, pciInfos map[string]*pciDeviceInfo) error {
	// IOMMU groups are organized as iommu_group_path/$GROUP, where $GROUP is the
	// IOMMU group number of which the device is a member.
	iommuGroupNums, err := hostDirEntries(iommuGroupsPath)
	if err != nil {
		// When IOMMU is not enabled, skip the rest of the process.
		if err == unix.ENOENT {
			return nil
		}
		return err
	}
	// The returned map from PCI device name to its IOMMU group.
	for _, iommuGroupNum := range iommuGroupNums {
		groupDevicesPath := path.Join(iommuGroupsPath, iommuGroupNum, "devices")
		pciDeviceNames, err := hostDirEntries(groupDevicesPath)
		if err != nil {
			return err
		}
		// An IOMMU group may include multiple devices.
		for _, pciDeviceName := range pciDeviceNames {
			groupNum, err := strconv.Atoi(iommuGroupNum)
			if err != nil {
				return err
			}
			pciInfos[pciDeviceName].iommuGroup = groupNum
		}
	}
	return nil
}

func findIntInString(s string) (int, error) {
	re := regex.MustCompile(`\d+`)
	numMatch := re.FindString(s)
	if numMatch == "" {
		return 0, fmt.Errorf("no valid virtual function number for the device path at %v", s)
	}
	num, err := strconv.Atoi(numMatch)
	if err != nil {
		return 0, err
	}
	return num, nil
}

// Creates TPU devices' symlinks under /sys/class/. TPU device types that are
// not present on host will be ignored.
//
// TPU v4 symlinks are created at /sys/class/accel/accel#.
// TPU v5 symlinks go to /sys/class/vfio-dev/vfio#.
func (fs *filesystem) newDeviceClassDir(ctx context.Context, creds *auth.Credentials, tpuDeviceTypes []string, sysDevicesPath string, pciPaths map[string]*pciDeviceInfo) (map[string]map[string]kernfs.Inode, error) {
	dirs := map[string]map[string]kernfs.Inode{}
	for _, tpuDeviceType := range tpuDeviceTypes {
		dirs[tpuDeviceType] = map[string]kernfs.Inode{}
	}
	for _, pciPath := range pciPaths {
		for _, tpuDeviceType := range tpuDeviceTypes {
			subPath := path.Join(sysDevicesPath, pciPath.path, tpuDeviceType)
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

			dirs[tpuDeviceType][deviceDents[0]] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), fmt.Sprintf("../../devices/%s/%s/%s", pciPath.path, tpuDeviceType, deviceDents[0]))
		}
	}
	if len(dirs) == 0 {
		return nil, errors.New("no TPU device sysfile is found")
	}
	return dirs, nil
}

// Create /sys/bus/pci/devices symlinks.
func (fs *filesystem) newBusPCIDevicesDir(ctx context.Context, creds *auth.Credentials, pciPaths map[string]*pciDeviceInfo) (map[string]kernfs.Inode, error) {
	pciDevicesDir := map[string]kernfs.Inode{}
	for pciDevice, pciPath := range pciPaths {
		pciDevicesDir[pciDevice] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), fmt.Sprintf("../../../devices/%s", pciPath.path))
	}
	return pciDevicesDir, nil
}

// Recursively build out sysfs directories according to the allowlisted files,
// directories, and symlinks defined in this package.
func (fs *filesystem) mirrorSysDevicesDir(ctx context.Context, creds *auth.Credentials, dir string, pciInfos map[string]*pciDeviceInfo) (map[string]kernfs.Inode, error) {
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
			contents, err := fs.mirrorSysDevicesDir(ctx, creds, dentPath, pciInfos)
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
				pciPath := pciBusRegex.ReplaceAllString(pciInfos[pciDeviceName].path, "")
				// Both the device and PCI address entries are links to the original PCI
				// device directory that's at the same place earlier in the dir tree.
				linkContent = path.Join("../../../", pciPath)
			case dent == "physfn" || strings.Contains(dent, "virtfn"):
				pciDirName := path.Base(path.Dir(dir))
				if dent == "physfn" {
					linkContent = path.Join("../", pciInfos[pciDirName].physfn.String())
				} else if strings.Contains(dent, "virtfn") {
					num, err := findIntInString(dent)
					if err != nil {
						return nil, err
					}
					linkContent = path.Join("../", pciInfos[pciDirName].virtfn[num].String())
				}
			case dent == "iommu_group":
				pciDeviceName, err := pciDeviceName(dir)
				if err != nil {
					return nil, err
				}
				pciInfo, exist := pciInfos[pciDeviceName]
				if !exist {
					return nil, fmt.Errorf("no IOMMU group is found for device %v", pciDeviceName)
				}
				// A PCI device path looks something like pci0000:00/0000:00:04.0. To
				// get to the /sys directory, we need to go up as many directories as
				// are in the pciPath plus one more for the "devices" directory.
				pciPathComponents := strings.Split(pciInfos[pciDeviceName].path, "/")
				upDirs := strings.Repeat("../", len(pciPathComponents)+1)
				linkContent = fmt.Sprintf("%skernel/iommu_groups/%d", upDirs, pciInfo.iommuGroup)
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
