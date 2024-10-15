// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/tpu"
)

const (
	googleVendorID            = 0x1AE0
	accelDevicePathRegex      = `^/dev/accel(\d+)$`
	accelSysfsFormat          = "/sys/class/accel/accel%d/device/%s"
	vfioDevicePathRegex       = `^/dev/vfio/(\d+)$`
	iommuGroupSysfsGlobFormat = "/sys/kernel/iommu_groups/%s/devices/*"
	vendorFile                = "vendor"
	deviceFile                = "device"
	pciAddressMaxLength       = 13
)

var (
	tpuV4DeviceIDs = map[uint64]struct{}{tpu.TPUV4DeviceID: {}, tpu.TPUV4liteDeviceID: {}}
	tpuV5DeviceIDs = map[uint64]struct{}{tpu.TPUV5eDeviceID: {}, tpu.TPUV5pDeviceID: {}}
	pciDeviceRegex = regexp.MustCompile(`0000:([[:xdigit:]]{2}|[[:xdigit:]]{4}):[[:xdigit:]]{2}\.[[:xdigit:]]{1,2}`)
)

// IsPCIDeviceDirTPU returns if the given PCI device sysfs path is a TPU device
// with one of the allowed device IDs.
func IsPCIDeviceDirTPU(sysfsPath string, allowedDeviceIDs map[uint64]struct{}) bool {
	dir := path.Base(sysfsPath)
	if !pciDeviceRegex.MatchString(dir) || len(dir) > pciAddressMaxLength {
		return false
	}
	vendor, err := readHexInt(path.Join(sysfsPath, vendorFile))
	if err != nil {
		return false
	}
	if vendor != googleVendorID {
		return false
	}
	deviceID, err := readHexInt(path.Join(sysfsPath, deviceFile))
	if err != nil {
		return false
	}
	if _, ok := allowedDeviceIDs[deviceID]; !ok {
		return false
	}
	return true
}

// IsTPUDeviceValid returns if the accelerator device is valid.
func IsTPUDeviceValid(path string) (bool, error) {
	valid, err := tpuV4DeviceValid(path)
	if err != nil {
		return false, err
	}
	if valid {
		return valid, err
	}
	return tpuV5DeviceValid(path)
}

// tpuV4DeviceValid returns v4 and v4lite TPU device minor number for the given path.
// A valid v4 TPU device is defined as:
// * Path is /dev/accel#.
// * Vendor is googleVendorID.
// * Device ID is one of tpuV4DeviceIDs.
func tpuV4DeviceValid(devPath string) (bool, error) {
	deviceRegex := regexp.MustCompile(accelDevicePathRegex)
	matches := deviceRegex.FindStringSubmatch(devPath)
	if matches == nil {
		return false, nil
	}
	if len(matches) < 1 {
		return false, fmt.Errorf("found %d matches for %s", len(matches), devPath)
	}
	devNum, err := strconv.ParseUint(matches[1], 10, 32)
	if err != nil {
		return false, err
	}
	vendor, err := readHexInt(fmt.Sprintf(accelSysfsFormat, devNum, vendorFile))
	if err != nil {
		return false, err
	}
	if vendor != googleVendorID {
		return false, nil
	}
	deviceID, err := readHexInt(fmt.Sprintf(accelSysfsFormat, devNum, deviceFile))
	if err != nil {
		return false, err
	}
	if _, ok := tpuV4DeviceIDs[deviceID]; !ok {
		return false, nil
	}
	return true, nil
}

// tpuV5DeviceValid returns the v5e TPU device minor number for te given path.
// A valid v5 TPU device is defined as:
// * Path is /dev/vfio/#.
// * Vendor is googleVendorID.
// * Device ID is one of tpuV5DeviceIDs.
func tpuV5DeviceValid(devPath string) (bool, error) {
	paths, err := filepath.Glob(fmt.Sprintf(iommuGroupSysfsGlobFormat, path.Base(devPath)))
	if err != nil {
		return false, err
	}
	if len(paths) != 1 {
		return false, fmt.Errorf("found %d paths for %s", len(paths), devPath)
	}
	sysfsPath := paths[0]
	vendor, err := readHexInt(path.Join(sysfsPath, vendorFile))
	if err != nil {
		return false, err
	}
	if vendor != googleVendorID {
		return false, nil
	}
	deviceID, err := readHexInt(path.Join(sysfsPath, deviceFile))
	if err != nil {
		return false, err
	}
	if _, ok := tpuV5DeviceIDs[deviceID]; !ok {
		return false, nil
	}
	return true, nil
}

func readHexInt(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	numStr := strings.Trim(strings.TrimSpace(strings.TrimPrefix(string(data), "0x")), "\x00")
	return strconv.ParseUint(numStr, 16, 64)
}
