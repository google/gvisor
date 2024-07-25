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
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/tpu"
)

const (
	googleVendorID       = 0x1AE0
	accelDevicePathRegex = `^/dev/accel(\d+)$`
	accelSysfsFormat     = "/sys/class/accel/accel%d/device/%s"
	vfioDevicePathRegex  = `^/dev/vfio/(\d+)$`
	vfioSysfsFormat      = "/sys/class/vfio-dev/vfio%d/device/%s"
	vendorFile           = "vendor"
	deviceFile           = "device"
)

var tpuV4DeviceIDs = map[uint64]any{tpu.TPUV4DeviceID: nil, tpu.TPUV4liteDeviceID: nil}
var tpuV5DeviceIDs = map[uint64]any{tpu.TPUV5eDeviceID: nil, tpu.TPUV5pDeviceID: nil}

// ExtractTPUDeviceMinor returns the accelerator device minor number for that
// the passed device path. If the passed device is not a valid TPU device, then
// it returns false.
func ExtractTPUDeviceMinor(path string) (uint32, bool, error) {
	devNum, valid, err := tpuV4DeviceMinor(path)
	if err != nil {
		return 0, false, err
	}
	if valid {
		return devNum, valid, err
	}
	return tpuV5DeviceMinor(path)
}

// tpuDeviceMinor returns the accelerator device minor number for that
// the passed device path. If the passed device is not a valid TPU device, then
// it returns false.
func tpuDeviceMinor(devicePath, devicePathRegex, sysfsFormat string, allowedDeviceIDs map[uint64]any) (uint32, bool, error) {
	deviceRegex := regexp.MustCompile(devicePathRegex)
	matches := deviceRegex.FindStringSubmatch(devicePath)
	if matches == nil {
		return 0, false, nil
	}
	var st syscall.Stat_t
	if err := syscall.Stat(devicePath, &st); err != nil {
		return 0, false, err
	}
	minor := unix.Minor(st.Rdev)
	vendor, err := readHexInt(fmt.Sprintf(sysfsFormat, minor, vendorFile))
	if err != nil {
		return 0, false, err
	}
	if vendor != googleVendorID {
		return 0, false, nil
	}
	deviceID, err := readHexInt(fmt.Sprintf(sysfsFormat, minor, deviceFile))
	if err != nil {
		return 0, false, err
	}
	if _, ok := allowedDeviceIDs[deviceID]; !ok {
		return 0, false, nil
	}
	return minor, true, nil
}

// tpuv4DeviceMinor returns v4 and v4lite TPU device minor number for the given path.
// A valid v4 TPU device is defined as:
// * Path is /dev/accel#.
// * Vendor is googleVendorID.
// * Device ID is one of tpuV4DeviceIDs.
func tpuV4DeviceMinor(path string) (uint32, bool, error) {
	return tpuDeviceMinor(path, accelDevicePathRegex, accelSysfsFormat, tpuV4DeviceIDs)
}

// tpuV5DeviceMinor returns the v5e TPU device minor number for te given path.
// A valid v5 TPU device is defined as:
// * Path is /dev/vfio/#.
// * Vendor is googleVendorID.
// * Device ID is one of tpuV5DeviceIDs.
func tpuV5DeviceMinor(path string) (uint32, bool, error) {
	return tpuDeviceMinor(path, vfioDevicePathRegex, vfioSysfsFormat, tpuV5DeviceIDs)
}

func readHexInt(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	numStr := strings.Trim(strings.TrimSpace(strings.TrimPrefix(string(data), "0x")), "\x00")
	return strconv.ParseUint(numStr, 16, 64)
}
