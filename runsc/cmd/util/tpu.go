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

	"gvisor.dev/gvisor/pkg/abi/tpu"
)

const googleVendorID = 0x1AE0

var tpuV4DeviceIDs = map[uint64]any{tpu.TPUV4DeviceID: nil, tpu.TPUV4liteDeviceID: nil}

// TODO(b/288456802): Add support for /dev/vfio controlled accelerators.
// This is required for v5+ TPUs.

// ExtractTpuDeviceMinor returns the accelerator device minor number for that
// the passed device path. If the passed device is not a valid TPU device, then
// it returns false. TPU device is defined as:
// * Path is /dev/accel#.
// * Vendor is googleVendorID.
// * Device ID is one of tpuV4DeviceIDs.
func ExtractTpuDeviceMinor(path string) (uint32, bool, error) {
	accelDeviceRegex := regexp.MustCompile(`^/dev/accel(\d+)$`)
	ms := accelDeviceRegex.FindStringSubmatch(path)
	if ms == nil {
		return 0, false, nil
	}
	index, err := strconv.ParseUint(ms[1], 10, 32)
	if err != nil {
		return 0, false, fmt.Errorf("invalid host device file %q: %w", path, err)
	}
	vendor, err := readHexInt(fmt.Sprintf("/sys/class/accel/accel%d/device/vendor", index))
	if err != nil {
		return 0, false, err
	}
	if vendor != googleVendorID {
		return 0, false, nil
	}
	deviceID, err := readHexInt(fmt.Sprintf("/sys/class/accel/accel%d/device/device", index))
	if err != nil {
		return 0, false, err
	}
	if _, ok := tpuV4DeviceIDs[deviceID]; !ok {
		return 0, false, nil
	}
	return uint32(index), true, nil
}

func readHexInt(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	numStr := strings.Trim(strings.TrimSpace(strings.TrimPrefix(string(data), "0x")), "\x00")
	return strconv.ParseUint(numStr, 16, 64)
}
