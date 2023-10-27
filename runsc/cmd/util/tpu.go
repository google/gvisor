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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/tpu"
)

const googleVendorID = 0x1AE0

var tpuV4DeviceIDs = map[uint64]any{tpu.TPUV4DeviceID: nil, tpu.TPUV4liteDeviceID: nil}

// TODO(b/288456802): Add support for /dev/vfio controlled accelerators.
// This is required for v5+ TPUs.

// EnumerateHostTPUDevices returns the accelerator device minor numbers of all
// TPUs on the machine.
func EnumerateHostTPUDevices() ([]uint32, error) {
	paths, err := filepath.Glob("/dev/accel*")
	if err != nil {
		return nil, fmt.Errorf("enumerating TPU device files: %w", err)
	}

	accelDeviceRegex := regexp.MustCompile(`^/dev/accel(\d+)$`)
	var devMinors []uint32
	for _, path := range paths {
		if ms := accelDeviceRegex.FindStringSubmatch(path); ms != nil {
			index, err := strconv.ParseUint(ms[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid host device file %q: %w", path, err)
			}

			vendor, err := readHexInt(fmt.Sprintf("/sys/class/accel/accel%d/device/vendor", index))
			if err != nil {
				return nil, err
			}
			if vendor != googleVendorID {
				continue
			}
			deviceID, err := readHexInt(fmt.Sprintf("/sys/class/accel/accel%d/device/device", index))
			if err != nil {
				return nil, err
			}
			if _, ok := tpuV4DeviceIDs[deviceID]; !ok {
				continue
			}

			devMinors = append(devMinors, uint32(index))
		}
	}
	return devMinors, nil
}

func readHexInt(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	numStr := strings.Trim(strings.TrimSpace(strings.TrimPrefix(string(data), "0x")), "\x00")
	return strconv.ParseUint(numStr, 16, 64)
}
