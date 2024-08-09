// Copyright 2024 The gVisor Authors.
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

// Package tpuproxy contains tpu backend driver proxy implementations and
// helper functions.
package tpuproxy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/tpu"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy/accel"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy/vfio"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	pciPathGlobTPUv4   = "/sys/devices/pci0000:*/*/accel/accel*"
	pciPathGlobTPUv5   = "/sys/devices/pci0000:*/*/vfio-dev/vfio*"
	iommuGroupPathGlob = "/sys/kernel/iommu_groups/*/devices/*"
)

var (
	// pathGlobToPathRegex is a map that points a TPU PCI path glob to its path regex.
	// TPU v4 devices are accessible via /sys/devices/pci0000:00/<pci_address>/accel/accel# on the host.
	// TPU v5 devices are accessible via at /sys/devices/pci0000:00/<pci_address>/vfio-dev/vfio# on the host.
	pathGlobToPathRegex = map[string]string{
		pciPathGlobTPUv4: `^/sys/devices/pci0000:[[:xdigit:]]{2}/\d+:\d+:\d+\.\d+/accel/accel(\d+)$`,
		pciPathGlobTPUv5: `^/sys/devices/pci0000:[[:xdigit:]]{2}/\d+:\d+:\d+\.\d+/vfio-dev/vfio(\d+)$`,
	}
)

// RegisterHostTPUDevices enumerates TPU devices on the host and registers them
// in the sandbox VFS.
func RegisterHostTPUDevices(vfsObj *vfs.VirtualFilesystem) error {
	for pciPathGlobal, pathRegex := range pathGlobToPathRegex {
		pciAddrs, err := filepath.Glob(pciPathGlobal)
		if err != nil {
			return fmt.Errorf("enumerating PCI device files: %w", err)
		}
		pciPathRegex := regexp.MustCompile(pathRegex)
		for _, pciPath := range pciAddrs {
			ms := pciPathRegex.FindStringSubmatch(pciPath)
			if ms == nil {
				continue
			}
			deviceNum, err := strconv.ParseUint(ms[1], 10, 32)
			if err != nil {
				return fmt.Errorf("parsing PCI device number: %w", err)
			}
			var deviceIDBytes []byte
			if deviceIDBytes, err = os.ReadFile(path.Join(pciPath, "device/device")); err != nil {
				return fmt.Errorf("reading PCI device ID: %w", err)
			}
			deviceIDStr := strings.Replace(string(deviceIDBytes), "0x", "", -1)
			deviceID, err := strconv.ParseInt(strings.TrimSpace(deviceIDStr), 16, 64)
			if err != nil {
				return fmt.Errorf("parsing PCI device ID: %w", err)
			}
			// VFIO iommu groups correspond to the device minor number. Use these
			// paths to get the correct minor number for the sentry-internal TPU
			// device files.
			var minorNum int
			switch deviceID {
			case tpu.TPUV4DeviceID, tpu.TPUV4liteDeviceID:
				minorNum = int(deviceNum)
			case tpu.TPUV5eDeviceID, tpu.TPUV5pDeviceID:
				groupPaths, err := filepath.Glob(iommuGroupPathGlob)
				if err != nil {
					return fmt.Errorf("enumerating IOMMU group files: %w", err)
				}
				for _, groupPath := range groupPaths {
					pci := path.Base(groupPath)
					if strings.Contains(pciPath, pci) {
						minor, err := strconv.Atoi(strings.Split(groupPath, "/")[4])
						if err != nil {
							return fmt.Errorf("parsing IOMMU group minor number: %w", err)
						}
						minorNum = minor
						break
					}
				}
			default:
				return fmt.Errorf("unsupported TPU device with ID: 0x%x", deviceID)
			}
			if err := registerTPUDevice(vfsObj, uint32(minorNum), uint32(deviceNum), deviceID); err != nil {
				return fmt.Errorf("registering TPU driver: %w", err)
			}
		}
	}
	return nil
}

// registerTPUDevice registers a TPU device in vfsObj based on the given device ID.
func registerTPUDevice(vfsObj *vfs.VirtualFilesystem, minor, deviceNum uint32, deviceID int64) error {
	switch deviceID {
	case tpu.TPUV4DeviceID, tpu.TPUV4liteDeviceID:
		return accel.RegisterTPUDevice(vfsObj, minor, deviceID == tpu.TPUV4liteDeviceID)
	case tpu.TPUV5eDeviceID, tpu.TPUV5pDeviceID:
		return vfio.RegisterTPUDevice(vfsObj, minor, deviceNum)
	default:
		return fmt.Errorf("unsupported TPU device with ID: 0x%x", deviceID)
	}
}
