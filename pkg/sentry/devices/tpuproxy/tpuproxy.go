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
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/tpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy/accel"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy/vfio"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

var (
	// TPUv4DeviceRegex is the regex for detecting TPUv4 device paths.
	TPUv4DeviceRegex = regexp.MustCompile(`/dev/accel(\d+)`)

	// TPUv5DeviceRegex is the regex for detecting TPUv5 device paths.
	TPUv5DeviceRegex = regexp.MustCompile(`/dev/vfio/(\d+)`)
)

// RegisterTPUv4Device registers the TPUv4 device with the provided minor number
// where the corresponding PCI device is located at pciPath. Accel devices
// always have their device file number set to their minor number.
func RegisterTPUv4Device(ctx context.Context, creds *auth.Credentials, root vfs.VirtualDentry, vfsObj *vfs.VirtualFilesystem, devPath string, minorNum uint32) error {
	// Get the PCI path from the accel device's symlink at
	// /sys/class/accel/accel\d+. The link will be in the form
	// "../../devices/pci0000:*/**/accel/accel\d+".
	linkPath := filepath.Join("/sys/class/accel", filepath.Base(devPath))
	linkContent, err := vfsObj.ReadlinkAt(ctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(linkPath)})
	if err != nil {
		return fmt.Errorf("reading link %q: %w", linkPath, err)
	}
	// Exclude the ../../devices prefix and the accel/accel\d+ suffix.
	pciPath := strings.TrimSuffix(strings.TrimPrefix(linkContent, "../../devices"), fmt.Sprintf("accel/%s", filepath.Base(devPath)))
	pciDeviceIDPath := path.Join("/sys/devices", pciPath, "device")

	fd, err := unix.Openat(-1, pciDeviceIDPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), pciDeviceIDPath)
	defer file.Close()
	buf := bytes.Buffer{}
	if _, err := buf.ReadFrom(file); err != nil {
		return err
	}

	deviceIDStr := strings.Replace(buf.String(), "0x", "", -1)
	deviceID, err := strconv.ParseInt(strings.TrimSpace(deviceIDStr), 16, 64)
	if err != nil {
		return fmt.Errorf("parsing PCI device ID: %w", err)
	}
	if err := accel.RegisterTPUDevice(vfsObj, minorNum, deviceID == tpu.TPUV4liteDeviceID); err != nil {
		return fmt.Errorf("registering TPU driver: %w", err)
	}
	return nil
}

// RegisterTPUv5Device registers the TPUv5 device with the provided device path
// and minor number.
func RegisterTPUv5Device(vfsObj *vfs.VirtualFilesystem, devPath string, minorNum uint32) error {
	deviceNum, err := strconv.ParseInt(path.Base(devPath), 10, 32)
	if err != nil {
		return fmt.Errorf("parsing device path number: %w", err)
	}
	if err := vfio.RegisterTPUDevice(vfsObj, uint32(minorNum), uint32(deviceNum), true /* useDevGofer */); err != nil {
		return fmt.Errorf("registering TPU driver: %w", err)
	}
	return nil
}
