// Copyright 2026 The gVisor Authors.
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

package nvconf

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

// DefaultDevRoots is the default list of dev roots: the host's root, then
// where the NVIDIA GPU Operator's driver container publishes the driver.
const DefaultDevRoots = "/,/run/nvidia/driver"

// ParseDevRoots parses commaSeparatedRoots, a comma-separated list of absolute
// host directories under which the NVIDIA device files may be found.
func ParseDevRoots(commaSeparatedRoots string) ([]string, error) {
	roots := strings.Split(commaSeparatedRoots, ",")
	for _, root := range roots {
		if root == "" {
			return nil, errors.New("dev root must not be empty")
		}
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("dev root %q must be an absolute path", root)
		}
	}
	return roots, nil
}

// ResolveDevRoot returns the host directory under which the NVIDIA device
// files are found: the first of the directories in commaSeparatedRoots that
// contains the NVIDIA control device, dev/nvidiactl. The control device must be
// a character device with the control device's major and minor numbers. The
// result has its symlinks resolved. It is an error if there is none.
func ResolveDevRoot(commaSeparatedRoots string) (string, error) {
	return resolveDevRoot(commaSeparatedRoots, unix.Lstat)
}

// resolveDevRoot is ResolveDevRoot with the function that stats the control
// device, so that tests can stand regular files in for device files.
func resolveDevRoot(commaSeparatedRoots string, lstat func(string, *unix.Stat_t) error) (string, error) {
	roots, err := ParseDevRoots(commaSeparatedRoots)
	if err != nil {
		return "", err
	}

	var errs []error
	for _, root := range roots {
		devRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := checkNVControlDevice(devRoot, lstat); err != nil {
			errs = append(errs, err)
			continue
		}
		return devRoot, nil
	}
	return "", fmt.Errorf("no NVIDIA control device found: %w", errors.Join(errs...))
}

// checkNVControlDevice returns an error unless devRoot has the NVIDIA control
// device. A dev root belongs to whatever installed the driver, so a regular
// file or a symlink there must not pass for the device.
func checkNVControlDevice(devRoot string, lstat func(string, *unix.Stat_t) error) error {
	path := filepath.Join(devRoot, "/dev/nvidiactl")
	var st unix.Stat_t
	if err := lstat(path, &st); err != nil {
		return fmt.Errorf("lstat(%q): %w", path, err)
	}
	return checkNVControlDeviceStat(path, &st)
}

// checkNVControlDeviceStat returns an error unless st, the stat of path, is
// that of the NVIDIA control device.
func checkNVControlDeviceStat(path string, st *unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return fmt.Errorf("%s is not a character device", path)
	}
	major, minor := unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))
	if major != nvgpu.NV_MAJOR_DEVICE_NUMBER || minor != nvgpu.NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE {
		return fmt.Errorf("%s is device %d:%d, want %d:%d", path, major, minor, nvgpu.NV_MAJOR_DEVICE_NUMBER, nvgpu.NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE)
	}
	return nil
}
