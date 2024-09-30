// Copyright 2019 The gVisor Authors.
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

package cmd

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/tpu"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// mountInChroot creates the destination mount point in the given chroot and
// mounts the source.
func mountInChroot(chroot, src, dst, typ string, flags uint32) error {
	chrootDst := filepath.Join(chroot, dst)
	log.Infof("Mounting %q at %q", src, chrootDst)

	if err := specutils.SafeSetupAndMount(src, chrootDst, typ, flags, "/proc"); err != nil {
		return fmt.Errorf("error mounting %q at %q: %v", src, chrootDst, err)
	}
	return nil
}

func pivotRoot(root string) error {
	if err := os.Chdir(root); err != nil {
		return fmt.Errorf("error changing working directory: %v", err)
	}
	// pivot_root(new_root, put_old) moves the root filesystem (old_root)
	// of the calling process to the directory put_old and makes new_root
	// the new root filesystem of the calling process.
	//
	// pivot_root(".", ".") makes a mount of the working directory the new
	// root filesystem, so it will be moved in "/" and then the old_root
	// will be moved to "/" too. The parent mount of the old_root will be
	// new_root, so after umounting the old_root, we will see only
	// the new_root in "/".
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root failed, make sure that the root mount has a parent: %v", err)
	}

	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("error umounting the old root file system: %v", err)
	}
	return nil
}

func copyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.ReadFrom(in)
	return err
}

// setUpChroot creates an empty directory with runsc mounted at /runsc and proc
// mounted at /proc.
func setUpChroot(spec *specs.Spec, conf *config.Config) error {
	// Convert all shared mounts into slave to be sure that nothing will be
	// propagated outside of our namespace.
	if err := specutils.SafeMount("", "/", "", unix.MS_SLAVE|unix.MS_REC, "", "/proc"); err != nil {
		return fmt.Errorf("error converting mounts: %v", err)
	}

	// We are a new mount namespace. So create a tmpfs mount over /tmp, which
	// will be released when this sandbox exits. Then create a chroot directory
	// inside this new tmpfs mount at /tmp.
	// NOTE(gvisor.dev/issue/10965): We do not use /tmp as the chroot directory
	// because the runtime or other libraries could have open FDs to it, which
	// would fail some of the below operations with EBUSY.
	tmpDir := os.TempDir()
	if err := specutils.SafeMount("runsc-root", tmpDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "", "/proc"); err != nil {
		return fmt.Errorf("error mounting tmpfs in %q: %v", tmpDir, err)
	}
	chroot, err := os.MkdirTemp(tmpDir, "runsc-chroot-")
	if err != nil {
		return fmt.Errorf("error creating chroot directory: %w", err)
	}
	if err := specutils.SafeMount("runsc-root", chroot, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "", "/proc"); err != nil {
		return fmt.Errorf("error mounting tmpfs in chroot: %v", err)
	}
	log.Infof("Setting up sandbox chroot in %q", chroot)

	if err := os.Mkdir(filepath.Join(chroot, "etc"), 0755); err != nil {
		return fmt.Errorf("error creating /etc in chroot: %v", err)
	}

	if err := copyFile(filepath.Join(chroot, "etc/localtime"), "/etc/localtime"); err != nil {
		log.Warningf("Failed to copy /etc/localtime: %v. UTC timezone will be used.", err)
	}

	flags := uint32(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY)
	if err := mountInChroot(chroot, "proc", "/proc", "proc", flags); err != nil {
		return fmt.Errorf("error mounting proc in chroot: %v", err)
	}

	if err := tpuProxyUpdateChroot("/", chroot, spec, conf); err != nil {
		return fmt.Errorf("error configuring chroot for TPU devices: %w", err)
	}

	if err := specutils.SafeMount("", chroot, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_BIND, "", "/proc"); err != nil {
		return fmt.Errorf("error remounting chroot in read-only: %v", err)
	}

	return pivotRoot(chroot)
}

func tpuProxyUpdateChroot(hostRoot, chroot string, spec *specs.Spec, conf *config.Config) error {
	if !specutils.TPUProxyIsEnabled(spec, conf) {
		return nil
	}
	allowedDeviceIDs := map[uint64]struct{}{}
	paths, err := filepath.Glob(path.Join(hostRoot, "dev/vfio/*"))
	if err != nil {
		return fmt.Errorf("enumerating TPU device files: %w", err)
	}
	vfioDevicePath := path.Join(hostRoot, "dev/vfio/vfio")
	for _, devPath := range paths {
		if devPath == vfioDevicePath {
			continue
		}
		devNum := path.Base(devPath)
		iommuGroupPath := path.Join("/sys/kernel/iommu_groups", devNum)
		if err := mountInChroot(chroot, path.Join(hostRoot, iommuGroupPath), iommuGroupPath, "bind", unix.MS_BIND|unix.MS_RDONLY); err != nil {
			return fmt.Errorf("error mounting %q in chroot: %v", iommuGroupPath, err)
		}
		allowedDeviceIDs[tpu.TPUV5pDeviceID] = struct{}{}
		allowedDeviceIDs[tpu.TPUV5eDeviceID] = struct{}{}
	}
	if len(allowedDeviceIDs) == 0 {
		paths, err = filepath.Glob(path.Join(hostRoot, "dev/accel*"))
		if err != nil {
			return fmt.Errorf("enumerating TPU device files: %w", err)
		}
		if len(paths) == 0 {
			return fmt.Errorf("could not find any TPU devices on the host")
		}
		allowedDeviceIDs[tpu.TPUV4DeviceID] = struct{}{}
		allowedDeviceIDs[tpu.TPUV4liteDeviceID] = struct{}{}
	}
	if len(allowedDeviceIDs) == 0 {
		return fmt.Errorf("no TPU devices found on the host")
	}
	sysDevicesGlob := path.Join(hostRoot, "/sys/devices/pci*")
	sysDevicesPaths, err := filepath.Glob(sysDevicesGlob)
	if err != nil {
		return fmt.Errorf("enumerating PCI device files: %w", err)
	}
	for _, sysDevicesPath := range sysDevicesPaths {
		if err := filepath.WalkDir(sysDevicesPath, func(path string, d os.DirEntry, err error) error {
			if d.Type().IsDir() && util.IsPCIDeviceDirTPU(path, allowedDeviceIDs) {
				chrootPath := strings.Replace(path, hostRoot, "/", 1)
				if err := mountInChroot(chroot, path, chrootPath, "bind", unix.MS_BIND|unix.MS_RDONLY); err != nil {
					return fmt.Errorf("error mounting %q in chroot: %v", path, err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("walking %q: %w", sysDevicesPath, err)
		}
	}
	return err
}
