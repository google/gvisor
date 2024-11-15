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

// setupMinimalProcfs creates a minimal procfs-like tree at `${chroot}/proc`.
func setupMinimalProcfs(chroot string) error {
	// We can't always directly mount procfs because it may be obstructed
	// by submounts within it. See https://gvisor.dev/issue/10944.
	// All we really need from procfs is /proc/self and a few kernel
	// parameter files, which are typically not obstructed.
	// So we create a tmpfs at /proc and manually copy the kernel parameter
	// files into it. Then, to get /proc/self, we mount either a new
	// instance of procfs (if possible), or a recursive bind mount of the
	// procfs we do have access to (which still contains the obstructed
	// submounts but /proc/self is not obstructed), and we symlink
	// our /proc/self to the one in that mount.
	//
	// Why not try to mount the new procfs instance at /proc directly?
	// Because that would cause the set of files at /proc to differ
	// between the "new procfs instance" case and the "recursive bind
	// mount" case. Thus, this could introduce a bug whereby gVisor starts
	// to depend on a /proc file that is present in one case but not the
	// other, without decent test coverage to catch it.
	procRoot := filepath.Join(chroot, "/proc")
	if err := os.Mkdir(procRoot, 0755); err != nil {
		return fmt.Errorf("error creating /proc in chroot: %v", err)
	}
	if err := specutils.SafeMount("runsc-proc", procRoot, "tmpfs",
		unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "", "/proc"); err != nil {
		return fmt.Errorf("error mounting tmpfs in /proc: %v", err)
	}
	flags := uint32(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY)
	procSubmountDir := "sandbox-proc"
	if newProcfsErr := mountInChroot(chroot, "proc", "/proc/"+procSubmountDir, "proc", flags); newProcfsErr != nil {
		log.Debugf("Unable to mount a new instance of the procfs file system at %q (%v); trying a recursive bind mount instead.", filepath.Join(procRoot, procSubmountDir), newProcfsErr)
		procSubmountDir = "host-proc"
		if bindErr := mountInChroot(chroot, "/proc", "/proc/"+procSubmountDir, "bind",
			unix.MS_BIND|unix.MS_REC|flags); bindErr != nil {
			return fmt.Errorf("error recursively bind-mounting proc at %q (%w) after also failing to mount a new procfs instance there (%v)", filepath.Join(procRoot, procSubmountDir), bindErr, newProcfsErr)
		}
		log.Debugf("Successfully mounted a recursive bind mount of procfs at %q; continuing.", filepath.Join(procRoot, procSubmountDir))
	}
	// Create needed directories.
	for _, d := range []string{
		"/proc/sys",
		"/proc/sys/kernel",
		"/proc/sys/vm",
	} {
		if err := os.Mkdir(filepath.Join(chroot, d), 0755); err != nil {
			return fmt.Errorf("error creating directory %q: %v", filepath.Join(chroot, d), err)
		}
	}
	// Copy needed files.
	for _, f := range []string{
		"/proc/sys/vm/mmap_min_addr",
		"/proc/sys/kernel/cap_last_cap",
	} {
		if err := copyFile(filepath.Join(chroot, f), f); err != nil {
			return fmt.Errorf("failed to copy %q -> %q: %w", f, filepath.Join(chroot, f), err)
		}
	}
	// Create symlink for /proc/self.
	if err := os.Symlink(procSubmountDir+"/self", filepath.Join(procRoot, "self")); err != nil {
		return fmt.Errorf("error creating symlink %q -> %q: %w", filepath.Join(procRoot, "self"), procSubmountDir+"/self", err)
	}
	if err := os.Symlink(procSubmountDir+"/cpuinfo", filepath.Join(procRoot, "cpuinfo")); err != nil {
		return fmt.Errorf("error creating symlink %q -> %q: %w", filepath.Join(procRoot, "cpuinfo"), procSubmountDir+"/cpuinfo", err)
	}
	if err := os.Chmod(procRoot, 0o111); err != nil {
		return fmt.Errorf("error chmodding %q: %v", procRoot, err)
	}
	return nil
}

// setUpChroot creates an empty directory with runsc mounted at /runsc and proc
// mounted at /proc.
func setUpChroot(spec *specs.Spec, conf *config.Config) error {
	// We are a new mount namespace, so we can use /tmp as a directory to
	// construct a new root.
	chroot := os.TempDir()

	log.Infof("Setting up sandbox chroot in %q", chroot)

	// Convert all shared mounts into slave to be sure that nothing will be
	// propagated outside of our namespace.
	if err := specutils.SafeMount("", "/", "", unix.MS_SLAVE|unix.MS_REC, "", "/proc"); err != nil {
		return fmt.Errorf("error converting mounts: %v", err)
	}

	if err := specutils.SafeMount("runsc-root", chroot, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "", "/proc"); err != nil {
		return fmt.Errorf("error mounting tmpfs in chroot: %v", err)
	}

	if err := os.Mkdir(filepath.Join(chroot, "etc"), 0755); err != nil {
		return fmt.Errorf("error creating /etc in chroot: %v", err)
	}

	if err := copyFile(filepath.Join(chroot, "etc/localtime"), "/etc/localtime"); err != nil {
		log.Warningf("Failed to copy /etc/localtime: %v. UTC timezone will be used.", err)
	}

	if err := setupMinimalProcfs(chroot); err != nil {
		return fmt.Errorf("error setting up minimal procfs in chroot %q: %v", chroot, err)
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
		allowedDeviceIDs[tpu.TPUV6eDeviceID] = struct{}{}
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
