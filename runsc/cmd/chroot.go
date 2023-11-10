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
	"regexp"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
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
func setUpChroot(pidns bool, spec *specs.Spec, conf *config.Config) error {
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

	if pidns {
		flags := uint32(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY)
		if err := mountInChroot(chroot, "proc", "/proc", "proc", flags); err != nil {
			return fmt.Errorf("error mounting proc in chroot: %v", err)
		}
	} else {
		if err := mountInChroot(chroot, "/proc", "/proc", "bind", unix.MS_BIND|unix.MS_RDONLY|unix.MS_REC); err != nil {
			return fmt.Errorf("error mounting proc in chroot: %v", err)
		}
	}

	if err := tpuProxyUpdateChroot(chroot, spec, conf); err != nil {
		return fmt.Errorf("error configuring chroot for TPU devices: %w", err)
	}

	if err := specutils.SafeMount("", chroot, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_BIND, "", "/proc"); err != nil {
		return fmt.Errorf("error remounting chroot in read-only: %v", err)
	}

	return pivotRoot(chroot)
}

func tpuProxyUpdateChroot(chroot string, spec *specs.Spec, conf *config.Config) error {
	if !specutils.TPUProxyIsEnabled(spec, conf) {
		return nil
	}
	devices, err := util.EnumerateHostTPUDevices()
	if err != nil {
		return fmt.Errorf("enumerating TPU device files: %w", err)
	}
	for _, deviceNum := range devices {
		devPath := fmt.Sprintf("/dev/accel%d", deviceNum)
		if err := mountInChroot(chroot, devPath, devPath, "bind", unix.MS_BIND); err != nil {
			return fmt.Errorf("error mounting %q in chroot: %v", devPath, err)
		}
		finfo, err := os.Stat(path.Join(chroot, devPath))
		if err != nil {
			return fmt.Errorf("error statting %q: %v", devPath, err)
		}
		// Ensure the file mounted in was a char device file.
		if finfo.Mode()&os.ModeType != os.ModeCharDevice|os.ModeDevice {
			return fmt.Errorf("unexpected file type for %q, want %s, got %s", path.Join(chroot, devPath), os.ModeCharDevice|os.ModeDevice, finfo.Mode()&os.ModeType)

		}
		// Multiple paths link to the /sys/devices/pci0000:00/<pci_address>
		// directory that contains all relevant sysfs accel device info that we need
		// bind mounted into the sandbox chroot. We can construct this path by
		// reading the link below, which points to
		// /sys/devices/pci0000:00/<pci_address>/accel/accel# and traversing up 2
		// directories.
		sysAccelPath := fmt.Sprintf("/sys/class/accel/accel%d", deviceNum)
		sysAccelLink, err := os.Readlink(sysAccelPath)
		if err != nil {
			return fmt.Errorf("error reading %q: %v", sysAccelPath, err)
		}
		// Ensure the link is in the form we expect.
		sysAccelLinkMatcher := regexp.MustCompile(fmt.Sprintf(`../../devices/pci0000:00/(\d+:\d+:\d+\.\d+)/accel/accel%d`, deviceNum))
		if !sysAccelLinkMatcher.MatchString(sysAccelLink) {
			return fmt.Errorf("unexpected link %q -> %q, link should have %q format", sysAccelPath, sysAccelLink, sysAccelLinkMatcher.String())
		}
		sysPCIDeviceDir, err := filepath.Abs(path.Join(filepath.Dir(sysAccelPath), sysAccelLink, "../.."))
		if err != nil {
			return fmt.Errorf("error parsing path %q: %v", sysAccelPath, err)
		}
		if err := mountInChroot(chroot, sysPCIDeviceDir, sysPCIDeviceDir, "bind", unix.MS_BIND|unix.MS_RDONLY); err != nil {
			return fmt.Errorf("error mounting %q in chroot: %v", sysAccelPath, err)
		}
	}
	return nil
}
