// Copyright 2018 Google Inc.
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

package sandbox

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// chrootBinPath is the location inside the chroot where the runsc binary will
// be mounted.
const chrootBinPath = "/runsc"

// mountInChroot creates the destination mount point in the given chroot and
// mounts the source.
func mountInChroot(chroot, src, dst, typ string, flags uint32) error {
	chrootDst := filepath.Join(chroot, dst)
	log.Infof("Mounting %q at %q", src, chrootDst)

	if err := specutils.Mount(src, chrootDst, typ, flags); err != nil {
		return fmt.Errorf("error mounting %q at %q: %v", src, chrootDst, err)
	}
	return nil
}

// setUpChroot creates an empty directory with runsc mounted at /runsc and proc
// mounted at /proc.
func setUpChroot() (string, error) {
	// Create the chroot directory and make it accessible to all users.
	chroot, err := ioutil.TempDir("", "runsc-sandbox-chroot-")
	if err != nil {
		return "", fmt.Errorf("TempDir() failed: %v", err)
	}
	if err := os.Chmod(chroot, 0777); err != nil {
		return "", fmt.Errorf("Chmod(%q) failed: %v", chroot, err)
	}
	log.Infof("Setting up sandbox chroot in %q", chroot)

	// Mount /proc.
	if err := mountInChroot(chroot, "proc", "/proc", "proc", 0); err != nil {
		return "", fmt.Errorf("error mounting proc in chroot: %v", err)
	}

	// Mount runsc at /runsc in the chroot.
	binPath, err := specutils.BinPath()
	if err != nil {
		return "", err
	}
	if err := mountInChroot(chroot, binPath, chrootBinPath, "bind", syscall.MS_BIND|syscall.MS_RDONLY); err != nil {
		return "", fmt.Errorf("error mounting runsc in chroot: %v", err)
	}

	return chroot, nil
}

// tearDownChroot unmounts /proc and /runsc from the chroot before deleting the
// directory.
func tearDownChroot(chroot string) error {
	// Unmount /proc.
	proc := filepath.Join(chroot, "proc")
	if err := syscall.Unmount(proc, 0); err != nil {
		return fmt.Errorf("error unmounting %q: %v", proc, err)
	}

	// Unmount /runsc.
	exe := filepath.Join(chroot, chrootBinPath)
	if err := syscall.Unmount(exe, 0); err != nil {
		return fmt.Errorf("error unmounting %q: %v", exe, err)
	}

	// Remove chroot directory.
	if err := os.RemoveAll(chroot); err != nil {
		return fmt.Errorf("error removing %q: %v", chroot, err)
	}

	return nil
}
