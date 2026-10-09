// Copyright 2024 The gVisor Authors.
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

package sentrycmd

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strconv"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

func setup(t *testing.T) (string, string) {
	t.Helper()
	testDir := t.TempDir()
	gvisorChroot := path.Join(testDir, "gvisor_chroot")
	os.Mkdir(gvisorChroot, 0755)

	// Mounting the gvisor chroot makes the submounts easier to cleanup at the
	// end of the test.
	if err := unix.Mount(gvisorChroot, gvisorChroot, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("failed to bind mount gvisor chroot: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(gvisorChroot, unix.MNT_DETACH); err != nil {
			t.Fatalf("failed to unmount gvisor chroot: %v", err)
		}
	})
	return testDir, gvisorChroot
}

func TestTPUProxyV5(t *testing.T) {
	testDir, gvisorChroot := setup(t)

	for i := 0; i < 3; i++ {
		os.MkdirAll(path.Join(testDir, "sys", "kernel", "iommu_groups", fmt.Sprintf("%d", i)), 0755)
		writeFile(t, path.Join(testDir, "dev", "vfio", fmt.Sprintf("%d", i)), "")
		pciPath := path.Join(testDir, "sys", "devices", "pci0000:00", fmt.Sprintf("0000:00:00.%d", i))
		writeFile(t, path.Join(pciPath, "device"), "0x0062")
		writeFile(t, path.Join(pciPath, "vendor"), "0x1ae0")
	}

	if err := tpuProxyUpdateChroot(testDir, gvisorChroot, &specs.Spec{}, &config.Config{TPUProxy: true}); err != nil {
		t.Fatalf("failed to update chroot: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := os.Stat(path.Join(gvisorChroot, "sys", "kernel", "iommu_groups", fmt.Sprintf("%d", i))); err != nil {
			t.Errorf("failed to stat iommu group file: %v", err)
		}
		devicePath := path.Join(gvisorChroot, "sys", "devices", "pci0000:00", fmt.Sprintf("0000:00:00.%d", i), "device")
		if _, err := os.ReadFile(devicePath); err != nil {
			t.Errorf("failed to read device file: %v", err)
		}
		vendorPath := path.Join(gvisorChroot, "sys", "devices", "pci0000:00", fmt.Sprintf("0000:00:00.%d", i), "vendor")
		if _, err := os.ReadFile(vendorPath); err != nil {
			t.Errorf("failed to read device file: %v", err)
		}
	}
}

func TestTPUProxyV5NestedPCIDevice(t *testing.T) {
	testDir, gvisorChroot := setup(t)

	for i := 0; i < 3; i++ {
		os.MkdirAll(path.Join(testDir, "sys", "kernel", "iommu_groups", fmt.Sprintf("%d", i)), 0755)
		writeFile(t, path.Join(testDir, "dev", "vfio", fmt.Sprintf("%d", i)), "")
		pciPath := path.Join(testDir, "sys", "devices", "pci0000:00", fmt.Sprintf("0000:00:00.%d", i))
		writeFile(t, path.Join(pciPath, "device"), "0x0062")
		writeFile(t, path.Join(pciPath, "vendor"), "0x1ae0")
	}

	nestedDeviceNum := 3
	writeFile(t, path.Join(testDir, "dev", "vfio", fmt.Sprintf("%d", nestedDeviceNum)), "")
	os.MkdirAll(path.Join(testDir, "sys", "kernel", "iommu_groups", fmt.Sprintf("%d", nestedDeviceNum)), 0755)
	pciPath := path.Join(testDir, "sys", "devices", "pci0000:00", "0000:00:00.2", "0000:00:00.3.0")
	writeFile(t, path.Join(pciPath, "device"), "0x0062")
	writeFile(t, path.Join(pciPath, "vendor"), "0x1ae0")

	if err := tpuProxyUpdateChroot(testDir, gvisorChroot, &specs.Spec{}, &config.Config{TPUProxy: true}); err != nil {
		t.Fatalf("failed to update chroot: %v", err)
	}

	if _, err := os.Stat(path.Join(gvisorChroot, "sys", "kernel", "iommu_groups", fmt.Sprintf("%d", nestedDeviceNum))); err != nil {
		t.Errorf("failed to stat iommu group file: %v", err)
	}
	devicePath := path.Join(gvisorChroot, "sys", "devices", "pci0000:00", "0000:00:00.2", "0000:00:00.3.0", "device")
	if _, err := os.ReadFile(devicePath); err != nil {
		t.Errorf("failed to read device file: %v", err)
	}
}

func TestTPUProxyV4(t *testing.T) {
	testDir, gvisorChroot := setup(t)

	for i := 0; i < 3; i++ {
		os.MkdirAll(path.Join(testDir, "sys", "kernel", "iommu_groups", fmt.Sprintf("%d", i)), 0755)
		writeFile(t, path.Join(testDir, "dev", fmt.Sprintf("accel%d", i)), "")
		pciPath := path.Join(testDir, "sys", "devices", "pci0000:00", fmt.Sprintf("0000:00:00.%d", i))
		writeFile(t, path.Join(pciPath, "device"), "0x005e")
		writeFile(t, path.Join(pciPath, "vendor"), "0x1ae0")
	}

	if err := tpuProxyUpdateChroot(testDir, gvisorChroot, &specs.Spec{}, &config.Config{TPUProxy: true}); err != nil {
		t.Fatalf("failed to update chroot: %v", err)
	}

	for i := 0; i < 3; i++ {
		devicePath := path.Join(gvisorChroot, "sys", "devices", "pci0000:00", fmt.Sprintf("0000:00:00.%d", i), "device")
		if _, err := os.ReadFile(devicePath); err != nil {
			t.Errorf("failed to read device file: %v", err)
		}
		vendorPath := path.Join(gvisorChroot, "sys", "devices", "pci0000:00", fmt.Sprintf("0000:00:00.%d", i), "vendor")
		if _, err := os.ReadFile(vendorPath); err != nil {
			t.Errorf("failed to read device file: %v", err)
		}
	}
}

// TestProcSelfFDBindMount checks that the bind mount of procfs' self/fd set
// up for directfs resolves this process's FDs and does not lead back into
// procfs.
func TestProcSelfFDBindMount(t *testing.T) {
	testDir, gvisorChroot := setup(t)
	if err := setupMinimalProcfs(gvisorChroot, true /* directfs */, nil /* timer */); err != nil {
		t.Fatalf("setupMinimalProcfs failed: %v", err)
	}
	fdDir, err := unix.Open(path.Join(gvisorChroot, procSelfFDBindMount), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("failed to open %q: %v", procSelfFDBindMount, err)
	}
	defer unix.Close(fdDir)

	f, err := os.CreateTemp(testDir, "file")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()
	var want, got unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &want); err != nil {
		t.Fatalf("fstat failed: %v", err)
	}
	if err := unix.Fstatat(fdDir, strconv.Itoa(int(f.Fd())), &got, 0); err != nil {
		t.Fatalf("failed to stat the file through its magic link: %v", err)
	}
	if got.Dev != want.Dev || got.Ino != want.Ino {
		t.Errorf("magic link resolved to (dev %d, ino %d), want (dev %d, ino %d)", got.Dev, got.Ino, want.Dev, want.Ino)
	}

	parent, err := unix.Openat(fdDir, "..", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("failed to open parent of the bind mount: %v", err)
	}
	defer unix.Close(parent)
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(parent, &statfs); err != nil {
		t.Fatalf("fstatfs failed: %v", err)
	}
	if statfs.Type == unix.PROC_SUPER_MAGIC {
		t.Errorf("parent of the bind mount is in procfs")
	}
	var procRoot unix.Stat_t
	if err := unix.Stat(path.Join(gvisorChroot, "proc"), &procRoot); err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if err := unix.Fstat(parent, &got); err != nil {
		t.Fatalf("fstat failed: %v", err)
	}
	if got.Dev != procRoot.Dev || got.Ino != procRoot.Ino {
		t.Errorf("parent of the bind mount is (dev %d, ino %d), want /proc in chroot (dev %d, ino %d)", got.Dev, got.Ino, procRoot.Dev, procRoot.Ino)
	}
}

func writeFile(t *testing.T, fpath string, contents string) {
	t.Helper()
	dir := path.Dir(fpath)
	if st, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}
		} else {
			t.Fatalf("failed to stat directory: %v", err)
		}
	} else if !st.IsDir() {
		t.Fatalf("path %q is not a directory", dir)
	}
	f, err := os.Create(fpath)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	f.WriteString(contents)
	f.Close()
}
