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
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rdma"
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
		writeFile(t, path.Join(testDir, "dev", "vfio", "devices", fmt.Sprintf("vfio%d", i)), "")
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
		writeFile(t, path.Join(testDir, "dev", "vfio", "devices", fmt.Sprintf("vfio%d", i)), "")
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

// addTestPCIFunction adds an NVIDIA PCI function at leaf, relative to sysRoot,
// and binds it to driver.
func addTestPCIFunction(t *testing.T, sysRoot, leaf, driver string) {
	t.Helper()
	writeFile(t, path.Join(sysRoot, leaf, "vendor"), "0x10de\n")
	link := path.Join(sysRoot, "bus/pci/drivers", driver, path.Base(leaf))
	if err := os.MkdirAll(path.Dir(link), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.Symlink(path.Join(sysRoot, leaf), link); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}
}

func TestGPUSysfsUpdateChroot(t *testing.T) {
	sysRoot, chroot := t.TempDir(), t.TempDir()
	const (
		gpu      = "devices/pci0000:00/0000:00:09.0"
		nvswitch = "devices/pci0000:00/0000:00:0a.0"
		vfioGPU  = "devices/pci0000:00/0000:00:0b.0"
	)
	addTestPCIFunction(t, sysRoot, gpu, "nvidia")
	addTestPCIFunction(t, sysRoot, nvswitch, "nvidia-nvswitch")
	addTestPCIFunction(t, sysRoot, vfioGPU, "vfio-pci")
	config := strings.Repeat("c", 256)
	writeFile(t, path.Join(sysRoot, gpu, "config"), config)

	// GPUs bound to VFIO drivers are left out, and only the header of the
	// config space is kept.
	if !gpuSysfsUpdateChroot(sysRoot, chroot) {
		t.Fatal("gpuSysfsUpdateChroot saved no snapshot")
	}
	snap, err := rdma.Load(path.Join(chroot, rdma.Path))
	if err != nil {
		t.Fatalf("loading the snapshot failed: %v", err)
	}
	var got []string
	for _, n := range snap.PCINodes {
		got = append(got, n.Path)
		if n.Path == gpu && string(n.Config) != config[:64] {
			t.Errorf("GPU config = %q, want its header", n.Config)
		}
	}
	if want := []string{"devices/pci0000:00", gpu, nvswitch}; !slices.Equal(got, want) {
		t.Errorf("PCI node paths = %v, want %v", got, want)
	}
}

func TestGPUSysfsUpdateChrootWithoutSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name string
		leaf string
	}{
		{name: "no GPUs"},
		// Hyper-V places PCI root complexes below a VMBus device, outside
		// /sys/devices/pci*, which the collector does not handle.
		{name: "unsupported layout", leaf: "devices/LNXSYSTM:00/VMBUS:00/7e8a5a8c-0000-0000-0000-000000000000/pci0001:00/0001:00:00.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sysRoot, chroot := t.TempDir(), t.TempDir()
			if tc.leaf != "" {
				addTestPCIFunction(t, sysRoot, tc.leaf, "nvidia")
			}
			if gpuSysfsUpdateChroot(sysRoot, chroot) {
				t.Error("gpuSysfsUpdateChroot saved a snapshot")
			}
			if _, err := os.Stat(path.Join(chroot, rdma.Path)); !os.IsNotExist(err) {
				t.Errorf("stat of the snapshot returned %v, want ENOENT", err)
			}
		})
	}
}

// TestLoadGPUSysfsSnapshot checks that sandboxes start without the GPU sysfs
// snapshot if it is absent or cannot be loaded.
func TestLoadGPUSysfsSnapshot(t *testing.T) {
	dir := t.TempDir()
	if snap := loadGPUSysfsSnapshot(path.Join(dir, "absent.json")); snap != nil {
		t.Errorf("loadGPUSysfsSnapshot of an absent file = %+v, want nil", snap)
	}
	corrupt := path.Join(dir, "corrupt.json")
	writeFile(t, corrupt, "{")
	if snap := loadGPUSysfsSnapshot(corrupt); snap != nil {
		t.Errorf("loadGPUSysfsSnapshot of a corrupt file = %+v, want nil", snap)
	}
	want := &rdma.Snapshot{PCINodes: []rdma.PCINode{{Path: "devices/pci0000:00"}}}
	saved := path.Join(dir, "saved.json")
	if err := want.Save(saved); err != nil {
		t.Fatalf("Save(%q) failed: %v", saved, err)
	}
	if got := loadGPUSysfsSnapshot(saved); !reflect.DeepEqual(got, want) {
		t.Errorf("loadGPUSysfsSnapshot of a saved snapshot = %+v, want %+v", got, want)
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
