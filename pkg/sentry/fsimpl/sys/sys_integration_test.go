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

package sys_test

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	vfioDev = "vfio-dev"
)

func newTestSystem(t *testing.T, pciTestDir string) *testutil.System {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("Failed to create test kernel: %v", err)
	}
	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)
	k.VFS().MustRegisterFilesystemType(sys.Name, sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	mountOpts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: &sys.InternalData{
				EnableTPUProxyPaths: pciTestDir != "",
				TestSysfsPathPrefix: pciTestDir,
			},
		},
	}

	mns, err := k.VFS().NewMountNamespace(ctx, creds, "", sys.Name, mountOpts, nil)
	if err != nil {
		t.Fatalf("Failed to create new mount namespace: %v", err)
	}
	return testutil.NewSystem(ctx, t, k.VFS(), mns)
}

func TestReadCPUFile(t *testing.T) {
	s := newTestSystem(t, "" /*pciTestDir*/)
	defer s.Destroy()
	k := kernel.KernelFromContext(s.Ctx)
	maxCPUCores := k.ApplicationCores()

	expected := fmt.Sprintf("0-%d\n", maxCPUCores-1)

	for _, fname := range []string{"online", "possible", "present"} {
		pop := s.PathOpAtRoot(fmt.Sprintf("devices/system/cpu/%s", fname))
		fd, err := s.VFS.OpenAt(s.Ctx, s.Creds, pop, &vfs.OpenOptions{})
		if err != nil {
			t.Fatalf("OpenAt(pop:%+v) = %+v failed: %v", pop, fd, err)
		}
		defer fd.DecRef(s.Ctx)
		content, err := s.ReadToEnd(fd)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if diff := cmp.Diff(expected, content); diff != "" {
			t.Fatalf("Read returned unexpected data:\n--- want\n+++ got\n%v", diff)
		}
	}
}

func TestSysRootContainsExpectedEntries(t *testing.T) {
	s := newTestSystem(t, "" /*pciTestDir*/)
	defer s.Destroy()
	pop := s.PathOpAtRoot("/")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
		"block":    linux.DT_DIR,
		"bus":      linux.DT_DIR,
		"class":    linux.DT_DIR,
		"dev":      linux.DT_DIR,
		"devices":  linux.DT_DIR,
		"firmware": linux.DT_DIR,
		"fs":       linux.DT_DIR,
		"kernel":   linux.DT_DIR,
		"module":   linux.DT_DIR,
		"power":    linux.DT_DIR,
	})
}

func TestCgroupMountpointExists(t *testing.T) {
	// Note: The mountpoint is only created if cgroups are available.
	s := newTestSystem(t, "" /*pciTestDir*/)
	defer s.Destroy()
	pop := s.PathOpAtRoot("/fs")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
		"cgroup": linux.DT_DIR,
	})
	pop = s.PathOpAtRoot("/fs/cgroup")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{ /*empty*/ })
}

// Check that sysfs creates the required PCI paths for V4 TPUs.
func TestEnableTPUProxyPathsV4(t *testing.T) {
	// Set up the fs tree that will be mirrored in the sentry.
	sysfsTestDir := t.TempDir()
	busPath := path.Join(sysfsTestDir, "sys", "bus", "pci", "devices")
	if err := os.MkdirAll(busPath, 0755); err != nil {
		t.Fatalf("Failed to create bus directory: %v", err)
	}
	classAccelPath := path.Join(sysfsTestDir, "sys", "class", "accel")
	if err := os.MkdirAll(classAccelPath, 0755); err != nil {
		t.Fatalf("Failed to create accel directory: %v", err)
	}
	for i, pciAddress := range []string{"0000:00:04.0", "0000:00:05.0"} {
		accelDev := fmt.Sprintf("accel%d", i)
		accelPath := path.Join(sysfsTestDir, "sys", "devices", "pci0000:00", pciAddress, "accel", accelDev)
		if err := os.MkdirAll(accelPath, 0755); err != nil {
			t.Fatalf("Failed to create accel directory: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "..", pciAddress), path.Join(accelPath, pciAddress)); err != nil {
			t.Fatalf("Failed to symlink accel directory: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "..", pciAddress), path.Join(accelPath, "device")); err != nil {
			t.Fatalf("Failed to symlink accel device directory: %v", err)
		}
		if _, err := os.Create(path.Join(accelPath, "chip_model")); err != nil {
			t.Fatalf("Failed to create chip_model: %v", err)
		}
		if _, err := os.Create(path.Join(accelPath, "device_owner")); err != nil {
			t.Fatalf("Failed to create device_owner: %v", err)
		}
		if _, err := os.Create(path.Join(accelPath, "pci_address")); err != nil {
			t.Fatalf("Failed to create pci_address: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "..", "devices", "pci0000:00", pciAddress), path.Join(busPath, pciAddress)); err != nil {
			t.Fatalf("Failed to symlink bus directory: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "devices", "pci0000:00", pciAddress, "accel", accelDev), path.Join(classAccelPath, accelDev)); err != nil {
			t.Fatalf("Failed to symlink accel directory: %v", err)
		}
	}

	s := newTestSystem(t, sysfsTestDir)
	defer s.Destroy()

	pop := s.PathOpAtRoot("/devices/pci0000:00")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
		"0000:00:04.0": linux.DT_DIR,
		"0000:00:05.0": linux.DT_DIR,
	})
	pop = s.PathOpAtRoot("/devices/pci0000:00/0000:00:04.0/accel/accel0")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
		"0000:00:04.0": linux.DT_LNK,
		"device":       linux.DT_LNK,
		"chip_model":   linux.DT_REG,
		"device_owner": linux.DT_REG,
		"pci_address":  linux.DT_REG,
	})
	pop = s.PathOpAtRoot("/bus/pci/devices")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
		"0000:00:04.0": linux.DT_LNK,
		"0000:00:05.0": linux.DT_LNK,
	})
	pop = s.PathOpAtRoot("/class/accel")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
		"accel0": linux.DT_LNK,
		"accel1": linux.DT_LNK,
	})
}

type PCIDeviceInfo struct {
	// IOMMU group.
	group             string
	pciPath           string
	pciAddress        string
	name              string
	nestedDeviceIndex int
}

func (dev PCIDeviceInfo) path() string {
	return path.Join(dev.pciPath, dev.pciAddress, vfioDev, dev.name)
}

func TestEnableTPUProxyPathsV5(t *testing.T) {
	// Set up the fs tree that will be mirrored in the sentry.
	sysfsTestDir := t.TempDir()
	pciPath0 := path.Join(sysfsTestDir, "sys", "devices", "pci0000:00")
	if err := os.MkdirAll(pciPath0, 0755); err != nil {
		t.Fatalf("Failed to create PCI directory: %v", err)
	}
	pciPath1 := path.Join(sysfsTestDir, "sys", "devices", "pci0000:10")
	if err := os.MkdirAll(pciPath1, 0755); err != nil {
		t.Fatalf("Failed to create PCI directory: %v", err)
	}
	busPath := path.Join(sysfsTestDir, "sys", "bus", "pci", "devices")
	if err := os.MkdirAll(busPath, 0755); err != nil {
		t.Fatalf("Failed to create bus directory: %v", err)
	}
	sysClassPath := path.Join(sysfsTestDir, "sys", "class", vfioDev)
	if err := os.MkdirAll(sysClassPath, 0755); err != nil {
		t.Fatalf("Failed to create class directory: %v", err)
	}

	devices := []PCIDeviceInfo{
		{
			group:             "0",
			pciPath:           pciPath0,
			pciAddress:        "0000:00:04.0",
			name:              "vfio0",
			nestedDeviceIndex: -1,
		},
		{
			group:             "1",
			pciPath:           pciPath0,
			pciAddress:        "0000:00:05.0",
			name:              "vfio1",
			nestedDeviceIndex: -1,
		},
		{
			group:             "2",
			pciPath:           pciPath1,
			pciAddress:        "0000:10:05.0",
			name:              "vfio2",
			nestedDeviceIndex: 3,
		},
		{
			group:             "3",
			pciPath:           pciPath1,
			pciAddress:        "0000:10:05.0/0000:03:00.1",
			name:              "vfio3",
			nestedDeviceIndex: -1,
		},
	}
	for _, device := range devices {
		devicePath := device.path()
		if err := os.MkdirAll(devicePath, 0755); err != nil {
			t.Fatalf("Failed to create PCI device directory: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "..", device.pciAddress), path.Join(devicePath, "device")); err != nil {
			t.Fatalf("Failed to symlink device directory: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "..", "devices", path.Base(device.pciPath), device.pciAddress), path.Join(busPath, path.Base(device.pciAddress))); err != nil {
			t.Fatalf("Failed to symlink bus directory: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "devices", path.Base(device.pciPath), device.pciAddress, vfioDev, device.name), path.Join(sysClassPath, device.name)); err != nil {
			t.Fatalf("Failed to symlink class directory: %v", err)
		}
		iommuPath := path.Join(sysfsTestDir, "sys", "kernel", "iommu_groups", device.group, "devices")
		if err := os.MkdirAll(iommuPath, 0755); err != nil {
			t.Fatalf("Failed to create iommu_groups directory: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "..", "..", "devices", path.Base(device.pciPath), device.pciAddress), path.Join(iommuPath, path.Base(device.pciAddress))); err != nil {
			t.Fatalf("Failed to symlink iommu_group devices directory: %v", err)
		}
		if err := os.Symlink(path.Join("..", "..", "..", "kernel", "iommu_groups", device.group), path.Join(device.pciPath, device.pciAddress, "iommu_group")); err != nil {
			t.Fatalf("Failed to symlink iommu_groups directory: %v", err)
		}
	}
	s := newTestSystem(t, sysfsTestDir)
	defer s.Destroy()

	for _, device := range devices {
		// Validate PCI device symlinks.
		pop := s.PathOpAtRoot(path.Join("devices", path.Base(device.pciPath), device.pciAddress))
		contents := map[string]testutil.DirentType{
			"iommu_group": linux.DT_LNK,
			vfioDev:       linux.DT_DIR,
		}
		if device.nestedDeviceIndex != -1 {
			deviceName := path.Base(devices[device.nestedDeviceIndex].pciAddress)
			contents[deviceName] = linux.DT_DIR
		}
		s.AssertAllDirentTypes(s.ListDirents(pop), contents)
		// Validate VFIO device symlinks.
		pop = s.PathOpAtRoot(path.Join("devices", path.Base(device.pciPath), device.pciAddress, vfioDev, device.name))
		s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
			"device": linux.DT_LNK,
		})
		// Validate $IOMMU_GROUP/devices.
		pop = s.PathOpAtRoot(path.Join("kernel", "iommu_groups", string(device.group), "devices"))
		s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
			path.Base(device.pciAddress): linux.DT_LNK,
		})
	}
}
