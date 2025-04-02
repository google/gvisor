// Copyright 2025 The gVisor Authors.
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

package sys

import (
	"path"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context) error {
	return nil
}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	// If TPU proxy paths are not enabled, there is nothing to restore. Otherwise,
	// we need to repopulate the PCI devices and IOMMU groups from a potentially
	// different host. The easiest way to do that is just rebuild these paths from
	// scratch.
	if !fs.enableTPUProxyPaths {
		return nil
	}
	creds := auth.CredentialsFromContext(ctx)

	if err := removeSysDir(ctx, fs.root, "class"); err != nil {
		return err
	}
	if err := removeSysDir(ctx, fs.root, "devices"); err != nil {
		return err
	}
	if err := removeSysDir(ctx, fs.root, "bus"); err != nil {
		return err
	}
	if err := removeSysDir(ctx, fs.root, "kernel"); err != nil {
		return err
	}

	classSub := map[string]kernfs.Inode{
		"power_supply": fs.newDir(ctx, creds, defaultSysDirMode, nil),
	}
	devicesSub := map[string]kernfs.Inode{
		"system": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"cpu": cpuDir(ctx, fs, creds),
		}),
	}
	busSub := make(map[string]kernfs.Inode)
	kernelSub := kernelDir(ctx, fs, creds)

	sysDevicesPath := path.Join(fs.testSysfsPathPrefix, sysDevicesMainPath)
	iommuGroupsPath := path.Join(fs.testSysfsPathPrefix, iommuGroupSysPath)
	pciInfos, err := pciDeviceInfos(sysDevicesPath, iommuGroupsPath)
	if err != nil {
		return err
	}

	sysDevicesSub, err := fs.mirrorSysDevicesDir(ctx, creds, sysDevicesPath, pciInfos)
	if err != nil {
		return err
	}
	for dir, sub := range sysDevicesSub {
		devicesSub[dir] = sub
	}

	deviceDirs, err := fs.newDeviceClassDir(ctx, creds, []string{accelDevice, vfioDevice}, sysDevicesPath, pciInfos)
	if err != nil {
		return err
	}
	for tpuDeviceType, symlinkDir := range deviceDirs {
		classSub[tpuDeviceType] = fs.newDir(ctx, creds, defaultSysDirMode, symlinkDir)
	}

	pciDevicesSub, err := fs.newBusPCIDevicesDir(ctx, creds, pciInfos)
	if err != nil {
		return err
	}
	busSub["pci"] = fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
		"devices": fs.newDir(ctx, creds, defaultSysDirMode, pciDevicesSub),
	})

	iommuGroups, err := fs.mirrorIOMMUGroups(ctx, creds, iommuGroupsPath, pciInfos)
	if err != nil {
		return err
	}
	kernelSub["iommu_groups"] = fs.newDir(ctx, creds, defaultSysDirMode, iommuGroups)

	fs.root.OrderedChildren.Populate(map[string]kernfs.Inode{
		"class":   fs.newDir(ctx, creds, defaultSysDirMode, classSub),
		"devices": fs.newDir(ctx, creds, defaultSysDirMode, devicesSub),
		"bus":     fs.newDir(ctx, creds, defaultSysDirMode, busSub),
		"kernel":  fs.newDir(ctx, creds, defaultSysDirMode, kernelSub),
	})
	return nil
}

func removeSysDir(ctx context.Context, root *dir, name string) error {
	dir, err := root.OrderedChildren.Lookup(ctx, name)
	if err != nil {
		return err
	}
	return root.OrderedChildren.RmDir(ctx, name, dir)
}
