// Copyright 2025 The gVisor Authors.
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

package vfio

import (
	goContext "context"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy/util"
)

// TPUContextID is a Context.Value key for TPU-related context values.
type TPUContextID int

const (
	// CtxTPUDeviceRemapping is a Context.Value key for a TPUDeviceRemapping.
	CtxTPUDeviceRemapping TPUContextID = iota
)

// TPUDeviceRemapID identifies a TPU device for remapping.
type TPUDeviceRemapID struct {
	BDF      string `json:"bdf"`
	GroupNum uint32 `json:"group_num"`
}

// TPUDeviceRemapping specifies the remapping for TPU devices.
type TPUDeviceRemapping struct {
	NewBDFByOldBDF     map[string]string
	NewGroupByOldGroup map[uint32]uint32
	NewGroupByNewBDF   map[string]uint32
}

// TPUDeviceRemappingFromContext returns the TPUDeviceRemapping associated witw
// ctx.
func TPUDeviceRemappingFromContext(ctx goContext.Context) *TPUDeviceRemapping {
	if r := ctx.Value(CtxTPUDeviceRemapping); r != nil {
		return r.(*TPUDeviceRemapping)
	}
	return nil
}

func (fd *tpuFD) beforeSave() {
	fd.Release(context.Background())
	fd.hostFD = -1
}

func (fd *tpuFD) afterLoad(ctx goContext.Context) {
	oldGroup := fd.device.num
	newGroup := oldGroup

	if dr := TPUDeviceRemappingFromContext(ctx); dr != nil {
		if g, ok := dr.NewGroupByOldGroup[oldGroup]; ok {
			newGroup = g
		}
	}

	devPath := filepath.Join("vfio", fmt.Sprintf("%d", newGroup))
	fd.hostFD = openHostFileForRestore(ctx, devPath, fd.device.useDevGofer, fd.containerName, fd.vfsfd.StatusFlags())
	if err := fdnotifier.AddFD(fd.hostFD, &fd.queue); err != nil {
		panic(fmt.Sprintf("fdnotifier.AddFD(%d) failed for vfio group %d: %v", fd.hostFD, newGroup, err))
	}
	fd.memmapFile.SetFD(int(fd.hostFD))

	fd.device.num = newGroup

	fd.device.tpuproxy.trackFD(fd)
}

func (fd *vfioFD) beforeSave() {
	fd.Release(context.Background())
	fd.hostFD = -1
}

func (fd *vfioFD) afterLoad(ctx goContext.Context) {
	fd.hostFD = openHostFileForRestore(ctx, "vfio/vfio", fd.device.useDevGofer, fd.containerName, fd.vfsfd.StatusFlags())
	if err := fdnotifier.AddFD(fd.hostFD, &fd.queue); err != nil {
		panic(fmt.Sprintf("fdnotifier.AddFD(%d) failed for vfio container: %v", fd.hostFD, err))
	}
	fd.memmapFile.SetFD(int(fd.hostFD))
	fd.device.tpuproxy.trackFD(fd)
}

func (fd *pciDeviceFD) beforeSave() {
	fd.Release(context.Background())
	fd.hostFD = -1
}

func (fd *pciDeviceFD) afterLoad(ctx goContext.Context) {
	oldBDF := fd.deviceAddress
	newBDF := oldBDF

	dr := TPUDeviceRemappingFromContext(ctx)
	if dr != nil {
		if b, ok := dr.NewBDFByOldBDF[oldBDF]; ok {
			newBDF = b
		}
	}

	var newGroup uint32
	if dr != nil {
		newGroup = dr.NewGroupByNewBDF[newBDF]
	} else {
		// If no remapping, we assume the group is the same as the old one.
		// Since we don't have the old group, we panic. We require remapping.
		panic("TPUDeviceRemapping is required for TPU restore")
	}

	groupDevPath := filepath.Join("vfio", fmt.Sprintf("%d", newGroup))
	useDevGofer := false
	if clientProvider := devutil.GoferClientProviderFromContext(ctx); clientProvider != nil {
		useDevGofer = true
	}

	groupHostFD := openHostFileForRestore(ctx, groupDevPath, useDevGofer, fd.containerName, uint32(unix.O_RDWR))
	defer unix.Close(int(groupHostFD))

	pciAddressBytes, err := unix.ByteSliceFromString(newBDF)
	if err != nil {
		panic(fmt.Sprintf("failed to create BDF byte slice for %s: %v", newBDF, err))
	}
	hostFD, err := util.IOCTLInvokePtrArg[uint32](groupHostFD, linux.VFIO_GROUP_GET_DEVICE_FD, &pciAddressBytes[0])
	if err != nil {
		panic(fmt.Sprintf("VFIO_GROUP_GET_DEVICE_FD failed for BDF %s in group %d: %v", newBDF, newGroup, err))
	}

	fd.hostFD = int32(hostFD)
	fd.deviceAddress = newBDF

	if err := fdnotifier.AddFD(fd.hostFD, &fd.queue); err != nil {
		unix.Close(int(hostFD))
		panic(fmt.Sprintf("fdnotifier.AddFD(%d) failed for pci device %s: %v", fd.hostFD, newBDF, err))
	}

	fd.memmapFile.SetFD(int(fd.hostFD))
	fd.tpuproxy.trackFD(fd)
}

func openHostFileForRestore(ctx goContext.Context, relpath string, useDevGofer bool, containerName string, openFlags uint32) int32 {
	if useDevGofer {
		clientProvider := devutil.GoferClientProviderFromContext(ctx)
		if clientProvider == nil {
			panic("devutil.CtxDevGoferClientProvider is not set")
		}
		devClient := clientProvider.GetDevGoferClient(containerName)
		hostFD, err := devClient.OpenAt(ctx.(context.Context), relpath, openFlags)
		if err != nil {
			panic(fmt.Sprintf("failed to open device gofer %s: %v", relpath, err))
		}
		return int32(hostFD)
	}
	abspath := filepath.Join("/dev", relpath)
	hostFD, err := unix.Openat(-1, abspath, int(openFlags&unix.O_ACCMODE|unix.O_NOFOLLOW), 0)
	if err != nil {
		panic(fmt.Sprintf("failed to open host %s: %v", abspath, err))
	}
	return int32(hostFD)
}
