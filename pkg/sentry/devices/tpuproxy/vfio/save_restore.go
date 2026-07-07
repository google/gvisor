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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/fdnotifier"
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

// TPUDeviceRemappingFromContext returns the TPUDeviceRemapping associated with
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

	dr := TPUDeviceRemappingFromContext(ctx)
	if dr == nil {
		panic("TPUDeviceRemapping is required for TPU restore")
	}
	if g, ok := dr.NewGroupByOldGroup[oldGroup]; ok {
		newGroup = g
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
