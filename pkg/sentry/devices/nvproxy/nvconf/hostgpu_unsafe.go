// Copyright 2026 The gVisor Authors.
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

package nvconf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

// GPUArchInfo identifies a GPU chip, as returned by
// NV2080_CTRL_CMD_MC_GET_ARCH_INFO.
type GPUArchInfo struct {
	Architecture   uint32
	Implementation uint32
}

// GPUArchitectures returns the host-reported architecture and implementation
// for each exposed GPU minor. It allocates a temporary RM client and children
// on ctlFD, which must be a freshly opened /dev/nvidiactl. The caller must close
// ctlFD afterward to release these resources, and hold an open host FD for
// each queried GPU until this function returns. The host driver checks those
// FDs to authorize device allocation.
func GPUArchitectures(ctlFD int, minors []uint32) (map[uint32]GPUArchInfo, error) {
	if len(minors) == 0 {
		return nil, nil
	}

	var cards [nvgpu.NV_MAX_DEVICES]nvgpu.IoctlCardInfo
	if err := hostGPUIoctl(ctlFD, nvgpu.NV_ESC_CARD_INFO, unsafe.Pointer(&cards), unsafe.Sizeof(cards)); err != nil {
		return nil, fmt.Errorf("NV_ESC_CARD_INFO: %w", err)
	}
	cardByMinor := make(map[uint32]nvgpu.IoctlCardInfo)
	for _, card := range cards {
		if card.Valid != 0 {
			cardByMinor[card.MinorNumber] = card
		}
	}
	var selected []nvgpu.IoctlCardInfo
	seen := make(map[uint32]struct{})
	for _, minor := range minors {
		if _, ok := seen[minor]; ok {
			continue
		}
		card, ok := cardByMinor[minor]
		if !ok {
			return nil, fmt.Errorf("GPU minor %d is exposed but missing from NV_ESC_CARD_INFO", minor)
		}
		seen[minor] = struct{}{}
		selected = append(selected, card)
	}

	var root nvgpu.NVOS64_PARAMETERS
	if err := hostGPUIoctl(ctlFD, nvgpu.NV_ESC_RM_ALLOC, unsafe.Pointer(&root), unsafe.Sizeof(root)); err != nil {
		return nil, fmt.Errorf("allocate GPU architecture query client: %w", err)
	}
	if root.Status != nvgpu.NV_OK {
		return nil, fmt.Errorf("allocate GPU architecture query client: status=%#x", root.Status)
	}
	client := root.HObjectNew

	architectures := make(map[uint32]GPUArchInfo, len(selected))
	for i, card := range selected {
		id := nvgpu.NV0000_CTRL_GPU_GET_ID_INFO_PARAMS{GpuID: card.GPUID}
		if err := hostGPUControl(ctlFD, client, client, nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO, uintptr(unsafe.Pointer(&id)), unsafe.Sizeof(id)); err != nil {
			return nil, fmt.Errorf("query GPU minor %d device instance: %w", card.MinorNumber, err)
		}
		device := nvgpu.Handle{Val: uint32(2*i + 1)}
		subdevice := nvgpu.Handle{Val: uint32(2*i + 2)}
		deviceParams := nvgpu.NV0080_ALLOC_PARAMETERS{DeviceID: id.DeviceInstance}
		if err := hostGPUAlloc(ctlFD, client, client, device, nvgpu.NV01_DEVICE_0, uintptr(unsafe.Pointer(&deviceParams)), unsafe.Sizeof(deviceParams)); err != nil {
			return nil, fmt.Errorf("allocate GPU minor %d device: %w", card.MinorNumber, err)
		}
		subdeviceParams := nvgpu.NV2080_ALLOC_PARAMETERS{SubDeviceID: id.SubDeviceInstance}
		if err := hostGPUAlloc(ctlFD, client, device, subdevice, nvgpu.NV20_SUBDEVICE_0, uintptr(unsafe.Pointer(&subdeviceParams)), unsafe.Sizeof(subdeviceParams)); err != nil {
			return nil, fmt.Errorf("allocate GPU minor %d subdevice: %w", card.MinorNumber, err)
		}
		var arch nvgpu.NV2080_CTRL_MC_GET_ARCH_INFO_PARAMS
		if err := hostGPUControl(ctlFD, client, subdevice, nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO, uintptr(unsafe.Pointer(&arch)), unsafe.Sizeof(arch)); err != nil {
			return nil, fmt.Errorf("query GPU minor %d architecture: %w", card.MinorNumber, err)
		}
		architectures[card.MinorNumber] = GPUArchInfo{Architecture: arch.Architecture, Implementation: arch.Implementation}
	}
	return architectures, nil
}

func hostGPUIoctl(fd int, nr uint32, params unsafe.Pointer, size uintptr) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(linux.IOWR(nvgpu.NV_IOCTL_MAGIC, nr, uint32(size))), uintptr(params)); errno != 0 {
		return errno
	}
	return nil
}

// Parameters stored in a P64 must escape the Go stack before the ioctl helper
// can grow it. uintptrescapes also keeps the target alive throughout this call.
//
//go:uintptrescapes
func hostGPUControl(fd int, client, object nvgpu.Handle, cmd uint32, params uintptr, size uintptr) error {
	ctrl := nvgpu.NVOS54_PARAMETERS{
		HClient:    client,
		HObject:    object,
		Cmd:        cmd,
		Params:     nvgpu.P64(params),
		ParamsSize: uint32(size),
	}
	if err := hostGPUIoctl(fd, nvgpu.NV_ESC_RM_CONTROL, unsafe.Pointer(&ctrl), unsafe.Sizeof(ctrl)); err != nil {
		return err
	}
	if ctrl.Status != nvgpu.NV_OK {
		return fmt.Errorf("control %#x: status=%#x", cmd, ctrl.Status)
	}
	return nil
}

//go:uintptrescapes
func hostGPUAlloc(fd int, client, parent, object nvgpu.Handle, class nvgpu.ClassID, params uintptr, size uintptr) error {
	alloc := nvgpu.NVOS64_PARAMETERS{
		HRoot:         client,
		HObjectParent: parent,
		HObjectNew:    object,
		HClass:        class,
		PAllocParms:   nvgpu.P64(params),
		ParamsSize:    uint32(size),
	}
	if err := hostGPUIoctl(fd, nvgpu.NV_ESC_RM_ALLOC, unsafe.Pointer(&alloc), unsafe.Sizeof(alloc)); err != nil {
		return err
	}
	if alloc.Status != nvgpu.NV_OK {
		return fmt.Errorf("allocate class %#x: status=%#x", class, alloc.Status)
	}
	return nil
}
