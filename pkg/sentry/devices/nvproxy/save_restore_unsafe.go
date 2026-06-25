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

package nvproxy

import (
	"fmt"
	"maps"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
)

// FillDeviceRemapIDsFromMinor fills all DeviceRemapID fields in ids based on
// DeviceRemapID.Minor and DeviceRemapID.DevGoferClient.
func FillDeviceRemapIDsFromMinor(ctx context.Context, ctlDevClient *devutil.GoferClient, ids []DeviceRemapID) error {
	if len(ids) == 0 {
		return nil
	}

	var ctlFD uintptr
	if ctlDevClient != nil {
		fd, err := ctlDevClient.OpenAt(ctx, "nvidiactl", unix.O_RDONLY)
		if err != nil {
			return fmt.Errorf("failed to open nvidiactl: %w", err)
		}
		ctlFD = uintptr(fd)
	} else {
		fd, err := unix.Openat(-1, "/dev/nvidiactl", unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("failed to open nvidiactl: %w", err)
		}
		ctlFD = uintptr(fd)
	}
	defer unix.Close(int(ctlFD))

	// Minor => PCIVendorID, PCIDeviceID, GPUID
	var cardInfos [nvgpu.NV_MAX_DEVICES]nvgpu.IoctlCardInfo
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, ctlFD, frontendIoctlCmd(nvgpu.NV_ESC_CARD_INFO, uint32(unsafe.Sizeof(cardInfos))), uintptr(unsafe.Pointer(&cardInfos))); errno != 0 {
		return fmt.Errorf("NV_ESC_CARD_INFO failed: %w", errno)
	}
	cardInfoFromMinor := make(map[uint32]*nvgpu.IoctlCardInfo)
	for i := range cardInfos {
		ci := &cardInfos[i]
		if ci.Valid != 0 {
			cardInfoFromMinor[ci.MinorNumber] = ci
		}
	}
	for i := range ids {
		id := &ids[i]
		ci, ok := cardInfoFromMinor[id.Minor]
		if !ok {
			return fmt.Errorf("NV_ESC_CARD_INFO returned no info for minor %d: got minors %v", id.Minor, slices.Collect(maps.Keys(cardInfoFromMinor)))
		}
		id.PCIVendorID = ci.PCIInfo.VendorID
		id.PCIDeviceID = ci.PCIInfo.DeviceID
		id.GPUID = ci.GPUID
	}

	// GPUID => DeviceInstance, SubDeviceInstance
	var allocParams nvgpu.NVOS64_PARAMETERS
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, ctlFD, frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC, uint32(unsafe.Sizeof(allocParams))), uintptr(unsafe.Pointer(&allocParams))); errno != 0 {
		return fmt.Errorf("failed to allocate root client: %w", errno)
	}
	if allocParams.Status != nvgpu.NV_OK {
		return fmt.Errorf("failed to allocate root client: status=%#x", allocParams.Status)
	}
	hClient := allocParams.HObjectNew
	for i := range ids {
		id := &ids[i]
		idInfoParams := nvgpu.NV0000_CTRL_GPU_GET_ID_INFO_PARAMS{
			GpuID: id.GPUID,
		}
		ctrlParams := nvgpu.NVOS54_PARAMETERS{
			HClient:    hClient,
			HObject:    hClient,
			Cmd:        nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO,
			Params:     p64FromPtr(unsafe.Pointer(&idInfoParams)),
			ParamsSize: uint32(unsafe.Sizeof(idInfoParams)),
		}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, ctlFD, frontendIoctlCmd(nvgpu.NV_ESC_RM_CONTROL, uint32(unsafe.Sizeof(ctrlParams))), uintptr(unsafe.Pointer(&ctrlParams))); errno != 0 {
			return fmt.Errorf("NV0000_CTRL_CMD_GPU_GET_ID_INFO for minor=%d gpuId=%#x failed: %w", id.Minor, id.GPUID, errno)
		}
		if ctrlParams.Status != nvgpu.NV_OK {
			return fmt.Errorf("NV0000_CTRL_CMD_GPU_GET_ID_INFO for minor=%d gpuId=%#x failed: status=%#x", id.Minor, id.GPUID, ctrlParams.Status)
		}
		id.DeviceInstance = idInfoParams.DeviceInstance
		id.SubDeviceInstance = idInfoParams.SubDeviceInstance
	}

	// GPUID => UUID
	var attachIDsParams nvgpu.NV0000_CTRL_GPU_ATTACH_IDS_PARAMS
	for i := range ids {
		attachIDsParams.GPUIDs[i] = ids[i].GPUID
	}
	if len(ids) < len(attachIDsParams.GPUIDs) {
		attachIDsParams.GPUIDs[len(ids)] = nvgpu.NV0000_CTRL_GPU_INVALID_ID
	}
	ctrlParams := nvgpu.NVOS54_PARAMETERS{
		HClient:    hClient,
		HObject:    hClient,
		Cmd:        nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS,
		Params:     p64FromPtr(unsafe.Pointer(&attachIDsParams)),
		ParamsSize: uint32(unsafe.Sizeof(attachIDsParams)),
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, ctlFD, frontendIoctlCmd(nvgpu.NV_ESC_RM_CONTROL, uint32(unsafe.Sizeof(ctrlParams))), uintptr(unsafe.Pointer(&ctrlParams))); errno != 0 {
		return fmt.Errorf("NV0000_CTRL_CMD_GPU_ATTACH_IDS failed: %w", errno)
	}
	if ctrlParams.Status != nvgpu.NV_OK {
		return fmt.Errorf("NV0000_CTRL_CMD_GPU_ATTACH_IDS failed: failedId=%#x status=%#x", attachIDsParams.FailedID, ctrlParams.Status)
	}
	for i := range ids {
		id := &ids[i]
		getUUIDParams := nvgpu.NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS{
			GPUID: id.GPUID,
		}
		ctrlParams := nvgpu.NVOS54_PARAMETERS{
			HClient:    hClient,
			HObject:    hClient,
			Cmd:        nvgpu.NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID,
			Params:     p64FromPtr(unsafe.Pointer(&getUUIDParams)),
			ParamsSize: uint32(unsafe.Sizeof(getUUIDParams)),
		}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, ctlFD, frontendIoctlCmd(nvgpu.NV_ESC_RM_CONTROL, uint32(unsafe.Sizeof(ctrlParams))), uintptr(unsafe.Pointer(&ctrlParams))); errno != 0 {
			return fmt.Errorf("NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID for minor=%d gpuId=%#x failed: %w", id.Minor, id.GPUID, errno)
		}
		if ctrlParams.Status != nvgpu.NV_OK {
			return fmt.Errorf("NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID for minor=%d gpuId=%#x failed: status=%#x", id.Minor, id.GPUID, ctrlParams.Status)
		}
		// UUIDStrLen includes the trailing zero byte; see
		// src/nvidia/src/kernel/gpu/gpu_uuid.c:transformGidToUserFriendlyString()
		// => src/nvidia/inc/kernel/gpu/gpu_uuid.h:NV_UUID_STR_LEN.
		if getUUIDParams.UUIDStrLen > 0 {
			id.UUID = string(getUUIDParams.GPUUUID[:getUUIDParams.UUIDStrLen-1])
		}
	}

	return nil
}

func (c *capturedRmAllocParams) restore() error {
	// Copy all parameters that might be driver-mutated to avoid modifying c.
	ioctlParams := c.ioctlParams
	rightsRequested := c.rightsRequested
	allocParams := append([]byte{}, c.allocParams...)
	if ioctlParams.PRightsRequested != 0 {
		defer runtime.KeepAlive(rightsRequested)
		ioctlParams.PRightsRequested = p64FromPtr(unsafe.Pointer(&rightsRequested))
	}
	if len(allocParams) == 0 {
		ioctlParams.PAllocParms = 0
	} else {
		defer runtime.KeepAlive(allocParams)
		ioctlParams.PAllocParms = p64FromPtr(unsafe.Pointer(&allocParams[0]))
	}

	h := ioctlParams.HObjectNew
	if _, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(c.fd.hostFD), frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC, nvgpu.SizeofNVOS64Parameters), uintptr(unsafe.Pointer(&ioctlParams))); errno != 0 {
		return errno
	}
	if ioctlParams.Status != 0 {
		return fmt.Errorf("NvStatus %d", ioctlParams.Status)
	}
	if ioctlParams.HObjectNew != h {
		return fmt.Errorf("got unexpected handle %#x", ioctlParams.HObjectNew)
	}
	return nil
}
