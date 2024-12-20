// Copyright 2023 The gVisor Authors.
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
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

func frontendIoctlInvoke[Params any, PtrParams hasStatusPtr[Params]](fi *frontendIoctlState, ioctlParams PtrParams) (uintptr, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fi.fd.hostFD), frontendIoctlCmd(fi.nr, fi.ioctlParamsSize), uintptr(unsafe.Pointer(ioctlParams)))
	if errno != 0 {
		return n, errno
	}
	if log.IsLogging(log.Debug) {
		if status := ioctlParams.GetStatus(); status != nvgpu.NV_OK {
			fi.ctx.Debugf("nvproxy: frontend ioctl failed: status=%#x", status)
		}
	}
	return n, nil
}

func frontendIoctlBytesInvoke(fi *frontendIoctlState, sentryParams *byte) (uintptr, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fi.fd.hostFD), frontendIoctlCmd(fi.nr, fi.ioctlParamsSize), uintptr(unsafe.Pointer(sentryParams)))
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

func rmControlInvoke[Params any](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters, ctrlParams *Params) (uintptr, error) {
	defer runtime.KeepAlive(ctrlParams) // since we convert to non-pointer-typed P64
	origParams := ioctlParams.Params
	ioctlParams.Params = p64FromPtr(unsafe.Pointer(ctrlParams))
	n, err := frontendIoctlInvoke(fi, ioctlParams)
	ioctlParams.Params = origParams
	if err != nil {
		return n, err
	}
	if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlClientSystemGetBuildVersionInvoke(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters, ctrlParams *nvgpu.NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS, driverVersionBuf, versionBuf, titleBuf *byte) (uintptr, error) {
	// *Buf arguments don't need runtime.KeepAlive() since our caller
	// ctrlClientSystemGetBuildVersion() copies them out, keeping them alive
	// during this function.
	origPDriverVersionBuffer := ctrlParams.PDriverVersionBuffer
	origPVersionBuffer := ctrlParams.PVersionBuffer
	origPTitleBuffer := ctrlParams.PTitleBuffer
	ctrlParams.PDriverVersionBuffer = p64FromPtr(unsafe.Pointer(driverVersionBuf))
	ctrlParams.PVersionBuffer = p64FromPtr(unsafe.Pointer(versionBuf))
	ctrlParams.PTitleBuffer = p64FromPtr(unsafe.Pointer(titleBuf))
	n, err := rmControlInvoke(fi, ioctlParams, ctrlParams)
	ctrlParams.PDriverVersionBuffer = origPDriverVersionBuffer
	ctrlParams.PVersionBuffer = origPVersionBuffer
	ctrlParams.PTitleBuffer = origPTitleBuffer
	if err != nil {
		return n, err
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlIoctlHasInfoList[Params any, PtrParams hasCtrlInfoListPtr[Params]](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParamsValue Params
	ctrlParams := PtrParams(&ctrlParamsValue)

	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}
	var infoList []byte
	if listSize := ctrlParams.ListSize(); listSize > 0 {
		if !rmapiParamsSizeCheck(listSize, nvgpu.CtrlXxxInfoSize) {
			return 0, ctrlCmdFailWithStatus(fi, ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
		}
		infoList = make([]byte, listSize*nvgpu.CtrlXxxInfoSize)
		if _, err := fi.t.CopyInBytes(addrFromP64(ctrlParams.CtrlInfoList()), infoList); err != nil {
			return 0, err
		}
	}

	origInfoList := ctrlParams.CtrlInfoList()
	if infoList == nil {
		ctrlParams.SetCtrlInfoList(p64FromPtr(unsafe.Pointer(nil)))
	} else {
		ctrlParams.SetCtrlInfoList(p64FromPtr(unsafe.Pointer(&infoList[0])))
	}
	n, err := rmControlInvoke(fi, ioctlParams, ctrlParams)
	ctrlParams.SetCtrlInfoList(origInfoList)
	if err != nil {
		return n, err
	}

	if infoList != nil {
		if _, err := fi.t.CopyOutBytes(addrFromP64(origInfoList), infoList); err != nil {
			return n, err
		}
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}

	return n, nil
}

func ctrlGetNvU32ListInvoke(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters, ctrlParams *nvgpu.RmapiParamNvU32List, list []uint32) (uintptr, error) {
	origList := ctrlParams.List
	ctrlParams.List = p64FromPtr(unsafe.Pointer(&list[0]))
	n, err := rmControlInvoke(fi, ioctlParams, ctrlParams)
	ctrlParams.List = origList
	if err != nil {
		return n, err
	}
	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(ctrlParams.List), list); err != nil {
		return n, err
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlDevGRGetCapsInvoke(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters, ctrlParams *nvgpu.NV0080_CTRL_GET_CAPS_PARAMS, capsTbl []byte) (uintptr, error) {
	origCapsTbl := ctrlParams.CapsTbl
	ctrlParams.CapsTbl = p64FromPtr(unsafe.Pointer(&capsTbl[0]))
	n, err := rmControlInvoke(fi, ioctlParams, ctrlParams)
	ctrlParams.CapsTbl = origCapsTbl
	if err != nil {
		return n, err
	}
	if _, err := primitive.CopyByteSliceOut(fi.t, addrFromP64(ctrlParams.CapsTbl), capsTbl); err != nil {
		return n, err
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlDevFIFOGetChannelList(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}
	if ctrlParams.NumChannels == 0 {
		// Compare
		// src/nvidia/src/kernel/gpu/fifo/kernel_fifo_ctrl.c:deviceCtrlCmdFifoGetChannelList_IMPL().
		return 0, linuxerr.EINVAL
	}
	channelHandleList := make([]uint32, ctrlParams.NumChannels)
	if _, err := primitive.CopyUint32SliceIn(fi.t, addrFromP64(ctrlParams.PChannelHandleList), channelHandleList); err != nil {
		return 0, err
	}
	channelList := make([]uint32, ctrlParams.NumChannels)
	if _, err := primitive.CopyUint32SliceIn(fi.t, addrFromP64(ctrlParams.PChannelList), channelList); err != nil {
		return 0, err
	}

	origPChannelHandleList := ctrlParams.PChannelHandleList
	origPChannelList := ctrlParams.PChannelList
	ctrlParams.PChannelHandleList = p64FromPtr(unsafe.Pointer(&channelHandleList[0]))
	ctrlParams.PChannelList = p64FromPtr(unsafe.Pointer(&channelList[0]))
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	ctrlParams.PChannelHandleList = origPChannelHandleList
	ctrlParams.PChannelList = origPChannelList
	if err != nil {
		return n, err
	}

	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(origPChannelHandleList), channelHandleList); err != nil {
		return n, err
	}
	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(origPChannelList), channelList); err != nil {
		return n, err
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}

	return n, nil
}

func ctrlClientSystemGetP2PCapsInitializeArray(origArr nvgpu.P64, gpuCount uint32) (nvgpu.P64, []uint32, bool) {
	// The driver doesn't try and copy memory if the array is null. See
	// src/nvidia/src/kernel/rmapi/embedded_param_copy.c::embeddedParamCopyIn(),
	// case NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS.
	if origArr == 0 {
		return 0, nil, true
	}

	// Params size is gpuCount * gpuCount * sizeof(NvU32).
	numEntries := gpuCount * gpuCount
	if numEntries*4 > nvgpu.RMAPI_PARAM_COPY_MAX_PARAMS_SIZE {
		return 0, nil, false
	}

	arr := make([]uint32, numEntries)
	return p64FromPtr(unsafe.Pointer(&arr[0])), arr, true
}

func ctrlClientSystemGetP2PCaps(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	origBusPeerIDs := ctrlParams.BusPeerIDs
	busPeerIDs, busPeerIDsBuf, ok := ctrlClientSystemGetP2PCapsInitializeArray(origBusPeerIDs, ctrlParams.GpuCount)
	if !ok {
		return 0, ctrlCmdFailWithStatus(fi, ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
	}
	ctrlParams.BusPeerIDs = busPeerIDs

	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	ctrlParams.BusPeerIDs = origBusPeerIDs
	if err != nil {
		return n, err
	}

	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(origBusPeerIDs), busPeerIDsBuf); err != nil {
		return n, err
	}

	_, err = ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params))
	return n, err
}

func ctrlClientSystemGetP2PCapsV550(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	origBusPeerIDs := ctrlParams.BusPeerIDs
	busPeerIDs, busPeerIDsBuf, ok := ctrlClientSystemGetP2PCapsInitializeArray(origBusPeerIDs, ctrlParams.GpuCount)
	if !ok {
		return 0, ctrlCmdFailWithStatus(fi, ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
	}
	ctrlParams.BusPeerIDs = busPeerIDs

	origBusEgmPeerIDs := ctrlParams.BusEgmPeerIDs
	busEgmPeerIDs, busEgmPeerIDsBuf, ok := ctrlClientSystemGetP2PCapsInitializeArray(origBusEgmPeerIDs, ctrlParams.GpuCount)
	if !ok {
		return 0, ctrlCmdFailWithStatus(fi, ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
	}
	ctrlParams.BusEgmPeerIDs = busEgmPeerIDs

	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	ctrlParams.BusPeerIDs = origBusPeerIDs
	ctrlParams.BusEgmPeerIDs = origBusEgmPeerIDs
	if err != nil {
		return n, err
	}

	// If origBufPeerIDS or origBusEgmPeerIDs is null, the corresponding buffer will be nil
	// and CopyUint32SliceOut() will be a no-op.
	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(origBusPeerIDs), busPeerIDsBuf); err != nil {
		return n, err
	}
	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(origBusEgmPeerIDs), busEgmPeerIDsBuf); err != nil {
		return n, err
	}
	_, err = ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params))
	return n, err
}

func rmAllocInvoke[Params any](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, allocParams *Params, isNVOS64 bool, addObjLocked func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *Params)) (uintptr, error) {
	defer runtime.KeepAlive(allocParams) // since we convert to non-pointer-typed P64

	// Temporarily replace application pointers with sentry pointers.
	origPAllocParms := ioctlParams.PAllocParms
	origPRightsRequested := ioctlParams.PRightsRequested
	var rightsRequested nvgpu.RS_ACCESS_MASK
	if ioctlParams.PRightsRequested != 0 {
		if _, err := rightsRequested.CopyIn(fi.t, addrFromP64(ioctlParams.PRightsRequested)); err != nil {
			return 0, err
		}
		ioctlParams.PRightsRequested = p64FromPtr(unsafe.Pointer(&rightsRequested))
	}
	ioctlParams.PAllocParms = p64FromPtr(unsafe.Pointer(allocParams))

	// Invoke the driver ioctl and restore application pointers. We always pass
	// NVOS64Parameters to the driver even if !isNVOS64, as this is handled
	// identically to the equivalent NVOS21Parameters; compare
	// src/nvidia/src/kernel/rmapi/entry_points.c:_nv04AllocWithSecInfo() and
	// _nv04AllocWithAccessSecInfo().
	origParamsSize := fi.ioctlParamsSize
	fi.ioctlParamsSize = nvgpu.SizeofNVOS64Parameters
	fi.fd.dev.nvp.objsLock()
	n, err := frontendIoctlInvoke(fi, ioctlParams)
	fi.ioctlParamsSize = origParamsSize
	if err == nil && ioctlParams.Status == nvgpu.NV_OK {
		addObjLocked(fi, ioctlParams, rightsRequested, allocParams)
	}
	fi.fd.dev.nvp.objsUnlock()
	ioctlParams.PAllocParms = origPAllocParms
	ioctlParams.PRightsRequested = origPRightsRequested
	if err != nil {
		return n, err
	}

	// Copy updated params out to the application.
	outIoctlParams := nvgpu.GetRmAllocParamObj(isNVOS64)
	outIoctlParams.FromOS64(*ioctlParams)
	if ioctlParams.PRightsRequested != 0 {
		if _, err := rightsRequested.CopyOut(fi.t, addrFromP64(ioctlParams.PRightsRequested)); err != nil {
			return n, err
		}
	}
	if _, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func rmIdleChannelsInvoke(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS30Parameters, clientsBuf, devicesBuf, channelsBuf *byte) (uintptr, error) {
	origClients := ioctlParams.Clients
	origDevices := ioctlParams.Devices
	origChannels := ioctlParams.Channels
	ioctlParams.Clients = p64FromPtr(unsafe.Pointer(clientsBuf))
	ioctlParams.Devices = p64FromPtr(unsafe.Pointer(devicesBuf))
	ioctlParams.Channels = p64FromPtr(unsafe.Pointer(channelsBuf))
	n, err := frontendIoctlInvoke(fi, ioctlParams)
	ioctlParams.Clients = origClients
	ioctlParams.Devices = origDevices
	ioctlParams.Channels = origChannels
	if err != nil {
		return n, err
	}
	if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func rmVidHeapControlAllocSize(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS32Parameters) (uintptr, error) {
	allocSizeParams := (*nvgpu.NVOS32AllocSize)(unsafe.Pointer(&ioctlParams.Data))
	origAddress := allocSizeParams.Address
	var addr uint64
	if allocSizeParams.Address != 0 {
		if _, err := primitive.CopyUint64In(fi.t, addrFromP64(allocSizeParams.Address), &addr); err != nil {
			return 0, err
		}
		allocSizeParams.Address = p64FromPtr(unsafe.Pointer(&addr))
	}

	fi.fd.dev.nvp.objsLock()
	n, err := frontendIoctlInvoke(fi, ioctlParams)
	if err == nil && ioctlParams.Status == nvgpu.NV_OK {
		// src/nvidia/interface/deprecated/rmapi_deprecated_vidheapctrl.c:_rmVidHeapControlAllocCommon()
		if allocSizeParams.Flags&nvgpu.NVOS32_ALLOC_FLAGS_VIRTUAL != 0 {
			// src/nvidia/src/kernel/mem_mgr/virtual_mem.c:virtmemConstruct_IMPL() => refAddDependant()
			fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, allocSizeParams.HMemory, nvgpu.NV50_MEMORY_VIRTUAL, &miscObject{}, ioctlParams.HObjectParent, ioctlParams.HVASpace)
		} else {
			classID := nvgpu.ClassID(nvgpu.NV01_MEMORY_SYSTEM)
			if (allocSizeParams.Attr2>>nvgpu.NVOS32_ATTR2_USE_EGM_SHIFT)&nvgpu.NVOS32_ATTR2_USE_EGM_MASK == nvgpu.NVOS32_ATTR2_USE_EGM_TRUE {
				classID = nvgpu.NV_MEMORY_EXTENDED_USER
			} else if (allocSizeParams.Attr>>nvgpu.NVOS32_ATTR_LOCATION_SHIFT)&nvgpu.NVOS32_ATTR_LOCATION_MASK == nvgpu.NVOS32_ATTR_LOCATION_VIDMEM {
				classID = nvgpu.NV01_MEMORY_LOCAL_USER
			}
			fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, allocSizeParams.HMemory, classID, &miscObject{}, ioctlParams.HObjectParent)
		}
	}
	fi.fd.dev.nvp.objsUnlock()
	allocSizeParams.Address = origAddress
	if err != nil {
		return n, err
	}

	if allocSizeParams.Address != 0 {
		if _, err := primitive.CopyUint64Out(fi.t, addrFromP64(allocSizeParams.Address), addr); err != nil {
			return n, err
		}
	}
	if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}

	return n, nil
}
