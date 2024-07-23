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
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

func frontendIoctlInvoke[Params any](fi *frontendIoctlState, sentryParams *Params) (uintptr, error) {
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

func ctrlDevGpuGetClasslistInvoke(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters, ctrlParams *nvgpu.NV0080_CTRL_GPU_GET_CLASSLIST_PARAMS, classList []uint32) (uintptr, error) {
	origClassList := ctrlParams.ClassList
	ctrlParams.ClassList = p64FromPtr(unsafe.Pointer(&classList[0]))
	n, err := rmControlInvoke(fi, ioctlParams, ctrlParams)
	ctrlParams.ClassList = origClassList
	if err != nil {
		return n, err
	}
	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(origClassList), classList); err != nil {
		return 0, err
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
		return 0, err
	}
	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(origPChannelList), channelList); err != nil {
		return 0, err
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}

	return n, nil
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
	fi.fd.dev.nvp.objsLock()
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fi.fd.hostFD), frontendIoctlCmd(nvgpu.NV_ESC_RM_ALLOC, nvgpu.SizeofNVOS64Parameters), uintptr(unsafe.Pointer(ioctlParams)))
	if errno == 0 && ioctlParams.Status == nvgpu.NV_OK {
		addObjLocked(fi, ioctlParams, rightsRequested, allocParams)
	}
	fi.fd.dev.nvp.objsUnlock()
	ioctlParams.PAllocParms = origPAllocParms
	ioctlParams.PRightsRequested = origPRightsRequested
	if errno != 0 {
		return n, errno
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
		// src/nvidia/src/kernel/mem_mgr/virtual_mem.c:virtmemConstruct_IMPL() => refAddDependant()
		fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, allocSizeParams.HMemory, nvgpu.NV50_MEMORY_VIRTUAL, &virtMem{}, ioctlParams.HObjectParent, ioctlParams.HVASpace)
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
