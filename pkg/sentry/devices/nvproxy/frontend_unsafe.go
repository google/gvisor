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

func frontendIoctlInvokePtr(fi *frontendIoctlState, sentryParams uintptr) (uintptr, error) {
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fi.fd.hostFD), frontendIoctlCmd(fi.nr, fi.ioctlParamsSize), sentryParams)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

func rmControlInvoke[Params any](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters, ctrlParams *Params) (uintptr, error) {
	defer runtime.KeepAlive(ctrlParams) // since we convert to non-pointer-typed P64
	sentryIoctlParams := *ioctlParams
	sentryIoctlParams.Params = p64FromPtr(unsafe.Pointer(ctrlParams))
	n, err := frontendIoctlInvoke(fi, &sentryIoctlParams)
	if err != nil {
		return n, err
	}
	outIoctlParams := sentryIoctlParams
	outIoctlParams.Params = ioctlParams.Params
	if _, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlClientSystemGetBuildVersionInvoke(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters, ctrlParams *nvgpu.NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS, driverVersionBuf, versionBuf, titleBuf *byte) (uintptr, error) {
	sentryCtrlParams := *ctrlParams
	sentryCtrlParams.PDriverVersionBuffer = p64FromPtr(unsafe.Pointer(driverVersionBuf))
	sentryCtrlParams.PVersionBuffer = p64FromPtr(unsafe.Pointer(versionBuf))
	sentryCtrlParams.PTitleBuffer = p64FromPtr(unsafe.Pointer(titleBuf))
	n, err := rmControlInvoke(fi, ioctlParams, &sentryCtrlParams)
	if err != nil {
		return n, err
	}
	outCtrlParams := sentryCtrlParams
	outCtrlParams.PDriverVersionBuffer = ctrlParams.PDriverVersionBuffer
	outCtrlParams.PVersionBuffer = ctrlParams.PVersionBuffer
	outCtrlParams.PTitleBuffer = ctrlParams.PTitleBuffer
	if _, err := outCtrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
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
	sentryCtrlParams := ctrlParams
	sentryCtrlParams.PChannelHandleList = p64FromPtr(unsafe.Pointer(&channelHandleList[0]))
	sentryCtrlParams.PChannelList = p64FromPtr(unsafe.Pointer(&channelList[0]))

	n, err := rmControlInvoke(fi, ioctlParams, &sentryCtrlParams)
	if err != nil {
		return n, err
	}

	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(ctrlParams.PChannelHandleList), channelHandleList); err != nil {
		return 0, err
	}
	if _, err := primitive.CopyUint32SliceOut(fi.t, addrFromP64(ctrlParams.PChannelList), channelList); err != nil {
		return 0, err
	}
	outCtrlParams := sentryCtrlParams
	outCtrlParams.PChannelHandleList = ctrlParams.PChannelHandleList
	outCtrlParams.PChannelList = ctrlParams.PChannelList
	if _, err := outCtrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}

	return n, nil
}

func ctrlSubdevGRGetInfo(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV2080_CTRL_GR_GET_INFO_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}
	if ctrlParams.GRInfoListSize == 0 {
		// Compare
		// src/nvidia/src/kernel/gpu/gr/kernel_graphics.c:_kgraphicsCtrlCmdGrGetInfoV2().
		return 0, linuxerr.EINVAL
	}
	infoList := make([]byte, int(ctrlParams.GRInfoListSize)*(*nvgpu.NVXXXX_CTRL_XXX_INFO)(nil).SizeBytes())
	if _, err := fi.t.CopyInBytes(addrFromP64(ctrlParams.GRInfoList), infoList); err != nil {
		return 0, err
	}
	sentryCtrlParams := ctrlParams
	sentryCtrlParams.GRInfoList = p64FromPtr(unsafe.Pointer(&infoList[0]))

	n, err := rmControlInvoke(fi, ioctlParams, &sentryCtrlParams)
	if err != nil {
		return n, err
	}

	if _, err := fi.t.CopyOutBytes(addrFromP64(ctrlParams.GRInfoList), infoList); err != nil {
		return n, err
	}
	outCtrlParams := sentryCtrlParams
	outCtrlParams.GRInfoList = ctrlParams.GRInfoList
	if _, err := outCtrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}

	return n, nil
}

func rmAllocInvoke[Params any](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, allocParams *Params, isNVOS64 bool) (uintptr, error) {
	defer runtime.KeepAlive(allocParams) // since we convert to non-pointer-typed P64

	sentryIoctlParams := nvgpu.GetRmAllocParamObj(isNVOS64)
	sentryIoctlParams.FromOS64(*ioctlParams)
	sentryIoctlParams.SetPAllocParms(p64FromPtr(unsafe.Pointer(allocParams)))
	var rightsRequested nvgpu.RS_ACCESS_MASK
	if ioctlParams.PRightsRequested != 0 {
		if _, err := rightsRequested.CopyIn(fi.t, addrFromP64(ioctlParams.PRightsRequested)); err != nil {
			return 0, err
		}
		sentryIoctlParams.SetPRightsRequested(p64FromPtr(unsafe.Pointer(&rightsRequested)))
	}
	n, err := frontendIoctlInvokePtr(fi, sentryIoctlParams.GetPointer())
	if err != nil {
		return n, err
	}
	if ioctlParams.PRightsRequested != 0 {
		if _, err := rightsRequested.CopyOut(fi.t, addrFromP64(ioctlParams.PRightsRequested)); err != nil {
			return n, err
		}
	}
	// Reuse sentryIoctlParams to write out params.
	sentryIoctlParams.SetPAllocParms(ioctlParams.PAllocParms)
	if ioctlParams.PRightsRequested != 0 {
		sentryIoctlParams.SetPRightsRequested(ioctlParams.PRightsRequested)
	}
	if _, err := sentryIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func rmVidHeapControlAllocSize(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS32Parameters) (uintptr, error) {
	allocSizeParams := (*nvgpu.NVOS32AllocSize)(unsafe.Pointer(&ioctlParams.Data))

	sentryIoctlParams := *ioctlParams
	sentryAllocSizeParams := (*nvgpu.NVOS32AllocSize)(unsafe.Pointer(&sentryIoctlParams.Data))
	var addr uint64
	if allocSizeParams.Address != 0 {
		if _, err := primitive.CopyUint64In(fi.t, addrFromP64(allocSizeParams.Address), &addr); err != nil {
			return 0, err
		}
		sentryAllocSizeParams.Address = p64FromPtr(unsafe.Pointer(&addr))
	}

	n, err := frontendIoctlInvoke(fi, &sentryIoctlParams)
	if err != nil {
		return n, err
	}

	outIoctlParams := sentryIoctlParams
	outAllocSizeParams := (*nvgpu.NVOS32AllocSize)(unsafe.Pointer(&outIoctlParams.Data))
	if allocSizeParams.Address != 0 {
		if _, err := primitive.CopyUint64Out(fi.t, addrFromP64(allocSizeParams.Address), addr); err != nil {
			return n, err
		}
		outAllocSizeParams.Address = allocSizeParams.Address
	}
	if _, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}

	return n, nil
}
