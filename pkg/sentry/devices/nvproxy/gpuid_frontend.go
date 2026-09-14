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

package nvproxy

import (
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
)

// RM control handlers that translate device identifiers across a restore that
// remapped devices. See gpuid.go for the identifier families and the tables.

// ctrlTranslateRawIDs proxies a control whose parameters nvproxy does not
// model as a marshallable struct, translating the identifier fields named by
// rawIDSpecs at fixed byte offsets.
//
// A control whose ParamsSize does not match the modelled layout is passed
// through untranslated rather than rejected: the driver in the sandbox may not
// be the one the layout was taken from, and passing it through is exactly the
// behaviour before this handler existed.
func ctrlTranslateRawIDs(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	spec := rawIDSpecs[ioctlParams.Cmd]
	ids := nvp.ids()
	scope := scopeFor(fi.t)
	if spec == nil || ids.empty() || !scope.Restored || int(ioctlParams.ParamsSize) != spec.Size {
		if spec != nil && scope.Restored && int(ioctlParams.ParamsSize) != spec.Size && !ids.empty() {
			log.Warningf("nvproxy: %s params are %d bytes, not the %d this build models; passing identifiers through untranslated",
				spec.Name, ioctlParams.ParamsSize, spec.Size)
		}
		return rmControlSimple(fi, ioctlParams)
	}
	if ioctlParams.Params == 0 {
		return 0, linuxerr.EINVAL
	}

	ctrlParams := make([]byte, ioctlParams.ParamsSize)
	if _, err := fi.t.CopyInBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return 0, err
	}

	onTranslate := func(dir string) func(kind idKind, from, to uint32) {
		return func(kind idKind, from, to uint32) {
			if log.IsLogging(log.Debug) {
				fi.ctx.Debugf("nvproxy: %s: translated %s %d to %d (%s) [%v]", spec.Name, idKindName(kind), from, to, dir, scope)
			}
		}
	}

	applyRawIDFields(ctrlParams, spec, idIn, false, ids, onTranslate("guest->host"))
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams[0])
	if err != nil {
		return n, err
	}
	// Put the inbound identifiers back to what the application passed, then
	// translate the ones the driver filled.
	applyRawIDFields(ctrlParams, spec, idIn, true, ids, nil)
	if ioctlParams.Status == nvgpu.NV_OK {
		removeShadowedGPUIDs(ctrlParams, ioctlParams.Cmd, ids)
		applyRawIDFields(ctrlParams, spec, idOut, false, ids, onTranslate("host->guest"))
		if log.IsLogging(log.Debug) {
			for _, f := range spec.Fields {
				if f.Dir != idOut {
					continue
				}
				fi.ctx.Debugf("nvproxy: %s: %s out (guest) at +%d: %s [%v]",
					spec.Name, idKindName(f.Kind), f.Offset, describeRawIDField(ctrlParams, f), scope)
			}
		}
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return n, err
	}
	return n, nil
}

// idKindName names an idKind for a log line.
func idKindName(kind idKind) string {
	switch kind {
	case idGPUID:
		return "gpuId"
	case idDeviceInstance:
		return "device instance"
	case idDeviceInstanceMask:
		return "device instance mask"
	}
	return "identifier"
}

// ctrlGpuGetIDInfoTranslate is ctrlGpuGetIDInfo plus translation: the
// application supplies a guest gpuId and the driver answers with a host device
// instance.
func ctrlGpuGetIDInfoTranslate(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	scope := scopeFor(fi.t)
	var ctrlParams nvgpu.NV0000_CTRL_GPU_GET_ID_INFO_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if !scope.Restored {
		return ctrlGpuGetIDInfo(fi, ioctlParams)
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	// szName is not used anywhere in the driver, so we explicitly set it to null.
	// See src/nvidia/src/kernel/gpu_mgr/gpu_mgr.c::gpumgrGetGpuIdInfo().
	ctrlParams.SzName = 0

	guestGPUID := ctrlParams.GpuID
	if hostGPUID, ok := translateID(guestGPUID, nvp.guestToHostGPUID); ok {
		ctrlParams.GpuID = hostGPUID
		if log.IsLogging(log.Debug) {
			fi.ctx.Debugf("nvproxy: NV0000_CTRL_CMD_GPU_GET_ID_INFO: translated gpuId %d (guest) to %d (host) [%v]", guestGPUID, hostGPUID, scope)
		}
	}

	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	hostGPUIDUsed := ctrlParams.GpuID
	// The application must read back the gpuId it passed, not the host one it
	// was resolved to; this control echoes the field.
	ctrlParams.GpuID = guestGPUID
	if err != nil {
		return n, err
	}
	if ioctlParams.Status == nvgpu.NV_OK {
		hostDevInst, hostGPUInst, hostSubDevInst := ctrlParams.DeviceInstance, ctrlParams.GpuInstance, ctrlParams.SubDeviceInstance
		ctrlParams.DeviceInstance, ctrlParams.GpuInstance = translateIDInfoIdentity(fi, "NV0000_CTRL_CMD_GPU_GET_ID_INFO", nvp, scope, hostDevInst, hostGPUInst, hostSubDevInst)
		if log.IsLogging(log.Debug) {
			fi.ctx.Debugf("nvproxy: NV0000_CTRL_CMD_GPU_GET_ID_INFO: gpuIdIn=%d(guest)/%d(host) gpuIdOut=%d deviceInstance=%d(host)->%d(guest) gpuInstance=%d(host)->%d(guest) subDeviceInstance=%d [%v]",
				guestGPUID, hostGPUIDUsed, ctrlParams.GpuID, hostDevInst, ctrlParams.DeviceInstance, hostGPUInst, ctrlParams.GpuInstance, hostSubDevInst, scope)
		}
	}
	_, err = ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params))
	return n, err
}

// Byte offsets within NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS{gpuId, gpuFlags,
// deviceInstance, subDeviceInstance, sliStatus, boardId, gpuInstance, numaId},
// from src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000gpu.h. Unlike the
// non-V2 struct this one has no embedded szName pointer, so every field is a
// bare NvU32 and the struct is 32 bytes.
const (
	idInfoV2GpuID             = 0
	idInfoV2DeviceInstance    = 8
	idInfoV2SubDeviceInstance = 12
	idInfoV2GpuInstance       = 24
	idInfoV2ParamsSize        = 32
)

// ctrlGpuGetIDInfoV2 implements NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2. nvproxy
// models no Go struct for it, so its fields are addressed by offset; a params
// size that does not match the modelled layout is passed through untranslated.
func ctrlGpuGetIDInfoV2(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	scope := scopeFor(fi.t)
	if !scope.Restored || nvp.ids().empty() || int(ioctlParams.ParamsSize) != idInfoV2ParamsSize || ioctlParams.Params == 0 {
		if scope.Restored && !nvp.ids().empty() && int(ioctlParams.ParamsSize) != idInfoV2ParamsSize {
			log.Warningf("nvproxy: NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 params are %d bytes, not the %d this build models; passing identifiers through untranslated",
				ioctlParams.ParamsSize, idInfoV2ParamsSize)
		}
		return rmControlSimple(fi, ioctlParams)
	}

	ctrlParams := make([]byte, ioctlParams.ParamsSize)
	if _, err := fi.t.CopyInBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return 0, err
	}

	guestGPUID := hostarch.ByteOrder.Uint32(ctrlParams[idInfoV2GpuID:])
	hostGPUIDUsed := guestGPUID
	if host, ok := translateID(guestGPUID, nvp.guestToHostGPUID); ok {
		hostGPUIDUsed = host
		hostarch.ByteOrder.PutUint32(ctrlParams[idInfoV2GpuID:], host)
	}

	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams[0])
	// Put back the gpuId the application passed; this control echoes it, and
	// the user-mode driver keys its device table on what it reads back.
	hostarch.ByteOrder.PutUint32(ctrlParams[idInfoV2GpuID:], guestGPUID)
	if err != nil {
		return n, err
	}
	if ioctlParams.Status == nvgpu.NV_OK {
		hostDevInst := hostarch.ByteOrder.Uint32(ctrlParams[idInfoV2DeviceInstance:])
		hostGPUInst := hostarch.ByteOrder.Uint32(ctrlParams[idInfoV2GpuInstance:])
		hostSubDevInst := hostarch.ByteOrder.Uint32(ctrlParams[idInfoV2SubDeviceInstance:])
		guestDevInst, guestGPUInst := translateIDInfoIdentity(fi, "NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2", nvp, scope, hostDevInst, hostGPUInst, hostSubDevInst)
		hostarch.ByteOrder.PutUint32(ctrlParams[idInfoV2DeviceInstance:], guestDevInst)
		hostarch.ByteOrder.PutUint32(ctrlParams[idInfoV2GpuInstance:], guestGPUInst)
		if log.IsLogging(log.Debug) {
			fi.ctx.Debugf("nvproxy: NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2: gpuIdIn=%d(guest)/%d(host) gpuIdOut=%d deviceInstance=%d(host)->%d(guest) gpuInstance=%d(host)->%d(guest) subDeviceInstance=%d [%v]",
				guestGPUID, hostGPUIDUsed, guestGPUID, hostDevInst, guestDevInst, hostGPUInst, guestGPUInst, hostSubDevInst, scope)
		}
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return n, err
	}
	return n, nil
}

// translateIDInfoIdentity translates the identity a GET_ID_INFO answer
// carries, returning the guest device instance and gpu instance.
//
// gpuInstance is gpuGetInstance(pGpu), an index into the GPU manager's table
// rather than into the device-group table, so it is a host identifier of its
// own family and DeviceRemapID carries no mapping for it. It is translated
// only where the driver reports it as equal to the device instance, which is
// the case on a system where each device has exactly one subdevice -- the
// property CheckDevicesRemappable() already requires in order to save at all.
// Where the two differ nvproxy leaves gpuInstance alone and says so, rather
// than guessing a mapping.
func translateIDInfoIdentity(fi *frontendIoctlState, name string, nvp *nvproxy, scope translationScope, hostDevInst, hostGPUInst, hostSubDevInst uint32) (guestDevInst, guestGPUInst uint32) {
	guestDevInst, guestGPUInst = hostDevInst, hostGPUInst
	if g, ok := translateID(hostDevInst, nvp.hostToGuestDeviceInstance); ok {
		guestDevInst = g
		if hostGPUInst == hostDevInst {
			guestGPUInst = g
		} else {
			log.Warningf("nvproxy: %s reports gpuInstance %d != deviceInstance %d; leaving gpuInstance untranslated", name, hostGPUInst, hostDevInst)
		}
	}
	if hostSubDevInst != 0 {
		log.Warningf("nvproxy: %s reports subDeviceInstance %d, but remapping requires it to be 0", name, hostSubDevInst)
	}
	return guestDevInst, guestGPUInst
}

// ctrlGpuAttachIDs implements NV0000_CTRL_CMD_GPU_ATTACH_IDS, whose gpuId
// array is an input and whose FailedID is an output.
func ctrlGpuAttachIDs(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	var ctrlParams nvgpu.NV0000_CTRL_GPU_ATTACH_IDS_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) || nvp.ids().empty() || !scopeFor(fi.t).Restored {
		return rmControlSimple(fi, ioctlParams)
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	origGPUIDs := ctrlParams.GPUIDs
	for i := range ctrlParams.GPUIDs {
		if host, ok := translateID(ctrlParams.GPUIDs[i], nvp.guestToHostGPUID); ok {
			ctrlParams.GPUIDs[i] = host
		}
	}
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	ctrlParams.GPUIDs = origGPUIDs
	if err != nil {
		return n, err
	}
	if guest, ok := translateID(ctrlParams.FailedID, nvp.hostToGuestGPUID); ok {
		ctrlParams.FailedID = guest
	}
	_, err = ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params))
	return n, err
}

// ctrlGpuGetUUIDFromGPUID implements NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID:
// a guest gpuId in, a host UUID out.
func ctrlGpuGetUUIDFromGPUID(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	var ctrlParams nvgpu.NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) || nvp.ids().empty() || !scopeFor(fi.t).Restored {
		return rmControlSimple(fi, ioctlParams)
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	guestGPUID := ctrlParams.GPUID
	if host, ok := translateID(guestGPUID, nvp.guestToHostGPUID); ok {
		ctrlParams.GPUID = host
	}
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	ctrlParams.GPUID = guestGPUID
	if err != nil {
		return n, err
	}
	if ioctlParams.Status == nvgpu.NV_OK {
		// NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_FLAGS_FORMAT_BINARY is bit 0 of
		// Flags, matching NV2080_GPU_CMD_GPU_GET_GID_FLAGS_FORMAT.
		binary := ctrlParams.Flags&nvgpu.NV2080_GPU_CMD_GPU_GET_GID_FLAGS_FORMAT_MASK == nvgpu.NV2080_GPU_CMD_GPU_GET_GID_FLAGS_FORMAT_BINARY
		if from, to, ok := translateUUIDBytes(ctrlParams.GPUUUID[:], binary, nvp.hostToGuestUUID); ok && log.IsLogging(log.Debug) {
			fi.ctx.Debugf("nvproxy: NV0000_CTRL_CMD_GPU_GET_UUID_FROM_GPU_ID: translated UUID %s (host) to %s (guest)", from, to)
		}
	}
	_, err = ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params))
	return n, err
}

// gidInfoParamsSize is the size of NV2080_CTRL_GPU_GET_GID_INFO_PARAMS
// {index, flags, length, data[256]}.
const gidInfoParamsSize = 4 + 4 + 4 + nvgpu.NV2080_GPU_MAX_GID_LENGTH

// ctrlGpuGetGidInfo implements NV2080_CTRL_CMD_GPU_GET_GID_INFO, which returns
// a host GPU UUID through a subdevice handle in either ASCII or binary form.
func ctrlGpuGetGidInfo(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	if int(ioctlParams.ParamsSize) != gidInfoParamsSize || len(nvp.hostToGuestUUID) == 0 || ioctlParams.Params == 0 || !scopeFor(fi.t).Restored {
		return rmControlSimple(fi, ioctlParams)
	}
	ctrlParams := make([]byte, ioctlParams.ParamsSize)
	if _, err := fi.t.CopyInBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return 0, err
	}
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams[0])
	if err != nil {
		return n, err
	}
	if ioctlParams.Status == nvgpu.NV_OK {
		flags := hostarch.ByteOrder.Uint32(ctrlParams[4:])
		length := hostarch.ByteOrder.Uint32(ctrlParams[8:])
		data := ctrlParams[12:]
		if int(length) < len(data) && length != 0 {
			data = data[:length]
		}
		binary := flags&nvgpu.NV2080_GPU_CMD_GPU_GET_GID_FLAGS_FORMAT_MASK == nvgpu.NV2080_GPU_CMD_GPU_GET_GID_FLAGS_FORMAT_BINARY
		if from, to, ok := translateUUIDBytes(data, binary, nvp.hostToGuestUUID); ok && log.IsLogging(log.Debug) {
			fi.ctx.Debugf("nvproxy: NV2080_CTRL_CMD_GPU_GET_GID_INFO: translated UUID %s (host) to %s (guest)", from, to)
		}
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return n, err
	}
	return n, nil
}

// rmAllocDevice implements NV01_DEVICE_0 allocation.
//
// NV0080_ALLOC_PARAMETERS.DeviceID is a device instance, and a process
// restored from a checkpoint supplies the one it recorded then.
// nvproxy.afterLoad() rewrites this field in the objects that already existed
// at checkpoint time, but a restored process that allocates a *new*
// NV01_DEVICE_0 -- which is what a CUDA restore leg does, on a fresh RM client
// -- was passing the guest instance straight through, and RM answered
// NV_ERR_INSUFFICIENT_PERMISSIONS because that client has no access to a
// device by that number.
func rmAllocDevice(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64_PARAMETERS, isNVOS64 bool) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	scope := scopeFor(fi.t)
	if !scope.Restored || len(nvp.guestToHostDeviceInstance) == 0 {
		return rmAllocSimple[nvgpu.NV0080_ALLOC_PARAMETERS](fi, ioctlParams, isNVOS64)
	}

	// src/nvidia/src/kernel/gpu/device.c:deviceConstruct_IMPL() treats NULL
	// allocParams for NV01_DEVICE_0 as the zero value, so an application that
	// passes none is asking for device instance 0. If guest instance 0 needs
	// translating we have to materialise the parameters to say so.
	var allocParams nvgpu.NV0080_ALLOC_PARAMETERS
	appPassedParams := ioctlParams.PAllocParms != 0
	if appPassedParams {
		if _, err := allocParams.CopyIn(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
			return 0, err
		}
	}

	guestDevInst := allocParams.DeviceID
	hostDevInst, translate := nvp.guestToHostDeviceInstance[guestDevInst]
	if !translate {
		// Nothing to do; take the ordinary path so that behaviour is
		// bit-identical for a device instance we know nothing about.
		if log.IsLogging(log.Debug) {
			fi.ctx.Debugf("nvproxy: NV01_DEVICE_0 alloc: device instance %d has no translation, passing through [%v]", guestDevInst, scope)
		}
		return rmAllocSimple[nvgpu.NV0080_ALLOC_PARAMETERS](fi, ioctlParams, isNVOS64)
	}

	allocParams.DeviceID = hostDevInst
	if log.IsLogging(log.Debug) {
		fi.ctx.Debugf("nvproxy: NV01_DEVICE_0 alloc: translated device instance %d (guest) to %d (host)%s hRoot=%v hObjectNew=%v [%v]",
			guestDevInst, hostDevInst, nullParamsNote(appPassedParams), ioctlParams.HRoot, ioctlParams.HObjectNew, scope)
	}

	// rmAllocInvoke() points PAllocParms at allocParams for the duration of
	// the ioctl and restores the application's value afterwards, so passing
	// parameters the application did not is invisible to it. ParamsSize is
	// deliberately left alone: the driver derives the size from the class and
	// ignores it (see rmAllocSimpleParams), and it is copied back out to the
	// application.
	n, err := rmAllocInvoke(fi, ioctlParams, &allocParams, isNVOS64, addSimpleObjDepParentLocked)
	// The object captured for a future checkpoint holds the host device
	// instance, which is what nvproxy.afterLoad() expects to remap; restore
	// the application's value only after that capture has happened.
	allocParams.DeviceID = guestDevInst
	if err != nil {
		return n, err
	}
	if appPassedParams {
		if _, err := allocParams.CopyOut(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
			return n, err
		}
	}
	return n, nil
}

// nullParamsNote annotates a log line for the case where the application
// passed no allocation parameters at all.
func nullParamsNote(appPassedParams bool) string {
	if appPassedParams {
		return ""
	}
	return " (materialised from null allocParams)"
}

// rmAllocMemoryExport implements NV_MEMORY_EXPORT allocation.
//
// NV00E0_ALLOCATION_PARAMETERS.DeviceInstanceMask is a bitmask of device
// instances and GIIDMasks is indexed by device instance, so both are the
// guest's numbering when a restored process supplies them.
//
// This path is reachable only with the fabric IMEX management capability
// enabled, so it is untested here; it is translated for the same reason as
// NV01_DEVICE_0 rather than left as a second instance of the same bug.
func rmAllocMemoryExport(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64_PARAMETERS, isNVOS64 bool) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	scope := scopeFor(fi.t)
	if !scope.Restored || len(nvp.guestToHostDeviceInstance) == 0 || ioctlParams.PAllocParms == 0 {
		return rmAllocSimple[nvgpu.NV00E0_ALLOCATION_PARAMETERS](fi, ioctlParams, isNVOS64)
	}

	var allocParams nvgpu.NV00E0_ALLOCATION_PARAMETERS
	if _, err := allocParams.CopyIn(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return 0, err
	}

	origMask := allocParams.DeviceInstanceMask
	origGIIDMasks := allocParams.GIIDMasks
	allocParams.DeviceInstanceMask = permuteDeviceInstanceMask(origMask, nvp.guestToHostDeviceInstance)
	allocParams.GIIDMasks = permuteByDeviceInstance(origGIIDMasks, nvp.guestToHostDeviceInstance)
	if log.IsLogging(log.Debug) && allocParams.DeviceInstanceMask != origMask {
		fi.ctx.Debugf("nvproxy: NV_MEMORY_EXPORT alloc: translated device instance mask %#x (guest) to %#x (host) [%v]",
			origMask, allocParams.DeviceInstanceMask, scope)
	}

	n, err := rmAllocInvoke(fi, ioctlParams, &allocParams, isNVOS64, addSimpleObjDepParentLocked)
	allocParams.DeviceInstanceMask = origMask
	allocParams.GIIDMasks = origGIIDMasks
	if err != nil {
		return n, err
	}
	if _, err := allocParams.CopyOut(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return n, err
	}
	return n, nil
}
