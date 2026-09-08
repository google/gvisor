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

// translatePCIAddrToGuest translates a host PCI address to the one the
// application saw before the checkpoint, reporting whether it did.
func (nvp *nvproxy) translatePCIAddrToGuest(domain uint32, bus, slot, function uint8) (uint32, uint8, uint8, uint8, bool) {
	if len(nvp.hostToGuestPCIAddr) == 0 {
		return domain, bus, slot, function, false
	}
	guest, ok := nvp.hostToGuestPCIAddr[PackPCIAddr(domain, bus, slot, function)]
	if !ok {
		return domain, bus, slot, function, false
	}
	d, b, s, f := UnpackPCIAddr(guest)
	return d, b, s, f, true
}

// frontendIoctlCardInfo implements NV_ESC_CARD_INFO, which reports an array of
// nv_ioctl_card_info_t: one entry per card, each naming the card by gpuId, by
// PCI address and by device file minor number. All three are host identities,
// and a restored process matches its own recorded state against them.
//
// This is frontendIoctlBytes plus that translation. A parameter buffer that is
// not a whole number of entries is passed through untouched.
func frontendIoctlCardInfo(fi *frontendIoctlState) (uintptr, error) {
	if fi.ioctlParamsSize == 0 {
		return frontendIoctlInvokeNoStatus[byte](fi, nil)
	}

	ioctlParams := make([]byte, fi.ioctlParamsSize)
	if _, err := fi.t.CopyInBytes(fi.ioctlParamsAddr, ioctlParams); err != nil {
		return 0, err
	}
	n, err := frontendIoctlInvokeNoStatus(fi, &ioctlParams[0])
	if err != nil {
		return n, err
	}
	translateCardInfo(fi, ioctlParams)
	if _, err := fi.t.CopyOutBytes(fi.ioctlParamsAddr, ioctlParams); err != nil {
		return n, err
	}
	return n, nil
}

// translateCardInfo rewrites, in place, every host identity in an
// NV_ESC_CARD_INFO reply.
func translateCardInfo(fi *frontendIoctlState, buf []byte) {
	nvp := fi.fd.dev.nvp
	scope := scopeFor(fi.t)
	if !scope.Restored || nvp.ids().empty() {
		return
	}
	var one nvgpu.IoctlCardInfo
	stride := one.SizeBytes()
	if stride == 0 || len(buf)%stride != 0 {
		log.Warningf("nvproxy: NV_ESC_CARD_INFO reply is %d bytes, not a multiple of the %d-byte entry this build models; passing identities through untranslated", len(buf), stride)
		return
	}
	for off := 0; off+stride <= len(buf); off += stride {
		var ci nvgpu.IoctlCardInfo
		ci.UnmarshalBytes(buf[off : off+stride])
		if ci.Valid == 0 {
			continue
		}
		changed := false
		if guest, ok := translateID(ci.GPUID, nvp.hostToGuestGPUID); ok {
			if log.IsLogging(log.Debug) {
				fi.ctx.Debugf("nvproxy: NV_ESC_CARD_INFO: translated gpuId %d (host) to %d (guest) [%v]", ci.GPUID, guest, scope)
			}
			ci.GPUID = guest
			changed = true
		}
		if guest, ok := nvp.hostToGuestMinor[ci.MinorNumber]; ok {
			if log.IsLogging(log.Debug) {
				fi.ctx.Debugf("nvproxy: NV_ESC_CARD_INFO: translated minor %d (host) to %d (guest) [%v]", ci.MinorNumber, guest, scope)
			}
			ci.MinorNumber = guest
			changed = true
		}
		if d, b, sl, f, ok := nvp.translatePCIAddrToGuest(ci.PCIInfo.Domain, ci.PCIInfo.Bus, ci.PCIInfo.Slot, ci.PCIInfo.Function); ok {
			if log.IsLogging(log.Debug) {
				fi.ctx.Debugf("nvproxy: NV_ESC_CARD_INFO: translated PCI address %s (host) to %s (guest) [%v]",
					formatPCIAddr(PackPCIAddr(ci.PCIInfo.Domain, ci.PCIInfo.Bus, ci.PCIInfo.Slot, ci.PCIInfo.Function)),
					formatPCIAddr(PackPCIAddr(d, b, sl, f)), scope)
			}
			ci.PCIInfo.Domain, ci.PCIInfo.Bus, ci.PCIInfo.Slot, ci.PCIInfo.Function = d, b, sl, f
			changed = true
		}
		if changed {
			ci.MarshalBytes(buf[off : off+stride])
		}
	}
}

// Byte offsets within NV0000_CTRL_GPU_GET_PCI_INFO_PARAMS{NvU32 gpuId, NvU32
// domain, NvU16 bus, NvU16 slot}, from
// src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000gpu.h. Note that bus and
// slot are 16-bit here, unlike the 8-bit fields of nv_pci_info_t, and that
// there is no function field.
const (
	pciInfoGpuID      = 0
	pciInfoDomain     = 4
	pciInfoBus        = 8
	pciInfoSlot       = 10
	pciInfoParamsSize = 12
)

// ctrlGpuGetPCIInfo implements NV0000_CTRL_CMD_GPU_GET_PCI_INFO: a guest gpuId
// in, a host PCI address out.
func ctrlGpuGetPCIInfo(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	scope := scopeFor(fi.t)
	if !scope.Restored || nvp.ids().empty() || int(ioctlParams.ParamsSize) != pciInfoParamsSize || ioctlParams.Params == 0 {
		if scope.Restored && !nvp.ids().empty() && int(ioctlParams.ParamsSize) != pciInfoParamsSize {
			log.Warningf("nvproxy: NV0000_CTRL_CMD_GPU_GET_PCI_INFO params are %d bytes, not the %d this build models; passing identifiers through untranslated",
				ioctlParams.ParamsSize, pciInfoParamsSize)
		}
		return rmControlSimple(fi, ioctlParams)
	}

	ctrlParams := make([]byte, ioctlParams.ParamsSize)
	if _, err := fi.t.CopyInBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return 0, err
	}

	guestGPUID := hostarch.ByteOrder.Uint32(ctrlParams[pciInfoGpuID:])
	if host, ok := translateID(guestGPUID, nvp.guestToHostGPUID); ok {
		hostarch.ByteOrder.PutUint32(ctrlParams[pciInfoGpuID:], host)
		if log.IsLogging(log.Debug) {
			fi.ctx.Debugf("nvproxy: NV0000_CTRL_CMD_GPU_GET_PCI_INFO: translated gpuId %d (guest) to %d (host) [%v]", guestGPUID, host, scope)
		}
	}

	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams[0])
	// The application must read back the gpuId it passed.
	hostarch.ByteOrder.PutUint32(ctrlParams[pciInfoGpuID:], guestGPUID)
	if err != nil {
		return n, err
	}
	if ioctlParams.Status == nvgpu.NV_OK {
		hostDomain := hostarch.ByteOrder.Uint32(ctrlParams[pciInfoDomain:])
		hostBus := hostarch.ByteOrder.Uint16(ctrlParams[pciInfoBus:])
		hostSlot := hostarch.ByteOrder.Uint16(ctrlParams[pciInfoSlot:])
		// The function is not reported by this control, so translate against
		// function 0, which is what every GPU uses.
		if d, b, sl, _, ok := nvp.translatePCIAddrToGuest(hostDomain, uint8(hostBus), uint8(hostSlot), 0); ok {
			hostarch.ByteOrder.PutUint32(ctrlParams[pciInfoDomain:], d)
			hostarch.ByteOrder.PutUint16(ctrlParams[pciInfoBus:], uint16(b))
			hostarch.ByteOrder.PutUint16(ctrlParams[pciInfoSlot:], uint16(sl))
			if log.IsLogging(log.Debug) {
				fi.ctx.Debugf("nvproxy: NV0000_CTRL_CMD_GPU_GET_PCI_INFO: gpuId=%d translated PCI address %s (host) to %s (guest) [%v]",
					guestGPUID, formatPCIAddr(PackPCIAddr(hostDomain, uint8(hostBus), uint8(hostSlot), 0)),
					formatPCIAddr(PackPCIAddr(d, b, sl, 0)), scope)
			}
		}
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return n, err
	}
	return n, nil
}

// NV2080_CTRL_BUS_GET_INFO_V2_PARAMS{NvU32 busInfoListSize,
// NV2080_CTRL_BUS_INFO busInfoList[NV2080_CTRL_BUS_INFO_MAX_LIST_SIZE]}, each
// entry being NVXXXX_CTRL_XXX_INFO{NvU32 index, NvU32 data}. From
// src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080bus.h.
const (
	busInfoListSizeOff       = 0
	busInfoListOff           = 4
	busInfoMaxListSize       = 0x34
	busInfoIndexBusNumber    = 0x0000000f
	busInfoIndexDeviceNumber = 0x00000010
	busInfoIndexDomainNumber = 0x0000002c
)

// busGetInfoV2ParamsSize is the size of the modelled layout.
var busGetInfoV2ParamsSize = busInfoListOff + busInfoMaxListSize*int(nvgpu.CtrlXxxInfoSize)

// ctrlBusGetInfoV2 implements NV2080_CTRL_CMD_BUS_GET_INFO_V2, an
// index/value list in which three indices report the GPU's PCI address one
// component at a time.
//
// The components are translated together: a bus number translated without the
// domain and device it belongs to would name a device that does not exist. The
// application asks for them in separate entries of one list, so this handler
// resolves whichever components the list requests against the one host address
// they must all belong to.
func ctrlBusGetInfoV2(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	nvp := fi.fd.dev.nvp
	scope := scopeFor(fi.t)
	if !scope.Restored || len(nvp.hostToGuestPCIAddr) == 0 || int(ioctlParams.ParamsSize) != busGetInfoV2ParamsSize || ioctlParams.Params == 0 {
		if scope.Restored && len(nvp.hostToGuestPCIAddr) != 0 && int(ioctlParams.ParamsSize) != busGetInfoV2ParamsSize {
			log.Warningf("nvproxy: NV2080_CTRL_CMD_BUS_GET_INFO_V2 params are %d bytes, not the %d this build models; passing PCI identifiers through untranslated",
				ioctlParams.ParamsSize, busGetInfoV2ParamsSize)
		}
		return rmControlSimple(fi, ioctlParams)
	}
	if ioctlParams.ParamsSize > nvgpu.RMAPI_PARAM_COPY_MAX_PARAMS_SIZE {
		return 0, linuxerr.EINVAL
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
		translateBusInfoPCIAddr(fi, ctrlParams, scope)
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return n, err
	}
	return n, nil
}

// translateBusInfoPCIAddr rewrites the PCI address components of a
// NV2080_CTRL_BUS_GET_INFO_V2 reply.
func translateBusInfoPCIAddr(fi *frontendIoctlState, buf []byte, scope translationScope) {
	nvp := fi.fd.dev.nvp
	stride := int(nvgpu.CtrlXxxInfoSize)
	count := int(hostarch.ByteOrder.Uint32(buf[busInfoListSizeOff:]))
	if count > busInfoMaxListSize {
		count = busInfoMaxListSize
	}

	// First pass: find which components the list asks for, and their offsets.
	var (
		hostDomain, hostBus, hostSlot uint32
		offDomain, offBus, offSlot    = -1, -1, -1
		haveDomain, haveBus, haveSlot bool
	)
	for i := 0; i < count; i++ {
		off := busInfoListOff + i*stride
		if off+stride > len(buf) {
			break
		}
		index := hostarch.ByteOrder.Uint32(buf[off:])
		dataOff := off + 4
		switch index {
		case busInfoIndexDomainNumber:
			hostDomain, offDomain, haveDomain = hostarch.ByteOrder.Uint32(buf[dataOff:]), dataOff, true
		case busInfoIndexBusNumber:
			hostBus, offBus, haveBus = hostarch.ByteOrder.Uint32(buf[dataOff:]), dataOff, true
		case busInfoIndexDeviceNumber:
			hostSlot, offSlot, haveSlot = hostarch.ByteOrder.Uint32(buf[dataOff:]), dataOff, true
		}
	}
	if !haveDomain && !haveBus && !haveSlot {
		return
	}

	// The list may request only some components, so complete the host address
	// from the mapping: exactly one host device can match the components that
	// were asked for.
	hostAddr, ok := matchHostPCIAddr(nvp.hostToGuestPCIAddr, hostDomain, haveDomain, hostBus, haveBus, hostSlot, haveSlot)
	if !ok {
		return
	}
	guestAddr := nvp.hostToGuestPCIAddr[hostAddr]
	guestDomain, guestBus, guestSlot, _ := UnpackPCIAddr(guestAddr)
	if offDomain >= 0 {
		hostarch.ByteOrder.PutUint32(buf[offDomain:], guestDomain)
	}
	if offBus >= 0 {
		hostarch.ByteOrder.PutUint32(buf[offBus:], uint32(guestBus))
	}
	if offSlot >= 0 {
		hostarch.ByteOrder.PutUint32(buf[offSlot:], uint32(guestSlot))
	}
	if log.IsLogging(log.Debug) {
		fi.ctx.Debugf("nvproxy: NV2080_CTRL_CMD_BUS_GET_INFO_V2: translated PCI address %s (host) to %s (guest) [%v]",
			formatPCIAddr(hostAddr), formatPCIAddr(guestAddr), scope)
	}
}

// matchHostPCIAddr returns the single host PCI address in m consistent with
// the components that were reported, and whether there is exactly one. A
// request that names components matching no device, or more than one, is left
// alone: guessing which device was meant is how the wrong GPU gets picked.
func matchHostPCIAddr(m map[uint64]uint64, domain uint32, haveDomain bool, bus uint32, haveBus bool, slot uint32, haveSlot bool) (uint64, bool) {
	var found uint64
	n := 0
	for host := range m {
		hDomain, hBus, hSlot, _ := UnpackPCIAddr(host)
		if haveDomain && hDomain != domain {
			continue
		}
		if haveBus && uint32(hBus) != bus {
			continue
		}
		if haveSlot && uint32(hSlot) != slot {
			continue
		}
		found = host
		n++
	}
	return found, n == 1
}
