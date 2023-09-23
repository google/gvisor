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

package nvgpu

// Class handles, from src/nvidia/generated/g_allclasses.h.
const (
	NV01_ROOT                        = 0x00000000
	NV01_ROOT_NON_PRIV               = 0x00000001
	NV01_MEMORY_SYSTEM               = 0x0000003e
	NV01_ROOT_CLIENT                 = 0x00000041
	NV01_MEMORY_SYSTEM_OS_DESCRIPTOR = 0x00000071
	NV01_EVENT_OS_EVENT              = 0x00000079
	NV01_DEVICE_0                    = 0x00000080
	NV_MEMORY_FABRIC                 = 0x000000f8
	NV20_SUBDEVICE_0                 = 0x00002080
	NV50_THIRD_PARTY_P2P             = 0x0000503c
	GT200_DEBUGGER                   = 0x000083de
	GF100_SUBDEVICE_MASTER           = 0x000090e6
	FERMI_CONTEXT_SHARE_A            = 0x00009067
	FERMI_VASPACE_A                  = 0x000090f1
	KEPLER_CHANNEL_GROUP_A           = 0x0000a06c
	VOLTA_USERMODE_A                 = 0x0000c361
	VOLTA_CHANNEL_GPFIFO_A           = 0x0000c36f
	TURING_USERMODE_A                = 0x0000c461
	TURING_CHANNEL_GPFIFO_A          = 0x0000c46f
	AMPERE_CHANNEL_GPFIFO_A          = 0x0000c56f
	TURING_DMA_COPY_A                = 0x0000c5b5
	TURING_COMPUTE_A                 = 0x0000c5c0
	HOPPER_USERMODE_A                = 0x0000c661
	AMPERE_DMA_COPY_A                = 0x0000c6b5
	AMPERE_COMPUTE_A                 = 0x0000c6c0
	AMPERE_DMA_COPY_B                = 0x0000c7b5
	AMPERE_COMPUTE_B                 = 0x0000c7c0
	HOPPER_DMA_COPY_A                = 0x0000c8b5
	ADA_COMPUTE_A                    = 0x0000c9c0
	HOPPER_COMPUTE_A                 = 0x0000cbc0
)

// Class handles for older generations that are not supported by the open source
// driver. Volta was the last such generation. These are defined in files under
// src/common/sdk/nvidia/inc/class/.
const (
	VOLTA_COMPUTE_A  = 0x0000c3c0
	VOLTA_DMA_COPY_A = 0x0000c3b5
)

// NV0005_ALLOC_PARAMETERS is the alloc params type for NV01_EVENT_OS_EVENT,
// from src/common/sdk/nvidia/inc/class/cl0005.h.
//
// +marshal
type NV0005_ALLOC_PARAMETERS struct {
	HParentClient Handle
	HSrcResource  Handle
	HClass        uint32
	NotifyIndex   uint32
	Data          P64 // actually FD for NV01_EVENT_OS_EVENT, see src/nvidia/src/kernel/rmapi/event.c:eventConstruct_IMPL() => src/nvidia/arch/nvalloc/unix/src/os.c:osUserHandleToKernelPtr()
}

// NV0080_ALLOC_PARAMETERS is the alloc params type for NV01_DEVICE_0, from
// src/common/sdk/nvidia/inc/class/cl0080.h.
//
// +marshal
type NV0080_ALLOC_PARAMETERS struct {
	DeviceID        uint32
	HClientShare    Handle
	HTargetClient   Handle
	HTargetDevice   Handle
	Flags           uint32
	Pad0            [4]byte
	VASpaceSize     uint64
	VAStartInternal uint64
	VALimitInternal uint64
	VAMode          uint32
	Pad1            [4]byte
}

// NV2080_ALLOC_PARAMETERS is the alloc params type for NV20_SUBDEVICE_0, from
// src/common/sdk/nvidia/inc/class/cl2080.h.
//
// +marshal
type NV2080_ALLOC_PARAMETERS struct {
	SubDeviceID uint32
}

// NV503C_ALLOC_PARAMETERS is the alloc params type for NV50_THIRD_PARTY_P2P,
// from src/common/sdk/nvidia/inc/class/cl503c.h.
//
// +marshal
type NV503C_ALLOC_PARAMETERS struct {
	Flags uint32
}

// NV83DE_ALLOC_PARAMETERS is the alloc params type for GT200_DEBUGGER,
// from src/common/sdk/nvidia/inc/class/cl83de.h.
//
// +marshal
type NV83DE_ALLOC_PARAMETERS struct {
	HDebuggerClient_Obsolete Handle
	HAppClient               Handle
	HClass3DObject           Handle
}

// NV_CTXSHARE_ALLOCATION_PARAMETERS is the alloc params type for
// FERMI_CONTEXT_SHARE_A, from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_CTXSHARE_ALLOCATION_PARAMETERS struct {
	HVASpace Handle
	Flags    uint32
	SubctxID uint32
}

// NV_VASPACE_ALLOCATION_PARAMETERS is the alloc params type for
// FERMI_VASPACE_A, from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_VASPACE_ALLOCATION_PARAMETERS struct {
	Index           uint32
	Flags           uint32
	VASize          uint64
	VAStartInternal uint64
	VALimitInternal uint64
	BigPageSize     uint32
	Pad0            [4]byte
	VABase          uint64
}

// NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS is the alloc params type for
// KEPLER_CHANNEL_GROUP_A, from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS struct {
	HObjectError                Handle
	HObjectECCError             Handle
	HVASpace                    Handle
	EngineType                  uint32
	BIsCallingContextVgpuPlugin uint8
	Pad0                        [3]byte
}

// NV_MEMORY_DESC_PARAMS is from
// src/common/sdk/nvidia/inc/alloc/alloc_channel.h.
//
// +marshal
type NV_MEMORY_DESC_PARAMS struct {
	Base         uint64
	Size         uint64
	AddressSpace uint32
	CacheAttrib  uint32
}

// NV_CHANNEL_ALLOC_PARAMS is the alloc params type for TURING_CHANNEL_GPFIFO_A
// and AMPERE_CHANNEL_GPFIFO_A, from
// src/common/sdk/nvidia/inc/alloc/alloc_channel.h.
//
// +marshal
type NV_CHANNEL_ALLOC_PARAMS struct {
	HObjectError        Handle
	HObjectBuffer       Handle
	GPFIFOOffset        uint64
	GPFIFOEntries       uint32
	Flags               uint32
	HContextShare       Handle
	HVASpace            Handle
	HUserdMemory        [NV_MAX_SUBDEVICES]Handle
	UserdOffset         [NV_MAX_SUBDEVICES]uint64
	EngineType          uint32
	CID                 uint32
	SubDeviceID         uint32
	HObjectECCError     Handle
	InstanceMem         NV_MEMORY_DESC_PARAMS
	UserdMem            NV_MEMORY_DESC_PARAMS
	RamfcMem            NV_MEMORY_DESC_PARAMS
	MthdbufMem          NV_MEMORY_DESC_PARAMS
	HPhysChannelGroup   Handle
	InternalFlags       uint32
	ErrorNotifierMem    NV_MEMORY_DESC_PARAMS
	ECCErrorNotifierMem NV_MEMORY_DESC_PARAMS
	ProcessID           uint32
	SubProcessID        uint32
}

// NVB0B5_ALLOCATION_PARAMETERS is the alloc param type for TURING_DMA_COPY_A,
// AMPERE_DMA_COPY_A, and AMPERE_DMA_COPY_B from
// src/common/sdk/nvidia/inc/class/clb0b5sw.h.
//
// +marshal
type NVB0B5_ALLOCATION_PARAMETERS struct {
	Version    uint32
	EngineType uint32
}

// NV_GR_ALLOCATION_PARAMETERS is the alloc param type for TURING_COMPUTE_A,
// AMPERE_COMPUTE_A, and ADA_COMPUTE_A, from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_GR_ALLOCATION_PARAMETERS struct {
	Version uint32
	Flags   uint32
	Size    uint32
	Caps    uint32
}

// NV_HOPPER_USERMODE_A_PARAMS is the alloc param type for HOPPER_USERMODE_A,
// from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_HOPPER_USERMODE_A_PARAMS struct {
	Bar1Mapping uint8
	Priv        uint8
}

// +marshal
type nv00f8Map struct {
	offset  uint64
	hVidMem Handle
	flags   uint32
}

// NV00F8_ALLOCATION_PARAMETERS is the alloc param type for NV_MEMORY_FABRIC,
// from src/common/sdk/nvidia/inc/class/cl00f8.h
//
// +marshal
type NV00F8_ALLOCATION_PARAMETERS struct {
	Alignment  uint64
	AllocSize  uint64
	PageSize   uint32
	AllocFlags uint32
	Map        nv00f8Map
}
