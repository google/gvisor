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

import (
	"fmt"
)

// ClassID is a client class ID, in the sense of
// src/nvidia/src/kernel/rmapi/resource_desc.h:RS_RESOURCE_DESC::externalClassID.
//
// +marshal
type ClassID uint32

// String implements fmt.Stringer.String.
func (id ClassID) String() string {
	// Include leading zeroes for easier searchability, both here and in
	// g_allclasses.h.
	return fmt.Sprintf("0x%08x", uint32(id))
}

// IsRootClient returns true if the given class ID is a root client class.
func (id ClassID) IsRootClient() bool {
	switch id {
	case NV01_ROOT, NV01_ROOT_NON_PRIV, NV01_ROOT_CLIENT:
		return true
	default:
		return false
	}
}

// Class IDs, from src/nvidia/generated/g_allclasses.h.
const (
	NV01_ROOT                        = 0x00000000
	NV01_ROOT_NON_PRIV               = 0x00000001
	NV01_CONTEXT_DMA                 = 0x00000002
	NV01_EVENT                       = 0x00000005
	NV01_MEMORY_SYSTEM               = 0x0000003e
	NV01_MEMORY_LOCAL_PRIVILEGED     = 0x0000003f
	NV01_MEMORY_LOCAL_USER           = 0x00000040
	NV01_ROOT_CLIENT                 = 0x00000041
	NV_MEMORY_EXTENDED_USER          = 0x00000042
	NV01_MEMORY_VIRTUAL              = 0x00000070
	NV01_MEMORY_SYSTEM_OS_DESCRIPTOR = 0x00000071
	NV01_EVENT_OS_EVENT              = 0x00000079
	NV01_DEVICE_0                    = 0x00000080
	NV_SEMAPHORE_SURFACE             = 0x000000da
	RM_USER_SHARED_DATA              = 0x000000de
	NV_MEMORY_FABRIC                 = 0x000000f8
	NV_MEMORY_MULTICAST_FABRIC       = 0x000000fd
	NV_MEMORY_MAPPER                 = 0x000000fe
	NV20_SUBDEVICE_0                 = 0x00002080
	NV2081_BINAPI                    = 0x00002081
	NV50_P2P                         = 0x0000503b
	NV50_THIRD_PARTY_P2P             = 0x0000503c
	NV50_MEMORY_VIRTUAL              = 0x000050a0
	GT200_DEBUGGER                   = 0x000083de
	FERMI_TWOD_A                     = 0x0000902d
	FERMI_CONTEXT_SHARE_A            = 0x00009067
	GF100_DISP_SW                    = 0x00009072
	GF100_ZBC_CLEAR                  = 0x00009096
	GF100_PROFILER                   = 0x000090cc
	GF100_SUBDEVICE_MASTER           = 0x000090e6
	FERMI_VASPACE_A                  = 0x000090f1
	KEPLER_CHANNEL_GROUP_A           = 0x0000a06c
	NVENC_SW_SESSION                 = 0x0000a0bc
	KEPLER_INLINE_TO_MEMORY_B        = 0x0000a140
	VOLTA_USERMODE_A                 = 0x0000c361
	TURING_USERMODE_A                = 0x0000c461
	TURING_CHANNEL_GPFIFO_A          = 0x0000c46f
	NVB8B0_VIDEO_DECODER             = 0x0000b8b0 // Hopper
	NVC4B0_VIDEO_DECODER             = 0x0000c4b0 // Turing
	NVC6B0_VIDEO_DECODER             = 0x0000c6b0 // Ampere
	NVC7B0_VIDEO_DECODER             = 0x0000c7b0 // Ampere
	NVC9B0_VIDEO_DECODER             = 0x0000c9b0 // Ada
	NVCDB0_VIDEO_DECODER             = 0x0000cdb0 // Blackwell
	NVC4B7_VIDEO_ENCODER             = 0x0000c4b7
	NVC7B7_VIDEO_ENCODER             = 0x0000c7b7
	NVC9B7_VIDEO_ENCODER             = 0x0000c9b7
	AMPERE_CHANNEL_GPFIFO_A          = 0x0000c56f
	TURING_A                         = 0x0000c597
	TURING_DMA_COPY_A                = 0x0000c5b5
	TURING_COMPUTE_A                 = 0x0000c5c0
	HOPPER_USERMODE_A                = 0x0000c661
	BLACKWELL_USERMODE_A             = 0x0000c761
	AMPERE_A                         = 0x0000c697
	AMPERE_DMA_COPY_A                = 0x0000c6b5
	AMPERE_COMPUTE_A                 = 0x0000c6c0
	AMPERE_DMA_COPY_B                = 0x0000c7b5
	AMPERE_COMPUTE_B                 = 0x0000c7c0
	HOPPER_CHANNEL_GPFIFO_A          = 0x0000c86f
	HOPPER_DMA_COPY_A                = 0x0000c8b5
	BLACKWELL_CHANNEL_GPFIFO_A       = 0x0000c96f
	BLACKWELL_DMA_COPY_A             = 0x0000c9b5
	BLACKWELL_CHANNEL_GPFIFO_B       = 0x0000ca6f
	BLACKWELL_DMA_COPY_B             = 0x0000cab5
	ADA_A                            = 0x0000c997
	ADA_COMPUTE_A                    = 0x0000c9c0
	NV_CONFIDENTIAL_COMPUTE          = 0x0000cb33
	HOPPER_A                         = 0x0000cb97
	HOPPER_SEC2_WORK_LAUNCH_A        = 0x0000cba2
	HOPPER_COMPUTE_A                 = 0x0000cbc0
	BLACKWELL_INLINE_TO_MEMORY_A     = 0x0000cd40
	BLACKWELL_A                      = 0x0000cd97
	BLACKWELL_COMPUTE_A              = 0x0000cdc0
	BLACKWELL_B                      = 0x0000ce97
	BLACKWELL_COMPUTE_B              = 0x0000cec0
)

// From src/common/sdk/nvidia/inc/class/cl0000.h:
const (
	NV01_NULL_OBJECT = 0x0
)

// NV2081_ALLOC_PARAMETERS is the alloc params type for NV2081_BINAPI, from
// src/common/sdk/nvidia/inc/class/cl2081.h.
//
// +marshal
type NV2081_ALLOC_PARAMETERS struct {
	Reserved uint32
}

// NV0005_ALLOC_PARAMETERS is the alloc params type for NV01_EVENT* classes
// from src/common/sdk/nvidia/inc/class/cl0005.h.
//
// +marshal
type NV0005_ALLOC_PARAMETERS struct {
	HParentClient Handle
	HSrcResource  Handle
	HClass        ClassID
	NotifyIndex   uint32
	Data          P64 // actually FD for NV01_EVENT_OS_EVENT, see src/nvidia/src/kernel/rmapi/event.c:eventConstruct_IMPL() => src/nvidia/arch/nvalloc/unix/src/os.c:osUserHandleToKernelPtr()
}

// From src/common/sdk/nvidia/inc/class/cl208f.h
const (
	NV20_SUBDEVICE_DIAG = 0x0000208f
)

// From src/common/sdk/nvidia/inc/class/cl0070.h:
const (
	NV_MEMORY_VIRTUAL_SYSMEM_DYNAMIC_HVASPACE = 0xffffffff
)

// NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS is the alloc params type for
// NV01_MEMORY_VIRTUAL, from src/common/sdk/nvidia/inc/class/cl0070.h.
//
// +marshal
type NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS struct {
	Offset   uint64
	Limit    uint64
	HVASpace Handle
	Pad0     [4]byte
}

// From src/common/sdk/nvidia/inc/class/cl0073.h
const (
	NV04_DISPLAY_COMMON = 0x00000073
)

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

// NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS is the alloc params type for
// NV_SEMAPHORE_SURFACE, from src/common/sdk/nvidia/inc/class/cl00da.h.
//
// +marshal
type NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS struct {
	HSemaphoreMem    Handle
	HMaxSubmittedMem Handle
	flags            uint64
}

// NV2080_ALLOC_PARAMETERS is the alloc params type for NV20_SUBDEVICE_0, from
// src/common/sdk/nvidia/inc/class/cl2080.h.
//
// +marshal
type NV2080_ALLOC_PARAMETERS struct {
	SubDeviceID uint32
}

// NV_CONTEXT_DMA_ALLOCATION_PARAMS is the alloc params type for various NV01_CONTEXT_DMA
// allocation classes, from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_CONTEXT_DMA_ALLOCATION_PARAMS struct {
	HSubDevice Handle
	Flags      uint32
	HMemory    Handle
	_          uint32
	Offset     uint64
	Limit      uint64
}

// NV_MEMORY_ALLOCATION_PARAMS is the alloc params type for various NV*_MEMORY*
// allocation classes, from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_MEMORY_ALLOCATION_PARAMS struct {
	Owner         uint32
	Type          uint32
	Flags         uint32
	Width         uint32
	Height        uint32
	Pitch         int32
	Attr          uint32
	Attr2         uint32
	Format        uint32
	ComprCovg     uint32
	ZcullCovg     uint32
	_             uint32
	RangeLo       uint64
	RangeHi       uint64
	Size          uint64
	Alignment     uint64
	Offset        uint64
	Limit         uint64
	Address       P64
	CtagOffset    uint32
	HVASpace      Handle
	InternalFlags uint32
	Tag           uint32
}

// NV_MEMORY_ALLOCATION_PARAMS_V545 is the updated version of
// NV_MEMORY_ALLOCATION_PARAMS since 545.23.06.
//
// +marshal
type NV_MEMORY_ALLOCATION_PARAMS_V545 struct {
	NV_MEMORY_ALLOCATION_PARAMS
	NumaNode int32
	_        uint32
}

// NV503B_BAR1_P2P_DMA_INFO from src/common/sdk/nvidia/inc/class/cl503b.h.
//
// +marshal
type NV503B_BAR1_P2P_DMA_INFO struct {
	DmaAddress uint64
	DmaSize    uint64
}

// NV503B_ALLOC_PARAMETERS is the alloc params type for NV50_P2P, from
// src/common/sdk/nvidia/inc/class/cl503b.h.
//
// +marshal
type NV503B_ALLOC_PARAMETERS struct {
	HSubDevice                 Handle
	HPeerSubDevice             Handle
	SubDevicePeerIDMask        uint32
	PeerSubDevicePeerIDMask    uint32
	MailboxBar1Addr            uint64
	MailboxTotalSize           uint32
	Flags                      uint32
	SubDeviceEgmPeerIDMask     uint32
	PeerSubDeviceEgmPeerIDMask uint32
	L2pBar1P2PDmaInfo          NV503B_BAR1_P2P_DMA_INFO
	P2lBar1P2PDmaInfo          NV503B_BAR1_P2P_DMA_INFO
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

// NV_VASPACE_ALLOCATION_PARAMETERS_V580 is the updated version of
// NV_VASPACE_ALLOCATION_PARAMETERS since 580.65.06.
//
// +marshal
type NV_VASPACE_ALLOCATION_PARAMETERS_V580 struct {
	NV_VASPACE_ALLOCATION_PARAMETERS
	Pasid uint32
	Pad1  [4]byte
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

// NV_BSP_ALLOCATION_PARAMETERS is the alloc params type for
// NV*VIDEO_DECODER, from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_BSP_ALLOCATION_PARAMETERS struct {
	Size                      uint32
	ProhibitMultipleInstances uint32
	EngineInstance            uint32
}

// NV_MSENC_ALLOCATION_PARAMETERS is the alloc params type for
// NV*_VIDEO_ENCODER, from src/common/sdk/nvidia/inc/nvos.h.
//
// +marshal
type NV_MSENC_ALLOCATION_PARAMETERS struct {
	Size                      uint32
	ProhibitMultipleInstances uint32
	EngineInstance            uint32
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
	EncryptIv           [CC_CHAN_ALLOC_IV_SIZE_DWORD]uint32
	DecryptIv           [CC_CHAN_ALLOC_IV_SIZE_DWORD]uint32
	HmacNonce           [CC_CHAN_ALLOC_NONCE_SIZE_DWORD]uint32
}

// NV_CHANNEL_ALLOC_PARAMS_V570 is the updated version of
// NV_CHANNEL_ALLOC_PARAMS since 570.86.15.
//
// +marshal
type NV_CHANNEL_ALLOC_PARAMS_V570 struct {
	NV_CHANNEL_ALLOC_PARAMS
	TPCConfigID uint32
	_           uint32
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

// NV9072_ALLOCATION_PARAMETERS is the alloc param type for GF100_DISP_SW,
// from src/common/sdk/nvidia/inc/class/cl9072.h.
//
// +marshal
type NV9072_ALLOCATION_PARAMETERS struct {
	LogicalHeadID uint32
	DisplayMask   uint32
	Caps          uint32
}

// NV00DE_ALLOC_PARAMETERS is the alloc param type for RM_USER_SHARED_DATA,
// from src/common/sdk/nvidia/inc/class/cl00de.h.
//
// +marshal
type NV00DE_ALLOC_PARAMETERS struct {
	Reserved uint32
}

// NV00DE_ALLOC_PARAMETERS_V545 is the updated version of
// NV00DE_ALLOC_PARAMETERS since 545.23.06.
//
// +marshal
type NV00DE_ALLOC_PARAMETERS_V545 struct {
	PolledDataMask uint64
}

// +marshal
type nv00f8Map struct {
	offset  uint64
	hVidMem Handle
	flags   uint32
}

// NV00F8_ALLOCATION_PARAMETERS is the alloc param type for NV_MEMORY_FABRIC,
// from src/common/sdk/nvidia/inc/class/cl00f8.h.
//
// +marshal
type NV00F8_ALLOCATION_PARAMETERS struct {
	Alignment  uint64
	AllocSize  uint64
	PageSize   uint64
	AllocFlags uint32
	_          uint32
	Map        nv00f8Map
}

// From src/common/sdk/nvidia/inc/class/cl00e0.h
const (
	NV_MEM_EXPORT_UUID_LEN = 16
)

// NV_EXPORT_MEM_PACKET is from
// src/common/sdk/nvidia/inc/class/cl00e0.h
//
// +marshal
type NV_EXPORT_MEM_PACKET struct {
	UUID   [NV_MEM_EXPORT_UUID_LEN]uint8
	Opaque [16]uint8
}

// NV00FD_ALLOCATION_PARAMETERS is the alloc param type for NV_MEMORY_MULTICAST_FABRIC
// from src/common/sdk/nvidia/inc/class/cl00fd.h
//
// +marshal
type NV00FD_ALLOCATION_PARAMETERS struct {
	Alignment  uint64
	AllocSize  uint64
	PageSize   uint32
	AllocFlags uint32
	NumGPUs    uint32
	_          uint32
	POsEvent   P64
}

// NV00FD_ALLOCATION_PARAMETERS_V545 is the updated version of
// NV00FD_ALLOCATION_PARAMETERS since 545.23.06.
//
// +marshal
type NV00FD_ALLOCATION_PARAMETERS_V545 struct {
	ExpPacket NV_EXPORT_MEM_PACKET
	Index     uint16
	_         [6]byte
	NV00FD_ALLOCATION_PARAMETERS
}

// NV_MEMORY_MAPPER_ALLOCATION_PARAMS is the alloc param type for
// NV_MEMORY_MAPPER, from src/common/sdk/nvidia/inc/class/cl00fe.h.
//
// +marshal
type NV_MEMORY_MAPPER_ALLOCATION_PARAMS struct {
	unused uint8
}

// NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550 is the updated version of
// NV_MEMORY_MAPPER_ALLOCATION_PARAMS since 550.40.07.
//
// +marshal
type NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550 struct {
	HSemaphoreSurface Handle
	MaxQueueSize      uint32
}

// NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555 is the updated version of
// NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550 since 555.42.02.
//
// +marshal
type NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555 struct {
	NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550
	HNotificationMemory Handle
	_                   uint32
	NotificationOffset  uint64
}

// NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS is the alloc param type for
// NV_CONFIDENTIAL_COMPUTE, from src/common/sdk/nvidia/inc/class/clcb33.h.
//
// +marshal
type NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS struct {
	Handle Handle
}

// NVA0BC_ALLOC_PARAMETERS is the alloc param type for
// NVENC_SW_SESSION, from src/common/sdk/nvidia/inc/class/cla0bc.h
//
// +marshal
type NVA0BC_ALLOC_PARAMETERS struct {
	CodecType   uint32
	HResolution uint32
	VResolution uint32
	Version     uint32
	HMem        Handle
}
