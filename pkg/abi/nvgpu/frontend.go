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
	"gvisor.dev/gvisor/pkg/marshal"
)

// NV_IOCTL_MAGIC is the "canonical" IOC_TYPE for frontend ioctls.
// The driver ignores IOC_TYPE, allowing any value to be passed.
const NV_IOCTL_MAGIC = uint32('F')

// Frontend ioctl numbers.
// Note that these are only the IOC_NR part of the ioctl command.
const (
	// From kernel-open/common/inc/nv-ioctl-numbers.h:
	NV_IOCTL_BASE             = 200
	NV_ESC_CARD_INFO          = NV_IOCTL_BASE + 0
	NV_ESC_REGISTER_FD        = NV_IOCTL_BASE + 1
	NV_ESC_ALLOC_OS_EVENT     = NV_IOCTL_BASE + 6
	NV_ESC_FREE_OS_EVENT      = NV_IOCTL_BASE + 7
	NV_ESC_CHECK_VERSION_STR  = NV_IOCTL_BASE + 10
	NV_ESC_ATTACH_GPUS_TO_FD  = NV_IOCTL_BASE + 12
	NV_ESC_SYS_PARAMS         = NV_IOCTL_BASE + 14
	NV_ESC_WAIT_OPEN_COMPLETE = NV_IOCTL_BASE + 18

	// From kernel-open/common/inc/nv-ioctl-numa.h:
	NV_ESC_NUMA_INFO = NV_IOCTL_BASE + 15

	// From src/nvidia/arch/nvalloc/unix/include/nv_escape.h:
	NV_ESC_RM_ALLOC_MEMORY               = 0x27
	NV_ESC_RM_FREE                       = 0x29
	NV_ESC_RM_CONTROL                    = 0x2a
	NV_ESC_RM_ALLOC                      = 0x2b
	NV_ESC_RM_DUP_OBJECT                 = 0x34
	NV_ESC_RM_SHARE                      = 0x35
	NV_ESC_RM_IDLE_CHANNELS              = 0x41
	NV_ESC_RM_VID_HEAP_CONTROL           = 0x4a
	NV_ESC_RM_MAP_MEMORY                 = 0x4e
	NV_ESC_RM_UNMAP_MEMORY               = 0x4f
	NV_ESC_RM_ALLOC_CONTEXT_DMA2         = 0x54
	NV_ESC_RM_MAP_MEMORY_DMA             = 0x57
	NV_ESC_RM_UNMAP_MEMORY_DMA           = 0x58
	NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO = 0x5e
)

// Frontend ioctl parameter structs, from src/common/sdk/nvidia/inc/nvos.h or
// kernel-open/common/inc/nv-ioctl.h.

// IoctlRegisterFD is the parameter type for NV_ESC_REGISTER_FD.
//
// +marshal
type IoctlRegisterFD struct {
	CtlFD int32
}

// GetStatus implements HasStatus.GetStatus.
func (p *IoctlRegisterFD) GetStatus() uint32 {
	// nv_ioctl_register_fd_t doesn't have a NvStatus field. Any failures are
	// returned from src/nvidia/arch/nvalloc/unix/src/escape.c:nvidia_ioctl()'s
	// NV_ESC_REGISTER_FD case to kernel-open/nvidia/nv.c:nvidia_ioctl()'s
	// default case, which converts it to an ioctl(2) syscall error.
	return NV_OK
}

// IoctlAllocOSEvent is the parameter type for NV_ESC_ALLOC_OS_EVENT.
//
// +marshal
type IoctlAllocOSEvent struct {
	HClient Handle
	HDevice Handle
	FD      uint32
	Status  uint32
}

// GetFrontendFD implements HasFrontendFD.GetFrontendFD.
func (p *IoctlAllocOSEvent) GetFrontendFD() int32 {
	return int32(p.FD)
}

// SetFrontendFD implements HasFrontendFD.SetFrontendFD.
func (p *IoctlAllocOSEvent) SetFrontendFD(fd int32) {
	p.FD = uint32(fd)
}

// GetStatus implements HasStatus.GetStatus.
func (p *IoctlAllocOSEvent) GetStatus() uint32 {
	return p.Status
}

// IoctlFreeOSEvent is the parameter type for NV_ESC_FREE_OS_EVENT.
//
// +marshal
type IoctlFreeOSEvent struct {
	HClient Handle
	HDevice Handle
	FD      uint32
	Status  uint32
}

// GetFrontendFD implements HasFrontendFD.GetFrontendFD.
func (p *IoctlFreeOSEvent) GetFrontendFD() int32 {
	return int32(p.FD)
}

// SetFrontendFD implements HasFrontendFD.SetFrontendFD.
func (p *IoctlFreeOSEvent) SetFrontendFD(fd int32) {
	p.FD = uint32(fd)
}

// GetStatus implements HasStatus.GetStatus.
func (p *IoctlFreeOSEvent) GetStatus() uint32 {
	return p.Status
}

// RMAPIVersion is the parameter type for NV_ESC_CHECK_VERSION_STR.
//
// +marshal
type RMAPIVersion struct {
	Cmd           uint32
	Reply         uint32
	VersionString [64]byte
}

// GetStatus implements HasStatus.GetStatus.
func (p *RMAPIVersion) GetStatus() uint32 {
	// nv_ioctl_rm_api_version_t doesn't have a NvStatus field. The driver
	// translates the rmStatus to an ioctl(2) failure. See
	// kernel-open/nvidia/nv.c:nvidia_ioctl() => case NV_ESC_CHECK_VERSION_STR.
	return NV_OK
}

// IoctlSysParams is the parameter type for NV_ESC_SYS_PARAMS.
//
// +marshal
type IoctlSysParams struct {
	MemblockSize uint64
}

// GetStatus implements HasStatus.GetStatus.
func (p *IoctlSysParams) GetStatus() uint32 {
	// nv_ioctl_sys_params_t doesn't have a NvStatus field. The driver fails the
	// ioctl(2) syscall in case of any failure. See
	// kernel-open/nvidia/nv.c:nvidia_ioctl() => case NV_ESC_SYS_PARAMS.
	return NV_OK
}

// IoctlWaitOpenComplete is the parameter type for NV_ESC_WAIT_OPEN_COMPLETE.
//
// +marshal
type IoctlWaitOpenComplete struct {
	Rc            int32
	AdapterStatus uint32
}

// GetStatus implements HasStatus.GetStatus.
func (p *IoctlWaitOpenComplete) GetStatus() uint32 {
	return p.AdapterStatus
}

// IoctlNVOS02ParametersWithFD is the parameter type for NV_ESC_RM_ALLOC_MEMORY.
//
// +marshal
type IoctlNVOS02ParametersWithFD struct {
	Params NVOS02_PARAMETERS
	FD     int32
	Pad0   [4]byte
}

// GetStatus implements HasStatus.GetStatus.
func (p *IoctlNVOS02ParametersWithFD) GetStatus() uint32 {
	return p.Params.Status
}

// +marshal
type NVOS02_PARAMETERS struct {
	HRoot         Handle
	HObjectParent Handle
	HObjectNew    Handle
	HClass        ClassID
	Flags         uint32
	Pad0          [4]byte
	PMemory       P64 // address of application mapping, without indirection
	Limit         uint64
	Status        uint32
	Pad1          [4]byte
}

// Bitfields in NVOS02Parameters.Flags:
const (
	NVOS02_FLAGS_ALLOC_SHIFT = 16
	NVOS02_FLAGS_ALLOC_MASK  = 0x3
	NVOS02_FLAGS_ALLOC_NONE  = 0x00000001

	NVOS02_FLAGS_MAPPING_SHIFT  = 30
	NVOS02_FLAGS_MAPPING_MASK   = 0x3
	NVOS02_FLAGS_MAPPING_NO_MAP = 0x00000001
)

// NVOS00_PARAMETERS is the parameter type for NV_ESC_RM_FREE.
//
// +marshal
type NVOS00_PARAMETERS struct {
	HRoot         Handle
	HObjectParent Handle
	HObjectOld    Handle
	Status        uint32
}

// GetStatus implements HasStatus.GetStatus.
func (p *NVOS00_PARAMETERS) GetStatus() uint32 {
	return p.Status
}

// RmAllocParamType should be implemented by all possible parameter types for
// NV_ESC_RM_ALLOC.
type RmAllocParamType interface {
	GetHClass() ClassID
	GetPAllocParms() P64
	GetPRightsRequested() P64
	SetPAllocParms(p P64)
	SetPRightsRequested(p P64)
	FromOS64(other NVOS64_PARAMETERS)
	ToOS64() NVOS64_PARAMETERS
	GetPointer() uintptr
	HasStatus
	marshal.Marshallable
}

// GetRmAllocParamObj returns the appropriate implementation of
// RmAllocParamType based on passed parameters.
func GetRmAllocParamObj(isNVOS64 bool) RmAllocParamType {
	if isNVOS64 {
		return &NVOS64_PARAMETERS{}
	}
	return &NVOS21_PARAMETERS{}
}

// NVOS21_PARAMETERS is one possible parameter type for NV_ESC_RM_ALLOC.
//
// +marshal
type NVOS21_PARAMETERS struct {
	HRoot         Handle
	HObjectParent Handle
	HObjectNew    Handle
	HClass        ClassID
	PAllocParms   P64
	ParamsSize    uint32
	Status        uint32
}

// GetHClass implements RmAllocParamType.GetHClass.
func (n *NVOS21_PARAMETERS) GetHClass() ClassID {
	return n.HClass
}

// GetPAllocParms implements RmAllocParamType.GetPAllocParms.
func (n *NVOS21_PARAMETERS) GetPAllocParms() P64 {
	return n.PAllocParms
}

// GetPRightsRequested implements RmAllocParamType.GetPRightsRequested.
func (n *NVOS21_PARAMETERS) GetPRightsRequested() P64 {
	return 0
}

// SetPAllocParms implements RmAllocParamType.SetPAllocParms.
func (n *NVOS21_PARAMETERS) SetPAllocParms(p P64) { n.PAllocParms = p }

// SetPRightsRequested implements RmAllocParamType.SetPRightsRequested.
func (n *NVOS21_PARAMETERS) SetPRightsRequested(p P64) {
	panic("impossible")
}

// FromOS64 implements RmAllocParamType.FromOS64.
func (n *NVOS21_PARAMETERS) FromOS64(other NVOS64_PARAMETERS) {
	n.HRoot = other.HRoot
	n.HObjectParent = other.HObjectParent
	n.HObjectNew = other.HObjectNew
	n.HClass = other.HClass
	n.PAllocParms = other.PAllocParms
	n.ParamsSize = other.ParamsSize
	n.Status = other.Status
}

// ToOS64 implements RmAllocParamType.ToOS64.
func (n *NVOS21_PARAMETERS) ToOS64() NVOS64_PARAMETERS {
	return NVOS64_PARAMETERS{
		HRoot:         n.HRoot,
		HObjectParent: n.HObjectParent,
		HObjectNew:    n.HObjectNew,
		HClass:        n.HClass,
		PAllocParms:   n.PAllocParms,
		ParamsSize:    n.ParamsSize,
		Status:        n.Status,
	}
}

// GetStatus implements RmAllocParamType.GetStatus.
func (n *NVOS21_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS55_PARAMETERS is the parameter type for NV_ESC_RM_DUP_OBJECT.
//
// +marshal
type NVOS55_PARAMETERS struct {
	HClient    Handle
	HParent    Handle
	HObject    Handle
	HClientSrc Handle
	HObjectSrc Handle
	Flags      uint32
	Status     uint32
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS55_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS57_PARAMETERS is the parameter type for NV_ESC_RM_SHARE.
//
// +marshal
type NVOS57_PARAMETERS struct {
	HClient     Handle
	HObject     Handle
	SharePolicy RS_SHARE_POLICY
	Status      uint32
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS57_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS30_PARAMETERS is the parameter type for NV_ESC_RM_IDLE_CHANNELS.
//
// +marshal
type NVOS30_PARAMETERS struct {
	Client      Handle
	Device      Handle
	Channel     Handle
	NumChannels uint32

	Clients  P64
	Devices  P64
	Channels P64

	Flags   uint32
	Timeout uint32
	Status  uint32
	Pad0    [4]byte
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS30_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS32_PARAMETERS is the parameter type for NV_ESC_RM_VID_HEAP_CONTROL.
//
// +marshal
type NVOS32_PARAMETERS struct {
	HRoot         Handle
	HObjectParent Handle
	Function      uint32
	HVASpace      Handle
	IVCHeapNumber int16
	Pad           [2]byte
	Status        uint32
	Total         uint64
	Free          uint64
	Data          [144]byte // union
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS32_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// Possible values for NVOS32Parameters.Function:
const (
	NVOS32_FUNCTION_ALLOC_SIZE = 2
)

// NVOS32AllocSize is the type of NVOS32Parameters.Data for
// NVOS32_FUNCTION_ALLOC_SIZE.
type NVOS32AllocSize struct {
	Owner           uint32
	HMemory         Handle
	Type            uint32
	Flags           uint32
	Attr            uint32
	Format          uint32
	ComprCovg       uint32
	ZcullCovg       uint32
	PartitionStride uint32
	Width           uint32
	Height          uint32
	Pad0            [4]byte
	Size            uint64
	Alignment       uint64
	Offset          uint64
	Limit           uint64
	Address         P64
	RangeBegin      uint64
	RangeEnd        uint64
	Attr2           uint32
	CtagOffset      uint32
}

// Flags in NVOS32AllocSize.Flags:
const (
	NVOS32_ALLOC_FLAGS_VIRTUAL = 0x00080000
)

// Bitfields in NVOS32AllocSize.Attr:
const (
	NVOS32_ATTR_LOCATION_SHIFT  = 25
	NVOS32_ATTR_LOCATION_MASK   = 0x3
	NVOS32_ATTR_LOCATION_VIDMEM = 0
)

// Bitfields in NVOS32AllocSize.Attr2:
const (
	NVOS32_ATTR2_USE_EGM_SHIFT = 24
	NVOS32_ATTR2_USE_EGM_MASK  = 0x1
	NVOS32_ATTR2_USE_EGM_FALSE = 0
	NVOS32_ATTR2_USE_EGM_TRUE  = 1
)

// IoctlNVOS33ParametersWithFD is the parameter type for NV_ESC_RM_MAP_MEMORY,
// from src/nvidia/arch/nvalloc/unix/include/nv-unix-nvos-params-wrappers.h.
//
// +marshal
type IoctlNVOS33ParametersWithFD struct {
	Params NVOS33_PARAMETERS
	FD     int32
	Pad0   [4]byte
}

// GetStatus implements HasStatus.GetStatus.
func (p *IoctlNVOS33ParametersWithFD) GetStatus() uint32 {
	return p.Params.Status
}

// +marshal
type NVOS33_PARAMETERS struct {
	HClient        Handle
	HDevice        Handle
	HMemory        Handle
	Pad0           [4]byte
	Offset         uint64
	Length         uint64
	PLinearAddress P64 // address of application mapping, without indirection
	Status         uint32
	Flags          uint32
}

// NVOS34_PARAMETERS is the parameter type for NV_ESC_RM_UNMAP_MEMORY.
//
// +marshal
type NVOS34_PARAMETERS struct {
	HClient        Handle
	HDevice        Handle
	HMemory        Handle
	Pad0           [4]byte
	PLinearAddress P64 // address of application mapping, without indirection
	Status         uint32
	Flags          uint32
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS34_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS39_PARAMETERS is the parameter type for NV_ESC_RM_ALLOC_CONTEXT_DMA2.
//
// +marshal
type NVOS39_PARAMETERS struct {
	HObjectParent Handle
	HSubDevice    Handle
	HObjectNew    Handle
	HClass        ClassID
	Flags         uint32
	Selector      uint32
	HMemory       Handle
	Pad0          [4]byte
	Offset        uint64
	Limit         uint64
	Status        uint32
	Pad1          [4]byte
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS39_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS46_PARAMETERS is the parameter type for NV_ESC_RM_MAP_MEMORY_DMA.
//
// +marshal
type NVOS46_PARAMETERS struct {
	Client    Handle
	Device    Handle
	Dma       Handle
	Memory    Handle
	Offset    uint64
	Length    uint64
	Flags     uint32
	Pad0      [4]byte
	DmaOffset uint64
	Status    uint32
	Pad1      [4]byte
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS46_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS47_PARAMETERS is the parameter type for NV_ESC_RM_UNMAP_MEMORY_DMA.
//
// +marshal
type NVOS47_PARAMETERS struct {
	Client    Handle
	Device    Handle
	Dma       Handle
	Memory    Handle
	Flags     uint32
	Pad0      [4]byte
	DmaOffset uint64
	Status    uint32
	Pad1      [4]byte
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS47_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS47_PARAMETERS_V550 is the updated version of NVOS47_PARAMETERS since
// 550.54.04.
//
// +marshal
type NVOS47_PARAMETERS_V550 struct {
	Client    Handle
	Device    Handle
	Dma       Handle
	Memory    Handle
	Flags     uint32
	Pad0      [4]byte
	DmaOffset uint64
	Size      uint64
	Status    uint32
	Pad1      [4]byte
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS47_PARAMETERS_V550) GetStatus() uint32 {
	return n.Status
}

// NVOS54_PARAMETERS is the parameter type for NV_ESC_RM_CONTROL.
//
// +marshal
type NVOS54_PARAMETERS struct {
	HClient    Handle
	HObject    Handle
	Cmd        uint32
	Flags      uint32
	Params     P64
	ParamsSize uint32
	Status     uint32
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS54_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS56_PARAMETERS is the parameter type for NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO.
//
// +marshal
type NVOS56_PARAMETERS struct {
	HClient        Handle
	HDevice        Handle
	HMemory        Handle
	Pad0           [4]byte
	POldCPUAddress P64
	PNewCPUAddress P64
	Status         uint32
	Pad1           [4]byte
}

// GetStatus implements HasStatus.GetStatus.
func (n *NVOS56_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// NVOS64_PARAMETERS is one possible parameter type for NV_ESC_RM_ALLOC.
//
// +marshal
// +stateify savable
type NVOS64_PARAMETERS struct {
	HRoot            Handle
	HObjectParent    Handle
	HObjectNew       Handle
	HClass           ClassID
	PAllocParms      P64
	PRightsRequested P64
	ParamsSize       uint32
	Flags            uint32
	Status           uint32
	_                uint32
}

// GetHClass implements RmAllocParamType.GetHClass.
func (n *NVOS64_PARAMETERS) GetHClass() ClassID {
	return n.HClass
}

// GetPAllocParms implements RmAllocParamType.GetPAllocParms.
func (n *NVOS64_PARAMETERS) GetPAllocParms() P64 {
	return n.PAllocParms
}

// GetPRightsRequested implements RmAllocParamType.GetPRightsRequested.
func (n *NVOS64_PARAMETERS) GetPRightsRequested() P64 {
	return n.PRightsRequested
}

// SetPAllocParms implements RmAllocParamType.SetPAllocParms.
func (n *NVOS64_PARAMETERS) SetPAllocParms(p P64) { n.PAllocParms = p }

// SetPRightsRequested implements RmAllocParamType.SetPRightsRequested.
func (n *NVOS64_PARAMETERS) SetPRightsRequested(p P64) { n.PRightsRequested = p }

// FromOS64 implements RmAllocParamType.FromOS64.
func (n *NVOS64_PARAMETERS) FromOS64(other NVOS64_PARAMETERS) { *n = other }

// ToOS64 implements RmAllocParamType.ToOS64.
func (n *NVOS64_PARAMETERS) ToOS64() NVOS64_PARAMETERS { return *n }

// GetStatus implements RmAllocParamType.GetStatus.
func (n *NVOS64_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

// HasFrontendFD is a type constraint for parameter structs containing a
// frontend FD field. This is necessary because, as of this writing (Go 1.20),
// there is no way to enable field access using a Go type constraint.
type HasFrontendFD interface {
	GetFrontendFD() int32
	SetFrontendFD(int32)
}

// Frontend ioctl parameter struct sizes.
var (
	SizeofIoctlRegisterFD             = uint32((*IoctlRegisterFD)(nil).SizeBytes())
	SizeofIoctlAllocOSEvent           = uint32((*IoctlAllocOSEvent)(nil).SizeBytes())
	SizeofIoctlFreeOSEvent            = uint32((*IoctlFreeOSEvent)(nil).SizeBytes())
	SizeofRMAPIVersion                = uint32((*RMAPIVersion)(nil).SizeBytes())
	SizeofIoctlSysParams              = uint32((*IoctlSysParams)(nil).SizeBytes())
	SizeofIoctlWaitOpenComplete       = uint32((*IoctlWaitOpenComplete)(nil).SizeBytes())
	SizeofIoctlNVOS02ParametersWithFD = uint32((*IoctlNVOS02ParametersWithFD)(nil).SizeBytes())
	SizeofNVOS00Parameters            = uint32((*NVOS00_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS21Parameters            = uint32((*NVOS21_PARAMETERS)(nil).SizeBytes())
	SizeofIoctlNVOS33ParametersWithFD = uint32((*IoctlNVOS33ParametersWithFD)(nil).SizeBytes())
	SizeofNVOS30Parameters            = uint32((*NVOS30_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS32Parameters            = uint32((*NVOS32_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS34Parameters            = uint32((*NVOS34_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS39Parameters            = uint32((*NVOS39_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS46Parameters            = uint32((*NVOS46_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS54Parameters            = uint32((*NVOS54_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS55Parameters            = uint32((*NVOS55_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS56Parameters            = uint32((*NVOS56_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS57Parameters            = uint32((*NVOS57_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS64Parameters            = uint32((*NVOS64_PARAMETERS)(nil).SizeBytes())
)
