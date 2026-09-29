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

// Package amdgpu defines the Linux AMDGPU/KFD userspace ABI used by
// amdgpuproxy, from include/uapi/linux/kfd_ioctl.h,
// include/uapi/drm/{drm,amdgpu_drm}.h and the KFD mmap offset encoding in
// drivers/gpu/drm/amd/amdkfd/kfd_priv.h.
package amdgpu

import "structs"

// KFD ioctl requests.
const (
	AMDKFD_IOC_GET_VERSION               = 0x80084b01
	AMDKFD_IOC_CREATE_QUEUE              = 0xc0604b02
	AMDKFD_IOC_DESTROY_QUEUE             = 0xc0084b03
	AMDKFD_IOC_SET_MEMORY_POLICY         = 0x40204b04
	AMDKFD_IOC_GET_CLOCK_COUNTERS        = 0xc0284b05
	AMDKFD_IOC_CREATE_EVENT              = 0xc0204b08
	AMDKFD_IOC_DESTROY_EVENT             = 0x40084b09
	AMDKFD_IOC_SET_EVENT                 = 0x40084b0a
	AMDKFD_IOC_WAIT_EVENTS               = 0xc0184b0c
	AMDKFD_IOC_SET_SCRATCH_BACKING_VA    = 0xc0104b11
	AMDKFD_IOC_SET_TRAP_HANDLER          = 0x40184b13
	AMDKFD_IOC_GET_PROCESS_APERTURES_NEW = 0xc0104b14
	AMDKFD_IOC_ACQUIRE_VM                = 0x40084b15
	AMDKFD_IOC_ALLOC_MEMORY_OF_GPU       = 0xc0284b16
	AMDKFD_IOC_FREE_MEMORY_OF_GPU        = 0x40084b17
	AMDKFD_IOC_MAP_MEMORY_TO_GPU         = 0xc0184b18
	AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU     = 0xc0184b19
	AMDKFD_IOC_SET_XNACK_MODE            = 0xc0044b21
	AMDKFD_IOC_AVAILABLE_MEMORY          = 0xc0104b23
	AMDKFD_IOC_RUNTIME_ENABLE            = 0xc0104b25
)

// Queue types.
const (
	KFD_IOC_QUEUE_TYPE_COMPUTE     = 0x0
	KFD_IOC_QUEUE_TYPE_COMPUTE_AQL = 0x2
)

// Allocation flags.
const (
	KFD_IOC_ALLOC_MEM_FLAGS_VRAM          = 1 << 0
	KFD_IOC_ALLOC_MEM_FLAGS_GTT           = 1 << 1
	KFD_IOC_ALLOC_MEM_FLAGS_USERPTR       = 1 << 2
	KFD_IOC_ALLOC_MEM_FLAGS_AQL_QUEUE_MEM = 1 << 27
)

// KFD mmap offsets carry the GPU ID of doorbell and MMIO mappings.
const (
	KFD_MMAP_GPU_ID_SHIFT = 46
	KFD_MMAP_GPU_ID_MASK  = 0xffff << KFD_MMAP_GPU_ID_SHIFT
)

// Event wait results, timeouts and limits.
const (
	KFD_IOC_WAIT_RESULT_COMPLETE = 0
	KFD_IOC_WAIT_RESULT_TIMEOUT  = 1
	KFD_IOC_WAIT_RESULT_FAIL     = 2
	KFD_EVENT_TIMEOUT_IMMEDIATE  = 0
	KFD_EVENT_TIMEOUT_INFINITE   = 0xFFFFFFFF
	KFD_SIGNAL_EVENT_LIMIT       = 4096
)

// KFDCreateQueue is struct kfd_ioctl_create_queue_args.
//
// +marshal
type KFDCreateQueue struct {
	_                     structs.HostLayout
	RingBaseAddress       uint64
	WritePointerAddress   uint64
	ReadPointerAddress    uint64
	DoorbellOffset        uint64
	RingSize              uint32
	GPUID                 uint32
	QueueType             uint32
	QueuePercentage       uint32
	QueuePriority         uint32
	QueueID               uint32
	EOPBufferAddress      uint64
	EOPBufferSize         uint64
	CtxSaveRestoreAddress uint64
	CtxSaveRestoreSize    uint32
	CtlStackSize          uint32
	SDMAEngineID          uint32
	MetadataRingSize      uint32
}

// KFDSetMemoryPolicy is struct kfd_ioctl_set_memory_policy_args.
// AlternateApertureBase is a GPU address.
//
// +marshal
type KFDSetMemoryPolicy struct {
	_                     structs.HostLayout
	AlternateApertureBase uint64
	AlternateApertureSize uint64
	GPUID                 uint32
	DefaultPolicy         uint32
	AlternatePolicy       uint32
	MiscProcessFlag       uint32
}

// KFDSetScratchBackingVA is struct kfd_ioctl_set_scratch_backing_va_args.
//
// +marshal
type KFDSetScratchBackingVA struct {
	_      structs.HostLayout
	VAAddr uint64
	GPUID  uint32
	Pad    uint32
}

// KFDSetTrapHandler is struct kfd_ioctl_set_trap_handler_args.
//
// +marshal
type KFDSetTrapHandler struct {
	_       structs.HostLayout
	TBAAddr uint64
	TMAAddr uint64
	GPUID   uint32
	Pad     uint32
}

// KFDAvailableMemory is struct kfd_ioctl_get_available_memory_args.
//
// +marshal
type KFDAvailableMemory struct {
	_         structs.HostLayout
	Available uint64
	GPUID     uint32
	Pad       uint32
}

// KFDProcessDeviceApertures is struct kfd_process_device_apertures.
//
// +marshal
type KFDProcessDeviceApertures struct {
	_            structs.HostLayout
	LDSBase      uint64
	LDSLimit     uint64
	ScratchBase  uint64
	ScratchLimit uint64
	GPUVMBase    uint64
	GPUVMLimit   uint64
	GPUID        uint32
	Pad          uint32
}

// KFDGetProcessApertures is struct kfd_ioctl_get_process_apertures_new_args.
//
// +marshal
type KFDGetProcessApertures struct {
	_            structs.HostLayout
	AperturesPtr uint64
	NumOfNodes   uint32
	Pad          uint32
}

// KFDCreateEvent is struct kfd_ioctl_create_event_args. On input,
// EventPageOffset optionally names the allocation to use as the signal page.
//
// +marshal
type KFDCreateEvent struct {
	_                structs.HostLayout
	EventPageOffset  uint64
	EventTriggerData uint32
	EventType        uint32
	AutoReset        uint32
	NodeID           uint32
	EventID          uint32
	EventSlotIndex   uint32
}

// KFDEventData is struct kfd_event_data.
//
// +marshal
type KFDEventData struct {
	_            structs.HostLayout
	Data         [32]byte
	EventDataExt uint64
	EventID      uint32
	Pad          uint32
}

// KFDWaitEvents is struct kfd_ioctl_wait_events_args.
//
// +marshal
type KFDWaitEvents struct {
	_          structs.HostLayout
	EventsPtr  uint64
	NumEvents  uint32
	WaitForAll uint32
	Timeout    uint32
	WaitResult uint32
}

// KFDAcquireVM is struct kfd_ioctl_acquire_vm_args.
//
// +marshal
type KFDAcquireVM struct {
	_     structs.HostLayout
	DRMFD uint32
	GPUID uint32
}

// KFDAllocMemory is struct kfd_ioctl_alloc_memory_of_gpu_args. For USERPTR
// allocations, MmapOffset is the CPU address to register on input.
//
// +marshal
type KFDAllocMemory struct {
	_          structs.HostLayout
	VAAddr     uint64
	Size       uint64
	Handle     uint64
	MmapOffset uint64
	GPUID      uint32
	Flags      uint32
}

// KFDFreeMemory is struct kfd_ioctl_free_memory_of_gpu_args.
//
// +marshal
type KFDFreeMemory struct {
	_      structs.HostLayout
	Handle uint64
}

// KFDMapMemory is struct kfd_ioctl_map_memory_to_gpu_args and struct
// kfd_ioctl_unmap_memory_from_gpu_args.
//
// +marshal
type KFDMapMemory struct {
	_                 structs.HostLayout
	Handle            uint64
	DeviceIDsArrayPtr uint64
	NDevices          uint32
	NSuccess          uint32
}

// KFDSetXNACKMode is struct kfd_ioctl_set_xnack_mode_args.
//
// +marshal
type KFDSetXNACKMode struct {
	_            structs.HostLayout
	XNACKEnabled int32
}
