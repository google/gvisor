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

// HasRMCtrlFD is a type constraint for UVM parameter structs containing a
// RMCtrlFD field. This is necessary because, as of this writing (Go 1.20),
// there is no way to enable field access using a Go type constraint.
type HasRMCtrlFD interface {
	GetRMCtrlFD() int32
	SetRMCtrlFD(int32)
}

// UVM ioctl commands.
const (
	// From kernel-open/nvidia-uvm/uvm_linux_ioctl.h:
	UVM_INITIALIZE   = 0x30000001
	UVM_DEINITIALIZE = 0x30000002

	// From kernel-open/nvidia-uvm/uvm_ioctl.h:
	UVM_CREATE_RANGE_GROUP             = 23
	UVM_DESTROY_RANGE_GROUP            = 24
	UVM_REGISTER_GPU_VASPACE           = 25
	UVM_UNREGISTER_GPU_VASPACE         = 26
	UVM_REGISTER_CHANNEL               = 27
	UVM_UNREGISTER_CHANNEL             = 28
	UVM_MAP_EXTERNAL_ALLOCATION        = 33
	UVM_FREE                           = 34
	UVM_REGISTER_GPU                   = 37
	UVM_UNREGISTER_GPU                 = 38
	UVM_PAGEABLE_MEM_ACCESS            = 39
	UVM_MAP_DYNAMIC_PARALLELISM_REGION = 65
	UVM_ALLOC_SEMAPHORE_POOL           = 68
	UVM_VALIDATE_VA_RANGE              = 72
	UVM_CREATE_EXTERNAL_RANGE          = 73
	UVM_MM_INITIALIZE                  = 75
)

// +marshal
type UVM_INITIALIZE_PARAMS struct {
	Flags    uint64
	RMStatus uint32
	Pad0     [4]byte
}

// UVM_INITIALIZE_PARAMS flags, from kernel-open/nvidia-uvm/uvm_types.h.
const (
	UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE = 0x2
)

// +marshal
type UVM_CREATE_RANGE_GROUP_PARAMS struct {
	RangeGroupID uint64
	RMStatus     uint32
	Pad0         [4]byte
}

// +marshal
type UVM_DESTROY_RANGE_GROUP_PARAMS struct {
	RangeGroupID uint64
	RMStatus     uint32
	Pad0         [4]byte
}

// +marshal
type UVM_REGISTER_GPU_VASPACE_PARAMS struct {
	GPUUUID  [16]uint8
	RMCtrlFD int32
	HClient  Handle
	HVASpace Handle
	RMStatus uint32
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) GetRMCtrlFD() int32 {
	return p.RMCtrlFD
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) SetRMCtrlFD(fd int32) {
	p.RMCtrlFD = fd
}

// +marshal
type UVM_UNREGISTER_GPU_VASPACE_PARAMS struct {
	GPUUUID  [16]uint8
	RMStatus uint32
}

// +marshal
type UVM_REGISTER_CHANNEL_PARAMS struct {
	GPUUUID  [16]uint8
	RMCtrlFD int32
	HClient  Handle
	HChannel Handle
	Pad      [4]byte
	Base     uint64
	Length   uint64
	RMStatus uint32
	Pad0     [4]byte
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) GetRMCtrlFD() int32 {
	return p.RMCtrlFD
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) SetRMCtrlFD(fd int32) {
	p.RMCtrlFD = fd
}

// +marshal
type UVM_UNREGISTER_CHANNEL_PARAMS struct {
	GPUUUID  [16]uint8
	HClient  Handle
	HChannel Handle
	RMStatus uint32
}

// +marshal
type UVM_MAP_EXTERNAL_ALLOCATION_PARAMS struct {
	Base               uint64
	Length             uint64
	Offset             uint64
	PerGPUAttributes   [UVM_MAX_GPUS]UvmGpuMappingAttributes
	GPUAttributesCount uint64
	RMCtrlFD           int32
	HClient            Handle
	HMemory            Handle
	RMStatus           uint32
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) GetRMCtrlFD() int32 {
	return p.RMCtrlFD
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) SetRMCtrlFD(fd int32) {
	p.RMCtrlFD = fd
}

// +marshal
type UVM_FREE_PARAMS struct {
	Base     uint64
	Length   uint64
	RMStatus uint32
	Pad0     [4]byte
}

// +marshal
type UVM_REGISTER_GPU_PARAMS struct {
	GPUUUID     [16]uint8
	NumaEnabled uint8
	Pad         [3]byte
	NumaNodeID  int32
	RMCtrlFD    int32
	HClient     Handle
	HSMCPartRef Handle
	RMStatus    uint32
}

func (p *UVM_REGISTER_GPU_PARAMS) GetRMCtrlFD() int32 {
	return p.RMCtrlFD
}

func (p *UVM_REGISTER_GPU_PARAMS) SetRMCtrlFD(fd int32) {
	p.RMCtrlFD = fd
}

// +marshal
type UVM_UNREGISTER_GPU_PARAMS struct {
	GPUUUID  [16]uint8
	RMStatus uint32
}

// +marshal
type UVM_PAGEABLE_MEM_ACCESS_PARAMS struct {
	PageableMemAccess uint8
	Pad               [3]byte
	RMStatus          uint32
}

// +marshal
type UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS struct {
	Base     uint64
	Length   uint64
	GPUUUID  [16]uint8
	RMStatus uint32
	Pad0     [4]byte
}

// +marshal
type UVM_ALLOC_SEMAPHORE_POOL_PARAMS struct {
	Base               uint64
	Length             uint64
	PerGPUAttributes   [UVM_MAX_GPUS]UvmGpuMappingAttributes
	GPUAttributesCount uint64
	RMStatus           uint32
	Pad0               [4]byte
}

// +marshal
type UVM_VALIDATE_VA_RANGE_PARAMS struct {
	Base     uint64
	Length   uint64
	RMStatus uint32
	Pad0     [4]byte
}

// +marshal
type UVM_CREATE_EXTERNAL_RANGE_PARAMS struct {
	Base     uint64
	Length   uint64
	RMStatus uint32
	Pad0     [4]byte
}

// +marshal
type UVM_MM_INITIALIZE_PARAMS struct {
	UvmFD  int32
	Status uint32
}

// From kernel-open/nvidia-uvm/uvm_types.h:

const UVM_MAX_GPUS = NV_MAX_DEVICES

// +marshal
type UvmGpuMappingAttributes struct {
	GPUUUID            [16]byte
	GPUMappingType     uint32
	GPUCachingType     uint32
	GPUFormatType      uint32
	GPUElementBits     uint32
	GPUCompressionType uint32
}
