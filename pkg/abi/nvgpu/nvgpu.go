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

// Package nvgpu tracks the ABI of the Nvidia GPU Linux kernel driver:
// https://github.com/NVIDIA/open-gpu-kernel-modules
package nvgpu

import (
	"fmt"
)

// Device numbers.
const (
	NV_MAJOR_DEVICE_NUMBER          = 195 // from kernel-open/common/inc/nv.h
	NV_CONTROL_DEVICE_MINOR         = 255 // from kernel-open/common/inc/nv-linux.h
	NVIDIA_UVM_PRIMARY_MINOR_NUMBER = 0   // from kernel-open/nvidia-uvm/uvm_common.h
)

// Handle is NvHandle, from src/common/sdk/nvidia/inc/nvtypes.h.
//
// +marshal
// +stateify savable
type Handle struct {
	Val uint32
}

// String implements fmt.Stringer.String.
func (h Handle) String() string {
	return fmt.Sprintf("%#x", h.Val)
}

// P64 is NvP64, from src/common/sdk/nvidia/inc/nvtypes.h.
//
// +marshal
type P64 uint64

// From src/common/sdk/nvidia/inc/nvlimits.h:
const (
	NV_MAX_DEVICES    = 32
	NV_MAX_SUBDEVICES = 8
)

// From src/common/sdk/nvidia/inc/alloc/alloc_channel.h.
const (
	CC_CHAN_ALLOC_IV_SIZE_DWORD    = 3
	CC_CHAN_ALLOC_NONCE_SIZE_DWORD = 8
)

// RS_ACCESS_MASK is RS_ACCESS_MASK, from
// src/common/sdk/nvidia/inc/rs_access.h.
//
// +marshal
// +stateify savable
type RS_ACCESS_MASK struct {
	Limbs [SDK_RS_ACCESS_MAX_LIMBS]uint32 // RsAccessLimb
}

const SDK_RS_ACCESS_MAX_LIMBS = 1

// RS_SHARE_POLICY is RS_SHARE_POLICY, from
// src/common/sdk/nvidia/inc/rs_access.h.
//
// +marshal
type RS_SHARE_POLICY struct {
	Target     uint32
	AccessMask RS_ACCESS_MASK
	Type       uint16
	Action     uint8
	Pad        [1]byte
}

// NvUUID is defined in src/common/inc/nvCpuUuid.h.
//
// +marshal
type NvUUID [16]uint8
