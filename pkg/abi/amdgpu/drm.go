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

package amdgpu

import "structs"

// DRM ioctl requests, for 64-bit applications.
const (
	DRM_IOCTL_VERSION     = 0xc0406400
	DRM_IOCTL_AMDGPU_INFO = 0x40206445
)

// DRMVersion is struct drm_version.
//
// +marshal
type DRMVersion struct {
	_          structs.HostLayout
	Major      int32
	Minor      int32
	PatchLevel int32
	Pad        uint32
	NameLen    uint64
	Name       uint64
	DateLen    uint64
	Date       uint64
	DescLen    uint64
	Desc       uint64
}

// DRMAMDGPUInfo is struct drm_amdgpu_info. QueryData is the query-specific
// input union, none of whose members are pointers.
//
// +marshal
type DRMAMDGPUInfo struct {
	_             structs.HostLayout
	ReturnPointer uint64
	ReturnSize    uint32
	Query         uint32
	QueryData     [4]uint32
}
