// Copyright 2024 The gVisor Authors.
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

// The package implements VFIOuserspace driver interface.

package linux

// For IOCTLs requests from include/uapi/linux/vfio.h.
const (
	VFIO_TYPE = ';'
	VFIO_BASE = 100

	// VFIO extensions.
	VFIO_TYPE1_IOMMU     = 1
	VFIO_SPAPR_TCE_IOMMU = 2
	VFIO_TYPE1v2_IOMMU   = 3
)

// IOCTLs for VFIO file descriptor from include/uapi/linux/vfio.h.
var (
	VFIO_CHECK_EXTENSION     = IO(VFIO_TYPE, VFIO_BASE+1)
	VFIO_SET_IOMMU           = IO(VFIO_TYPE, VFIO_BASE+2)
	VFIO_GROUP_SET_CONTAINER = IO(VFIO_TYPE, VFIO_BASE+4)
	VFIO_GROUP_GET_DEVICE_FD = IO(VFIO_TYPE, VFIO_BASE+6)
)
