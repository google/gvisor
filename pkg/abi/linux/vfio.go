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

// VFIO device info flags.
const (
	// Device supports reset.
	VFIO_DEVICE_FLAGS_RESET = 1 << iota
	// VFIO-pci device.
	VFIO_DEVICE_FLAGS_PCI
	// VFIO-platform device.
	VFIO_DEVICE_FLAGS_PLATFORM
	// VFIO-amba device.
	VFIO_DEVICE_FLAGS_AMBA
	// VFIO-ccw device.
	VFIO_DEVICE_FLAGS_CCW
	// VFIO-ap device.
	VFIO_DEVICE_FLAGS_AP
	// VFIO-fsl-mc device.
	VFIO_DEVICE_FLAGS_FSL_MC
	// Info supports caps.
	VFIO_DEVICE_FLAGS_CAPS
	// VFIO-cdx device.
	VFIO_DEVICE_FLAGS_CDX
)

// IOCTLs for VFIO file descriptor from include/uapi/linux/vfio.h.
var (
	VFIO_CHECK_EXTENSION     = IO(VFIO_TYPE, VFIO_BASE+1)
	VFIO_SET_IOMMU           = IO(VFIO_TYPE, VFIO_BASE+2)
	VFIO_GROUP_SET_CONTAINER = IO(VFIO_TYPE, VFIO_BASE+4)
	VFIO_GROUP_GET_DEVICE_FD = IO(VFIO_TYPE, VFIO_BASE+6)
	VFIO_DEVICE_GET_INFO     = IO(VFIO_TYPE, VFIO_BASE+7)
)

// VFIODeviceInfo is analogous to vfio_device_info
// from include/uapi/linux/vfio.h.
//
// +marshal
type VFIODeviceInfo struct {
	Argsz uint32
	Flags uint32
	// The total amount of regions.
	NumRegions uint32
	// The maximum number of IRQ.
	NumIrqs uint32
	// Offset within info struct of first cap.
	CapOffset uint32
	pad       uint32
}
