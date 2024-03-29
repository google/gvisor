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

// VFIO region info flags.
const (
	// Region supports read.
	VFIO_REGION_INFO_FLAG_READ = 1 << iota
	// Region supports write.
	VFIO_REGION_INFO_FLAG_WRITE
	// Region supports mmap.
	VFIO_REGION_INFO_FLAG_MMAP
	// Info supports caps.
	VFIO_REGION_INFO_FLAG_CAPS
)

// VFIOIrqInfo flags.
const (
	VFIO_IRQ_INFO_EVENTFD = 1 << iota
	VFIO_IRQ_INFO_MASKABLE
	VFIO_IRQ_INFO_AUTOMASKED
	VFIO_IRQ_INFO_NORESIZE
)

// VFIOIrqSet flags.
const (
	VFIO_IRQ_SET_DATA_NONE = 1 << iota
	VFIO_IRQ_SET_DATA_BOOL
	VFIO_IRQ_SET_DATA_EVENTFD
	VFIO_IRQ_SET_ACTION_MASK
	VFIO_IRQ_SET_ACTION_UNMASK
	VFIO_IRQ_SET_ACTION_TRIGGER

	VFIO_IRQ_SET_DATA_TYPE_MASK = VFIO_IRQ_SET_DATA_NONE |
		VFIO_IRQ_SET_DATA_BOOL |
		VFIO_IRQ_SET_DATA_EVENTFD
	VFIO_IRQ_SET_ACTION_TYPE_MASK = VFIO_IRQ_SET_ACTION_MASK |
		VFIO_IRQ_SET_ACTION_UNMASK |
		VFIO_IRQ_SET_ACTION_TRIGGER
)

// VFIOIrqSet index.
const (
	VFIO_PCI_INTX_IRQ_INDEX = iota
	VFIO_PCI_MSI_IRQ_INDEX
	VFIO_PCI_MSIX_IRQ_INDEX
	VFIO_PCI_ERR_IRQ_INDEX
	VFIO_PCI_REQ_IRQ_INDEX
	VFIO_PCI_NUM_IRQS
)

// VFIOIommuType1DmaMap flags.
const (
	// Readable from device.
	VFIO_DMA_MAP_FLAG_READ = 1 << iota
	// Writable from device.
	VFIO_DMA_MAP_FLAG_WRITE
	// Update the device's virtual address.
	VFIO_DMA_MAP_FLAG_VADDR
)

const (
	VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP = 1
)

// IOCTLs for VFIO file descriptor from include/uapi/linux/vfio.h.
var (
	VFIO_CHECK_EXTENSION        = IO(VFIO_TYPE, VFIO_BASE+1)
	VFIO_SET_IOMMU              = IO(VFIO_TYPE, VFIO_BASE+2)
	VFIO_GROUP_SET_CONTAINER    = IO(VFIO_TYPE, VFIO_BASE+4)
	VFIO_GROUP_GET_DEVICE_FD    = IO(VFIO_TYPE, VFIO_BASE+6)
	VFIO_DEVICE_GET_INFO        = IO(VFIO_TYPE, VFIO_BASE+7)
	VFIO_DEVICE_GET_REGION_INFO = IO(VFIO_TYPE, VFIO_BASE+8)
	VFIO_DEVICE_GET_IRQ_INFO    = IO(VFIO_TYPE, VFIO_BASE+9)
	VFIO_DEVICE_SET_IRQS        = IO(VFIO_TYPE, VFIO_BASE+10)
	VFIO_DEVICE_RESET           = IO(VFIO_TYPE, VFIO_BASE+11)
	VFIO_IOMMU_MAP_DMA          = IO(VFIO_TYPE, VFIO_BASE+13)
	VFIO_IOMMU_UNMAP_DMA        = IO(VFIO_TYPE, VFIO_BASE+14)
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

// VFIORegionInfo is analogous to vfio_region_info
// from include/uapi/linux/vfio.h.
//
// +marshal
type VFIORegionInfo struct {
	Argsz uint32
	Flags uint32
	Index uint32
	// Offset within info struct of first cap.
	capOffset uint32
	// Region size in bytes.
	Size uint64
	// Region offset from start of device fd.
	Offset uint64
}

// VFIOIrqInfo is analogous to vfio_irq_info
// from include/uapi/linux/vfio.h.
//
// +marshal
type VFIOIrqInfo struct {
	Argsz uint32
	Flags uint32
	Index uint32
	Count uint32
}

// VFIOIrqSet is analogous to vfio_irq_set
// from include/uapi/linux/vfio.h.
// The last field `data` from vfio_irq_set is omitted which is an
// flexible array member. It will be handled separately.
//
// +marshal
type VFIOIrqSet struct {
	Argsz uint32
	Flags uint32
	Index uint32
	Start uint32
	Count uint32
}

// VFIOIommuType1DmaMap is analogous to vfio_iommu_type1_dma_map
// from include/uapi/linux/vfio.h.
//
// +marshal
type VFIOIommuType1DmaMap struct {
	Argsz uint32
	Flags uint32
	// Process virtual address.
	Vaddr uint64
	// IO virtual address.
	IOVa uint64
	// Size of mapping in bytes.
	Size uint64
}

// VFIOIommuType1DmaUnmap is analogous to vfio_iommu_type1_dma_unmap
// from include/uapi/linux/vfio.h.
//
// +marshal
type VFIOIommuType1DmaUnmap struct {
	Argsz uint32
	Flags uint32
	// IO virtual address.
	IOVa uint64
	// Size of mapping in bytes.
	Size uint64
	// The `data` field from vfio_iommu_type1_dma_unmap is omitted. The
	// field is a flexible array member, and is needed only if the flag
	// VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP is enabled.
}
