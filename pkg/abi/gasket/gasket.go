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

// Package gasket describes the userspace interface for Gasket devices.
package gasket

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// Ioctl represents a gasket ioctl command.
type Ioctl uint32

// From https://github.com/tensorflow/tpu/blob/master/tools/driver/include/linux/google/gasket.h
var (
	GASKET_IOCTL_BASE                   = uint32(0xDC)
	GASKET_IOCTL_RESET                  = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 0, SizeOfUnsignedLong))
	GASKET_IOCTL_SET_EVENTFD            = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 1, SizeofGasketInterruptEventFd))
	GASKET_IOCTL_CLEAR_EVENTFD          = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 2, SizeOfUnsignedLong))
	GASKET_IOCTL_NUMBER_PAGE_TABLES     = Ioctl(linux.IOR(GASKET_IOCTL_BASE, 4, SizeOfUnsignedLong))
	GASKET_IOCTL_PAGE_TABLE_SIZE        = Ioctl(linux.IOWR(GASKET_IOCTL_BASE, 5, SizeofGasketPageTableIoctl))
	GASKET_IOCTL_SIMPLE_PAGE_TABLE_SIZE = Ioctl(linux.IOWR(GASKET_IOCTL_BASE, 6, SizeofGasketPageTableIoctl))
	GASKET_IOCTL_PARTITION_PAGE_TABLE   = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 7, SizeofGasketPageTableIoctl))
	GASKET_IOCTL_MAP_BUFFER             = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 8, SizeofGasketPageTableIoctl))
	GASKET_IOCTL_UNMAP_BUFFER           = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 9, SizeofGasketPageTableIoctl))
	GASKET_IOCTL_CLEAR_INTERRUPT_COUNTS = Ioctl(linux.IO(GASKET_IOCTL_BASE, 10))
	GASKET_IOCTL_REGISTER_INTERRUPT     = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 11, SizeofGasketInterruptMapping))
	GASKET_IOCTL_UNREGISTER_INTERRUPT   = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 12, SizeOfUnsignedLong))
	GASKET_IOCTL_MAP_DMA_BUF            = Ioctl(linux.IOW(GASKET_IOCTL_BASE, 13, SizeofGasketPageTableDmaBufIoctl))
)

func (i Ioctl) String() string {
	switch i {
	case GASKET_IOCTL_RESET:
		return "GASKET_IOCTL_RESET"
	case GASKET_IOCTL_SET_EVENTFD:
		return "GASKET_IOCTL_SET_EVENTFD"
	case GASKET_IOCTL_CLEAR_EVENTFD:
		return "GASKET_IOCTL_CLEAR_EVENTFD"
	case GASKET_IOCTL_NUMBER_PAGE_TABLES:
		return "GASKET_IOCTL_NUMBER_PAGE_TABLES"
	case GASKET_IOCTL_PAGE_TABLE_SIZE:
		return "GASKET_IOCTL_PAGE_TABLE_SIZE"
	case GASKET_IOCTL_SIMPLE_PAGE_TABLE_SIZE:
		return "GASKET_IOCTL_SIMPLE_PAGE_TABLE_SIZE"
	case GASKET_IOCTL_PARTITION_PAGE_TABLE:
		return "GASKET_IOCTL_PARTITION_PAGE_TABLE"
	case GASKET_IOCTL_MAP_BUFFER:
		return "GASKET_IOCTL_MAP_BUFFER"
	case GASKET_IOCTL_UNMAP_BUFFER:
		return "GASKET_IOCTL_UNMAP_BUFFER"
	case GASKET_IOCTL_CLEAR_INTERRUPT_COUNTS:
		return "GASKET_IOCTL_CLEAR_INTERRUPT_COUNTS"
	case GASKET_IOCTL_REGISTER_INTERRUPT:
		return "GASKET_IOCTL_REGISTER_INTERRUPT"
	case GASKET_IOCTL_UNREGISTER_INTERRUPT:
		return "GASKET_IOCTL_UNREGISTER_INTERRUPT"
	case GASKET_IOCTL_MAP_DMA_BUF:
		return "GASKET_IOCTL_MAP_DMA_BUF"
	default:
		return fmt.Sprintf("UNKNOWN GASKET COMMAND %d", uint32(i))
	}
}

// GasketInterruptEventFd is the common structure for ioctls associating an
// eventfd with a device interrupt, when using the Gasket interrupt module.
//
// +marshal
type GasketInterruptEventFd struct {
	Interrupt uint64
	EventFD   uint64
}

// GasketPageTableIoctl is a common structure for ioctls mapping and unmapping
// buffers when using the Gasket page_table module.
//
// +marshal
type GasketPageTableIoctl struct {
	PageTableIndex uint64
	Size           uint64
	HostAddress    uint64
	DeviceAddress  uint64
}

// GasketInterruptMapping is a structure for ioctls associating an eventfd and
// interrupt controlling bar register with a device interrupt, when using the
// Gasket interrupt module.
//
// +marshal
type GasketInterruptMapping struct {
	Interrupt uint64
	EventFD   uint64
	BarIndex  uint64
	RegOffset uint64
}

// GasketPageTableDmaBufIoctl is a structure for dma_buf mapping ioctl
// parameters.
//
// +marshal
type GasketPageTableDmaBufIoctl struct {
	PageTableIndex uint64
	DeviceAddress  uint64
	DMABufID       int32 `marshal:"unaligned"` // Struct ends mid 64bit word.
}

// Ioctl parameter struct sizes.
var (
	SizeofGasketInterruptEventFd     = uint32((*GasketInterruptEventFd)(nil).SizeBytes())
	SizeofGasketPageTableIoctl       = uint32((*GasketPageTableIoctl)(nil).SizeBytes())
	SizeofGasketInterruptMapping     = uint32((*GasketInterruptMapping)(nil).SizeBytes())
	SizeofGasketPageTableDmaBufIoctl = uint32((*GasketPageTableDmaBufIoctl)(nil).SizeBytes())
	SizeOfUnsignedLong               = uint32(8)
)
