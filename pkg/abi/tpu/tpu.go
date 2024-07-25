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

// Package tpu defines constants used to interact with TPUs. The constants are
// derived from those listed in  https://github.com/tensorflow/tpu/blob/master/tools/driver/drivers/char/tpu_common
package tpu

const (
	// SizeOfTPUV4InterruptList is the total number of valid
	// (BAR Index, Register Offset) pairs.
	SizeOfTPUV4InterruptList = uint64(45)

	// NumberOfTPUV4PageTables is the number of gasket page tables used by the
	// TPU V4 driver.
	NumberOfTPUV4PageTables = uint64(1)

	// TPUV4DeviceID is the PCI device ID of TPU V4 hardware.
	TPUV4DeviceID = 0x005E

	// SizeOfTPUV4liteInterruptList is the total number of valid
	// (BAR Index, Register Offset) pairs.
	SizeOfTPUV4liteInterruptList = uint64(37)

	// NumberOfTPUV4litePageTables is the number of gasket page tables used by the
	// TPU V4 driver
	NumberOfTPUV4litePageTables = uint64(1)

	// TPUV4liteDeviceID is the PCI device ID of TPU V4lite hardware.
	TPUV4liteDeviceID = 0x0056

	// TPUV5eDeviceID is the PCI device ID of TPU V5e hardware.
	TPUV5eDeviceID = 0x0063

	// TPUV5pDeviceID is the PCI device ID of TPU V5p hardware.
	TPUV5pDeviceID = 0x0062
)

// TPUV4InterruptsMap maps BAR indices to valid register offsets.
var (
	TPUV4InterruptsMap = map[uint64]map[uint64]struct{}{
		2: map[uint64]struct{}{
			0x15b0008: struct{}{},
			0x15b0000: struct{}{},
			0x16b0008: struct{}{},
			0x16b0000: struct{}{},
			0x17b0008: struct{}{},
			0x17b0000: struct{}{},
			0x18b0008: struct{}{},
			0x18b0000: struct{}{},
			0x19b0020: struct{}{},
			0x19b0000: struct{}{},
			0x19b0008: struct{}{},
			0x19b0010: struct{}{},
			0x19b0018: struct{}{},
			0x1ab0020: struct{}{},
			0x1ab0000: struct{}{},
			0x1ab0008: struct{}{},
			0x1ab0010: struct{}{},
			0x1ab0018: struct{}{},
			0x4720000: struct{}{},
			0x1bb0000: struct{}{},
			0x1bb0008: struct{}{},
			0x1bb0010: struct{}{},
			0x1bb0018: struct{}{},
			0x90000:   struct{}{},
			0xb0000:   struct{}{},
			0xd0000:   struct{}{},
			0xf0000:   struct{}{},
			0x110000:  struct{}{},
			0x130000:  struct{}{},
			0x150000:  struct{}{},
			0x170000:  struct{}{},
			0x190000:  struct{}{},
			0x1b0000:  struct{}{},
			0x1d0000:  struct{}{},
			0x1f0000:  struct{}{},
			0x210000:  struct{}{},
			0x230000:  struct{}{},
			0x250000:  struct{}{},
			0x270000:  struct{}{},
			0x290000:  struct{}{},
			0x2b0000:  struct{}{},
			0x2d0000:  struct{}{},
			0x2f0000:  struct{}{},
			0x310000:  struct{}{},
			0x4720018: struct{}{},
		},
	}

	// TPUV4liteInterruptsMap maps BAR indices to valid register offsets.
	TPUV4liteInterruptsMap = map[uint64]map[uint64]struct{}{
		2: map[uint64]struct{}{
			0x19b0020: struct{}{},
			0x19b0000: struct{}{},
			0x19b0008: struct{}{},
			0x19b0010: struct{}{},
			0x19b0018: struct{}{},
			0x1ab0020: struct{}{},
			0x1ab0000: struct{}{},
			0x1ab0008: struct{}{},
			0x1ab0010: struct{}{},
			0x1ab0018: struct{}{},
			0x4720000: struct{}{},
			0x1bb0000: struct{}{},
			0x1bb0008: struct{}{},
			0x1bb0010: struct{}{},
			0x1bb0018: struct{}{},
			0x90000:   struct{}{},
			0xb0000:   struct{}{},
			0xd0000:   struct{}{},
			0xf0000:   struct{}{},
			0x110000:  struct{}{},
			0x130000:  struct{}{},
			0x150000:  struct{}{},
			0x170000:  struct{}{},
			0x190000:  struct{}{},
			0x1b0000:  struct{}{},
			0x1d0000:  struct{}{},
			0x1f0000:  struct{}{},
			0x210000:  struct{}{},
			0x230000:  struct{}{},
			0x250000:  struct{}{},
			0x270000:  struct{}{},
			0x290000:  struct{}{},
			0x2b0000:  struct{}{},
			0x2d0000:  struct{}{},
			0x2f0000:  struct{}{},
			0x310000:  struct{}{},
			0x4720018: struct{}{},
		},
	}
)
