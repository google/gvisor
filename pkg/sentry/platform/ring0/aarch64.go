// Copyright 2019 The gVisor Authors.
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

// +build arm64

package ring0

// Useful bits.
const (
	_PGD_PGT_BASE = 0x1000
	_PGD_PGT_SIZE = 0x1000
	_PUD_PGT_BASE = 0x2000
	_PUD_PGT_SIZE = 0x1000
	_PMD_PGT_BASE = 0x3000
	_PMD_PGT_SIZE = 0x4000
	_PTE_PGT_BASE = 0x7000
	_PTE_PGT_SIZE = 0x1000

	_PSR_MODE_EL0t = 0x0
	_PSR_MODE_EL1t = 0x4
	_PSR_MODE_EL1h = 0x5
	_PSR_EL_MASK   = 0xf

	_PSR_D_BIT = 0x200
	_PSR_A_BIT = 0x100
	_PSR_I_BIT = 0x80
	_PSR_F_BIT = 0x40
)

const (
	// KernelFlagsSet should always be set in the kernel.
	KernelFlagsSet = _PSR_MODE_EL1h

	// UserFlagsSet are always set in userspace.
	UserFlagsSet = _PSR_MODE_EL0t

	KernelFlagsClear = _PSR_EL_MASK
	UserFlagsClear   = _PSR_EL_MASK

	PsrDefaultSet = _PSR_D_BIT | _PSR_A_BIT | _PSR_I_BIT | _PSR_F_BIT
)

// Vector is an exception vector.
type Vector uintptr

// Exception vectors.
const (
	El1SyncInvalid = iota
	El1IrqInvalid
	El1FiqInvalid
	El1ErrorInvalid
	El1Sync
	El1Irq
	El1Fiq
	El1Error
	El0Sync
	El0Irq
	El0Fiq
	El0Error
	El0Sync_invalid
	El0Irq_invalid
	El0Fiq_invalid
	El0Error_invalid
	El1Sync_da
	El1Sync_ia
	El1Sync_sp_pc
	El1Sync_undef
	El1Sync_dbg
	El1Sync_inv
	El0Sync_svc
	El0Sync_da
	El0Sync_ia
	El0Sync_fpsimd_acc
	El0Sync_sve_acc
	El0Sync_sys
	El0Sync_sp_pc
	El0Sync_undef
	El0Sync_dbg
	El0Sync_inv
	VirtualizationException
	_NR_INTERRUPTS
)

// System call vectors.
const (
	Syscall   Vector = El0Sync_svc
	PageFault Vector = El0Sync_da
)

// VirtualAddressBits returns the number bits available for virtual addresses.
func VirtualAddressBits() uint32 {
	return 48
}

// PhysicalAddressBits returns the number of bits available for physical addresses.
func PhysicalAddressBits() uint32 {
	return 40
}
