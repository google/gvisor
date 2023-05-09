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

//go:build arm64
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
)

const (
	// VirtualAddressBits is fixed at 48.
	VirtualAddressBits = 48

	// PhysicalAddressBits is fixed at 40.
	PhysicalAddressBits = 40

	// DAIF bits:debug, sError, IRQ, FIQ.
	_PSR_D_BIT      = 0x00000200
	_PSR_A_BIT      = 0x00000100
	_PSR_I_BIT      = 0x00000080
	_PSR_F_BIT      = 0x00000040
	_PSR_DAIF_SHIFT = 6
	_PSR_DAIF_MASK  = 0xf << _PSR_DAIF_SHIFT

	// PSR bits.
	_PSR_MODE_EL0t = 0x00000000
	_PSR_MODE_EL1t = 0x00000004
	_PSR_MODE_EL1h = 0x00000005
	_PSR_MODE_MASK = 0x0000000f

	PsrFlagsClear = _PSR_MODE_MASK | _PSR_DAIF_MASK
	PsrModeMask   = _PSR_MODE_MASK

	// KernelFlagsSet should always be set in the kernel.
	KernelFlagsSet = _PSR_MODE_EL1h | _PSR_D_BIT | _PSR_A_BIT | _PSR_I_BIT | _PSR_F_BIT

	// UserFlagsSet are always set in userspace.
	UserFlagsSet = _PSR_MODE_EL0t
)

// Vector is an exception vector.
type Vector uintptr

// Exception vectors.
const (
	El1InvSync = iota
	El1InvIrq
	El1InvFiq
	El1InvError

	El1Sync
	El1Irq
	El1Fiq
	El1Err

	El0Sync
	El0Irq
	El0Fiq
	El0Err

	El0InvSync
	El0InvIrq
	El0InvFiq
	El0InvErr

	El1SyncDa
	El1SyncIa
	El1SyncSpPc
	El1SyncUndef
	El1SyncDbg
	El1SyncInv

	El0SyncSVC
	El0SyncDa
	El0SyncIa
	El0SyncFpsimdAcc
	El0SyncSveAcc
	El0SyncFpsimdExc
	El0SyncSys
	El0SyncSpPc
	El0SyncUndef
	El0SyncDbg
	El0SyncWfx
	El0SyncInv

	El0ErrNMI
	El0ErrBounce

	_NR_INTERRUPTS
)

// System call vectors.
const (
	Syscall                 Vector = El0SyncSVC
	PageFault               Vector = El0SyncDa
	VirtualizationException Vector = El0ErrBounce
)
