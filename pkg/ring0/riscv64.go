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

//go:build riscv64
// +build riscv64

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

	// PhysicalAddressBits is fixed at 56.
	PhysicalAddressBits = 56

	/*
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
	*/

	// KernelFlagsSet should always be set in the kernel.
	//KernelFlagsSet = _PSR_MODE_EL1h | _PSR_D_BIT | _PSR_A_BIT | _PSR_I_BIT | _PSR_F_BIT

	// UserFlagsSet are always set in userspace.
	//UserFlagsSet = _PSR_MODE_EL0t

	SPPMask = 1 << 8
)

// Vector is an exception vector.
type Vector uintptr

/*
const (
	DivideByZero Vector = iota
	Debug
	NMI
	Breakpoint
	Overflow
	BoundRangeExceeded
	InvalidOpcode
	DeviceNotAvailable
	DoubleFault
	CoprocessorSegmentOverrun
	InvalidTSS
	SegmentNotPresent
	StackSegmentFault
	GeneralProtectionFault
	//PageFault
	_
	X87FloatingPointException
	AlignmentCheck
	MachineCheck
	SIMDFloatingPointException
	SecurityException = 0x1e
	//SyscallInt80      = 0x80
	_NR_INTERRUPTS    = 0x100
)
*/


const (
	InstructionAccessFault Vector = 0x1
	IllegalInstruction = 0x2
	LoadAccessFault Vector = 0x5
	StoreAccessFault Vector = 0x7
	EcallFromUser Vector = 0x8
	InstPageFault Vector = 0xc
	LoadPageFault Vector = 0xd
	StorePageFault Vector = 0xf
	VirtualizationException = 0x9
	Bounce Vector = 0x18
	ExtDabt Vector = 0x19
	Sigbus Vector = 0x1a
	
)

const (
	SR_FS	= 0x6000
	SR_FS_DIRTY = 0x6000
	SR_FS_OFF = 0x0000
)
