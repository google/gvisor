// Copyright 2018 The gVisor Authors.
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

//go:build 386 || amd64
// +build 386 amd64

package ring0

// Useful bits.
const (
	_CR0_PE = 1 << 0
	_CR0_ET = 1 << 4
	_CR0_NE = 1 << 5
	_CR0_AM = 1 << 18
	_CR0_PG = 1 << 31

	_CR4_PSE        = 1 << 4
	_CR4_PAE        = 1 << 5
	_CR4_PGE        = 1 << 7
	_CR4_OSFXSR     = 1 << 9
	_CR4_OSXMMEXCPT = 1 << 10
	_CR4_FSGSBASE   = 1 << 16
	_CR4_PCIDE      = 1 << 17
	_CR4_OSXSAVE    = 1 << 18
	_CR4_SMEP       = 1 << 20
	_CR4_SMAP       = 1 << 21

	_RFLAGS_AC       = 1 << 18
	_RFLAGS_NT       = 1 << 14
	_RFLAGS_IOPL0    = 1 << 12
	_RFLAGS_IOPL1    = 1 << 13
	_RFLAGS_IOPL     = _RFLAGS_IOPL0 | _RFLAGS_IOPL1
	_RFLAGS_DF       = 1 << 10
	_RFLAGS_IF       = 1 << 9
	_RFLAGS_STEP     = 1 << 8
	_RFLAGS_RESERVED = 1 << 1

	_EFER_SCE = 0x001
	_EFER_LME = 0x100
	_EFER_LMA = 0x400
	_EFER_NX  = 0x800

	_MSR_STAR          = 0xc0000081
	_MSR_LSTAR         = 0xc0000082
	_MSR_CSTAR         = 0xc0000083
	_MSR_SYSCALL_MASK  = 0xc0000084
	_MSR_PLATFORM_INFO = 0xce
	_MSR_MISC_FEATURES = 0x140

	_PLATFORM_INFO_CPUID_FAULT = 1 << 31

	_MISC_FEATURE_CPUID_TRAP = 0x1
)

const (
	// KernelFlagsSet should always be set in the kernel.
	KernelFlagsSet = _RFLAGS_RESERVED

	// UserFlagsSet are always set in userspace.
	//
	// _RFLAGS_IOPL is a set of two bits and it shows the I/O privilege
	// level. The Current Privilege Level (CPL) of the task must be less
	// than or equal to the IOPL in order for the task or program to access
	// I/O ports.
	//
	// Here, _RFLAGS_IOPL0 is used only to determine whether the task is
	// running in the kernel or userspace mode. In the user mode, the CPL is
	// always 3 and it doesn't matter what IOPL is set if it is bellow CPL.
	//
	// We need to have one bit which will be always different in user and
	// kernel modes. And we have to remember that even though we have
	// KernelFlagsClear, we still can see some of these flags in the kernel
	// mode. This can happen when the goruntime switches on a goroutine
	// which has been saved in the host mode. On restore, the popf
	// instruction is used to restore flags and this means that all flags
	// what the goroutine has in the host mode will be restored in the
	// kernel mode.
	//
	// _RFLAGS_IOPL0 is never set in host and kernel modes and we always set
	// it in the user mode. So if this flag is set, the task is running in
	// the user mode and if it isn't set, the task is running in the kernel
	// mode.
	UserFlagsSet = _RFLAGS_RESERVED | _RFLAGS_IF | _RFLAGS_IOPL0

	// KernelFlagsClear should always be clear in the kernel.
	KernelFlagsClear = _RFLAGS_STEP | _RFLAGS_IF | _RFLAGS_IOPL | _RFLAGS_AC | _RFLAGS_NT

	// UserFlagsClear are always cleared in userspace.
	UserFlagsClear = _RFLAGS_NT | _RFLAGS_IOPL1
)

// IsKernelFlags returns true if rflags coresponds to the kernel mode.
//
//go:nosplit
func IsKernelFlags(rflags uint64) bool {
	return rflags&_RFLAGS_IOPL0 == 0
}

// Vector is an exception vector.
type Vector uintptr

// Exception vectors.
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
	PageFault
	_
	X87FloatingPointException
	AlignmentCheck
	MachineCheck
	SIMDFloatingPointException
	VirtualizationException
	SecurityException = 0x1e
	SyscallInt80      = 0x80
	_NR_INTERRUPTS    = 0x100
)

// System call vectors.
const (
	Syscall Vector = _NR_INTERRUPTS
)

// Selector is a segment Selector.
type Selector uint16

// SegmentDescriptor is a segment descriptor.
type SegmentDescriptor struct {
	bits [2]uint32
}

// descriptorTable is a collection of descriptors.
type descriptorTable [32]SegmentDescriptor

// SegmentDescriptorFlags are typed flags within a descriptor.
type SegmentDescriptorFlags uint32

// SegmentDescriptorFlag declarations.
const (
	SegmentDescriptorAccess     SegmentDescriptorFlags = 1 << 8  // Access bit (always set).
	SegmentDescriptorWrite                             = 1 << 9  // Write permission.
	SegmentDescriptorExpandDown                        = 1 << 10 // Grows down, not used.
	SegmentDescriptorExecute                           = 1 << 11 // Execute permission.
	SegmentDescriptorSystem                            = 1 << 12 // Zero => system, 1 => user code/data.
	SegmentDescriptorPresent                           = 1 << 15 // Present.
	SegmentDescriptorAVL                               = 1 << 20 // Available.
	SegmentDescriptorLong                              = 1 << 21 // Long mode.
	SegmentDescriptorDB                                = 1 << 22 // 16 or 32-bit.
	SegmentDescriptorG                                 = 1 << 23 // Granularity: page or byte.
)

// Base returns the descriptor's base linear address.
func (d *SegmentDescriptor) Base() uint32 {
	return d.bits[1]&0xFF000000 | (d.bits[1]&0x000000FF)<<16 | d.bits[0]>>16
}

// Limit returns the descriptor size.
func (d *SegmentDescriptor) Limit() uint32 {
	l := d.bits[0]&0xFFFF | d.bits[1]&0xF0000
	if d.bits[1]&uint32(SegmentDescriptorG) != 0 {
		l <<= 12
		l |= 0xFFF
	}
	return l
}

// Flags returns descriptor flags.
func (d *SegmentDescriptor) Flags() SegmentDescriptorFlags {
	return SegmentDescriptorFlags(d.bits[1] & 0x00F09F00)
}

// DPL returns the descriptor privilege level.
func (d *SegmentDescriptor) DPL() int {
	return int((d.bits[1] >> 13) & 3)
}

func (d *SegmentDescriptor) setNull() {
	d.bits[0] = 0
	d.bits[1] = 0
}

func (d *SegmentDescriptor) set(base, limit uint32, dpl int, flags SegmentDescriptorFlags) {
	flags |= SegmentDescriptorPresent
	if limit>>12 != 0 {
		limit >>= 12
		flags |= SegmentDescriptorG
	}
	d.bits[0] = base<<16 | limit&0xFFFF
	d.bits[1] = base&0xFF000000 | (base>>16)&0xFF | limit&0x000F0000 | uint32(flags) | uint32(dpl)<<13
}

func (d *SegmentDescriptor) setCode32(base, limit uint32, dpl int) {
	d.set(base, limit, dpl,
		SegmentDescriptorDB|
			SegmentDescriptorExecute|
			SegmentDescriptorSystem)
}

func (d *SegmentDescriptor) setCode64(base, limit uint32, dpl int) {
	d.set(base, limit, dpl,
		SegmentDescriptorG|
			SegmentDescriptorLong|
			SegmentDescriptorExecute|
			SegmentDescriptorSystem)
}

func (d *SegmentDescriptor) setData(base, limit uint32, dpl int) {
	d.set(base, limit, dpl,
		SegmentDescriptorWrite|
			SegmentDescriptorSystem)
}

// setHi is only used for the TSS segment, which is magically 64-bits.
func (d *SegmentDescriptor) setHi(base uint32) {
	d.bits[0] = base
	d.bits[1] = 0
}

// Gate64 is a 64-bit task, trap, or interrupt gate.
type Gate64 struct {
	bits [4]uint32
}

// idt64 is a 64-bit interrupt descriptor table.
type idt64 [_NR_INTERRUPTS]Gate64

func (g *Gate64) setInterrupt(cs Selector, rip uint64, dpl int, ist int) {
	g.bits[0] = uint32(cs)<<16 | uint32(rip)&0xFFFF
	g.bits[1] = uint32(rip)&0xFFFF0000 | SegmentDescriptorPresent | uint32(dpl)<<13 | 14<<8 | uint32(ist)&0x7
	g.bits[2] = uint32(rip >> 32)
}

func (g *Gate64) setTrap(cs Selector, rip uint64, dpl int, ist int) {
	g.setInterrupt(cs, rip, dpl, ist)
	g.bits[1] |= 1 << 8
}

// TaskState64 is a 64-bit task state structure.
type TaskState64 struct {
	_              uint32
	rsp0Lo, rsp0Hi uint32
	rsp1Lo, rsp1Hi uint32
	rsp2Lo, rsp2Hi uint32
	_              [2]uint32
	ist1Lo, ist1Hi uint32
	ist2Lo, ist2Hi uint32
	ist3Lo, ist3Hi uint32
	ist4Lo, ist4Hi uint32
	ist5Lo, ist5Hi uint32
	ist6Lo, ist6Hi uint32
	ist7Lo, ist7Hi uint32
	_              [2]uint32
	_              uint16
	ioPerm         uint16
}
