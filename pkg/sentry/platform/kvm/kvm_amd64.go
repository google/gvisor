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

// +build amd64

package kvm

import (
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/ring0"
)

// userRegs represents KVM user registers.
//
// This mirrors kvm_regs.
type userRegs struct {
	RAX    uint64
	RBX    uint64
	RCX    uint64
	RDX    uint64
	RSI    uint64
	RDI    uint64
	RSP    uint64
	RBP    uint64
	R8     uint64
	R9     uint64
	R10    uint64
	R11    uint64
	R12    uint64
	R13    uint64
	R14    uint64
	R15    uint64
	RIP    uint64
	RFLAGS uint64
}

// systemRegs represents KVM system registers.
//
// This mirrors kvm_sregs.
type systemRegs struct {
	CS              segment
	DS              segment
	ES              segment
	FS              segment
	GS              segment
	SS              segment
	TR              segment
	LDT             segment
	GDT             descriptor
	IDT             descriptor
	CR0             uint64
	CR2             uint64
	CR3             uint64
	CR4             uint64
	CR8             uint64
	EFER            uint64
	apicBase        uint64
	interruptBitmap [(_KVM_NR_INTERRUPTS + 63) / 64]uint64
}

// segment is the expanded form of a segment register.
//
// This mirrors kvm_segment.
type segment struct {
	base     uint64
	limit    uint32
	selector uint16
	typ      uint8
	present  uint8
	DPL      uint8
	DB       uint8
	S        uint8
	L        uint8
	G        uint8
	AVL      uint8
	unusable uint8
	_        uint8
}

// Clear clears the segment and marks it unusable.
func (s *segment) Clear() {
	*s = segment{unusable: 1}
}

// selector is a segment selector.
type selector uint16

// tobool is a simple helper.
func tobool(x ring0.SegmentDescriptorFlags) uint8 {
	if x != 0 {
		return 1
	}
	return 0
}

// Load loads the segment described by d into the segment s.
//
// The argument sel is recorded as the segment selector index.
func (s *segment) Load(d *ring0.SegmentDescriptor, sel ring0.Selector) {
	flag := d.Flags()
	if flag&ring0.SegmentDescriptorPresent == 0 {
		s.Clear()
		return
	}
	s.base = uint64(d.Base())
	s.limit = d.Limit()
	s.typ = uint8((flag>>8)&0xF) | 1
	s.S = tobool(flag & ring0.SegmentDescriptorSystem)
	s.DPL = uint8(d.DPL())
	s.present = tobool(flag & ring0.SegmentDescriptorPresent)
	s.AVL = tobool(flag & ring0.SegmentDescriptorAVL)
	s.L = tobool(flag & ring0.SegmentDescriptorLong)
	s.DB = tobool(flag & ring0.SegmentDescriptorDB)
	s.G = tobool(flag & ring0.SegmentDescriptorG)
	if s.L != 0 {
		s.limit = 0xffffffff
	}
	s.unusable = 0
	s.selector = uint16(sel)
}

// descriptor describes a region of physical memory.
//
// It corresponds to the pseudo-descriptor used in the x86 LGDT and LIDT
// instructions, and mirrors kvm_dtable.
type descriptor struct {
	base  uint64
	limit uint16
	_     [3]uint16
}

// modelControlRegister is an MSR entry.
//
// This mirrors kvm_msr_entry.
type modelControlRegister struct {
	index uint32
	_     uint32
	data  uint64
}

// modelControlRegisers is a collection of MSRs.
//
// This mirrors kvm_msrs.
type modelControlRegisters struct {
	nmsrs   uint32
	_       uint32
	entries [16]modelControlRegister
}

// cpuidEntry is a single CPUID entry.
//
// This mirrors kvm_cpuid_entry2.
type cpuidEntry struct {
	function uint32
	index    uint32
	flags    uint32
	eax      uint32
	ebx      uint32
	ecx      uint32
	edx      uint32
	_        [3]uint32
}

// cpuidEntries is a collection of CPUID entries.
//
// This mirrors kvm_cpuid2.
type cpuidEntries struct {
	nr      uint32
	_       uint32
	entries [_KVM_NR_CPUID_ENTRIES]cpuidEntry
}

// updateGlobalOnce does global initialization. It has to be called only once.
func updateGlobalOnce(fd int) error {
	physicalInit()
	err := updateSystemValues(int(fd))
	ring0.Init(cpuid.HostFeatureSet())
	return err
}
