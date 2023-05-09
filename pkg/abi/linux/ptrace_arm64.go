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

package linux

const (
	//PSR bits
	PSR_MODE_EL0t = 0x00000000
	PSR_MODE_EL1t = 0x00000004
	PSR_MODE_EL1h = 0x00000005
	PSR_MODE_EL2t = 0x00000008
	PSR_MODE_EL2h = 0x00000009
	PSR_MODE_EL3t = 0x0000000c
	PSR_MODE_EL3h = 0x0000000d
	PSR_MODE_MASK = 0x0000000f

	// AArch32 CPSR bits
	PSR_MODE32_BIT = 0x00000010

	// AArch64 SPSR bits
	PSR_F_BIT      = 0x00000040
	PSR_I_BIT      = 0x00000080
	PSR_A_BIT      = 0x00000100
	PSR_D_BIT      = 0x00000200
	PSR_BTYPE_MASK = 0x00000c00
	PSR_SSBS_BIT   = 0x00001000
	PSR_PAN_BIT    = 0x00400000
	PSR_UAO_BIT    = 0x00800000
	PSR_DIT_BIT    = 0x01000000
	PSR_TCO_BIT    = 0x02000000
	PSR_V_BIT      = 0x10000000
	PSR_C_BIT      = 0x20000000
	PSR_Z_BIT      = 0x40000000
	PSR_N_BIT      = 0x80000000
)

// PtraceRegs is the set of CPU registers exposed by ptrace. Source:
// syscall.PtraceRegs.
//
// +marshal
// +stateify savable
type PtraceRegs struct {
	Regs   [31]uint64
	Sp     uint64
	Pc     uint64
	Pstate uint64
}

// InstructionPointer returns the address of the next instruction to be
// executed.
func (p *PtraceRegs) InstructionPointer() uint64 {
	return p.Pc
}

// StackPointer returns the address of the Stack pointer.
func (p *PtraceRegs) StackPointer() uint64 {
	return p.Sp
}

// SetStackPointer sets the stack pointer to the specified value.
func (p *PtraceRegs) SetStackPointer(sp uint64) {
	p.Sp = sp
}
