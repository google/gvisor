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

//go:build loong64
// +build loong64

package linux

import (
	"structs"
)

// PtraceRegs is the set of CPU registers exposed by ptrace, matching
// LoongArch's struct user_pt_regs (arch/loongarch/include/uapi/asm/ptrace.h):
//
//	struct user_pt_regs {
//	    __u64 regs[32];
//	    __u64 orig_a0;
//	    __u64 csr_era;
//	    __u64 csr_badv;
//	    __u64 reserved[10];
//	} __attribute__((aligned(8)));
//
// The LoongArch ABI defines $sp = $r3 and $ra = $r1. The program counter on
// exception entry is held in CSR.ERA (Exception Return Address).
//
// +marshal
// +stateify savable
type PtraceRegs struct {
	_        structs.HostLayout
	Regs     [32]uint64
	OrigA0   uint64
	Era      uint64
	Badv     uint64
	Reserved [10]uint64
}

// InstructionPointer returns the address of the next instruction to be
// executed. On LoongArch this is held in CSR.ERA.
func (p *PtraceRegs) InstructionPointer() uint64 {
	return p.Era
}

// StackPointer returns the address of the stack pointer ($sp = $r3).
func (p *PtraceRegs) StackPointer() uint64 {
	return p.Regs[3]
}

// SetStackPointer sets the stack pointer ($sp = $r3) to the specified value.
func (p *PtraceRegs) SetStackPointer(sp uint64) {
	p.Regs[3] = sp
}
