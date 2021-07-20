// Copyright 2020 The gVisor Authors.
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

//go:build amd64
// +build amd64

package linux

// PtraceRegs is the set of CPU registers exposed by ptrace. Source:
// syscall.PtraceRegs.
//
// +marshal
// +stateify savable
type PtraceRegs struct {
	R15      uint64
	R14      uint64
	R13      uint64
	R12      uint64
	Rbp      uint64
	Rbx      uint64
	R11      uint64
	R10      uint64
	R9       uint64
	R8       uint64
	Rax      uint64
	Rcx      uint64
	Rdx      uint64
	Rsi      uint64
	Rdi      uint64
	Orig_rax uint64
	Rip      uint64
	Cs       uint64
	Eflags   uint64
	Rsp      uint64
	Ss       uint64
	Fs_base  uint64
	Gs_base  uint64
	Ds       uint64
	Es       uint64
	Fs       uint64
	Gs       uint64
}

// InstructionPointer returns the address of the next instruction to
// be executed.
func (p *PtraceRegs) InstructionPointer() uint64 {
	return p.Rip
}

// StackPointer returns the address of the Stack pointer.
func (p *PtraceRegs) StackPointer() uint64 {
	return p.Rsp
}

// SetStackPointer sets the stack pointer to the specified value.
func (p *PtraceRegs) SetStackPointer(sp uint64) {
	p.Rsp = sp
}
