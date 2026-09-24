// Copyright 2026 The gVisor Authors.
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

// Package ebpf provides tools for working with extended Berkely Packet Filter (eBPF) programs.
//
// gVisor currently does not support running eBPF programs.
package ebpf

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// BPFID is a sequential, globally-unique (though unloaded
// programs' IDs are reused) ID for an eBPF program.
type BPFID uint32

// UnverifiedProgram represents an eBPF program provided by userspace that has not
// been validated.
//
// +stateify savable
type UnverifiedProgram struct {
	// instructions is a list of eBPF instructions.
	//
	// Immutable.
	instructions []linux.EBPFInstruction
}

// NewUnverifiedProgram creates an unverified eBPF program from a set of instructions.
func NewUnverifiedProgram(instructions []linux.EBPFInstruction) UnverifiedProgram {
	return UnverifiedProgram{
		instructions: instructions,
	}
}

// Program represents an eBPF program that has been validated.
//
// All fields of Program are immutable.
//
// +stateify savable
type Program struct {
	// instructions is a list of eBPF instructions.
	instructions []linux.EBPFInstruction

	// id is the program's ID.
	id BPFID

	// progType is the program's type.
	progType linux.BPFProgramType
}

// ID returns the unique identifier for the eBPF program.
func (p *Program) ID() BPFID {
	return p.id
}

// ProgType returns the type of the eBPF program.
func (p *Program) ProgType() linux.BPFProgramType {
	return p.progType
}

// Validate validates an unverified eBPF program.
//
// Currently, no validation is performed, so the resulting program MUST not be run.
func (uprog *UnverifiedProgram) Validate(id BPFID, progType linux.BPFProgramType) (Program, error) {
	prog := Program{
		instructions: uprog.instructions,
		id:           id,
		progType:     progType,
	}
	return prog, nil
}
