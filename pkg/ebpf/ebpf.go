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

// BpfID is a sequential, globally-unique (though unloaded
// programs' IDs are reused) ID for an eBPF program.
type BpfID uint32

// UnverifiedProgram represents an eBPF program provided by userspace that has not
// been validated.
type UnverifiedProgram struct {
	// instructions is a list of eBPF instructions.
	//
	// Immutable.
	instructions []linux.EbpfInstruction
}

func NewUnverifiedProgram(instructions []linux.EbpfInstruction) UnverifiedProgram {
	return UnverifiedProgram{
		instructions: instructions,
	}
}

// Program represents an eBPF program that has been validated.
type Program struct {
	// instructions is a list of eBPF instructions.
	//
	// Immutable.
	instructions []linux.EbpfInstruction

	// id is the program's ID.
	//
	// Immutable
	id BpfID
}

func (p *Program) ID() BpfID {
	return p.id
}

// Validate validates an unverified eBPF program.
//
// Currently, no validation is performed, so the resulting program MUST not be run.
func (uprog *UnverifiedProgram) Validate(id BpfID) (Program, error) {
	prog := Program{
		instructions: uprog.instructions,
		id:           id,
	}
	return prog, nil
}
