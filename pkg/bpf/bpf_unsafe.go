// Copyright 2023 The gVisor Authors.
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

package bpf

import (
	"fmt"
	"unsafe"
)

// sizeOfInstruction is the size of a BPF instruction struct.
const sizeOfInstruction = int(unsafe.Sizeof(Instruction{}))

// ToBytecode converts BPF instructions into raw BPF bytecode.
func ToBytecode(insns []Instruction) []byte {
	return ([]byte)(unsafe.Slice((*byte)(unsafe.Pointer(&insns[0])), len(insns)*sizeOfInstruction))
}

// ParseBytecode converts raw BPF bytecode into BPF instructions.
// It verifies that the resulting set of instructions is a valid program.
func ParseBytecode(bytecode []byte) ([]Instruction, error) {
	if len(bytecode)%sizeOfInstruction != 0 {
		return nil, fmt.Errorf("bytecode size (%d bytes) is not a multiple of BPF instruction size of %d bytes", len(bytecode), sizeOfInstruction)
	}
	insns := ([]Instruction)(unsafe.Slice((*Instruction)(unsafe.Pointer(&bytecode[0])), len(bytecode)/sizeOfInstruction))
	if _, err := Compile(insns, false); err != nil {
		return nil, fmt.Errorf("not a valid BPF program: %v", err)
	}
	return insns, nil
}
