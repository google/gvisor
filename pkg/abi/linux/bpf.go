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

package linux

// BPFInstruction is a raw BPF virtual machine instruction.
//
// +marshal slice:BPFInstructionSlice
// +stateify savable
type BPFInstruction struct {
	// OpCode is the operation to execute.
	OpCode uint16

	// JumpIfTrue is the number of instructions to skip if OpCode is a
	// conditional instruction and the condition is true.
	JumpIfTrue uint8

	// JumpIfFalse is the number of instructions to skip if OpCode is a
	// conditional instruction and the condition is false.
	JumpIfFalse uint8

	// K is a constant parameter. The meaning depends on the value of OpCode.
	K uint32
}
