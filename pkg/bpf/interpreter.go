// Copyright 2018 Google LLC
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

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// Possible values for ProgramError.Code.
const (
	// DivisionByZero indicates that a program contains, or executed, a
	// division or modulo by zero.
	DivisionByZero = iota

	// InvalidEndOfProgram indicates that the last instruction of a program is
	// not a return.
	InvalidEndOfProgram

	// InvalidInstructionCount indicates that a program has zero instructions
	// or more than MaxInstructions instructions.
	InvalidInstructionCount

	// InvalidJumpTarget indicates that a program contains a jump whose target
	// is outside of the program's bounds.
	InvalidJumpTarget

	// InvalidLoad indicates that a program executed an invalid load of input
	// data.
	InvalidLoad

	// InvalidOpcode indicates that a program contains an instruction with an
	// invalid opcode.
	InvalidOpcode

	// InvalidRegister indicates that a program contains a load from, or store
	// to, a non-existent M register (index >= ScratchMemRegisters).
	InvalidRegister
)

// Error is an error encountered while compiling or executing a BPF program.
type Error struct {
	// Code indicates the kind of error that occurred.
	Code int

	// PC is the program counter (index into the list of instructions) at which
	// the error occurred.
	PC int
}

func (e Error) codeString() string {
	switch e.Code {
	case DivisionByZero:
		return "division by zero"
	case InvalidEndOfProgram:
		return "last instruction must be a return"
	case InvalidInstructionCount:
		return "invalid number of instructions"
	case InvalidJumpTarget:
		return "jump target out of bounds"
	case InvalidLoad:
		return "load out of bounds or violates input alignment requirements"
	case InvalidOpcode:
		return "invalid instruction opcode"
	case InvalidRegister:
		return "invalid M register"
	default:
		return "unknown error"
	}
}

// Error implements error.Error.
func (e Error) Error() string {
	return fmt.Sprintf("at l%d: %s", e.PC, e.codeString())
}

// Program is a BPF program that has been validated for consistency.
//
// +stateify savable
type Program struct {
	instructions []linux.BPFInstruction
}

// Length returns the number of instructions in the program.
func (p Program) Length() int {
	return len(p.instructions)
}

// Compile performs validation on a sequence of BPF instructions before
// wrapping them in a Program.
func Compile(insns []linux.BPFInstruction) (Program, error) {
	if len(insns) == 0 || len(insns) > MaxInstructions {
		return Program{}, Error{InvalidInstructionCount, len(insns)}
	}

	// The last instruction must be a return.
	if last := insns[len(insns)-1]; last.OpCode != (Ret|K) && last.OpCode != (Ret|A) {
		return Program{}, Error{InvalidEndOfProgram, len(insns) - 1}
	}

	// Validate each instruction. Note that we skip a validation Linux does:
	// Linux additionally verifies that every load from an M register is
	// preceded, in every path, by a store to the same M register, in order to
	// avoid having to clear M between programs
	// (net/core/filter.c:check_load_and_stores). We always start with a zeroed
	// M array.
	for pc, i := range insns {
		if i.OpCode&unusedBitsMask != 0 {
			return Program{}, Error{InvalidOpcode, pc}
		}
		switch i.OpCode & instructionClassMask {
		case Ld:
			mode := i.OpCode & loadModeMask
			switch i.OpCode & loadSizeMask {
			case W:
				if mode != Imm && mode != Abs && mode != Ind && mode != Mem && mode != Len {
					return Program{}, Error{InvalidOpcode, pc}
				}
				if mode == Mem && i.K >= ScratchMemRegisters {
					return Program{}, Error{InvalidRegister, pc}
				}
			case H, B:
				if mode != Abs && mode != Ind {
					return Program{}, Error{InvalidOpcode, pc}
				}
			default:
				return Program{}, Error{InvalidOpcode, pc}
			}
		case Ldx:
			mode := i.OpCode & loadModeMask
			switch i.OpCode & loadSizeMask {
			case W:
				if mode != Imm && mode != Mem && mode != Len {
					return Program{}, Error{InvalidOpcode, pc}
				}
				if mode == Mem && i.K >= ScratchMemRegisters {
					return Program{}, Error{InvalidRegister, pc}
				}
			case B:
				if mode != Msh {
					return Program{}, Error{InvalidOpcode, pc}
				}
			default:
				return Program{}, Error{InvalidOpcode, pc}
			}
		case St, Stx:
			if i.OpCode&storeUnusedBitsMask != 0 {
				return Program{}, Error{InvalidOpcode, pc}
			}
			if i.K >= ScratchMemRegisters {
				return Program{}, Error{InvalidRegister, pc}
			}
		case Alu:
			switch i.OpCode & aluMask {
			case Add, Sub, Mul, Or, And, Lsh, Rsh, Xor:
				break
			case Div, Mod:
				if src := i.OpCode & srcAluJmpMask; src == K && i.K == 0 {
					return Program{}, Error{DivisionByZero, pc}
				}
			case Neg:
				// Negation doesn't take a source operand.
				if i.OpCode&srcAluJmpMask != 0 {
					return Program{}, Error{InvalidOpcode, pc}
				}
			default:
				return Program{}, Error{InvalidOpcode, pc}
			}
		case Jmp:
			switch i.OpCode & jmpMask {
			case Ja:
				// Unconditional jump doesn't take a source operand.
				if i.OpCode&srcAluJmpMask != 0 {
					return Program{}, Error{InvalidOpcode, pc}
				}
				// Do the comparison in 64 bits to avoid the possibility of
				// overflow from a very large i.K.
				if uint64(pc)+uint64(i.K)+1 >= uint64(len(insns)) {
					return Program{}, Error{InvalidJumpTarget, pc}
				}
			case Jeq, Jgt, Jge, Jset:
				// jt and jf are uint16s, so there's no threat of overflow.
				if pc+int(i.JumpIfTrue)+1 >= len(insns) {
					return Program{}, Error{InvalidJumpTarget, pc}
				}
				if pc+int(i.JumpIfFalse)+1 >= len(insns) {
					return Program{}, Error{InvalidJumpTarget, pc}
				}
			default:
				return Program{}, Error{InvalidOpcode, pc}
			}
		case Ret:
			if i.OpCode&retUnusedBitsMask != 0 {
				return Program{}, Error{InvalidOpcode, pc}
			}
			if src := i.OpCode & srcRetMask; src != K && src != A {
				return Program{}, Error{InvalidOpcode, pc}
			}
		case Misc:
			if misc := i.OpCode & miscMask; misc != Tax && misc != Txa {
				return Program{}, Error{InvalidOpcode, pc}
			}
		}
	}

	return Program{insns}, nil
}

// Input represents a source of input data for a BPF program. (BPF
// documentation sometimes refers to the input data as the "packet" due to its
// origins as a packet processing DSL.)
//
// For all of Input's Load methods:
//
// - The second (bool) return value is true if the load succeeded and false
// otherwise.
//
// - Inputs should not assume that the loaded range falls within the input
// data's length. Inputs should return false if the load falls outside of the
// input data.
//
// - Inputs should not assume that the offset is correctly aligned. Inputs may
// choose to service or reject loads to unaligned addresses.
type Input interface {
	// Load32 reads 32 bits from the input starting at the given byte offset.
	Load32(off uint32) (uint32, bool)

	// Load16 reads 16 bits from the input starting at the given byte offset.
	Load16(off uint32) (uint16, bool)

	// Load8 reads 8 bits from the input starting at the given byte offset.
	Load8(off uint32) (uint8, bool)

	// Length returns the length of the input in bytes.
	Length() uint32
}

// machine represents the state of a BPF virtual machine.
type machine struct {
	A uint32
	X uint32
	M [ScratchMemRegisters]uint32
}

func conditionalJumpOffset(insn linux.BPFInstruction, cond bool) int {
	if cond {
		return int(insn.JumpIfTrue)
	}
	return int(insn.JumpIfFalse)
}

// Exec executes a BPF program over the given input and returns its return
// value.
func Exec(p Program, in Input) (uint32, error) {
	var m machine
	var pc int
	for ; pc < len(p.instructions); pc++ {
		i := p.instructions[pc]
		switch i.OpCode {
		case Ld | Imm | W:
			m.A = i.K
		case Ld | Abs | W:
			val, ok := in.Load32(i.K)
			if !ok {
				return 0, Error{InvalidLoad, pc}
			}
			m.A = val
		case Ld | Abs | H:
			val, ok := in.Load16(i.K)
			if !ok {
				return 0, Error{InvalidLoad, pc}
			}
			m.A = uint32(val)
		case Ld | Abs | B:
			val, ok := in.Load8(i.K)
			if !ok {
				return 0, Error{InvalidLoad, pc}
			}
			m.A = uint32(val)
		case Ld | Ind | W:
			val, ok := in.Load32(m.X + i.K)
			if !ok {
				return 0, Error{InvalidLoad, pc}
			}
			m.A = val
		case Ld | Ind | H:
			val, ok := in.Load16(m.X + i.K)
			if !ok {
				return 0, Error{InvalidLoad, pc}
			}
			m.A = uint32(val)
		case Ld | Ind | B:
			val, ok := in.Load8(m.X + i.K)
			if !ok {
				return 0, Error{InvalidLoad, pc}
			}
			m.A = uint32(val)
		case Ld | Mem | W:
			m.A = m.M[int(i.K)]
		case Ld | Len | W:
			m.A = in.Length()
		case Ldx | Imm | W:
			m.X = i.K
		case Ldx | Mem | W:
			m.X = m.M[int(i.K)]
		case Ldx | Len | W:
			m.X = in.Length()
		case Ldx | Msh | B:
			val, ok := in.Load8(i.K)
			if !ok {
				return 0, Error{InvalidLoad, pc}
			}
			m.X = 4 * uint32(val&0xf)
		case St:
			m.M[int(i.K)] = m.A
		case Stx:
			m.M[int(i.K)] = m.X
		case Alu | Add | K:
			m.A += i.K
		case Alu | Add | X:
			m.A += m.X
		case Alu | Sub | K:
			m.A -= i.K
		case Alu | Sub | X:
			m.A -= m.X
		case Alu | Mul | K:
			m.A *= i.K
		case Alu | Mul | X:
			m.A *= m.X
		case Alu | Div | K:
			// K != 0 already checked by Compile.
			m.A /= i.K
		case Alu | Div | X:
			if m.X == 0 {
				return 0, Error{DivisionByZero, pc}
			}
			m.A /= m.X
		case Alu | Or | K:
			m.A |= i.K
		case Alu | Or | X:
			m.A |= m.X
		case Alu | And | K:
			m.A &= i.K
		case Alu | And | X:
			m.A &= m.X
		case Alu | Lsh | K:
			m.A <<= i.K
		case Alu | Lsh | X:
			m.A <<= m.X
		case Alu | Rsh | K:
			m.A >>= i.K
		case Alu | Rsh | X:
			m.A >>= m.X
		case Alu | Neg:
			m.A = uint32(-int32(m.A))
		case Alu | Mod | K:
			// K != 0 already checked by Compile.
			m.A %= i.K
		case Alu | Mod | X:
			if m.X == 0 {
				return 0, Error{DivisionByZero, pc}
			}
			m.A %= m.X
		case Alu | Xor | K:
			m.A ^= i.K
		case Alu | Xor | X:
			m.A ^= m.X
		case Jmp | Ja:
			pc += int(i.K)
		case Jmp | Jeq | K:
			pc += conditionalJumpOffset(i, m.A == i.K)
		case Jmp | Jeq | X:
			pc += conditionalJumpOffset(i, m.A == m.X)
		case Jmp | Jgt | K:
			pc += conditionalJumpOffset(i, m.A > i.K)
		case Jmp | Jgt | X:
			pc += conditionalJumpOffset(i, m.A > m.X)
		case Jmp | Jge | K:
			pc += conditionalJumpOffset(i, m.A >= i.K)
		case Jmp | Jge | X:
			pc += conditionalJumpOffset(i, m.A >= m.X)
		case Jmp | Jset | K:
			pc += conditionalJumpOffset(i, (m.A&i.K) != 0)
		case Jmp | Jset | X:
			pc += conditionalJumpOffset(i, (m.A&m.X) != 0)
		case Ret | K:
			return i.K, nil
		case Ret | A:
			return m.A, nil
		case Misc | Tax:
			m.A = m.X
		case Misc | Txa:
			m.X = m.A
		default:
			return 0, Error{InvalidOpcode, pc}
		}
	}
	return 0, Error{InvalidEndOfProgram, pc}
}
