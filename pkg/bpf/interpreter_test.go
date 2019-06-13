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

package bpf

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
)

func TestCompilationErrors(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// insns is the BPF instructions to be compiled.
		insns []linux.BPFInstruction

		// expectedErr is the expected compilation error.
		expectedErr error
	}{
		{
			desc:        "Instructions must not be nil",
			expectedErr: Error{InvalidInstructionCount, 0},
		},
		{
			desc:        "Instructions must not be empty",
			insns:       []linux.BPFInstruction{},
			expectedErr: Error{InvalidInstructionCount, 0},
		},
		{
			desc:        "A program must end with a return",
			insns:       make([]linux.BPFInstruction, MaxInstructions),
			expectedErr: Error{InvalidEndOfProgram, MaxInstructions - 1},
		},
		{
			desc:        "A program must have MaxInstructions or fewer instructions",
			insns:       append(make([]linux.BPFInstruction, MaxInstructions), Stmt(Ret|K, 0)),
			expectedErr: Error{InvalidInstructionCount, MaxInstructions + 1},
		},
		{
			desc: "A load from an invalid M register is a compilation error",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Mem|W, ScratchMemRegisters), // A = M[16]
				Stmt(Ret|K, 0),                      // return 0
			},
			expectedErr: Error{InvalidRegister, 0},
		},
		{
			desc: "A store to an invalid M register is a compilation error",
			insns: []linux.BPFInstruction{
				Stmt(St, ScratchMemRegisters), // M[16] = A
				Stmt(Ret|K, 0),                // return 0
			},
			expectedErr: Error{InvalidRegister, 0},
		},
		{
			desc: "Division by literal zero is a compilation error",
			insns: []linux.BPFInstruction{
				Stmt(Alu|Div|K, 0), // A /= 0
				Stmt(Ret|K, 0),     // return 0
			},
			expectedErr: Error{DivisionByZero, 0},
		},
		{
			desc: "An unconditional jump outside of the program is a compilation error",
			insns: []linux.BPFInstruction{
				Jump(Jmp|Ja, 1, 0, 0), // jmp nextpc+1
				Stmt(Ret|K, 0),        // return 0
			},
			expectedErr: Error{InvalidJumpTarget, 0},
		},
		{
			desc: "A conditional jump outside of the program in the true case is a compilation error",
			insns: []linux.BPFInstruction{
				Jump(Jmp|Jeq|K, 0, 1, 0), // if (A == K) jmp nextpc+1
				Stmt(Ret|K, 0),           // return 0
			},
			expectedErr: Error{InvalidJumpTarget, 0},
		},
		{
			desc: "A conditional jump outside of the program in the false case is a compilation error",
			insns: []linux.BPFInstruction{
				Jump(Jmp|Jeq|K, 0, 0, 1), // if (A != K) jmp nextpc+1
				Stmt(Ret|K, 0),           // return 0
			},
			expectedErr: Error{InvalidJumpTarget, 0},
		},
	} {
		_, err := Compile(test.insns)
		if err != test.expectedErr {
			t.Errorf("%s: expected error %q, got error %q", test.desc, test.expectedErr, err)
		}
	}
}

func TestExecErrors(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// insns is the BPF instructions to be executed.
		insns []linux.BPFInstruction

		// expectedErr is the expected execution error.
		expectedErr error
	}{
		{
			desc: "An out-of-bounds load of input data is an execution error",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Abs|B, 0), // A = input[0]
				Stmt(Ret|K, 0),    // return 0
			},
			expectedErr: Error{InvalidLoad, 0},
		},
		{
			desc: "Division by zero at runtime is an execution error",
			insns: []linux.BPFInstruction{
				Stmt(Alu|Div|X, 0), // A /= X
				Stmt(Ret|K, 0),     // return 0
			},
			expectedErr: Error{DivisionByZero, 0},
		},
		{
			desc: "Modulo zero at runtime is an execution error",
			insns: []linux.BPFInstruction{
				Stmt(Alu|Mod|X, 0), // A %= X
				Stmt(Ret|K, 0),     // return 0
			},
			expectedErr: Error{DivisionByZero, 0},
		},
	} {
		p, err := Compile(test.insns)
		if err != nil {
			t.Errorf("%s: unexpected compilation error: %v", test.desc, err)
			continue
		}
		ret, err := Exec(p, InputBytes{nil, binary.BigEndian})
		if err != test.expectedErr {
			t.Errorf("%s: expected execution error %q, got (%d, %v)", test.desc, test.expectedErr, ret, err)
		}
	}
}

func TestValidInstructions(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// insns is the BPF instructions to be compiled.
		insns []linux.BPFInstruction

		// input is the input data. Note that input will be read as big-endian.
		input []byte

		// expectedRet is the expected return value of the BPF program.
		expectedRet uint32
	}{
		{
			desc: "Return of immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ret|K, 42), // return 42
			},
			expectedRet: 42,
		},
		{
			desc: "Load of immediate into A",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 42), // A = 42
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 42,
		},
		{
			desc: "Load of immediate into X and copying of X into A",
			insns: []linux.BPFInstruction{
				Stmt(Ldx|Imm|W, 42), // X = 42
				Stmt(Misc|Tax, 0),   // A = X
				Stmt(Ret|A, 0),      // return A
			},
			expectedRet: 42,
		},
		{
			desc: "Copying of A into X and back",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 42), // A = 42
				Stmt(Misc|Txa, 0),  // X = A
				Stmt(Ld|Imm|W, 0),  // A = 0
				Stmt(Misc|Tax, 0),  // A = X
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 42,
		},
		{
			desc: "Load of 32-bit input by absolute offset into A",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Abs|W, 1), // A = input[1..4]
				Stmt(Ret|A, 0),    // return A
			},
			input:       []byte{0x00, 0x11, 0x22, 0x33, 0x44},
			expectedRet: 0x11223344,
		},
		{
			desc: "Load of 16-bit input by absolute offset into A",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Abs|H, 1), // A = input[1..2]
				Stmt(Ret|A, 0),    // return A
			},
			input:       []byte{0x00, 0x11, 0x22},
			expectedRet: 0x1122,
		},
		{
			desc: "Load of 8-bit input by absolute offset into A",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Abs|B, 1), // A = input[1]
				Stmt(Ret|A, 0),    // return A
			},
			input:       []byte{0x00, 0x11},
			expectedRet: 0x11,
		},
		{
			desc: "Load of 32-bit input by relative offset into A",
			insns: []linux.BPFInstruction{
				Stmt(Ldx|Imm|W, 1), // X = 1
				Stmt(Ld|Ind|W, 1),  // A = input[X+1..X+4]
				Stmt(Ret|A, 0),     // return A
			},
			input:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			expectedRet: 0x22334455,
		},
		{
			desc: "Load of 16-bit input by relative offset into A",
			insns: []linux.BPFInstruction{
				Stmt(Ldx|Imm|W, 1), // X = 1
				Stmt(Ld|Ind|H, 1),  // A = input[X+1..X+2]
				Stmt(Ret|A, 0),     // return A
			},
			input:       []byte{0x00, 0x11, 0x22, 0x33},
			expectedRet: 0x2233,
		},
		{
			desc: "Load of 8-bit input by relative offset into A",
			insns: []linux.BPFInstruction{
				Stmt(Ldx|Imm|W, 1), // X = 1
				Stmt(Ld|Ind|B, 1),  // A = input[X+1]
				Stmt(Ret|A, 0),     // return A
			},
			input:       []byte{0x00, 0x11, 0x22},
			expectedRet: 0x22,
		},
		{
			desc: "Load/store between A and scratch memory",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 42), // A = 42
				Stmt(St, 2),        // M[2] = A
				Stmt(Ld|Imm|W, 0),  // A = 0
				Stmt(Ld|Mem|W, 2),  // A = M[2]
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 42,
		},
		{
			desc: "Load/store between X and scratch memory",
			insns: []linux.BPFInstruction{
				Stmt(Ldx|Imm|W, 42), // X = 42
				Stmt(Stx, 3),        // M[3] = X
				Stmt(Ldx|Imm|W, 0),  // X = 0
				Stmt(Ldx|Mem|W, 3),  // X = M[3]
				Stmt(Misc|Tax, 0),   // A = X
				Stmt(Ret|A, 0),      // return A
			},
			expectedRet: 42,
		},
		{
			desc: "Load of input length into A",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Len|W, 0), // A = len(input)
				Stmt(Ret|A, 0),    // return A
			},
			input:       []byte{1, 2, 3},
			expectedRet: 3,
		},
		{
			desc: "Load of input length into X",
			insns: []linux.BPFInstruction{
				Stmt(Ldx|Len|W, 0), // X = len(input)
				Stmt(Misc|Tax, 0),  // A = X
				Stmt(Ret|A, 0),     // return A
			},
			input:       []byte{1, 2, 3},
			expectedRet: 3,
		},
		{
			desc: "Load of MSH (?) into X",
			insns: []linux.BPFInstruction{
				Stmt(Ldx|Msh|B, 0), // X = 4*(input[0]&0xf)
				Stmt(Misc|Tax, 0),  // A = X
				Stmt(Ret|A, 0),     // return A
			},
			input:       []byte{0xf1},
			expectedRet: 4,
		},
		{
			desc: "Addition of immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),  // A = 10
				Stmt(Alu|Add|K, 20), // A += 20
				Stmt(Ret|A, 0),      // return A
			},
			expectedRet: 30,
		},
		{
			desc: "Addition of X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),  // A = 10
				Stmt(Ldx|Imm|W, 20), // X = 20
				Stmt(Alu|Add|X, 0),  // A += X
				Stmt(Ret|A, 0),      // return A
			},
			expectedRet: 30,
		},
		{
			desc: "Subtraction of immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 30),  // A = 30
				Stmt(Alu|Sub|K, 20), // A -= 20
				Stmt(Ret|A, 0),      // return A
			},
			expectedRet: 10,
		},
		{
			desc: "Subtraction of X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 30),  // A = 30
				Stmt(Ldx|Imm|W, 20), // X = 20
				Stmt(Alu|Sub|X, 0),  // A -= X
				Stmt(Ret|A, 0),      // return A
			},
			expectedRet: 10,
		},
		{
			desc: "Multiplication of immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 2),  // A = 2
				Stmt(Alu|Mul|K, 3), // A *= 3
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 6,
		},
		{
			desc: "Multiplication of X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 2),  // A = 2
				Stmt(Ldx|Imm|W, 3), // X = 3
				Stmt(Alu|Mul|X, 0), // A *= X
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 6,
		},
		{
			desc: "Division by immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 6),  // A = 6
				Stmt(Alu|Div|K, 3), // A /= 3
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 2,
		},
		{
			desc: "Division by X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 6),  // A = 6
				Stmt(Ldx|Imm|W, 3), // X = 3
				Stmt(Alu|Div|X, 0), // A /= X
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 2,
		},
		{
			desc: "Modulo immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 17), // A = 17
				Stmt(Alu|Mod|K, 7), // A %= 7
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 3,
		},
		{
			desc: "Modulo X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 17), // A = 17
				Stmt(Ldx|Imm|W, 7), // X = 7
				Stmt(Alu|Mod|X, 0), // A %= X
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 3,
		},
		{
			desc: "Arithmetic negation",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 1), // A = 1
				Stmt(Alu|Neg, 0),  // A = -A
				Stmt(Ret|A, 0),    // return A
			},
			expectedRet: 0xffffffff,
		},
		{
			desc: "Bitwise OR with immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xff00aa55), // A = 0xff00aa55
				Stmt(Alu|Or|K, 0xff0055aa), // A |= 0xff0055aa
				Stmt(Ret|A, 0),             // return A
			},
			expectedRet: 0xff00ffff,
		},
		{
			desc: "Bitwise OR with X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Ldx|Imm|W, 0xff0055aa), // X = 0xff0055aa
				Stmt(Alu|Or|X, 0),           // A |= X
				Stmt(Ret|A, 0),              // return A
			},
			expectedRet: 0xff00ffff,
		},
		{
			desc: "Bitwise AND with immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Alu|And|K, 0xff0055aa), // A &= 0xff0055aa
				Stmt(Ret|A, 0),              // return A
			},
			expectedRet: 0xff000000,
		},
		{
			desc: "Bitwise AND with X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Ldx|Imm|W, 0xff0055aa), // X = 0xff0055aa
				Stmt(Alu|And|X, 0),          // A &= X
				Stmt(Ret|A, 0),              // return A
			},
			expectedRet: 0xff000000,
		},
		{
			desc: "Bitwise XOR with immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Alu|Xor|K, 0xff0055aa), // A ^= 0xff0055aa
				Stmt(Ret|A, 0),              // return A
			},
			expectedRet: 0x0000ffff,
		},
		{
			desc: "Bitwise XOR with X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Ldx|Imm|W, 0xff0055aa), // X = 0xff0055aa
				Stmt(Alu|Xor|X, 0),          // A ^= X
				Stmt(Ret|A, 0),              // return A
			},
			expectedRet: 0x0000ffff,
		},
		{
			desc: "Left shift by immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 1),  // A = 1
				Stmt(Alu|Lsh|K, 5), // A <<= 5
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 32,
		},
		{
			desc: "Left shift by X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 1),  // A = 1
				Stmt(Ldx|Imm|W, 5), // X = 5
				Stmt(Alu|Lsh|X, 0), // A <<= X
				Stmt(Ret|A, 0),     // return A
			},
			expectedRet: 32,
		},
		{
			desc: "Right shift by immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xffffffff), // A = 0xffffffff
				Stmt(Alu|Rsh|K, 31),        // A >>= 31
				Stmt(Ret|A, 0),             // return A
			},
			expectedRet: 1,
		},
		{
			desc: "Right shift by X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xffffffff), // A = 0xffffffff
				Stmt(Ldx|Imm|W, 31),        // X = 31
				Stmt(Alu|Rsh|X, 0),         // A >>= X
				Stmt(Ret|A, 0),             // return A
			},
			expectedRet: 1,
		},
		{
			desc: "Unconditional jump",
			insns: []linux.BPFInstruction{
				Jump(Jmp|Ja, 1, 0, 0), // jmp nextpc+1
				Stmt(Ret|K, 0),        // return 0
				Stmt(Ret|K, 1),        // return 1
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A == immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 42),        // A = 42
				Jump(Jmp|Jeq|K, 42, 1, 2), // if (A == 42) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A != immediate",
			insns: []linux.BPFInstruction{
				Jump(Jmp|Jeq|K, 42, 1, 2), // if (A == 42) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expectedRet: 2,
		},
		{
			desc: "Jump when A == X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 42),       // A = 42
				Stmt(Ldx|Imm|W, 42),      // X = 42
				Jump(Jmp|Jeq|X, 0, 1, 2), // if (A == X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A != X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 42),       // A = 42
				Jump(Jmp|Jeq|X, 0, 1, 2), // if (A == X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expectedRet: 2,
		},
		{
			desc: "Jump when A > immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Jump(Jmp|Jgt|K, 9, 1, 2), // if (A > 9) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A <= immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),        // A = 10
				Jump(Jmp|Jgt|K, 10, 1, 2), // if (A > 10) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expectedRet: 2,
		},
		{
			desc: "Jump when A > X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Stmt(Ldx|Imm|W, 9),       // X = 9
				Jump(Jmp|Jgt|X, 0, 1, 2), // if (A > X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A <= X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Stmt(Ldx|Imm|W, 10),      // X = 10
				Jump(Jmp|Jgt|X, 0, 1, 2), // if (A > X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expectedRet: 2,
		},
		{
			desc: "Jump when A >= immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),        // A = 10
				Jump(Jmp|Jge|K, 10, 1, 2), // if (A >= 10) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A < immediate",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),        // A = 10
				Jump(Jmp|Jge|K, 11, 1, 2), // if (A >= 11) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expectedRet: 2,
		},
		{
			desc: "Jump when A >= X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Stmt(Ldx|Imm|W, 10),      // X = 10
				Jump(Jmp|Jge|X, 0, 1, 2), // if (A >= X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A < X",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Stmt(Ldx|Imm|W, 11),      // X = 11
				Jump(Jmp|Jge|X, 0, 1, 2), // if (A >= X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expectedRet: 2,
		},
		{
			desc: "Jump when A & immediate != 0",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xff),          // A = 0xff
				Jump(Jmp|Jset|K, 0x101, 1, 2), // if (A & 0x101) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),                // return 0
				Stmt(Ret|K, 1),                // return 1
				Stmt(Ret|K, 2),                // return 2
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A & immediate == 0",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xfe),          // A = 0xfe
				Jump(Jmp|Jset|K, 0x101, 1, 2), // if (A & 0x101) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),                // return 0
				Stmt(Ret|K, 1),                // return 1
				Stmt(Ret|K, 2),                // return 2
			},
			expectedRet: 2,
		},
		{
			desc: "Jump when A & X != 0",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xff),      // A = 0xff
				Stmt(Ldx|Imm|W, 0x101),    // X = 0x101
				Jump(Jmp|Jset|X, 0, 1, 2), // if (A & X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expectedRet: 1,
		},
		{
			desc: "Jump when A & X == 0",
			insns: []linux.BPFInstruction{
				Stmt(Ld|Imm|W, 0xfe),      // A = 0xfe
				Stmt(Ldx|Imm|W, 0x101),    // X = 0x101
				Jump(Jmp|Jset|X, 0, 1, 2), // if (A & X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expectedRet: 2,
		},
	} {
		p, err := Compile(test.insns)
		if err != nil {
			t.Errorf("%s: unexpected compilation error: %v", test.desc, err)
			continue
		}
		ret, err := Exec(p, InputBytes{test.input, binary.BigEndian})
		if err != nil {
			t.Errorf("%s: expected return value of %d, got execution error: %v", test.desc, test.expectedRet, err)
			continue
		}
		if ret != test.expectedRet {
			t.Errorf("%s: expected return value of %d, got value %d", test.desc, test.expectedRet, ret)
		}
	}
}

func TestSimpleFilter(t *testing.T) {
	// Seccomp filter example given in Linux's
	// Documentation/networking/filter.txt, translated to bytecode using the
	// Linux kernel tree's tools/net/bpf_asm.
	filter := []linux.BPFInstruction{
		{0x20, 0, 0, 0x00000004},  // ld [4]                  /* offsetof(struct seccomp_data, arch) */
		{0x15, 0, 11, 0xc000003e}, // jne #0xc000003e, bad    /* AUDIT_ARCH_X86_64 */
		{0x20, 0, 0, 0000000000},  // ld [0]                  /* offsetof(struct seccomp_data, nr) */
		{0x15, 10, 0, 0x0000000f}, // jeq #15, good           /* __NR_rt_sigreturn */
		{0x15, 9, 0, 0x000000e7},  // jeq #231, good          /* __NR_exit_group */
		{0x15, 8, 0, 0x0000003c},  // jeq #60, good           /* __NR_exit */
		{0x15, 7, 0, 0000000000},  // jeq #0, good            /* __NR_read */
		{0x15, 6, 0, 0x00000001},  // jeq #1, good            /* __NR_write */
		{0x15, 5, 0, 0x00000005},  // jeq #5, good            /* __NR_fstat */
		{0x15, 4, 0, 0x00000009},  // jeq #9, good            /* __NR_mmap */
		{0x15, 3, 0, 0x0000000e},  // jeq #14, good           /* __NR_rt_sigprocmask */
		{0x15, 2, 0, 0x0000000d},  // jeq #13, good           /* __NR_rt_sigaction */
		{0x15, 1, 0, 0x00000023},  // jeq #35, good           /* __NR_nanosleep */
		{0x06, 0, 0, 0000000000},  // bad: ret #0             /* SECCOMP_RET_KILL */
		{0x06, 0, 0, 0x7fff0000},  // good: ret #0x7fff0000   /* SECCOMP_RET_ALLOW */
	}
	p, err := Compile(filter)
	if err != nil {
		t.Fatalf("Unexpected compilation error: %v", err)
	}

	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// seccompData is the input data.
		seccompData

		// expectedRet is the expected return value of the BPF program.
		expectedRet uint32
	}{
		{
			desc:        "Invalid arch is rejected",
			seccompData: seccompData{nr: 1 /* x86 exit */, arch: 0x40000003 /* AUDIT_ARCH_I386 */},
			expectedRet: 0,
		},
		{
			desc:        "Disallowed syscall is rejected",
			seccompData: seccompData{nr: 105 /* __NR_setuid */, arch: 0xc000003e},
			expectedRet: 0,
		},
		{
			desc:        "Whitelisted syscall is allowed",
			seccompData: seccompData{nr: 231 /* __NR_exit_group */, arch: 0xc000003e},
			expectedRet: 0x7fff0000,
		},
	} {
		ret, err := Exec(p, test.seccompData.asInput())
		if err != nil {
			t.Errorf("%s: expected return value of %d, got execution error: %v", test.desc, test.expectedRet, err)
			continue
		}
		if ret != test.expectedRet {
			t.Errorf("%s: expected return value of %d, got value %d", test.desc, test.expectedRet, ret)
		}
	}
}

// seccompData is equivalent to struct seccomp_data.
type seccompData struct {
	nr                 uint32
	arch               uint32
	instructionPointer uint64
	args               [6]uint64
}

// asInput converts a seccompData to a bpf.Input.
func (d *seccompData) asInput() Input {
	return InputBytes{binary.Marshal(nil, binary.LittleEndian, d), binary.LittleEndian}
}
