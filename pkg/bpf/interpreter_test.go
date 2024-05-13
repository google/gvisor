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
	"reflect"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
)

func TestCompilationErrors(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// insns is the BPF instructions to be compiled.
		insns []Instruction

		// expectedErr is the expected compilation error.
		expectedErr error
	}{
		{
			desc:        "Instructions must not be nil",
			expectedErr: Error{InvalidInstructionCount, 0},
		},
		{
			desc:        "Instructions must not be empty",
			insns:       []Instruction{},
			expectedErr: Error{InvalidInstructionCount, 0},
		},
		{
			desc:        "A program must end with a return",
			insns:       make([]Instruction, MaxInstructions),
			expectedErr: Error{InvalidEndOfProgram, MaxInstructions - 1},
		},
		{
			desc:        "A program must have MaxInstructions or fewer instructions",
			insns:       append(make([]Instruction, MaxInstructions), Stmt(Ret|K, 0)),
			expectedErr: Error{InvalidInstructionCount, MaxInstructions + 1},
		},
		{
			desc: "A load from an invalid M register is a compilation error",
			insns: []Instruction{
				Stmt(Ld|Mem|W, ScratchMemRegisters), // A = M[16]
				Stmt(Ret|K, 0),                      // return 0
			},
			expectedErr: Error{InvalidRegister, 0},
		},
		{
			desc: "A store to an invalid M register is a compilation error",
			insns: []Instruction{
				Stmt(St, ScratchMemRegisters), // M[16] = A
				Stmt(Ret|K, 0),                // return 0
			},
			expectedErr: Error{InvalidRegister, 0},
		},
		{
			desc: "Division by literal zero is a compilation error",
			insns: []Instruction{
				Stmt(Alu|Div|K, 0), // A /= 0
				Stmt(Ret|K, 0),     // return 0
			},
			expectedErr: Error{DivisionByZero, 0},
		},
		{
			desc: "An unconditional jump outside of the program is a compilation error",
			insns: []Instruction{
				Jump(Jmp|Ja, 1, 0, 0), // jmp nextpc+1
				Stmt(Ret|K, 0),        // return 0
			},
			expectedErr: Error{InvalidJumpTarget, 0},
		},
		{
			desc: "A conditional jump outside of the program in the true case is a compilation error",
			insns: []Instruction{
				Jump(Jmp|Jeq|K, 0, 1, 0), // if (A == K) jmp nextpc+1
				Stmt(Ret|K, 0),           // return 0
			},
			expectedErr: Error{InvalidJumpTarget, 0},
		},
		{
			desc: "A conditional jump outside of the program in the false case is a compilation error",
			insns: []Instruction{
				Jump(Jmp|Jeq|K, 0, 0, 1), // if (A != K) jmp nextpc+1
				Stmt(Ret|K, 0),           // return 0
			},
			expectedErr: Error{InvalidJumpTarget, 0},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			_, err := Compile(test.insns, false)
			if err != test.expectedErr {
				t.Errorf("expected error %q, got error %q", test.expectedErr, err)
			}
		})
	}
}

func TestExecErrors(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// insns is the BPF instructions to be executed.
		insns []Instruction

		// expectedErr is the expected execution error.
		expectedErr error
	}{
		{
			desc: "An out-of-bounds load of input data is an execution error",
			insns: []Instruction{
				Stmt(Ld|Abs|B, 0), // A = input[0]
				Stmt(Ret|K, 0),    // return 0
			},
			expectedErr: Error{InvalidLoad, 0},
		},
		{
			desc: "Division by zero at runtime is an execution error",
			insns: []Instruction{
				Stmt(Alu|Div|X, 0), // A /= X
				Stmt(Ret|K, 0),     // return 0
			},
			expectedErr: Error{DivisionByZero, 0},
		},
		{
			desc: "Modulo zero at runtime is an execution error",
			insns: []Instruction{
				Stmt(Alu|Mod|X, 0), // A %= X
				Stmt(Ret|K, 0),     // return 0
			},
			expectedErr: Error{DivisionByZero, 0},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			p, err := Compile(test.insns, false)
			if err != nil {
				t.Fatalf("unexpected compilation error: %v", err)
			}
			inp := Input{}
			execution, err := InstrumentedExec[NativeEndian](p, inp)
			if err != test.expectedErr {
				t.Fatalf("expected execution error %q, got (%v, %v)", test.expectedErr, execution, err)
			}
			ret, err := Exec[NativeEndian](p, inp)
			if err != test.expectedErr {
				t.Fatalf("expected execution error %q, got (%d, %v)", test.expectedErr, ret, err)
			}
			optimizedProgram, err := Compile(test.insns, true)
			if err != nil {
				t.Fatalf("unexpected compilation error: %v", err)
			}
			if _, err := InstrumentedExec[NativeEndian](optimizedProgram, inp); err != test.expectedErr {
				t.Fatalf("expected execution error from optimized program %q, got (%v, %v)", test.expectedErr, execution, err)
			}
		})
	}
}

func TestValidInstructions(t *testing.T) {
	want := func(ex ExecutionMetrics) func(insns []Instruction, input []byte) ExecutionMetrics {
		return func(insns []Instruction, input []byte) ExecutionMetrics {
			return ex
		}
	}
	allCoveredNoneReadAndReturns := func(ret uint32) func(insns []Instruction, input []byte) ExecutionMetrics {
		return func(insns []Instruction, input []byte) ExecutionMetrics {
			coverage := make([]bool, len(insns))
			for i := range insns {
				coverage[i] = true
			}
			return ExecutionMetrics{
				Coverage:      coverage,
				InputAccessed: make([]bool, len(input)),
				ReturnValue:   ret,
			}
		}
	}
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// insns is the BPF instructions to be compiled.
		insns []Instruction

		// input is the input data. Note that input will be read as big-endian.
		input Input

		// expected is the expected result of executing the BPF program.
		// It takes in the instructions and input that the test will run.
		expected func(insns []Instruction, input []byte) ExecutionMetrics
	}{
		{
			desc: "Return of immediate",
			insns: []Instruction{
				Stmt(Ret|K, 42), // return 42
			},
			expected: allCoveredNoneReadAndReturns(42),
		},
		{
			desc: "Load of immediate into A",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42), // A = 42
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(42),
		},
		{
			desc: "Load of immediate into X and copying of X into A",
			insns: []Instruction{
				Stmt(Ldx|Imm|W, 42), // X = 42
				Stmt(Misc|Tax, 0),   // A = X
				Stmt(Ret|A, 0),      // return A
			},
			expected: allCoveredNoneReadAndReturns(42),
		},
		{
			desc: "Copying of A into X and back",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42), // A = 42
				Stmt(Misc|Txa, 0),  // X = A
				Stmt(Ld|Imm|W, 0),  // A = 0
				Stmt(Misc|Tax, 0),  // A = X
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(42),
		},
		{
			desc: "Load of 32-bit input by absolute offset into A",
			insns: []Instruction{
				Stmt(Ld|Abs|W, 1), // A = input[1..4]
				Stmt(Ret|A, 0),    // return A
			},
			input: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true},
				InputAccessed: []bool{false, true, true, true, true, false},
				ReturnValue:   hostarch.ByteOrder.Uint32([]byte{0x11, 0x22, 0x33, 0x44}),
			}),
		},
		{
			desc: "Load of 16-bit input by absolute offset into A",
			insns: []Instruction{
				Stmt(Ld|Abs|H, 1), // A = input[1..2]
				Stmt(Ret|A, 0),    // return A
			},
			input: []byte{0x00, 0x11, 0x22, 0x33},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true},
				InputAccessed: []bool{false, true, true, false},
				ReturnValue:   uint32(hostarch.ByteOrder.Uint16([]byte{0x11, 0x22})),
			}),
		},
		{
			desc: "Load of 8-bit input by absolute offset into A",
			insns: []Instruction{
				Stmt(Ld|Abs|B, 1), // A = input[1]
				Stmt(Ret|A, 0),    // return A
			},
			input: []byte{0x00, 0x11, 0x22},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true},
				InputAccessed: []bool{false, true, false},
				ReturnValue:   0x11,
			}),
		},
		{
			desc: "Load of 32-bit input by relative offset into A",
			insns: []Instruction{
				Stmt(Ldx|Imm|W, 1), // X = 1
				Stmt(Ld|Ind|W, 1),  // A = input[X+1..X+4]
				Stmt(Ret|A, 0),     // return A
			},
			input: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true},
				InputAccessed: []bool{false, false, true, true, true, true, false},
				ReturnValue:   hostarch.ByteOrder.Uint32([]byte{0x22, 0x33, 0x44, 0x55}),
			}),
		},
		{
			desc: "Load of 16-bit input by relative offset into A",
			insns: []Instruction{
				Stmt(Ldx|Imm|W, 1), // X = 1
				Stmt(Ld|Ind|H, 1),  // A = input[X+1..X+2]
				Stmt(Ret|A, 0),     // return A
			},
			input: []byte{0x00, 0x11, 0x22, 0x33, 0x44},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true},
				InputAccessed: []bool{false, false, true, true, false},
				ReturnValue:   uint32(hostarch.ByteOrder.Uint16([]byte{0x22, 0x33})),
			}),
		},
		{
			desc: "Load of 8-bit input by relative offset into A",
			insns: []Instruction{
				Stmt(Ldx|Imm|W, 1), // X = 1
				Stmt(Ld|Ind|B, 1),  // A = input[X+1]
				Stmt(Ret|A, 0),     // return A
			},
			input: []byte{0x00, 0x11, 0x22, 0x33},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true},
				InputAccessed: []bool{false, false, true, false},
				ReturnValue:   0x22,
			}),
		},
		{
			desc: "Load/store between A and scratch memory",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42), // A = 42
				Stmt(St, 2),        // M[2] = A
				Stmt(Ld|Imm|W, 0),  // A = 0
				Stmt(Ld|Mem|W, 2),  // A = M[2]
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(42),
		},
		{
			desc: "Load/store between X and scratch memory",
			insns: []Instruction{
				Stmt(Ldx|Imm|W, 42), // X = 42
				Stmt(Stx, 3),        // M[3] = X
				Stmt(Ldx|Imm|W, 0),  // X = 0
				Stmt(Ldx|Mem|W, 3),  // X = M[3]
				Stmt(Misc|Tax, 0),   // A = X
				Stmt(Ret|A, 0),      // return A
			},
			expected: allCoveredNoneReadAndReturns(42),
		},
		{
			desc: "Load of input length into A",
			insns: []Instruction{
				Stmt(Ld|Len|W, 0), // A = len(input)
				Stmt(Ret|A, 0),    // return A
			},
			input:    []byte{1, 2, 3},
			expected: allCoveredNoneReadAndReturns(3),
		},
		{
			desc: "Load of input length into X",
			insns: []Instruction{
				Stmt(Ldx|Len|W, 0), // X = len(input)
				Stmt(Misc|Tax, 0),  // A = X
				Stmt(Ret|A, 0),     // return A
			},
			input:    []byte{1, 2, 3},
			expected: allCoveredNoneReadAndReturns(3),
		},
		{
			desc: "Load of MSH (?) into X",
			insns: []Instruction{
				Stmt(Ldx|Msh|B, 0), // X = 4*(input[0]&0xf)
				Stmt(Misc|Tax, 0),  // A = X
				Stmt(Ret|A, 0),     // return A
			},
			input: []byte{0xf1},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true},
				InputAccessed: []bool{true},
				ReturnValue:   4,
			}),
		},
		{
			desc: "Addition of immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),  // A = 10
				Stmt(Alu|Add|K, 20), // A += 20
				Stmt(Ret|A, 0),      // return A
			},
			expected: allCoveredNoneReadAndReturns(30),
		},
		{
			desc: "Addition of X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),  // A = 10
				Stmt(Ldx|Imm|W, 20), // X = 20
				Stmt(Alu|Add|X, 0),  // A += X
				Stmt(Ret|A, 0),      // return A
			},
			expected: allCoveredNoneReadAndReturns(30),
		},
		{
			desc: "Subtraction of immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 30),  // A = 30
				Stmt(Alu|Sub|K, 20), // A -= 20
				Stmt(Ret|A, 0),      // return A
			},
			expected: allCoveredNoneReadAndReturns(10),
		},
		{
			desc: "Subtraction of X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 30),  // A = 30
				Stmt(Ldx|Imm|W, 20), // X = 20
				Stmt(Alu|Sub|X, 0),  // A -= X
				Stmt(Ret|A, 0),      // return A
			},
			expected: allCoveredNoneReadAndReturns(10),
		},
		{
			desc: "Multiplication of immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 2),  // A = 2
				Stmt(Alu|Mul|K, 3), // A *= 3
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(6),
		},
		{
			desc: "Multiplication of X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 2),  // A = 2
				Stmt(Ldx|Imm|W, 3), // X = 3
				Stmt(Alu|Mul|X, 0), // A *= X
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(6),
		},
		{
			desc: "Division by immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 6),  // A = 6
				Stmt(Alu|Div|K, 3), // A /= 3
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(2),
		},
		{
			desc: "Division by X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 6),  // A = 6
				Stmt(Ldx|Imm|W, 3), // X = 3
				Stmt(Alu|Div|X, 0), // A /= X
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(2),
		},
		{
			desc: "Modulo immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 17), // A = 17
				Stmt(Alu|Mod|K, 7), // A %= 7
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(3),
		},
		{
			desc: "Modulo X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 17), // A = 17
				Stmt(Ldx|Imm|W, 7), // X = 7
				Stmt(Alu|Mod|X, 0), // A %= X
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(3),
		},
		{
			desc: "Arithmetic negation",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 1), // A = 1
				Stmt(Alu|Neg, 0),  // A = -A
				Stmt(Ret|A, 0),    // return A
			},
			expected: allCoveredNoneReadAndReturns(0xffffffff),
		},
		{
			desc: "Bitwise OR with immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xff00aa55), // A = 0xff00aa55
				Stmt(Alu|Or|K, 0xff0055aa), // A |= 0xff0055aa
				Stmt(Ret|A, 0),             // return A
			},
			expected: allCoveredNoneReadAndReturns(0xff00ffff),
		},
		{
			desc: "Bitwise OR with X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Ldx|Imm|W, 0xff0055aa), // X = 0xff0055aa
				Stmt(Alu|Or|X, 0),           // A |= X
				Stmt(Ret|A, 0),              // return A
			},
			expected: allCoveredNoneReadAndReturns(0xff00ffff),
		},
		{
			desc: "Bitwise AND with immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Alu|And|K, 0xff0055aa), // A &= 0xff0055aa
				Stmt(Ret|A, 0),              // return A
			},
			expected: allCoveredNoneReadAndReturns(0xff000000),
		},
		{
			desc: "Bitwise AND with X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Ldx|Imm|W, 0xff0055aa), // X = 0xff0055aa
				Stmt(Alu|And|X, 0),          // A &= X
				Stmt(Ret|A, 0),              // return A
			},
			expected: allCoveredNoneReadAndReturns(0xff000000),
		},
		{
			desc: "Bitwise XOR with immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Alu|Xor|K, 0xff0055aa), // A ^= 0xff0055aa
				Stmt(Ret|A, 0),              // return A
			},
			expected: allCoveredNoneReadAndReturns(0x0000ffff),
		},
		{
			desc: "Bitwise XOR with X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xff00aa55),  // A = 0xff00aa55
				Stmt(Ldx|Imm|W, 0xff0055aa), // X = 0xff0055aa
				Stmt(Alu|Xor|X, 0),          // A ^= X
				Stmt(Ret|A, 0),              // return A
			},
			expected: allCoveredNoneReadAndReturns(0x0000ffff),
		},
		{
			desc: "Left shift by immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 1),  // A = 1
				Stmt(Alu|Lsh|K, 5), // A <<= 5
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(32),
		},
		{
			desc: "Left shift by X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 1),  // A = 1
				Stmt(Ldx|Imm|W, 5), // X = 5
				Stmt(Alu|Lsh|X, 0), // A <<= X
				Stmt(Ret|A, 0),     // return A
			},
			expected: allCoveredNoneReadAndReturns(32),
		},
		{
			desc: "Right shift by immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xffffffff), // A = 0xffffffff
				Stmt(Alu|Rsh|K, 31),        // A >>= 31
				Stmt(Ret|A, 0),             // return A
			},
			expected: allCoveredNoneReadAndReturns(1),
		},
		{
			desc: "Right shift by X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xffffffff), // A = 0xffffffff
				Stmt(Ldx|Imm|W, 31),        // X = 31
				Stmt(Alu|Rsh|X, 0),         // A >>= X
				Stmt(Ret|A, 0),             // return A
			},
			expected: allCoveredNoneReadAndReturns(1),
		},
		{
			desc: "Unconditional jump",
			insns: []Instruction{
				Jump(Jmp|Ja, 1, 0, 0), // jmp nextpc+1
				Stmt(Ret|K, 0),        // return 0
				Stmt(Ret|K, 1),        // return 1
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, false, true},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A == immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),        // A = 42
				Jump(Jmp|Jeq|K, 42, 1, 2), // if (A == 42) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, false, true, false},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A != immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 41),        // A = 41
				Jump(Jmp|Jeq|K, 42, 1, 2), // if (A == 42) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, false, false, true},
				InputAccessed: []bool{},
				ReturnValue:   2,
			}),
		},
		{
			desc: "Jump when A == X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),       // A = 42
				Stmt(Ldx|Imm|W, 42),      // X = 42
				Jump(Jmp|Jeq|X, 0, 1, 2), // if (A == X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, true, false},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A != X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),       // A = 42
				Stmt(Ldx|Imm|W, 41),      // X = 41
				Jump(Jmp|Jeq|X, 0, 1, 2), // if (A == X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, false, true},
				InputAccessed: []bool{},
				ReturnValue:   2,
			}),
		},
		{
			desc: "Jump when A > immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Jump(Jmp|Jgt|K, 9, 1, 2), // if (A > 9) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, false, true, false},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A <= immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),        // A = 10
				Jump(Jmp|Jgt|K, 10, 1, 2), // if (A > 10) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, false, false, true},
				InputAccessed: []bool{},
				ReturnValue:   2,
			}),
		},
		{
			desc: "Jump when A > X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Stmt(Ldx|Imm|W, 9),       // X = 9
				Jump(Jmp|Jgt|X, 0, 1, 2), // if (A > X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, true, false},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A <= X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Stmt(Ldx|Imm|W, 10),      // X = 10
				Jump(Jmp|Jgt|X, 0, 1, 2), // if (A > X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, false, true},
				InputAccessed: []bool{},
				ReturnValue:   2,
			}),
		},
		{
			desc: "Jump when A >= immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),        // A = 10
				Jump(Jmp|Jge|K, 10, 1, 2), // if (A >= 10) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, false, true, false},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A < immediate",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),        // A = 10
				Jump(Jmp|Jge|K, 11, 1, 2), // if (A >= 11) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, false, false, true},
				InputAccessed: []bool{},
				ReturnValue:   2,
			}),
		},
		{
			desc: "Jump when A >= X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Stmt(Ldx|Imm|W, 10),      // X = 10
				Jump(Jmp|Jge|X, 0, 1, 2), // if (A >= X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, true, false},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A < X",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 10),       // A = 10
				Stmt(Ldx|Imm|W, 11),      // X = 11
				Jump(Jmp|Jge|X, 0, 1, 2), // if (A >= X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),           // return 0
				Stmt(Ret|K, 1),           // return 1
				Stmt(Ret|K, 2),           // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, false, true},
				InputAccessed: []bool{},
				ReturnValue:   2,
			}),
		},
		{
			desc: "Jump when A & immediate != 0",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xff),          // A = 0xff
				Jump(Jmp|Jset|K, 0x101, 1, 2), // if (A & 0x101) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),                // return 0
				Stmt(Ret|K, 1),                // return 1
				Stmt(Ret|K, 2),                // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, false, true, false},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A & immediate == 0",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xfe),          // A = 0xfe
				Jump(Jmp|Jset|K, 0x101, 1, 2), // if (A & 0x101) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),                // return 0
				Stmt(Ret|K, 1),                // return 1
				Stmt(Ret|K, 2),                // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, false, false, true},
				InputAccessed: []bool{},
				ReturnValue:   2,
			}),
		},
		{
			desc: "Jump when A & X != 0",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xff),      // A = 0xff
				Stmt(Ldx|Imm|W, 0x101),    // X = 0x101
				Jump(Jmp|Jset|X, 0, 1, 2), // if (A & X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, true, false},
				InputAccessed: []bool{},
				ReturnValue:   1,
			}),
		},
		{
			desc: "Jump when A & X == 0",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 0xfe),      // A = 0xfe
				Stmt(Ldx|Imm|W, 0x101),    // X = 0x101
				Jump(Jmp|Jset|X, 0, 1, 2), // if (A & X) jmp nextpc+1 else jmp nextpc+2
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
				Stmt(Ret|K, 2),            // return 2
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, false, true},
				InputAccessed: []bool{},
				ReturnValue:   2,
			}),
		},
		{
			desc: "Optimizable program",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),        // A = 42
				Jump(Jmp|Jeq|K, 42, 0, 1), // if (A == 42) jmp 0 else 1
				Jump(Jmp|Ja, 1, 0, 0),     // jmp 1
				Jump(Jmp|Ja, 2, 0, 0),     // jmp 2
				Stmt(Ld|Imm|W, 37),        // A = 37
				Stmt(Ret|K, 0),            // return 0
				Stmt(Ret|K, 1),            // return 1
			},
			expected: want(ExecutionMetrics{
				Coverage:      []bool{true, true, true, false, true, true, false},
				InputAccessed: []bool{},
				ReturnValue:   0,
			}),
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			p, err := Compile(test.insns, false)
			if err != nil {
				t.Fatalf("unexpected compilation error: %v", err)
			}
			want := test.expected(test.insns, test.input)
			execution, err := InstrumentedExec[NativeEndian](p, test.input)
			if err != nil {
				t.Fatalf("unexpected execution error: %v", err)
			}
			if !reflect.DeepEqual(execution, want) {
				t.Fatalf("expected %s, got %s", want.String(), execution.String())
			}
			retFast, err := Exec[NativeEndian](p, test.input)
			if err != nil {
				t.Fatalf("unexpected execution error during fast execution: %v", err)
			}
			if retFast != execution.ReturnValue {
				t.Fatalf("instrumented execution returned %d, fast execution returned %d", execution.ReturnValue, retFast)
			}
			optimizedProgram, err := Compile(test.insns, true)
			if err != nil {
				t.Fatalf("unexpected compilation error: %v", err)
			}
			retOptimized, err := InstrumentedExec[NativeEndian](optimizedProgram, test.input)
			if err != nil {
				t.Fatalf("unexpected execution error: %v", err)
			}
			if retOptimized.ReturnValue != retFast {
				t.Fatalf("expected return value from optimized version: got %d, non-optimized execution returned %d", retOptimized.ReturnValue, retFast)
			}
			if !slices.Equal(retOptimized.InputAccessed, execution.InputAccessed) {
				t.Fatalf("expected input read coverage from optimized version: got %s, non-optimized execution was %s", retOptimized.String(), execution.String())
			}
		})
	}
}

// Seccomp filter example given in Linux's
// Documentation/networking/filter.txt, translated to bytecode using the
// Linux kernel tree's tools/net/bpf_asm.
var sampleFilter = []Instruction{
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

func TestSimpleFilter(t *testing.T) {
	p, err := Compile(sampleFilter, false)
	if err != nil {
		t.Fatalf("Unexpected compilation error: %v", err)
	}

	// linux.SeccompData is 64 bytes long.
	// The first 4 bytes is the syscall number.
	// The next 4 bytes is the architecture.
	// The last 56 bytes are the instruction pointer and the syscall arguments,
	// which this sample program never accesses.
	noRIPOrSyscallArgsAccess := make([]bool, 56)

	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// SeccompData is the input data.
		data linux.SeccompData

		// expected is the expected execution result of the BPF program.
		expected ExecutionMetrics
	}{
		{
			desc: "Invalid arch is rejected",
			data: linux.SeccompData{Nr: 1 /* x86 exit */, Arch: 0x40000003 /* AUDIT_ARCH_I386 */},
			expected: ExecutionMetrics{
				ReturnValue: 0,
				Coverage: []bool{
					true,  // ld [4]                  /* offsetof(struct seccomp_data, arch) */
					true,  // jne #0xc000003e, bad    /* AUDIT_ARCH_X86_64 */
					false, // ld [0]                  /* offsetof(struct seccomp_data, nr) */
					false, // jeq #15, good           /* __NR_rt_sigreturn */
					false, // jeq #231, good          /* __NR_exit_group */
					false, // jeq #60, good           /* __NR_exit */
					false, // jeq #0, good            /* __NR_read */
					false, // jeq #1, good            /* __NR_write */
					false, // jeq #5, good            /* __NR_fstat */
					false, // jeq #9, good            /* __NR_mmap */
					false, // jeq #14, good           /* __NR_rt_sigprocmask */
					false, // jeq #13, good           /* __NR_rt_sigaction */
					false, // jeq #35, good           /* __NR_nanosleep */
					true,  // bad: ret #0             /* SECCOMP_RET_KILL */
					false, // good: ret #0x7fff0000   /* SECCOMP_RET_ALLOW */
				},
				InputAccessed: append(
					[]bool{
						false, false, false, false, // Syscall number
						true, true, true, true, // Architecture
					},
					noRIPOrSyscallArgsAccess...),
			},
		},
		{
			desc: "Disallowed syscall is rejected",
			data: linux.SeccompData{Nr: 105 /* __NR_setuid */, Arch: 0xc000003e},
			expected: ExecutionMetrics{
				ReturnValue: 0,
				Coverage: []bool{
					true,  // ld [4]                  /* offsetof(struct seccomp_data, arch) */
					true,  // jne #0xc000003e, bad    /* AUDIT_ARCH_X86_64 */
					true,  // ld [0]                  /* offsetof(struct seccomp_data, nr) */
					true,  // jeq #15, good           /* __NR_rt_sigreturn */
					true,  // jeq #231, good          /* __NR_exit_group */
					true,  // jeq #60, good           /* __NR_exit */
					true,  // jeq #0, good            /* __NR_read */
					true,  // jeq #1, good            /* __NR_write */
					true,  // jeq #5, good            /* __NR_fstat */
					true,  // jeq #9, good            /* __NR_mmap */
					true,  // jeq #14, good           /* __NR_rt_sigprocmask */
					true,  // jeq #13, good           /* __NR_rt_sigaction */
					true,  // jeq #35, good           /* __NR_nanosleep */
					true,  // bad: ret #0             /* SECCOMP_RET_KILL */
					false, // good: ret #0x7fff0000   /* SECCOMP_RET_ALLOW */
				},
				InputAccessed: append(
					[]bool{
						true, true, true, true, // Syscall number
						true, true, true, true, // Architecture
					},
					noRIPOrSyscallArgsAccess...),
			},
		},
		{
			desc: "Allowed syscall is indeed allowed",
			data: linux.SeccompData{Nr: 231 /* __NR_exit_group */, Arch: 0xc000003e},
			expected: ExecutionMetrics{
				ReturnValue: 0x7fff0000, /* SECCOMP_RET_ALLOW */
				Coverage: []bool{
					true,  // ld [4]                  /* offsetof(struct seccomp_data, arch) */
					true,  // jne #0xc000003e, bad    /* AUDIT_ARCH_X86_64 */
					true,  // ld [0]                  /* offsetof(struct seccomp_data, nr) */
					true,  // jeq #15, good           /* __NR_rt_sigreturn */
					true,  // jeq #231, good          /* __NR_exit_group */
					false, // jeq #60, good           /* __NR_exit */
					false, // jeq #0, good            /* __NR_read */
					false, // jeq #1, good            /* __NR_write */
					false, // jeq #5, good            /* __NR_fstat */
					false, // jeq #9, good            /* __NR_mmap */
					false, // jeq #14, good           /* __NR_rt_sigprocmask */
					false, // jeq #13, good           /* __NR_rt_sigaction */
					false, // jeq #35, good           /* __NR_nanosleep */
					false, // bad: ret #0             /* SECCOMP_RET_KILL */
					true,  // good: ret #0x7fff0000   /* SECCOMP_RET_ALLOW */
				},
				InputAccessed: append(
					[]bool{
						true, true, true, true, // Syscall number
						true, true, true, true, // Architecture
					},
					noRIPOrSyscallArgsAccess...),
			},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			execution, err := InstrumentedExec[NativeEndian](p, dataAsInput(&test.data))
			if err != nil {
				t.Fatalf("expected return value of %d, got execution error: %v", test.expected.ReturnValue, err)
			}
			if !reflect.DeepEqual(execution, test.expected) {
				t.Errorf("expected %s, got %s", test.expected.String(), execution.String())
			}
		})
	}
}

// asInput converts a seccompData to a bpf.Input.
func dataAsInput(data *linux.SeccompData) Input {
	return marshal.Marshal(data)
}

// BenchmarkInterpreter benchmarks the execution of the sample filter
// for a sample syscall.
func BenchmarkInterpreter(b *testing.B) {
	p, err := Compile(sampleFilter, true)
	if err != nil {
		b.Fatalf("Unexpected compilation error: %v", err)
	}
	data := dataAsInput(&linux.SeccompData{Nr: 231 /* __NR_exit_group */, Arch: 0xc000003e})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Exec[NativeEndian](p, data); err != nil {
			b.Fatalf("Unexpected execution error: %v", err)
		}
	}
}

func BenchmarkInstrumentedInterpreter(b *testing.B) {
	p, err := Compile(sampleFilter, true)
	if err != nil {
		b.Fatalf("Unexpected compilation error: %v", err)
	}
	data := dataAsInput(&linux.SeccompData{Nr: 231 /* __NR_exit_group */, Arch: 0xc000003e})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := InstrumentedExec[NativeEndian](p, data); err != nil {
			b.Fatalf("Unexpected execution error: %v", err)
		}
	}
}
