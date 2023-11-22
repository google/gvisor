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
	"reflect"
	"strings"
	"testing"
)

func prettyInstructions(insns []Instruction) string {
	if len(insns) == 0 {
		return "[no instructions]"
	}
	if len(insns) == 1 {
		return insns[0].String()
	}
	var sb strings.Builder
	sb.WriteString("{\n")
	for _, ins := range insns {
		sb.WriteString("  ")
		sb.WriteString(ins.String())
		sb.WriteRune('\n')
	}
	sb.WriteRune('}')
	return sb.String()
}

func TestOptimize(t *testing.T) {
	for _, test := range []struct {
		name       string
		optimizers []optimizerFunc // If unset, use all optimizers
		insns      []Instruction
		want       []Instruction
	}{
		{
			name: "trivial program",
			insns: []Instruction{
				Stmt(Ret|K, 0),
			},
			want: []Instruction{
				Stmt(Ret|K, 0),
			},
		},
		{
			name:       "conditional jump",
			optimizers: []optimizerFunc{optimizeConditionalJumps},
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Ja, 2, 0, 0),
				Jump(Jmp|Ja, 0, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
			},
			want: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 3, 2),
				Jump(Jmp|Ja, 2, 0, 0),
				Jump(Jmp|Ja, 0, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
			},
		},
		{
			name: "same final target jump",
			optimizers: []optimizerFunc{
				optimizeConditionalJumps,
				optimizeSameTargetConditionalJumps,
			},
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Ja, 1, 0, 0),
				Jump(Jmp|Ja, 0, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
			},
			want: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Ja, 2, 0, 0),
				Jump(Jmp|Ja, 1, 0, 0),
				Jump(Jmp|Ja, 0, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
			},
		},
		{
			name: "dead code removed",
			optimizers: []optimizerFunc{
				optimizeConditionalJumps,
				optimizeSameTargetConditionalJumps,
				removeDeadCode,
			},
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Ja, 1, 0, 0),
				Jump(Jmp|Ja, 0, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
			},
			want: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Ja, 0, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
			},
		},
		{
			name: "zero-instructions jumps removed",
			optimizers: []optimizerFunc{
				optimizeConditionalJumps,
				optimizeSameTargetConditionalJumps,
				removeZeroInstructionJumps,
				removeDeadCode,
			},
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Ja, 1, 0, 0),
				Jump(Jmp|Ja, 0, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
			},
			want: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
			},
		},
		{
			name: "jumps to return",
			optimizers: []optimizerFunc{
				optimizeJumpsToReturn,
			},
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Ja, 1, 0, 0),
				Jump(Jmp|Ja, 2, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
				Stmt(Ret|K, 1),
			},
			want: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Ja, 1, 0, 0),
				Stmt(Ret|K, 1),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
				Stmt(Ret|K, 1),
			},
		},
		{
			name: "jumps to smallest set of return",
			optimizers: []optimizerFunc{
				removeDeadCode,
				optimizeJumpsToSmallestSetOfReturns,
			},
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Stmt(Ret|K, 7),
				Jump(Jmp|Jeq|K, 43, 0, 1),
				Stmt(Ret|K, 7),
				Jump(Jmp|Jeq|K, 44, 0, 1),
				Stmt(Ret|K, 7),
				Jump(Jmp|Jeq|K, 45, 0, 1),
				Stmt(Ret|K, 7),
				Jump(Jmp|Jeq|K, 46, 0, 1),
				Stmt(Ret|K, 7),
				Jump(Jmp|Jeq|K, 47, 0, 1),
				Stmt(Ret|K, 7),
				Stmt(Ret|K, 3),
			},
			want: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 5, 0),
				Jump(Jmp|Jeq|K, 43, 4, 0),
				Jump(Jmp|Jeq|K, 44, 3, 0),
				Jump(Jmp|Jeq|K, 45, 2, 0),
				Jump(Jmp|Jeq|K, 46, 1, 0),
				Jump(Jmp|Jeq|K, 47, 0, 1),
				Stmt(Ret|K, 7),
				Stmt(Ret|K, 3),
			},
		},
		{
			name: "jumps to smallest set of return but keep fallthrough return statements",
			optimizers: []optimizerFunc{
				removeDeadCode,
				optimizeJumpsToSmallestSetOfReturns,
			},
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Jeq|K, 42, 1, 2),
				Stmt(Ld|Imm|W, 43),
				Stmt(Ret|K, 7),
				Jump(Jmp|Jeq|K, 43, 0, 1),
				Stmt(Ret|K, 7),
				Jump(Jmp|Jeq|K, 44, 0, 1),
				Stmt(Ret|K, 7),
				Stmt(Ret|K, 3),
			},
			want: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Jeq|K, 42, 1, 2),
				Stmt(Ld|Imm|W, 43),
				Stmt(Ret|K, 7),
				Jump(Jmp|Jeq|K, 43, 1, 0),
				Jump(Jmp|Jeq|K, 44, 0, 1),
				Stmt(Ret|K, 7),
				Stmt(Ret|K, 3),
			},
		},
		{
			name: "all optimizations",
			insns: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 1),
				Jump(Jmp|Ja, 1, 0, 0),
				Jump(Jmp|Ja, 2, 0, 0),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
				Stmt(Ret|K, 1),
			},
			want: []Instruction{
				Stmt(Ld|Imm|W, 42),
				Jump(Jmp|Jeq|K, 42, 0, 2),
				Stmt(Ld|Imm|W, 37),
				Stmt(Ret|K, 0),
				Stmt(Ret|K, 1),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			optimizedInsns := make([]Instruction, len(test.insns))
			copy(optimizedInsns, test.insns)
			if len(test.optimizers) > 0 {
				optimizedInsns = optimize(optimizedInsns, test.optimizers)
			} else {
				optimizedInsns = Optimize(optimizedInsns)
			}
			if !reflect.DeepEqual(optimizedInsns, test.want) {
				t.Errorf("got optimized instructions:\n%v\nwant:\n%v\n", prettyInstructions(optimizedInsns), prettyInstructions(test.want))
			}
		})
	}
}
