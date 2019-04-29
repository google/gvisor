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

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

func TestDecode(t *testing.T) {
	for _, test := range []struct {
		filter   linux.BPFInstruction
		expected string
		fail     bool
	}{
		{filter: Stmt(Ld+Imm, 10), expected: "A <- 10"},
		{filter: Stmt(Ld+Abs+W, 10), expected: "A <- P[10:4]"},
		{filter: Stmt(Ld+Ind+H, 10), expected: "A <- P[X+10:2]"},
		{filter: Stmt(Ld+Ind+B, 10), expected: "A <- P[X+10:1]"},
		{filter: Stmt(Ld+Mem, 10), expected: "A <- M[10]"},
		{filter: Stmt(Ld+Len, 0), expected: "A <- len"},
		{filter: Stmt(Ldx+Imm, 10), expected: "X <- 10"},
		{filter: Stmt(Ldx+Mem, 10), expected: "X <- M[10]"},
		{filter: Stmt(Ldx+Len, 0), expected: "X <- len"},
		{filter: Stmt(Ldx+Msh, 10), expected: "X <- 4*(P[10:1]&0xf)"},
		{filter: Stmt(St, 10), expected: "M[10] <- A"},
		{filter: Stmt(Stx, 10), expected: "M[10] <- X"},
		{filter: Stmt(Alu+Add+K, 10), expected: "A <- A + 10"},
		{filter: Stmt(Alu+Sub+K, 10), expected: "A <- A - 10"},
		{filter: Stmt(Alu+Mul+K, 10), expected: "A <- A * 10"},
		{filter: Stmt(Alu+Div+K, 10), expected: "A <- A / 10"},
		{filter: Stmt(Alu+Or+K, 10), expected: "A <- A | 10"},
		{filter: Stmt(Alu+And+K, 10), expected: "A <- A & 10"},
		{filter: Stmt(Alu+Lsh+K, 10), expected: "A <- A << 10"},
		{filter: Stmt(Alu+Rsh+K, 10), expected: "A <- A >> 10"},
		{filter: Stmt(Alu+Mod+K, 10), expected: "A <- A % 10"},
		{filter: Stmt(Alu+Xor+K, 10), expected: "A <- A ^ 10"},
		{filter: Stmt(Alu+Add+X, 0), expected: "A <- A + X"},
		{filter: Stmt(Alu+Sub+X, 0), expected: "A <- A - X"},
		{filter: Stmt(Alu+Mul+X, 0), expected: "A <- A * X"},
		{filter: Stmt(Alu+Div+X, 0), expected: "A <- A / X"},
		{filter: Stmt(Alu+Or+X, 0), expected: "A <- A | X"},
		{filter: Stmt(Alu+And+X, 0), expected: "A <- A & X"},
		{filter: Stmt(Alu+Lsh+X, 0), expected: "A <- A << X"},
		{filter: Stmt(Alu+Rsh+X, 0), expected: "A <- A >> X"},
		{filter: Stmt(Alu+Mod+X, 0), expected: "A <- A % X"},
		{filter: Stmt(Alu+Xor+X, 0), expected: "A <- A ^ X"},
		{filter: Stmt(Alu+Neg, 0), expected: "A <- -A"},
		{filter: Stmt(Jmp+Ja, 10), expected: "pc += 10"},
		{filter: Jump(Jmp+Jeq+K, 10, 2, 5), expected: "pc += (A == 10) ? 2 : 5"},
		{filter: Jump(Jmp+Jgt+K, 10, 2, 5), expected: "pc += (A > 10) ? 2 : 5"},
		{filter: Jump(Jmp+Jge+K, 10, 2, 5), expected: "pc += (A >= 10) ? 2 : 5"},
		{filter: Jump(Jmp+Jset+K, 10, 2, 5), expected: "pc += (A & 10) ? 2 : 5"},
		{filter: Jump(Jmp+Jeq+X, 0, 2, 5), expected: "pc += (A == X) ? 2 : 5"},
		{filter: Jump(Jmp+Jgt+X, 0, 2, 5), expected: "pc += (A > X) ? 2 : 5"},
		{filter: Jump(Jmp+Jge+X, 0, 2, 5), expected: "pc += (A >= X) ? 2 : 5"},
		{filter: Jump(Jmp+Jset+X, 0, 2, 5), expected: "pc += (A & X) ? 2 : 5"},
		{filter: Stmt(Ret+K, 10), expected: "ret 10"},
		{filter: Stmt(Ret+A, 0), expected: "ret A"},
		{filter: Stmt(Misc+Tax, 0), expected: "X <- A"},
		{filter: Stmt(Misc+Txa, 0), expected: "A <- X"},
		{filter: Stmt(Ld+Ind+Msh, 0), fail: true},
	} {
		got, err := Decode(test.filter)
		if test.fail {
			if err == nil {
				t.Errorf("Decode(%v) failed, expected: 'error', got: %q", test.filter, got)
				continue
			}
		} else {
			if err != nil {
				t.Errorf("Decode(%v) failed for test %q, error: %q", test.filter, test.expected, err)
				continue
			}
			if got != test.expected {
				t.Errorf("Decode(%v) failed, expected: %q, got: %q", test.filter, test.expected, got)
				continue
			}
		}
	}
}

func TestDecodeProgram(t *testing.T) {
	for _, test := range []struct {
		name     string
		program  []linux.BPFInstruction
		expected string
		fail     bool
	}{
		{name: "basic with jump indexes",
			program: []linux.BPFInstruction{
				Stmt(Ld+Abs+W, 10),
				Stmt(Ldx+Mem, 10),
				Stmt(St, 10),
				Stmt(Stx, 10),
				Stmt(Alu+Add+K, 10),
				Stmt(Jmp+Ja, 10),
				Jump(Jmp+Jeq+K, 10, 2, 5),
				Jump(Jmp+Jset+X, 0, 0, 5),
				Stmt(Misc+Tax, 0),
			},
			expected: "0: A <- P[10:4]\n" +
				"1: X <- M[10]\n" +
				"2: M[10] <- A\n" +
				"3: M[10] <- X\n" +
				"4: A <- A + 10\n" +
				"5: pc += 10 [16]\n" +
				"6: pc += (A == 10) ? 2 [9] : 5 [12]\n" +
				"7: pc += (A & X) ? 0 [8] : 5 [13]\n" +
				"8: X <- A\n",
		},
		{name: "invalid instruction",
			program: []linux.BPFInstruction{Stmt(Ld+Abs+W, 10), Stmt(Ld+Len+Mem, 0)},
			fail:    true},
	} {
		got, err := DecodeProgram(test.program)
		if test.fail {
			if err == nil {
				t.Errorf("%s: Decode(...) failed, expected: 'error', got: %q", test.name, got)
				continue
			}
		} else {
			if err != nil {
				t.Errorf("%s: Decode failed: %v", test.name, err)
				continue
			}
			if got != test.expected {
				t.Errorf("%s: Decode(...) failed, expected: %q, got: %q", test.name, test.expected, got)
				continue
			}
		}
	}
}
