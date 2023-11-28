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
	"testing"
)

func TestEqual(t *testing.T) {
	for _, test := range []struct {
		name string
		a, b Instruction
		want bool
	}{
		{
			name: "empty instructions",
			want: true,
		},
		{
			name: "two different invalid instructions",
			a: Instruction{
				OpCode: 0xffff,
			},
			b: Instruction{
				OpCode: 0xfffe,
			},
			want: false,
		},
		{
			name: "two loads from different offsets",
			a: Instruction{
				OpCode: Ld | Imm | W,
				K:      1234,
			},
			b: Instruction{
				OpCode: Ld | Imm | W,
				K:      5678,
			},
			want: false,
		},
		{
			name: "two loads from same offsets but different source",
			a: Instruction{
				OpCode: Ld | Mem | W,
				K:      1234,
			},
			b: Instruction{
				OpCode: Ld | Imm | W,
				K:      1234,
			},
			want: false,
		},
		{
			name: "two loads from same offsets but different conditional jump fields",
			a: Instruction{
				OpCode:     Ld | Mem | W,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode: Ld | Mem | W,
				K:      1234,
			},
			want: true,
		},
		{
			name: "two length loads",
			a: Instruction{
				OpCode:     Ld | Len | W,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode:     Ld | Len | W,
				K:          5678,
				JumpIfTrue: 99,
			},
			want: true,
		},
		{
			name: "two length loads in different registers",
			a: Instruction{
				OpCode:     Ld | Len | W,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode:     Ldx | Len | W,
				K:          1234,
				JumpIfTrue: 12,
			},
			want: false,
		},
		{
			name: "two stores at different offsets",
			a: Instruction{
				OpCode: St,
				K:      1234,
			},
			b: Instruction{
				OpCode: St,
				K:      5678,
			},
			want: false,
		},
		{
			name: "two stores at same offsets but different source",
			a: Instruction{
				OpCode: St,
				K:      1234,
			},
			b: Instruction{
				OpCode: Stx,
				K:      1234,
			},
			want: false,
		},
		{
			name: "two stores at same offsets but different conditional jump fields",
			a: Instruction{
				OpCode:     St,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode: St,
				K:      1234,
			},
			want: true,
		},
		{
			name: "two negation ALUs with different other fields",
			a: Instruction{
				OpCode:     Alu | Neg,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode:     Alu | Neg,
				K:          5678,
				JumpIfTrue: 34,
			},
			want: true,
		},
		{
			name: "two 'add K' ALUs with different K",
			a: Instruction{
				OpCode:     Alu | Add | K,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode:     Alu | Add | K,
				K:          5678,
				JumpIfTrue: 34,
			},
			want: false,
		},
		{
			name: "two 'add X' ALUs with different K",
			a: Instruction{
				OpCode:     Alu | Add | X,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode:     Alu | Add | X,
				K:          5678,
				JumpIfTrue: 34,
			},
			want: true,
		},
		{
			name: "two 'return A' instructions with different K",
			a: Instruction{
				OpCode:     Ret | A,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode:     Ret | A,
				K:          5678,
				JumpIfTrue: 34,
			},
			want: true,
		},
		{
			name: "two 'return K' instructions with same K",
			a: Instruction{
				OpCode:     Ret | K,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode:     Ret | K,
				K:          1234,
				JumpIfTrue: 34,
			},
			want: true,
		},
		{
			name: "two 'return K' instructions with different K",
			a: Instruction{
				OpCode: Ret | K,
				K:      1234,
			},
			b: Instruction{
				OpCode: Ret | K,
				K:      5678,
			},
			want: false,
		},
		{
			name: "two unconditional jumps with different K",
			a: Instruction{
				OpCode: Jmp | Ja,
				K:      1234,
			},
			b: Instruction{
				OpCode: Jmp | Ja,
				K:      5678,
			},
			want: false,
		},
		{
			name: "two unconditional jumps with same K",
			a: Instruction{
				OpCode:     Jmp | Ja,
				K:          1234,
				JumpIfTrue: 12,
			},
			b: Instruction{
				OpCode:     Jmp | Ja,
				K:          1234,
				JumpIfTrue: 34,
			},
			want: true,
		},
		{
			name: "two conditional jumps using K with same K",
			a: Instruction{
				OpCode:      Jmp | Jgt | K,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			b: Instruction{
				OpCode:      Jmp | Jgt | K,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			want: true,
		},
		{
			name: "two conditional jumps using K with different K",
			a: Instruction{
				OpCode:      Jmp | Jgt | K,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			b: Instruction{
				OpCode:      Jmp | Jgt | K,
				K:           5678,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			want: false,
		},
		{
			name: "two conditional jumps using X with different K",
			a: Instruction{
				OpCode:      Jmp | Jgt | X,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			b: Instruction{
				OpCode:      Jmp | Jgt | X,
				K:           5678,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			want: true,
		},
		{
			name: "two conditional jumps with different 'true' jump target",
			a: Instruction{
				OpCode:      Jmp | Jgt | X,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			b: Instruction{
				OpCode:      Jmp | Jgt | X,
				K:           1234,
				JumpIfTrue:  99,
				JumpIfFalse: 21,
			},
			want: false,
		},
		{
			name: "two conditional jumps with different 'false' jump target",
			a: Instruction{
				OpCode:      Jmp | Jgt | X,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			b: Instruction{
				OpCode:      Jmp | Jgt | X,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 99,
			},
			want: false,
		},
		{
			name: "two txa instructions",
			a: Instruction{
				OpCode:      Misc | Txa,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			b: Instruction{
				OpCode:      Misc | Txa,
				K:           5678,
				JumpIfTrue:  34,
				JumpIfFalse: 42,
			},
			want: true,
		},
		{
			name: "two tax instructions",
			a: Instruction{
				OpCode:      Misc | Tax,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			b: Instruction{
				OpCode:      Misc | Tax,
				K:           5678,
				JumpIfTrue:  34,
				JumpIfFalse: 42,
			},
			want: true,
		},
		{
			name: "two different misc instructions",
			a: Instruction{
				OpCode:      Misc | Txa,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			b: Instruction{
				OpCode:      Misc | Tax,
				K:           1234,
				JumpIfTrue:  12,
				JumpIfFalse: 21,
			},
			want: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			as := test.a.String()
			bs := test.b.String()
			got := test.a.Equal(test.b)
			if got != test.want {
				t.Errorf("%v.Equal(%v) = %v, want %v", as, bs, got, test.want)
			}
			if reverse := test.b.Equal(test.a); reverse != got {
				t.Errorf("%v.Equal(%v) [%v] != %v.Equal(%v) [%v]", as, bs, got, bs, as, reverse)
			}
			if !t.Failed() && !got && test.a == test.b {
				t.Errorf("%v == %v, yet %v.Equal(%v) is false", as, bs, as, bs)
			}
		})
	}
}
