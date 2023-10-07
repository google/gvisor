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
	"fmt"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

func validate(p *ProgramBuilder, expected []Instruction) error {
	instructions, err := p.Instructions()
	if err != nil {
		return fmt.Errorf("Instructions() failed: %v", err)
	}
	got, err := DecodeInstructions(instructions)
	if err != nil {
		return fmt.Errorf("DecodeInstructions('instructions') failed: %v", err)
	}
	expectedDecoded, err := DecodeInstructions(expected)
	if err != nil {
		return fmt.Errorf("DecodeInstructions('expected') failed: %v", err)
	}
	if got != expectedDecoded {
		return fmt.Errorf("DecodeInstructions() failed, expected: %q, got: %q", expectedDecoded, got)
	}
	return nil
}

func TestProgramBuilderSimple(t *testing.T) {
	p := NewProgramBuilder()
	p.AddStmt(Ld+Abs+W, 10)
	p.AddJump(Jmp+Ja, 10, 0, 0)

	expected := []Instruction{
		Stmt(Ld+Abs+W, 10),
		Jump(Jmp+Ja, 10, 0, 0),
	}

	if err := validate(p, expected); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

func TestProgramBuilderLabels(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJumpTrueLabel(Jmp+Jeq+K, 11, "label_1", 0)
	p.AddJumpFalseLabel(Jmp+Jeq+K, 12, 0, "label_2")
	p.AddJumpLabels(Jmp+Jeq+K, 13, "label_3", "label_4")
	if err := p.AddLabel("label_1"); err != nil {
		t.Errorf("AddLabel(label_1) failed: %v", err)
	}
	p.AddStmt(Ld+Abs+W, 1)
	if err := p.AddLabel("label_3"); err != nil {
		t.Errorf("AddLabel(label_3) failed: %v", err)
	}
	p.AddJumpLabels(Jmp+Jeq+K, 14, "label_4", "label_5")
	if err := p.AddLabel("label_2"); err != nil {
		t.Errorf("AddLabel(label_2) failed: %v", err)
	}
	p.AddJumpLabels(Jmp+Jeq+K, 15, "label_4", "label_6")
	if err := p.AddLabel("label_4"); err != nil {
		t.Errorf("AddLabel(label_4) failed: %v", err)
	}
	p.AddStmt(Ld+Abs+W, 4)
	if err := p.AddLabel("label_5"); err != nil {
		t.Errorf("AddLabel(label_5) failed: %v", err)
	}
	if err := p.AddLabel("label_6"); err != nil {
		t.Errorf("AddLabel(label_6) failed: %v", err)
	}
	p.AddStmt(Ld+Abs+W, 5)

	expected := []Instruction{
		Jump(Jmp+Jeq+K, 11, 2, 0),
		Jump(Jmp+Jeq+K, 12, 0, 3),
		Jump(Jmp+Jeq+K, 13, 1, 3),
		Stmt(Ld+Abs+W, 1),
		Jump(Jmp+Jeq+K, 14, 1, 2),
		Jump(Jmp+Jeq+K, 15, 0, 1),
		Stmt(Ld+Abs+W, 4),
		Stmt(Ld+Abs+W, 5),
	}
	if err := validate(p, expected); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
	// Calling validate()=>p.Instructions() again to make sure
	// Instructions can be called multiple times without ruining
	// the program.
	if err := validate(p, expected); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

func TestProgramBuilderMissingErrorTarget(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJumpTrueLabel(Jmp+Jeq+K, 10, "label_1", 0)
	if _, err := p.Instructions(); err == nil {
		t.Errorf("Instructions() should have failed")
	}
}

func TestProgramBuilderLabelWithNoInstruction(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJumpTrueLabel(Jmp+Jeq+K, 10, "label_1", 0)
	if err := p.AddLabel("label_1"); err != nil {
		t.Errorf("AddLabel(label_1) failed: %v", err)
	}
	if _, err := p.Instructions(); err == nil {
		t.Errorf("Instructions() should have failed")
	}
}

// TestProgramBuilderUnusedLabel tests that adding an unused label doesn't
// cause program generation to fail.
func TestProgramBuilderUnusedLabel(t *testing.T) {
	p := NewProgramBuilder()
	p.AddStmt(Ld+Abs+W, 10)
	p.AddJump(Jmp+Ja, 10, 0, 0)

	expected := []Instruction{
		Stmt(Ld+Abs+W, 10),
		Jump(Jmp+Ja, 10, 0, 0),
	}

	if err := p.AddLabel("unused"); err != nil {
		t.Errorf("AddLabel(unused) should have succeeded")
	}

	if err := validate(p, expected); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

// TestProgramBuilderBackwardsReference tests that including a backwards
// reference to a label in a program causes a failure.
func TestProgramBuilderBackwardsReference(t *testing.T) {
	p := NewProgramBuilder()
	if err := p.AddLabel("bw_label"); err != nil {
		t.Errorf("failed to add label")
	}
	p.AddStmt(Ld+Abs+W, 10)
	p.AddJumpTrueLabel(Jmp+Jeq+K, 10, "bw_label", 0)
	if _, err := p.Instructions(); err == nil {
		t.Errorf("Instructions() should have failed")
	}
}

func TestProgramBuilderLabelAddedTwice(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJumpTrueLabel(Jmp+Jeq+K, 10, "label_1", 0)
	if err := p.AddLabel("label_1"); err != nil {
		t.Errorf("AddLabel(label_1) failed: %v", err)
	}
	p.AddStmt(Ld+Abs+W, 0)
	if err := p.AddLabel("label_1"); err == nil {
		t.Errorf("AddLabel(label_1) failed: %v", err)
	}
}

func TestProgramBuilderJumpBackwards(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJumpTrueLabel(Jmp+Jeq+K, 10, "label_1", 0)
	if err := p.AddLabel("label_1"); err != nil {
		t.Errorf("AddLabel(label_1) failed: %v", err)
	}
	p.AddStmt(Ld+Abs+W, 0)
	p.AddJumpTrueLabel(Jmp+Jeq+K, 10, "label_1", 0)
	if _, err := p.Instructions(); err == nil {
		t.Errorf("Instructions() should have failed")
	}
}

func TestProgramBuilderOutcomes(t *testing.T) {
	p := NewProgramBuilder()
	getOverallFragment := p.Record()
	fixup := func(f FragmentOutcomes) FragmentOutcomes {
		if f.MayJumpToUnresolvedLabels == nil {
			f.MayJumpToUnresolvedLabels = map[string]struct{}{}
		}
		if f.MayReturnImmediate == nil {
			f.MayReturnImmediate = map[linux.BPFAction]struct{}{}
		}
		return f
	}
	for _, test := range []struct {
		// Name of the sub-test.
		name string

		// Function that adds statements to `p`.
		build func()

		// Expected outcomes from recording the instructions added
		// by `build` alone.
		wantLocal FragmentOutcomes

		// Expected value of calling `MayReturn` on the local fragment.
		wantLocalMayReturn bool

		// Expected outcomes from recording the instructions added
		// to the program since the test began.
		wantOverall FragmentOutcomes
	}{
		{
			name:        "empty program",
			build:       func() {},
			wantLocal:   FragmentOutcomes{MayFallThrough: true},
			wantOverall: FragmentOutcomes{MayFallThrough: true},
		},
		{
			name: "simple instruction",
			build: func() {
				p.AddStmt(Ld|Abs|W, 10)
			},
			wantLocal:   FragmentOutcomes{MayFallThrough: true},
			wantOverall: FragmentOutcomes{MayFallThrough: true},
		},
		{
			name: "jump to unresolved label",
			build: func() {
				p.AddDirectJumpLabel("label1")
			},
			wantLocal: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"label1": struct{}{},
				},
			},
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"label1": struct{}{},
				},
			},
		},
		{
			name: "another simple load so may fall through again",
			build: func() {
				p.AddStmt(Ld|Abs|W, 10)
			},
			wantLocal: FragmentOutcomes{
				MayFallThrough: true,
			},
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"label1": struct{}{},
				},
				MayFallThrough: true,
			},
		},
		{
			name: "resolve label1",
			build: func() {
				p.AddLabel("label1")
			},
			wantLocal: FragmentOutcomes{
				MayFallThrough: true,
			},
			wantOverall: FragmentOutcomes{
				MayFallThrough: true,
			},
		},
		{
			name: "populate instruction at label1",
			build: func() {
				p.AddStmt(Ld|Abs|W, 10)
			},
			wantLocal: FragmentOutcomes{
				MayFallThrough: true,
			},
			wantOverall: FragmentOutcomes{
				MayFallThrough: true,
			},
		},
		{
			name: "conditional jump to two unresolved labels",
			build: func() {
				p.AddJumpLabels(Jmp|Jeq|K, 1337, "truelabel", "falselabel")
			},
			wantLocal: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"truelabel":  struct{}{},
					"falselabel": struct{}{},
				},
			},
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"truelabel":  struct{}{},
					"falselabel": struct{}{},
				},
			},
		},
		{
			name: "resolve truelabel only",
			build: func() {
				p.AddLabel("truelabel")
			},
			wantLocal: FragmentOutcomes{
				MayFallThrough: true,
			},
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayFallThrough: true,
			},
		},
		{
			name: "jump one beyond end of program",
			build: func() {
				p.AddJump(Jmp|Ja, 1, 0, 0)
			},
			wantLocal: FragmentOutcomes{
				MayJumpToKnownOffsetBeyondFragment: true,
			},
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayJumpToKnownOffsetBeyondFragment: true,
			},
		},
		{
			name: "add immediate return",
			build: func() {
				p.AddStmt(Ret|K, 1337)
			},
			wantLocal: FragmentOutcomes{
				MayReturnImmediate: map[linux.BPFAction]struct{}{
					1337: struct{}{},
				},
			},
			wantLocalMayReturn: true,
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayFallThrough: true, // From jump in previous test.
				MayReturnImmediate: map[linux.BPFAction]struct{}{
					1337: struct{}{},
				},
			},
		},
		{
			name: "add register A return",
			build: func() {
				p.AddStmt(Ret|A, 0)
			},
			wantLocal: FragmentOutcomes{
				MayReturnRegisterA: true,
			},
			wantLocalMayReturn: true,
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayFallThrough: false, // Jump no longer pointing at end of fragment.
				MayReturnImmediate: map[linux.BPFAction]struct{}{
					1337: struct{}{},
				},
				MayReturnRegisterA: true,
			},
		},
		{
			name: "add another instruction after return",
			build: func() {
				p.AddStmt(Ld|Abs|W, 10)
			},
			wantLocal: FragmentOutcomes{
				MayFallThrough: true,
			},
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayReturnImmediate: map[linux.BPFAction]struct{}{
					1337: struct{}{},
				},
				MayReturnRegisterA: true,
				MayFallThrough:     true,
			},
		},
		{
			name: "zero-instruction jump counts as fallthrough",
			build: func() {
				p.AddJump(Jmp|Ja, 0, 0, 0)
			},
			wantLocal: FragmentOutcomes{
				MayFallThrough: true,
			},
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayReturnImmediate: map[linux.BPFAction]struct{}{
					1337: struct{}{},
				},
				MayReturnRegisterA: true,
				MayFallThrough:     true,
			},
		},
		{
			name: "non-zero-instruction jumps that points to end of fragment also counts as fallthrough",
			build: func() {
				p.AddJump(Jmp|Jeq|K, 42, 3, 1)
				p.AddJump(Jmp|Ja, 2, 0, 0)
				p.AddStmt(Ld|Abs|W, 11)
				p.AddStmt(Ld|Abs|W, 12)
			},
			wantLocal: FragmentOutcomes{
				MayFallThrough: true,
			},
			wantOverall: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayReturnImmediate: map[linux.BPFAction]struct{}{
					1337: struct{}{},
				},
				MayReturnRegisterA: true,
				MayFallThrough:     true,
			},
		},
		{
			name: "jump forward beyond fragment",
			build: func() {
				p.AddJumpFalseLabel(Jmp|Jeq|K, 1337, 123, "falselabel")
			},
			wantLocal: FragmentOutcomes{
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayJumpToKnownOffsetBeyondFragment: true,
			},
			wantOverall: FragmentOutcomes{
				MayJumpToKnownOffsetBeyondFragment: true,
				MayJumpToUnresolvedLabels: map[string]struct{}{
					"falselabel": struct{}{},
				},
				MayReturnImmediate: map[linux.BPFAction]struct{}{
					1337: struct{}{},
				},
				MayReturnRegisterA: true,
			},
		},
		{
			name: "resolve falselabel",
			build: func() {
				p.AddLabel("falselabel")
			},
			wantLocal: FragmentOutcomes{
				MayFallThrough: true,
			},
			wantOverall: FragmentOutcomes{
				MayJumpToKnownOffsetBeyondFragment: true,
				MayReturnImmediate: map[linux.BPFAction]struct{}{
					1337: struct{}{},
				},
				MayReturnRegisterA: true,
				MayFallThrough:     true,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			getLocalFragment := p.Record()
			test.build()
			localFragment := getLocalFragment()
			localOutcomes := localFragment.Outcomes()
			if !reflect.DeepEqual(fixup(localOutcomes), fixup(test.wantLocal)) {
				t.Errorf("local fragment %v: got outcomes %v want %v", localFragment, localOutcomes, test.wantLocal)
			}
			if gotMayReturn := localOutcomes.MayReturn(); gotMayReturn != test.wantLocalMayReturn {
				t.Errorf("local fragment MayReturn(): got %v want %v", gotMayReturn, test.wantLocalMayReturn)
			}
			overallFragment := getOverallFragment()
			if overallOutcomes := overallFragment.Outcomes(); !reflect.DeepEqual(fixup(overallOutcomes), fixup(test.wantOverall)) {
				t.Errorf("overall fragment %v: got outcomes %v want %v", overallFragment, overallOutcomes, test.wantOverall)
			}
		})
	}
}

func TestProgramBuilderMayModifyRegisterA(t *testing.T) {
	t.Run("empty program", func(t *testing.T) {
		if got := NewProgramBuilder().Record()().MayModifyRegisterA(); got != false {
			t.Errorf("MayModifyRegisterA: got %v want %v", got, false)
		}
	})
	t.Run("does not modify register A", func(t *testing.T) {
		b := NewProgramBuilder()
		stop := b.Record()
		b.AddJump(Jmp|Ja, 0, 0, 0)
		b.AddJump(Jmp|Jeq|K, 0, 0, 0)
		b.AddStmt(Misc|Txa, 0)
		b.AddStmt(Ret|K, 1337)
		if got := stop().MayModifyRegisterA(); got != false {
			t.Errorf("MayModifyRegisterA: got %v want %v", got, false)
		}
	})
	for _, ins := range []Instruction{
		Stmt(Ld|Abs|W, 0),
		Stmt(Alu|Neg, 0),
		Stmt(Misc|Tax, 0),
	} {
		t.Run(fmt.Sprintf("modifies register A via %v", ins), func(t *testing.T) {
			b := NewProgramBuilder()
			stop := b.Record()
			b.AddJump(Jmp|Ja, 0, 0, 0)
			b.AddJump(Jmp|Jeq|K, 0, 0, 0)
			b.AddStmt(ins.OpCode, ins.K)
			b.AddStmt(Ret|K, 1337)
			if got := stop().MayModifyRegisterA(); got != true {
				t.Errorf("MayModifyRegisterA: got %v want %v", got, true)
			}
		})
	}
}
