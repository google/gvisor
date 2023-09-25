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
	"testing"
)

func validate(t *testing.T, p *ProgramBuilder, expected []Instruction) error {
	t.Helper()
	instructions, err := p.Instructions()
	for i, instruction := range instructions {
		t.Logf("[%d] %v", i, instruction.String())
	}
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
	p.AddJump(Jmp+Ja, 1, 0, 0)
	p.AddStmt(Ld+Abs+W, 3)
	p.AddStmt(Ret+K, 1337)

	expected := []Instruction{
		Stmt(Ld+Abs+W, 10),
		Jump(Jmp+Ja, 1, 0, 0),
		Stmt(Ld+Abs+W, 3),
		Stmt(Ret+K, 1337),
	}

	if err := validate(t, p, expected); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
}

func TestProgramBuilderLabels(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJumpTrueLabel(Jmp+Jeq+K, 5, "label_1", 0)
	p.AddJumpFalseLabel(Jmp+Jeq+K, 4, 0, "label_2")
	p.AddJumpLabels(Jmp+Jeq+K, 3, "label_3", "label_4")
	if err := p.AddLabel("label_1"); err != nil {
		t.Errorf("AddLabel(label_1) failed: %v", err)
	}
	p.AddStmt(Ld+Abs+W, 1)
	if err := p.AddLabel("label_3"); err != nil {
		t.Errorf("AddLabel(label_3) failed: %v", err)
	}
	p.AddJumpLabels(Jmp+Jeq+K, 2, "label_4", "label_5")
	if err := p.AddLabel("label_2"); err != nil {
		t.Errorf("AddLabel(label_2) failed: %v", err)
	}
	p.AddJumpLabels(Jmp+Jeq+K, 1, "label_4", "label_6")
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
	p.AddStmt(Ret+K, 42)

	expected := []Instruction{
		Jump(Jmp+Jeq+K, 5, 2, 0),
		Jump(Jmp+Jeq+K, 4, 0, 3),
		Jump(Jmp+Jeq+K, 3, 1, 3),
		Stmt(Ld+Abs+W, 1),
		Jump(Jmp+Jeq+K, 2, 1, 2),
		Jump(Jmp+Jeq+K, 1, 0, 1),
		Stmt(Ld+Abs+W, 4),
		Stmt(Ld+Abs+W, 5),
		Stmt(Ret+K, 42),
	}
	if err := validate(t, p, expected); err != nil {
		t.Errorf("Validate() failed: %v", err)
	}
	// Calling validate()=>p.Instructions() again to make sure
	// Instructions can be called multiple times without ruining
	// the program.
	if err := validate(t, p, expected); err != nil {
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
	p.AddJump(Jmp+Ja, 1, 0, 0)
	p.AddStmt(Ld+Abs+W, 3)
	p.AddStmt(Ret+K, 1337)

	expected := []Instruction{
		Stmt(Ld+Abs+W, 10),
		Jump(Jmp+Ja, 1, 0, 0),
		Stmt(Ld+Abs+W, 3),
		Stmt(Ret+K, 1337),
	}

	if err := p.AddLabel("unused"); err != nil {
		t.Errorf("AddLabel(unused) should have succeeded")
	}

	if err := validate(t, p, expected); err != nil {
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

func TestProgramBuilderCannotDetermineReachability(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJump(Jmp|Ja, 1, 0, 0)
	p.AssertUnreachable()
	if _, err := p.Instructions(); err == nil {
		t.Errorf("Instructions() should have failed")
	}
	p.AddStmt(Ret|K, 0)
	want := []Instruction{
		Jump(Jmp|Ja, 1, 0, 0),
		Jump(Jmp|Ja, 0, 0, 0),
		Stmt(Ret|K, 0),
	}
	if err := validate(t, p, want); err != nil {
		t.Errorf("validation failed: %v", err)
	}
}

func TestProgramBuilderTrimUnreachableInstructions(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJump(Jmp|Ja, 1, 0, 0)
	p.AssertUnreachable()
	p.AddStmt(Ret|K, 0)
	p.AssertUnreachable()
	p.AssertUnreachable()
	p.AssertUnreachable()
	p.AssertUnreachable()
	want := []Instruction{
		Jump(Jmp|Ja, 1, 0, 0),
		Jump(Jmp|Ja, 0, 0, 0),
		Stmt(Ret|K, 0),
	}
	if err := validate(t, p, want); err != nil {
		t.Errorf("validation failed: %v", err)
	}
}

func TestProgramBuilderReachesSupposedlyUnreachableAssertion(t *testing.T) {
	p := NewProgramBuilder()
	p.AddJump(Jmp|Ja, 0, 0, 0)
	p.AssertUnreachable()
	if _, err := p.Instructions(); err == nil {
		t.Errorf("Instructions() should have failed")
	}
}
