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

	"gvisor.dev/gvisor/pkg/abi/linux"
)

func validate(p *ProgramBuilder, expected []linux.BPFInstruction) error {
	instructions, err := p.Instructions()
	if err != nil {
		return fmt.Errorf("Instructions() failed: %v", err)
	}
	got, err := DecodeProgram(instructions)
	if err != nil {
		return fmt.Errorf("DecodeProgram('instructions') failed: %v", err)
	}
	expectedDecoded, err := DecodeProgram(expected)
	if err != nil {
		return fmt.Errorf("DecodeProgram('expected') failed: %v", err)
	}
	if got != expectedDecoded {
		return fmt.Errorf("DecodeProgram() failed, expected: %q, got: %q", expectedDecoded, got)
	}
	return nil
}

func TestProgramBuilderSimple(t *testing.T) {
	p := NewProgramBuilder()
	p.AddStmt(Ld+Abs+W, 10)
	p.AddJump(Jmp+Ja, 10, 0, 0)

	expected := []linux.BPFInstruction{
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

	expected := []linux.BPFInstruction{
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

func TestProgramBuilderUnusedLabel(t *testing.T) {
	p := NewProgramBuilder()
	if err := p.AddLabel("unused"); err == nil {
		t.Errorf("AddLabel(unused) should have failed")
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
