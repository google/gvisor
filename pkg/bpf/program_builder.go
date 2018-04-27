// Copyright 2018 Google Inc.
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
	"math"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

const labelTarget = math.MaxUint8

// ProgramBuilder assists with building a BPF program with jump
// labels that are resolved to their proper offsets.
type ProgramBuilder struct {
	// Maps label names to label objects.
	labels map[string]*label

	// Array of BPF instructions that makes up the program.
	instructions []linux.BPFInstruction
}

// NewProgramBuilder creates a new ProgramBuilder instance.
func NewProgramBuilder() *ProgramBuilder {
	return &ProgramBuilder{labels: map[string]*label{}}
}

// label contains information to resolve a label to an offset.
type label struct {
	// List of locations that reference the label in the program.
	sources []source

	// Program line when the label is located.
	target int
}

// source contains information about a single reference to a label.
type source struct {
	// Program line where the label reference is present.
	line int

	// True if label reference is in the 'jump if true' part of the jump.
	// False if label reference is in the 'jump if false' part of the jump.
	jt bool
}

// AddStmt adds a new statement to the program.
func (b *ProgramBuilder) AddStmt(code uint16, k uint32) {
	b.instructions = append(b.instructions, Stmt(code, k))
}

// AddJump adds a new jump to the program.
func (b *ProgramBuilder) AddJump(code uint16, k uint32, jt, jf uint8) {
	b.instructions = append(b.instructions, Jump(code, k, jt, jf))
}

// AddJumpTrueLabel adds a new jump to the program where 'jump if true' is a label.
func (b *ProgramBuilder) AddJumpTrueLabel(code uint16, k uint32, jtLabel string, jf uint8) {
	b.addLabelSource(jtLabel, true)
	b.AddJump(code, k, labelTarget, jf)
}

// AddJumpFalseLabel adds a new jump to the program where 'jump if false' is a label.
func (b *ProgramBuilder) AddJumpFalseLabel(code uint16, k uint32, jt uint8, jfLabel string) {
	b.addLabelSource(jfLabel, false)
	b.AddJump(code, k, jt, math.MaxUint8)
}

// AddJumpLabels adds a new jump to the program where both jump targets are labels.
func (b *ProgramBuilder) AddJumpLabels(code uint16, k uint32, jtLabel, jfLabel string) {
	b.addLabelSource(jtLabel, true)
	b.addLabelSource(jfLabel, false)
	b.AddJump(code, k, math.MaxUint8, math.MaxUint8)
}

// AddLabel sets the given label name at the current location. The next instruction is executed
// when the any code jumps to this label. More than one label can be added to the same location.
func (b *ProgramBuilder) AddLabel(name string) error {
	l, ok := b.labels[name]
	if !ok {
		// This is done to catch jump backwards cases, but it's not strictly wrong
		// to have unused labels.
		return fmt.Errorf("Adding a label that hasn't been used is not allowed: %v", name)
	}
	if l.target != -1 {
		return fmt.Errorf("label %q target already set: %v", name, l.target)
	}
	l.target = len(b.instructions)
	return nil
}

// Instructions returns an array of BPF instructions representing the program with all labels
// resolved. Return error in case label resolution failed due to an invalid program.
func (b *ProgramBuilder) Instructions() ([]linux.BPFInstruction, error) {
	if err := b.resolveLabels(); err != nil {
		return nil, err
	}
	return b.instructions, nil
}

func (b *ProgramBuilder) addLabelSource(labelName string, jt bool) {
	l, ok := b.labels[labelName]
	if !ok {
		l = &label{sources: make([]source, 0), target: -1}
		b.labels[labelName] = l
	}
	l.sources = append(l.sources, source{line: len(b.instructions), jt: jt})
}

func (b *ProgramBuilder) resolveLabels() error {
	for key, v := range b.labels {
		if v.target == -1 {
			return fmt.Errorf("label target not set: %v", key)
		}
		if v.target >= len(b.instructions) {
			return fmt.Errorf("target is beyond end of ProgramBuilder")
		}
		for _, s := range v.sources {
			// Finds jump instruction that references the label.
			inst := b.instructions[s.line]
			if s.line >= v.target {
				return fmt.Errorf("cannot jump backwards")
			}
			// Calculates the jump offset from current line.
			offset := v.target - s.line - 1
			if offset > math.MaxUint8 {
				return fmt.Errorf("jump offset to label '%v' is too large: %v", key, offset)
			}
			// Sets offset into jump instruction.
			if s.jt {
				if inst.JumpIfTrue != labelTarget {
					return fmt.Errorf("jump target is not a label")
				}
				inst.JumpIfTrue = uint8(offset)
			} else {
				if inst.JumpIfFalse != labelTarget {
					return fmt.Errorf("jump target is not a label")
				}
				inst.JumpIfFalse = uint8(offset)
			}
			b.instructions[s.line] = inst
		}
	}
	b.labels = map[string]*label{}
	return nil
}
