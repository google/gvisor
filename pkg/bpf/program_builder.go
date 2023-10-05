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
	"math"
	"sort"
	"strings"
)

const (
	labelTarget       = math.MaxUint8
	labelDirectTarget = math.MaxUint32
)

// ProgramBuilder assists with building a BPF program with jump
// labels that are resolved to their proper offsets.
type ProgramBuilder struct {
	// Maps label names to label objects.
	labels map[string]*label

	// unusableLabels are labels that are added before being referenced in a
	// jump. Any labels added this way cannot be referenced later in order to
	// avoid backwards references.
	unusableLabels map[string]bool

	// Array of BPF instructions that makes up the program.
	instructions []Instruction
}

// NewProgramBuilder creates a new ProgramBuilder instance.
func NewProgramBuilder() *ProgramBuilder {
	return &ProgramBuilder{
		labels:         map[string]*label{},
		unusableLabels: map[string]bool{},
	}
}

// label contains information to resolve a label to an offset.
type label struct {
	// List of locations that reference the label in the program.
	sources []source

	// Program line when the label is located.
	target int
}

// JumpType is the type of jump target that an instruction may use.
type JumpType int

// Types of jump that an instruction may use.
const (
	JumpDirect JumpType = iota
	JumpTrue
	JumpFalse
)

// source contains information about a single reference to a label.
type source struct {
	// Program line where the label reference is present.
	line int

	// True if label reference is in the 'jump if true' part of the jump.
	// False if label reference is in the 'jump if false' part of the jump.
	jt JumpType
}

// AddStmt adds a new statement to the program.
func (b *ProgramBuilder) AddStmt(code uint16, k uint32) {
	b.instructions = append(b.instructions, Stmt(code, k))
}

// AddJump adds a new jump to the program.
func (b *ProgramBuilder) AddJump(code uint16, k uint32, jt, jf uint8) {
	b.instructions = append(b.instructions, Jump(code, k, jt, jf))
}

// AddDirectJumpLabel adds a new jump to the program where is labelled.
func (b *ProgramBuilder) AddDirectJumpLabel(labelName string) {
	b.addLabelSource(labelName, JumpDirect)
	b.AddJump(Jmp|Ja, labelDirectTarget, 0, 0)
}

// AddJumpTrueLabel adds a new jump to the program where 'jump if true' is a label.
func (b *ProgramBuilder) AddJumpTrueLabel(code uint16, k uint32, jtLabel string, jf uint8) {
	b.addLabelSource(jtLabel, JumpTrue)
	b.AddJump(code, k, labelTarget, jf)
}

// AddJumpFalseLabel adds a new jump to the program where 'jump if false' is a label.
func (b *ProgramBuilder) AddJumpFalseLabel(code uint16, k uint32, jt uint8, jfLabel string) {
	b.addLabelSource(jfLabel, JumpFalse)
	b.AddJump(code, k, jt, labelTarget)
}

// AddJumpLabels adds a new jump to the program where both jump targets are labels.
func (b *ProgramBuilder) AddJumpLabels(code uint16, k uint32, jtLabel, jfLabel string) {
	b.addLabelSource(jtLabel, JumpTrue)
	b.addLabelSource(jfLabel, JumpFalse)
	b.AddJump(code, k, labelTarget, labelTarget)
}

// AddLabel sets the given label name at the current location. The next instruction is executed
// when the any code jumps to this label. More than one label can be added to the same location.
func (b *ProgramBuilder) AddLabel(name string) error {
	l, ok := b.labels[name]
	if !ok {
		if _, ok = b.unusableLabels[name]; ok {
			return fmt.Errorf("label %q already set", name)
		}
		// Mark the label as unusable. This is done to catch backwards jumps.
		b.unusableLabels[name] = true
		return nil
	}
	if l.target != -1 {
		return fmt.Errorf("label %q target already set: %v", name, l.target)
	}
	l.target = len(b.instructions)
	return nil
}

// Instructions returns an array of BPF instructions representing the program with all labels
// resolved. Return error in case label resolution failed due to an invalid program.
//
// N.B. Partial results will be returned in the error case, which is useful for debugging.
func (b *ProgramBuilder) Instructions() ([]Instruction, error) {
	if err := b.resolveLabels(); err != nil {
		return b.instructions, err
	}
	return b.instructions, nil
}

func (b *ProgramBuilder) addLabelSource(labelName string, t JumpType) {
	l, ok := b.labels[labelName]
	if !ok {
		l = &label{sources: make([]source, 0), target: -1}
		b.labels[labelName] = l
	}
	l.sources = append(l.sources, source{line: len(b.instructions), jt: t})
}

func (b *ProgramBuilder) resolveLabels() error {
	for key, v := range b.labels {
		if _, ok := b.unusableLabels[key]; ok {
			return fmt.Errorf("backwards reference detected for label: %q", key)
		}

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
			// Sets offset into jump instruction.
			switch s.jt {
			case JumpDirect:
				if offset > labelDirectTarget {
					return fmt.Errorf("jump offset to label '%v' is too large: %v, inst: %v, lineno: %v", key, offset, inst, s.line)
				}
				if inst.K != labelDirectTarget {
					return fmt.Errorf("jump target is not a label")
				}
				inst.K = uint32(offset)
			case JumpTrue:
				if offset > labelTarget {
					return fmt.Errorf("jump offset to label '%v' is too large: %v, inst: %v, lineno: %v", key, offset, inst, s.line)
				}
				if inst.JumpIfTrue != labelTarget {
					return fmt.Errorf("jump target is not a label")
				}
				inst.JumpIfTrue = uint8(offset)
			case JumpFalse:
				if offset > labelTarget {
					return fmt.Errorf("jump offset to label '%v' is too large: %v, inst: %v, lineno: %v", key, offset, inst, s.line)
				}
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

// ProgramFragment is a set of not-compiled instructions that were added to
// a ProgramBuilder from the moment the `Record` function was called on it.
type ProgramFragment struct {
	// b is a reference to the ProgramBuilder that this is a fragment from.
	b *ProgramBuilder

	// fromPC is the index of the first instruction that was recorded.
	// If no instruction was recorded, this index will be equal to `toPC`.
	fromPC int

	// toPC is the index *after* the last instruction that was recorded.
	// This means that right after recording, the program will not have
	// any instruction at index `toPC`.
	toPC int
}

// Record starts recording the instructions being added to the ProgramBuilder
// until the returned function is called.
// The returned function returns a ProgramFragment which represents the
// recorded instructions. It may be called repeatedly.
func (b *ProgramBuilder) Record() func() ProgramFragment {
	currentPC := len(b.instructions)
	return func() ProgramFragment {
		return ProgramFragment{
			b:      b,
			fromPC: currentPC,
			toPC:   len(b.instructions),
		}
	}
}

// String returns a string version of the fragment.
func (f ProgramFragment) String() string {
	return fmt.Sprintf("fromPC=%d toPC=%d", f.fromPC, f.toPC)
}

// FragmentOutcomes represents the set of outcomes that a ProgramFragment
// execution may result into.
type FragmentOutcomes struct {
	// MayFallThrough is true if executing the fragment may cause it to start
	// executing the program instruction that comes right after the last
	// instruction in this fragment (i.e. at `Fragment.toPC`).
	MayFallThrough bool

	// MayJumpToKnownOffsetBeyondFragment is true if executing the fragment may
	// jump to a fixed offset (or resolved label) that is not within the range
	// of the fragment itself, nor does it point to the instruction that would
	// come right after this fragment.
	// If the fragment jumps to an unresolved label, this will instead be
	// indicated in `MayJumpToUnresolvedLabels`.
	MayJumpToKnownOffsetBeyondFragment bool

	// MayJumpToUnresolvedLabels is the set of named labels that have not yet
	// been added to the program (the labels are not resolvable) but that the
	// fragment may jump to.
	MayJumpToUnresolvedLabels map[string]struct{}

	// MayReturn is true if executing the fragment may cause a return statement
	// to be executed.
	MayReturn bool
}

// String returns a list of possible human-readable outcomes.
func (o FragmentOutcomes) String() string {
	var s []string
	if o.MayJumpToKnownOffsetBeyondFragment {
		s = append(s, "may jump to known offset beyond fragment")
	}
	if o.MayJumpToUnresolvedLabels != nil {
		sortedLabels := make([]string, 0, len(o.MayJumpToUnresolvedLabels))
		for lbl := range o.MayJumpToUnresolvedLabels {
			sortedLabels = append(sortedLabels, lbl)
		}
		sort.Strings(sortedLabels)
		for _, lbl := range sortedLabels {
			s = append(s, fmt.Sprintf("may jump to unresolved label %q", lbl))
		}
	}
	if o.MayFallThrough {
		s = append(s, "may fall through")
	}
	if o.MayReturn {
		s = append(s, "may return")
	}
	if len(s) == 0 {
		return "no outcomes (this should never happen)"
	}
	return strings.Join(s, ", ")
}

// Outcomes returns the set of possible outcomes that executing this fragment
// may result into.
func (f ProgramFragment) Outcomes() FragmentOutcomes {
	if f.fromPC == f.toPC {
		// No instructions, this just falls through.
		return FragmentOutcomes{
			MayFallThrough: true,
		}
	}
	outcomes := FragmentOutcomes{
		MayJumpToUnresolvedLabels: make(map[string]struct{}),
	}
	for pc := f.fromPC; pc < f.toPC; pc++ {
		ins := f.b.instructions[pc]
		isLastInstruction := pc == f.toPC-1
		switch ins.OpCode & instructionClassMask {
		case Ret:
			outcomes.MayReturn = true
		case Jmp:
			for _, offset := range ins.JumpOffsets() {
				var foundLabelName string
				var foundLabel *label
				for labelName, label := range f.b.labels {
					for _, s := range label.sources {
						if s.jt == offset.Type && s.line == pc {
							foundLabelName = labelName
							foundLabel = label
							break
						}
					}
				}
				if foundLabel != nil && foundLabel.target == -1 {
					outcomes.MayJumpToUnresolvedLabels[foundLabelName] = struct{}{}
					continue
				}
				var target int
				if foundLabel != nil {
					target = foundLabel.target
				} else {
					target = pc + int(offset.Offset) + 1
				}
				if target == f.toPC {
					outcomes.MayFallThrough = true
				} else if target > f.toPC {
					outcomes.MayJumpToKnownOffsetBeyondFragment = true
				}
			}
		default:
			if isLastInstruction {
				outcomes.MayFallThrough = true
			}
		}
	}
	return outcomes
}
