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

// optimizerFunc is a function type that can optimize a BPF program.
// It returns the updated set of instructions, along with whether any
// modification was made.
type optimizerFunc func(insns []Instruction) ([]Instruction, bool)

// optimizeConditionalJumps looks for conditional jumps which go to an
// unconditional jump that goes to a final target fewer than 256 instructions
// away.
// These can safely be rewritten to not require the extra unconditional jump.
// It returns the optimized set of instructions, along with whether any change
// was made.
func optimizeConditionalJumps(insns []Instruction) ([]Instruction, bool) {
	changed := false
	for pc, ins := range insns {
		if !ins.IsConditionalJump() {
			continue // Not a conditional jump instruction.
		}
		// Take care of "true" target:
		{
			jumpTrueOffset := pc + int(ins.JumpIfTrue) + 1
			jumpTrueIns := insns[jumpTrueOffset]
			if jumpTrueIns.OpCode&instructionClassMask == Jmp && jumpTrueIns.OpCode&jmpMask == Ja {
				if finalJumpTrueOffset := int(ins.JumpIfTrue) + 1 + int(jumpTrueIns.K); finalJumpTrueOffset < 256 {
					// We can optimize the "true" target.
					ins.JumpIfTrue = uint8(finalJumpTrueOffset)
					changed = true
				}
			}
		}
		// Take care of "false" target:
		{
			jumpFalseOffset := pc + int(ins.JumpIfFalse) + 1
			jumpFalseIns := insns[jumpFalseOffset]
			if jumpFalseIns.OpCode&instructionClassMask == Jmp && jumpFalseIns.OpCode&jmpMask == Ja {
				if finalJumpFalseOffset := int(ins.JumpIfFalse) + 1 + int(jumpFalseIns.K); finalJumpFalseOffset < 256 {
					// We can optimize the "false" target.
					ins.JumpIfFalse = uint8(finalJumpFalseOffset)
					changed = true
				}
			}
		}
		insns[pc] = ins
	}
	return insns, changed
}

// optimizeSameTargetConditionalJumps looks for conditional jumps where both
// the "true" and "false" targets go to the same place, and rewrites them to
// an unconditional jump to that place.
// This can happen even for legitimate programs when resolving the target of
// indirect jumps ends up at the same place.
// It returns the optimized set of instructions, along with whether any change
// was made.
func optimizeSameTargetConditionalJumps(insns []Instruction) ([]Instruction, bool) {
	changed := false
	for pc, ins := range insns {
		if !ins.IsConditionalJump() {
			continue // Not a conditional jump instruction.
		}
		if ins.JumpIfTrue != ins.JumpIfFalse {
			continue // Not the same target.
		}
		insns[pc] = Jump(Jmp|Ja, uint32(ins.JumpIfTrue), 0, 0)
		changed = true
	}
	return insns, changed
}

// optimizeUnconditionalJumps looks for conditional jumps which go to another
// unconditional jump.
func optimizeUnconditionalJumps(insns []Instruction) ([]Instruction, bool) {
	changed := false
	for pc, ins := range insns {
		if !ins.IsUnconditionalJump() {
			continue // Not an unconditional jump instruction.
		}
		jumpOffset := pc + int(ins.K) + 1
		jumpIns := insns[jumpOffset]
		if !jumpIns.IsUnconditionalJump() {
			// Not jumping to an unconditional jump.
			continue
		}
		finalJumpOffset := int(ins.K) + 1 + int(jumpIns.K)
		if finalJumpOffset >= 65536 {
			// Final jump offset too large to fit in a single unconditional jump.
			continue
		}
		// We can optimize the final target.
		ins.K = uint32(finalJumpOffset)
		insns[pc] = ins
		changed = true
	}
	return insns, changed
}

// decrementJumps decrements all jumps within `insns` that are jumping to an
// instruction with index larger than `target`, the index of an
// instruction that just got removed (i.e. `target` now points to the
// instruction that was directly following the removed instruction).
// Jumps that targeted `target` itself will not be affected, i.e. they will
// point to the instruction that directly followed the removed instruction.
// `insns` is modified in-place.
func decrementJumps(insns []Instruction, target int) {
	for pc := 0; pc < target; pc++ {
		ins := insns[pc]
		if !ins.IsJump() {
			continue
		}
		if ins.IsUnconditionalJump() {
			// Unconditional jump, check K:
			if pc+int(ins.K)+1 > target {
				ins.K--
			}
		} else {
			// Conditional jump, check true target:
			if pc+int(ins.JumpIfTrue)+1 > target {
				ins.JumpIfTrue--
			}
			// ... And check false target:
			if pc+int(ins.JumpIfFalse)+1 > target {
				ins.JumpIfFalse--
			}
		}
		insns[pc] = ins
	}
}

// removeZeroInstructionJumps removes unconditional jumps that jump zero
// instructions forward. This may seem silly but it can happen due to other
// optimizations in this file which decrement jump target indexes.
func removeZeroInstructionJumps(insns []Instruction) ([]Instruction, bool) {
	changed := false
	for pc := 0; pc < len(insns); pc++ {
		ins := insns[pc]
		if !ins.IsUnconditionalJump() || ins.K != 0 {
			continue
		}
		insns = append(insns[:pc], insns[pc+1:]...)
		decrementJumps(insns, pc)
		changed = true

		// Rewind back one instruction, in case the instruction now at `pc`
		// is also a zero-instruction unconditional jump.
		pc--
	}
	return insns, changed
}

// removeDeadCode removes instructions which are unreachable.
// This can happen due to the other optimizations in this file,
// e.g. optimizeConditionalJumps.
// In addition, removing dead code means the program is shorter,
// which in turn may make further jump optimizations possible.
func removeDeadCode(insns []Instruction) ([]Instruction, bool) {
	if len(insns) == 0 {
		return insns, false
	}

	// Keep track of which lines are reachable from all instructions in the program.
	reachable := make([]bool, len(insns))
	cursors := make([]int, 1, len(insns))
	cursors[0] = 0
	for len(cursors) > 0 {
		cursor := cursors[0]
		cursors = cursors[1:]
		if reachable[cursor] {
			continue
		}
		reachable[cursor] = true
		ins := insns[cursor]
		switch ins.OpCode & instructionClassMask {
		case Ret:
			// Return instructions are terminal, add no new cursor.
		case Jmp:
			// Add a new cursor wherever the jump can go.
			if ins.IsUnconditionalJump() {
				// Unconditional jump:
				cursors = append(cursors, cursor+int(ins.K)+1)
			} else {
				// Conditional jump:
				cursors = append(cursors, cursor+int(ins.JumpIfTrue)+1, cursor+int(ins.JumpIfFalse)+1)
			}
		default:
			// Other instructions simply flow forward.
			cursors = append(cursors, cursor+1)
		}
	}

	// Now scan for unreachable code.
	var unreachable []int
	for i := 0; i < len(reachable); i++ {
		if !reachable[i] {
			unreachable = append(unreachable, i)
		}
	}

	// And finally cull unreachable code.
	for u := 0; u < len(unreachable); u++ {
		i := unreachable[u]
		// Remove the instruction at this index:
		insns = append(insns[:i], insns[i+1:]...)

		// Rewrite all previous jumps which would have straddled over this instruction:
		decrementJumps(insns, i)

		// And decrement all future unreachable indexes, since we just shortened `insns` by one:
		for u2 := u + 1; u2 < len(unreachable); u2++ {
			unreachable[u2] = unreachable[u2] - 1
		}
	}

	return insns, len(unreachable) > 0
}

// optimizeJumpsToReturn replaces unconditional jumps that go to return
// statements by a copy of that return statement.
func optimizeJumpsToReturn(insns []Instruction) ([]Instruction, bool) {
	changed := false
	for pc, ins := range insns {
		if !ins.IsUnconditionalJump() {
			continue // Not an unconditional jump instruction.
		}
		targetIns := insns[pc+int(ins.K)+1]
		if targetIns.OpCode&instructionClassMask != Ret {
			continue // Not jumping to a return instruction.
		}
		insns[pc] = targetIns
		changed = true
	}
	return insns, changed
}

// Optimize losslessly optimizes a BPF program using the given optimization
// functions.
// Optimizers should be ranked in order of importance, with the most
// important first.
// An optimizer will be exhausted before the next one is ever run.
// Earlier optimizers are re-exhausted if later optimizers cause change.
// The BPF instructions are assumed to have been checked for validity and
// consistency.
// The instructions in `insns` may be modified in-place.
func optimize(insns []Instruction, funcs []optimizerFunc) []Instruction {
	for changed := true; changed; {
		for _, fn := range funcs {
			if insns, changed = fn(insns); changed {
				break
			}
		}
	}
	return insns
}

// Optimize losslessly optimizes a BPF program.
// The BPF instructions are assumed to have been checked for validity and
// consistency.
// The instructions in `insns` may be modified in-place.
func Optimize(insns []Instruction) []Instruction {
	return optimize(insns, []optimizerFunc{
		optimizeConditionalJumps,
		optimizeSameTargetConditionalJumps,
		optimizeUnconditionalJumps,
		optimizeJumpsToReturn,
		removeZeroInstructionJumps,
		removeDeadCode,
	})
}
