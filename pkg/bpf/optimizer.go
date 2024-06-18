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
	"fmt"
	"sort"
)

const (
	// maxConditionalJumpOffset is the maximum offset of a conditional
	// jump instruction. Conditional jump offsets are specified as an
	// unsigned 8-bit integer.
	maxConditionalJumpOffset = (1 << 8) - 1
	// maxUnconditionalJumpOffset is the maximum offset of an unconditional
	// jump instruction.
	// Unconditional jumps are stored in an uint32, but here we limit it to
	// what would fit in a uint16.
	// BPF programs (once uploaded into the kernel) are limited to
	// `BPF_MAXINSNS`, which is 4096 in Linux as of this writing.
	// We need a value larger than `BPF_MAXINSNS` here in order to support
	// optimizing programs that are initially larger than `BPF_MAXINSNS` but
	// that can be optimized to fit within that limit. However, programs that
	// jump 2^32-1 instructions are probably not optimizable enough to fit
	// regardless.
	// This number is a middle ground that should be plenty given the type of
	// program we expect to optimize, while also not trying too hard to
	// optimize unoptimizable programs.
	maxUnconditionalJumpOffset = (1 << 16) - 1
)

// optimizerFunc is a function type that can optimize a BPF program.
// It returns the updated set of instructions, along with whether any
// modification was made.
type optimizerFunc func(insns []Instruction) ([]Instruction, bool)

// optimizeConditionalJumps looks for conditional jumps which go to an
// unconditional jump that goes to a final target fewer than
// `maxConditionalJumpOffset` instructions away.
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
				if finalJumpTrueOffset := int(ins.JumpIfTrue) + 1 + int(jumpTrueIns.K); finalJumpTrueOffset <= maxConditionalJumpOffset {
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
				if finalJumpFalseOffset := int(ins.JumpIfFalse) + 1 + int(jumpFalseIns.K); finalJumpFalseOffset <= maxConditionalJumpOffset {
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
		if finalJumpOffset > maxUnconditionalJumpOffset {
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

// codeRemoval efficiently tracks indexes to remove from instructions.
type codeRemoval struct {
	insns    []Instruction
	toRemove []int
}

// MarkRemoved adds a new instruction index to be removed.
func (cr *codeRemoval) MarkRemoved(index int) {
	if cr.toRemove == nil {
		cr.toRemove = make([]int, 0, len(cr.insns))
	}
	cr.toRemove = append(cr.toRemove, index)
}

// Apply returns the set of instructions after removing marked indexes,
// along with a boolean representing whether any instruction was removed.
func (cr *codeRemoval) Apply() ([]Instruction, bool) {
	if len(cr.toRemove) == 0 {
		return cr.insns, false
	}
	sort.Ints(cr.toRemove)
	for i := len(cr.toRemove) - 1; i >= 0; i-- {
		pc := cr.toRemove[i]
		cr.insns = append(cr.insns[:pc], cr.insns[pc+1:]...)
		decrementJumps(cr.insns, pc)
	}
	return cr.insns, true
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
	removal := codeRemoval{insns: insns}
	for pc, ins := range insns {
		if !ins.IsUnconditionalJump() || ins.K != 0 {
			continue
		}
		removal.MarkRemoved(pc)
	}
	return removal.Apply()
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

	// Now remove unreachable code.
	removal := codeRemoval{insns: insns}
	for pc := range insns {
		if !reachable[pc] {
			removal.MarkRemoved(pc)
		}
	}
	return removal.Apply()
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

// removeRedundantLoads removes some redundant load instructions
// when the value in register A is already the same value as what is
// being loaded.
func removeRedundantLoads(insns []Instruction) ([]Instruction, bool) {
	// reverseWalk maps instruction indexes I to the set of instruction indexes
	// that, after their execution, may result in the control flow jumping to I.
	reverseWalk := make([]map[int]struct{}, len(insns))
	for pc := range insns {
		reverseWalk[pc] = make(map[int]struct{})
	}
	for pc, ins := range insns {
		if ins.IsReturn() {
			continue // Return instructions are terminal.
		}
		if ins.IsJump() {
			for _, offset := range ins.JumpOffsets() {
				reverseWalk[pc+int(offset.Offset)+1][pc] = struct{}{}
			}
			continue
		}
		// All other instructions flow through.
		reverseWalk[pc+1][pc] = struct{}{}
	}

	// Now look for redundant load instructions.
	removal := codeRemoval{insns: insns}
	for pc, ins := range insns {
		if ins.OpCode&instructionClassMask != Ld {
			continue
		}
		// Walk backwards until either we've reached the beginning of the program,
		// or we've reached an operation which modifies register A.
		lastModifiedA := -1
		beforePCs := reverseWalk[pc]
	walk:
		for {
			switch len(beforePCs) {
			case 0:
				// We've reached the beginning of the program without modifying A.
				break walk
			case 1:
				var beforePC int
				for bpc := range beforePCs { // Note: we know that this map only has one element.
					beforePC = bpc
				}
				if !insns[beforePC].ModifiesRegisterA() {
					beforePCs = reverseWalk[beforePC]
					continue walk
				}
				lastModifiedA = beforePC
				break walk
			default:
				// Multiple ways to get to `pc`.
				// For simplicity, we only support the single-branch case right now.
				break walk
			}
		}
		if lastModifiedA != -1 && insns[pc].Equal(insns[lastModifiedA]) {
			removal.MarkRemoved(pc)
		}
	}
	return removal.Apply()
}

// jumpRewriteOperation rewrites a jump target.
type jumpRewriteOperation struct {
	pc        int      // Rewrite instruction at this offset.
	jumpType  JumpType // Rewrite this type of jump.
	rewriteTo int      // Rewrite the jump offset to this value.
}

// rewriteAllJumpsToReturn rewrites *all* jump instructions that go to
// `fromPC` to go to `toPC` instead, if possible without converting jumps
// from conditional to unconditional. `fromPC` and `toPC` must point to
// identical return instructions.
// It is all-or-nothing: either all jump instructions must be rewritable
// (in which case they will all be rewritten, and this function will
// return true), or no jump instructions will be rewritten, and this
// function will return false.
// This function also returns false in the vacuous case (i.e. there are
// no jump instructions that go to `fromPC` in the first place).
// This function is used in `optimizeJumpsToSmallestSetOfReturns`.
// As a sanity check, it verifies that `fromPC` and `toPC` are functionally
// identical return instruction, and panics otherwise.
// `rewriteOps` is a buffer of jump rewrite operations meant to be
// efficiently reusable across calls to this function.
func rewriteAllJumpsToReturn(insns []Instruction, fromPC, toPC int, rewriteOps []jumpRewriteOperation) bool {
	fromIns, toIns := insns[fromPC], insns[toPC]
	if !fromIns.IsReturn() {
		panic(fmt.Sprintf("attempted to rewrite jumps from {pc=%d: %v} which is not a return instruction", fromPC, fromIns))
	}
	if !toIns.IsReturn() {
		panic(fmt.Sprintf("attempted to rewrite jumps to {pc=%d: %v} which is not a return instruction", toPC, toIns))
	}
	if !fromIns.Equal(toIns) {
		panic(fmt.Sprintf("attempted to rewrite jump target to a different return instruction: from={pc=%d: %v}, to={pc=%d: %v}", fromPC, fromIns, toPC, toIns))
	}
	// Scan once, and populate `rewriteOps` as a list of rewrite operations
	// that should be run if the rewrite is feasible.
	rewriteOps = rewriteOps[:0]
	for pc := 0; pc < fromPC; pc++ {
		ins := insns[pc]
		// Note: `neededOffset` may be negative, in case where we are rewriting
		// the jump target to go to an earlier instruction, and we are dealing
		// with the instructions that come after that.
		// This isn't necessarily a dealbreaker, we just need to make sure that
		// `ins` is either not a jump statement, or it is a jump statement that
		// doesn't go to `fromPC` (otherwise, only then would it need to jump
		// backwards).
		neededOffset := toPC - pc - 1
		if ins.IsConditionalJump() {
			if jumpTrueTarget := pc + int(ins.JumpIfTrue) + 1; jumpTrueTarget == fromPC {
				if neededOffset < 0 || neededOffset > maxConditionalJumpOffset {
					return false
				}
				rewriteOps = append(rewriteOps, jumpRewriteOperation{
					pc:        pc,
					jumpType:  JumpTrue,
					rewriteTo: neededOffset,
				})
			}
			if jumpFalseTarget := pc + int(ins.JumpIfFalse) + 1; jumpFalseTarget == fromPC {
				if neededOffset < 0 || neededOffset > maxConditionalJumpOffset {
					return false
				}
				rewriteOps = append(rewriteOps, jumpRewriteOperation{
					pc:        pc,
					jumpType:  JumpFalse,
					rewriteTo: neededOffset,
				})
			}
		} else if ins.IsUnconditionalJump() {
			if jumpTarget := pc + int(ins.K) + 1; jumpTarget == fromPC {
				if neededOffset < 0 || neededOffset > maxUnconditionalJumpOffset {
					return false
				}
				rewriteOps = append(rewriteOps, jumpRewriteOperation{
					pc:        pc,
					jumpType:  JumpDirect,
					rewriteTo: neededOffset,
				})
			}
		}
	}
	if len(rewriteOps) == 0 {
		return false // No jump statements to rewrite.
	}
	// Rewrite is feasible, so do it.
	for _, op := range rewriteOps {
		ins := insns[op.pc]
		switch op.jumpType {
		case JumpTrue:
			ins.JumpIfTrue = uint8(op.rewriteTo)
		case JumpFalse:
			ins.JumpIfFalse = uint8(op.rewriteTo)
		case JumpDirect:
			ins.K = uint32(op.rewriteTo)
		}
		insns[op.pc] = ins
	}
	return true
}

// optimizeJumpsToSmallestSetOfReturns modifies jump targets that go to
// return statements to go to an identical return statement (which still
// fits within the maximum jump offsets), with the goal of minimizing the
// total number of such return statements needed within the program overall.
// The return statements that are skipped this way can then be removed by
// the `removeDeadCode` optimizer, which should come earlier in the
// optimizer list to ensure this optimizer only runs on instructions with
// no dead code in them.
// Within binary search trees, this allows deduplicating return statements
// across multiple conditions and makes them much shorter. In turn, this
// allows pruning these redundant return instructions as
// they become dead, and therefore makes the code shorter.
// (Essentially, we create a common "jump to return" doormat that everyone in
// Office Space^W^W^W^W any instruction in range can jump to.)
//
// Conceptually:
//
//	.. if (foo) goto A else goto B
//	A: return rejected
//	B: if (bar) goto C else goto D
//	C: return rejected
//	D: if (baz) goto E else goto F
//	E: return rejected
//	F: return accepted
//	...
//	(Another set of rules in the program):
//	.. if (foo2) goto G else goto H
//	G: return accepted
//	H: if (bar2) goto I else goto J
//	I: return accepted
//	J: return rejected
//
// becomes (after the dead code removal optimizer runs as well):
//
//	.. if (foo) goto J else goto B
//	B: if (bar) goto J else goto D
//	D: if (baz) goto J else goto I
//	...
//	.. if (foo2) goto I else goto H
//	H: if (bar2) goto I else goto J
//	I: return accepted
//	J: return rejected
func optimizeJumpsToSmallestSetOfReturns(insns []Instruction) ([]Instruction, bool) {
	// This is probably an NP-complete problem, so this approach does not
	// attempt to be optimal. Not being optimal is OK, we just end up with
	// a program that's slightly longer than necessary.
	// Rough sketch of the algorithm:
	//   For each return instruction in the program:
	//     Count the number of jump instructions that flow to it ("popularity").
	//     Also add `len(insns)` to the count if the instruction just before
	//     the return instruction is neither a jump or a return instruction,
	//     as the program can also flow through to it. This makes the return
	//     instruction non-removable, but that in turn means that it is a very
	//     good target for other jumps to jump to.
	//   Build a map of lists of return instructions sorted by how many other
	//   instructions flow to it, in ascending order.
	//   The map key is the return value of the return instruction.
	//   Iterate over this map (for each possible return value):
	//     Iterate over the list of return instructions that return this value:
	//       If the return instruction is unreachable, skip it.
	//       If the return instruction is reachable by fallthrough (i.e. the
	//       instruction just before it is not a jump nor a return), skip it.
	//       Otherwise, see if it's possible to move all jump targets of this
	//       instruction to any other return instruction in the list (starting
	//       from the end of the sorted list, i.e. the "most popular" return
	//       instruction that returns the same value), without needing to
	//       convert conditional jumps into unconditional ones.
	//       If it's possible, move all jump targets to it.
	// We may redundantly update multiple jump targets in one go which may be
	// optimized further in later passes (e.g. if unconditional jumps can be
	// removed and trim the program further, expanding the set of possible
	// rewrites beyond what we considered in this pass), but that's OK.
	// This pass will run again afterwards and eventually pick them up, and this
	// is still more efficient over running this (expensive) pass after each
	// single rewrite happens.
	changed := false

	// retPopularity maps offsets (pc) of return instructions to the number of
	// jump targets that point to them, +numInstructions if the program can also
	// fall through to it.
	numInstructions := len(insns)
	retPopularity := make([]int, numInstructions)

	// retCanBeFallenThrough maps offsets (pc) of return instructions to whether
	// or not they can be fallen through (i.e. not jumped to).
	retCanBeFallenThrough := make([]bool, numInstructions)

	// retValueToPC maps return values to a set of instructions that return
	// that value.
	// In BPF, the value of the K register is part of the return instruction
	// itself ("immediate" in assembly parlance), whereas the A register is
	// more of a regular register (previous operations may store/load/modify
	// it). So any return statement that returns the value of the A register
	// is functionally identical to any other, but any return statement that
	// returns the value of the K register must have the same value of K in
	// the return instruction for it to be functionally equivalent.
	// So, for return instructions that return K, we use the immediate value
	// of the K register (which is a uint32), and for return instructions
	// that return the A register, we use the stand-in value
	// "0xaaaaaaaaaaaaaaaa" (which doesn't fit in uint32, so it can't conflict
	// with an immediate value of K).
	const retRegisterA = 0xaaaaaaaaaaaaaaaa
	retValueToPC := make(map[uint64][]int)

	for pc, ins := range insns {
		if !ins.IsReturn() {
			continue // Not a conditional jump instruction.
		}
		var retValue uint64
		switch ins.OpCode - Ret {
		case A:
			retValue = retRegisterA
		case K:
			retValue = uint64(ins.K)
		default:
			panic(fmt.Sprintf("unknown return value in instruction at pc=%d: %v", pc, ins))
		}
		popularity := 0
		canBeFallenThrough := false
		for pc2 := 0; pc2 < pc; pc2++ {
			ins2 := insns[pc2]
			switch ins2.OpCode & instructionClassMask {
			case Ret:
				// Do nothing.
			case Jmp:
				if ins2.IsConditionalJump() {
					// Note that the optimizeSameTargetConditionalJumps should make it
					// such that it's not possible for there to be a conditional jump
					// with identical "true" and "false" targets, so this should not
					// result in adding 2 to `popularity`.
					if jumpTrueTarget := pc2 + int(ins2.JumpIfTrue) + 1; jumpTrueTarget == pc {
						popularity++
					}
					if jumpFalseTarget := pc2 + int(ins2.JumpIfFalse) + 1; jumpFalseTarget == pc {
						popularity++
					}
				} else {
					if jumpTarget := pc2 + int(ins2.K) + 1; jumpTarget == pc {
						popularity++
					}
				}
			default:
				if pc2 == pc-1 {
					// This return instruction can be fallen through to.
					popularity += numInstructions
					canBeFallenThrough = true
				}
			}
		}
		retValueToPC[retValue] = append(retValueToPC[retValue], pc)
		retPopularity[pc] = popularity
		retCanBeFallenThrough[pc] = canBeFallenThrough
	}

	rewriteOps := make([]jumpRewriteOperation, 0, len(insns))
	for _, pcs := range retValueToPC {
		sort.Slice(pcs, func(i, j int) bool {
			// Sort `pcs` in order of ascending popularity.
			// If the popularity is the same, sort by PC.
			if retPopularity[pcs[i]] != retPopularity[pcs[j]] {
				return retPopularity[pcs[i]] < retPopularity[pcs[j]]
			}
			return pcs[i] < pcs[j]
		})
		for i, unpopularPC := range pcs {
			if retCanBeFallenThrough[unpopularPC] {
				// Can't remove this return instruction, so no need to try
				// to check if we can rewrite other instructions that jump to it.
				continue
			}
			for j := len(pcs) - 1; j > i; j-- {
				popularPC := pcs[j]
				// Check if we can rewrite all instructions that jump to `unpopularPC`
				// to instead jump to `popularPC`.
				if rewriteAllJumpsToReturn(insns, unpopularPC, popularPC, rewriteOps) {
					changed = true
					break
				}
			}
		}
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
		removeRedundantLoads,
		optimizeJumpsToSmallestSetOfReturns,
	})
}
