// Copyright 2026 The gVisor Authors.
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

package checklocks

import (
	"go/token"
	"go/types"
	"maps"
	"slices"

	"golang.org/x/tools/go/ssa"
)

// A callbackSlot is the index of the only function parameter a helper calls.
// Apart from invoking or forwarding that parameter, the helper only reads
// data. In particular it cannot save the callback or release a caller's lock.
type callbackSlot int

func (*callbackSlot) AFact() {}

// callbackSlot follows the generic declaration: importers need its contract,
// not an SSA body for a particular instantiation. Only ordinary package-level
// functions own these facts; a generated wrapper may share a method's object.
func (pc *passContext) callbackSlot(fn *ssa.Function) int {
	if fn == nil || fn.Parent() != nil {
		return -1
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || fn.Pkg == nil || fn.Pkg.Members[obj.Name()] != fn {
		return -1
	}
	obj = obj.Origin()
	if obj.Pkg() != pc.pass.Pkg {
		var slot callbackSlot
		if pc.pass.ImportObjectFact(obj, &slot) {
			return int(slot)
		}
		return -1
	}
	if slot, ok := pc.callbackSlots[fn]; ok {
		return slot
	}
	for i, param := range fn.Params {
		if _, ok := param.Type().Underlying().(*types.Signature); !ok {
			continue
		}
		if pc.callbackSlots == nil {
			pc.callbackSlots = make(map[*ssa.Function]int)
		}
		// Reject recursive forwarding rather than assuming a cycle is safe.
		pc.callbackSlots[fn] = -1
		if pc.onlyCalls(fn, param) {
			pc.callbackSlots[fn] = i
			slot := callbackSlot(i)
			pc.pass.ExportObjectFact(obj, &slot)
			return i
		}
	}
	return -1
}

// onlyCalls accepts direct calls to param and calls that pass it to a
// previously proved slot. Even a completely synchronous call to another
// function value could change which locks are held before param runs.
func (pc *passContext) onlyCalls(fn *ssa.Function, param *ssa.Parameter) bool {
	called := false
	for _, block := range fn.Blocks {
		for _, inst := range block.Instrs {
			switch x := inst.(type) {
			case *ssa.Call:
				c := x.Common()
				n := slices.Index(c.Args, ssa.Value(param))
				if n >= 0 {
					if n != pc.callbackSlot(c.StaticCallee()) || slices.Contains(c.Args[n+1:], ssa.Value(param)) {
						return false
					}
				} else if c.Value != param {
					if b, ok := c.Value.(*ssa.Builtin); ok && b.Name() == "len" {
						continue
					}
					return false
				}
				called = true
				continue
			case *ssa.UnOp:
				if x.Op != token.MUL {
					return false
				}
			case *ssa.Panic:
				// A constant panic, such as MinFunc on an empty slice,
				// terminates this path without calling or escaping param.
				box, ok := x.X.(*ssa.MakeInterface)
				if !ok {
					return false
				}
				if _, ok := box.X.(*ssa.Const); !ok {
					return false
				}
			case *ssa.BinOp, *ssa.ChangeType, *ssa.Convert, *ssa.Extract,
				*ssa.Field, *ssa.FieldAddr, *ssa.If, *ssa.Index, *ssa.IndexAddr,
				*ssa.Jump, *ssa.MakeInterface, *ssa.Phi, *ssa.Return:
			default:
				// Includes stores, goroutines, defers and unknown instructions.
				return false
			}
			for _, operand := range inst.Operands(nil) {
				if *operand == param {
					return false
				}
			}
		}
	}
	return called
}

// callback returns the function value invoked by a proved helper. Passing the
// same value through another slot may let it escape.
func (pc *passContext) callback(call *ssa.Call) ssa.Value {
	args := call.Common().Args
	for i, arg := range args {
		switch arg.(type) {
		case *ssa.MakeClosure, *ssa.Function:
			if pc.callbackSlot(call.Common().StaticCallee()) == i &&
				!slices.Contains(args[:i], arg) && !slices.Contains(args[i+1:], arg) {
				return arg
			}
		}
	}
	return nil
}

// A callbackFailureKey identifies a source diagnostic across simulated invocations.
// The resolved receiver and the set of held locks can change on each visit.
type callbackFailureKey struct {
	pos    token.Pos
	format string
	guard  string // Declared guard, when an instruction checks several.
}

// checkCallback joins zero invocations with each possible subsequent one.
// For example, a callback can reassign a captured pointer without changing
// any held locks. Neither the next invocation nor the caller can rely on the
// old pointer value. As with loop backedges, each intersection only drops facts.
func (pc *passContext) checkCallback(pos token.Pos, callback ssa.Value, lff *lockFunctionFacts, ls *lockState) {
	// SSA puts the range keyword's position on the yield function it creates
	// for a range loop. The call to the iterator has no position of its own.
	if closure, ok := callback.(*ssa.MakeClosure); ok && !pos.IsValid() {
		pos = closure.Fn.Pos()
	}
	// The helper supplies the callback's arguments and consumes its result.
	// Only a captured receiver or a named predicate's global guards can be
	// resolved at this call site.
	site := &callSite{args: &ssa.CallCommon{Value: callback}, pos: pos}
	// The same instruction may fail on several visits. Issue each diagnostic
	// as often as it occurs within one visit, not once per simulated call.
	var reported map[callbackFailureKey]int
	checker := *pc
	for {
		remaining := maps.Clone(reported)
		checker.shouldReport = func(f callbackFailureKey) bool {
			if lff.Ignore {
				return false
			}
			if remaining[f] > 0 {
				remaining[f]--
				return false
			}
			if reported == nil {
				reported = make(map[callbackFailureKey]int)
			}
			reported[f]++
			return pc.shouldReport == nil || pc.shouldReport(f)
		}
		result := ls.fork()
		checker.checkCall(site, lff, result)
		if pc.observations == nil {
			pc.observations = checker.observations
		}
		pc.callbackSlots = checker.callbackSlots
		if !ls.hasSameLocks(result) {
			if !lff.Ignore {
				pc.maybeFail(pos, "callback must preserve held locks (before: %s, after: %s)", ls, result)
			}
			return
		}
		result.intersect(ls)
		if ls.equivalent(result) {
			return
		}
		*ls = *result
		// A repeat is not a new field use for inferred guard suggestions.
		checker.observations = nil
	}
}
