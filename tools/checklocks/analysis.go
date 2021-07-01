// Copyright 2020 The gVisor Authors.
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
	"strings"

	"golang.org/x/tools/go/ssa"
)

func gcd(a, b atomicAlignment) atomicAlignment {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// typeAlignment returns the type alignment for the given type.
func (pc *passContext) typeAlignment(pkg *types.Package, obj types.Object) atomicAlignment {
	requiredOffset := atomicAlignment(1)
	if pc.pass.ImportObjectFact(obj, &requiredOffset) {
		return requiredOffset
	}

	switch x := obj.Type().Underlying().(type) {
	case *types.Struct:
		fields := make([]*types.Var, x.NumFields())
		for i := 0; i < x.NumFields(); i++ {
			fields[i] = x.Field(i)
		}
		offsets := pc.pass.TypesSizes.Offsetsof(fields)
		for i := 0; i < x.NumFields(); i++ {
			// Check the offset, and then assuming that this offset
			// aligns with the offset for the broader type.
			fieldRequired := pc.typeAlignment(pkg, fields[i])
			if offsets[i]%int64(fieldRequired) != 0 {
				// The offset of this field is not compatible.
				pc.maybeFail(fields[i].Pos(), "have alignment %d, need %d", offsets[i], fieldRequired)
			}
			// Ensure the requiredOffset is the LCM of the offset.
			requiredOffset *= fieldRequired / gcd(requiredOffset, fieldRequired)
		}
	case *types.Array:
		// Export direct alignment requirements.
		if named, ok := x.Elem().(*types.Named); ok {
			requiredOffset = pc.typeAlignment(pkg, named.Obj())
		}
	default:
		// Use the compiler's underlying alignment.
		requiredOffset = atomicAlignment(pc.pass.TypesSizes.Alignof(obj.Type().Underlying()))
	}

	if pkg == obj.Pkg() {
		// Cache as an object fact, to subsequent calls. Note that we
		// can only export object facts for the package that we are
		// currently analyzing. There may be no exported facts for
		// array types or alias types, for example.
		pc.pass.ExportObjectFact(obj, &requiredOffset)
	}

	return requiredOffset
}

// checkTypeAlignment checks the alignment of the given type.
//
// This calls typeAlignment, which resolves all types recursively. This method
// should be called for all types individual to ensure full coverage.
func (pc *passContext) checkTypeAlignment(pkg *types.Package, typ *types.Named) {
	_ = pc.typeAlignment(pkg, typ.Obj())
}

// checkAtomicCall checks for an atomic access.
//
// inst is the instruction analyzed, obj is used only for maybeFail.
//
// If mustBeAtomic is true, then we assert that the instruction *is* an atomic
// fucnction call. If it is false, then we assert that it is *not* an atomic
// dispatch.
//
// If readOnly is true, then only atomic read access are allowed. Note that
// readOnly is only meaningful if mustBeAtomic is set.
func (pc *passContext) checkAtomicCall(inst ssa.Instruction, obj types.Object, mustBeAtomic, readOnly bool) {
	switch x := inst.(type) {
	case *ssa.Call:
		if x.Common().IsInvoke() {
			if mustBeAtomic {
				// This is an illegal interface dispatch.
				pc.maybeFail(inst.Pos(), "dynamic dispatch with atomic-only field")
			}
			return
		}
		fn, ok := x.Common().Value.(*ssa.Function)
		if !ok {
			if mustBeAtomic {
				// This is an illegal call to a non-static function.
				pc.maybeFail(inst.Pos(), "dispatch to non-static function with atomic-only field")
			}
			return
		}
		pkg := fn.Package()
		if pkg == nil {
			if mustBeAtomic {
				// This is a call to some shared wrapper function.
				pc.maybeFail(inst.Pos(), "dispatch to shared function or wrapper")
			}
			return
		}
		var lff lockFunctionFacts // Check for exemption.
		if obj := fn.Object(); obj != nil && pc.pass.ImportObjectFact(obj, &lff) && lff.Ignore {
			return
		}
		if name := pkg.Pkg.Name(); name != "atomic" && name != "atomicbitops" {
			if mustBeAtomic {
				// This is an illegal call to a non-atomic package function.
				pc.maybeFail(inst.Pos(), "dispatch to non-atomic function with atomic-only field")
			}
			return
		}
		if !mustBeAtomic {
			// We are *not* expecting an atomic dispatch.
			if _, ok := pc.forced[pc.positionKey(inst.Pos())]; !ok {
				pc.maybeFail(inst.Pos(), "unexpected call to atomic function")
			}
		}
		if !strings.HasPrefix(fn.Name(), "Load") && readOnly {
			// We are not allowing any reads in this context.
			if _, ok := pc.forced[pc.positionKey(inst.Pos())]; !ok {
				pc.maybeFail(inst.Pos(), "unexpected call to atomic write function, is a lock missing?")
			}
			return
		}
	default:
		if mustBeAtomic {
			// This is something else entirely.
			if _, ok := pc.forced[pc.positionKey(inst.Pos())]; !ok {
				pc.maybeFail(inst.Pos(), "illegal use of atomic-only field by %T instruction", inst)
			}
			return
		}
	}
}

func resolveStruct(typ types.Type) (*types.Struct, bool) {
	structType, ok := typ.Underlying().(*types.Struct)
	if ok {
		return structType, true
	}
	ptrType, ok := typ.Underlying().(*types.Pointer)
	if ok {
		return resolveStruct(ptrType.Elem())
	}
	return nil, false
}

func findField(typ types.Type, field int) (types.Object, bool) {
	structType, ok := resolveStruct(typ)
	if !ok {
		return nil, false
	}
	return structType.Field(field), true
}

// instructionWithReferrers is a generalization over ssa.Field, ssa.FieldAddr.
type instructionWithReferrers interface {
	ssa.Instruction
	Referrers() *[]ssa.Instruction
}

// checkFieldAccess checks the validity of a field access.
//
// This also enforces atomicity constraints for fields that must be accessed
// atomically. The parameter isWrite indicates whether this field is used
// downstream for a write operation.
func (pc *passContext) checkFieldAccess(inst instructionWithReferrers, structObj ssa.Value, field int, ls *lockState, isWrite bool) {
	var (
		lff         lockFieldFacts
		lgf         lockGuardFacts
		guardsFound int
		guardsHeld  int
	)

	fieldObj, _ := findField(structObj.Type(), field)
	pc.pass.ImportObjectFact(fieldObj, &lff)
	pc.pass.ImportObjectFact(fieldObj, &lgf)

	for guardName, fl := range lgf.GuardedBy {
		guardsFound++
		r := fl.resolve(structObj)
		if _, ok := ls.isHeld(r); ok {
			guardsHeld++
			continue
		}
		if _, ok := pc.forced[pc.positionKey(inst.Pos())]; ok {
			// Mark this as locked, since it has been forced.
			ls.lockField(r)
			guardsHeld++
			continue
		}
		// Note that we may allow this if the disposition is atomic,
		// and we are allowing atomic reads only. This will fall into
		// the atomic disposition check below, which asserts that the
		// access is atomic. Further, guardsHeld < guardsFound will be
		// true for this case, so we require it to be read-only.
		if lgf.AtomicDisposition != atomicRequired {
			// There is no force key, no atomic access and no lock held.
			pc.maybeFail(inst.Pos(), "invalid field access, %s must be locked when accessing %s (locks: %s)", guardName, fieldObj.Name(), ls.String())
		}
	}

	// Check the atomic access for this field.
	switch lgf.AtomicDisposition {
	case atomicRequired:
		// Check that this is used safely as an input.
		readOnly := guardsHeld < guardsFound
		if refs := inst.Referrers(); refs != nil {
			for _, otherInst := range *refs {
				pc.checkAtomicCall(otherInst, fieldObj, true, readOnly)
			}
		}
		// Check that this is not otherwise written non-atomically,
		// even if we do hold all the locks.
		if isWrite {
			pc.maybeFail(inst.Pos(), "non-atomic write of field %s, writes must still be atomic with locks held (locks: %s)", fieldObj.Name(), ls.String())
		}
	case atomicDisallow:
		// Check that this is *not* used atomically.
		if refs := inst.Referrers(); refs != nil {
			for _, otherInst := range *refs {
				pc.checkAtomicCall(otherInst, fieldObj, false, false)
			}
		}
	}
}

func (pc *passContext) checkCall(call callCommon, ls *lockState) {
	// See: https://godoc.org/golang.org/x/tools/go/ssa#CallCommon
	//
	// 1. "call" mode: when Method is nil (!IsInvoke), a CallCommon represents an ordinary
	//  function call of the value in Value, which may be a *Builtin, a *Function or any
	//  other value of kind 'func'.
	//
	// 	Value may be one of:
	// (a) a *Function, indicating a statically dispatched call
	// to a package-level function, an anonymous function, or
	// a method of a named type.
	//
	// (b) a *MakeClosure, indicating an immediately applied
	// function literal with free variables.
	//
	// (c) a *Builtin, indicating a statically dispatched call
	// to a built-in function.
	//
	// (d) any other value, indicating a dynamically dispatched
	//     function call.
	switch fn := call.Common().Value.(type) {
	case *ssa.Function:
		var lff lockFunctionFacts
		if fn.Object() != nil {
			pc.pass.ImportObjectFact(fn.Object(), &lff)
			pc.checkFunctionCall(call, fn, &lff, ls)
		} else {
			// Anonymous functions have no facts, and cannot be
			// annotated.  We don't check for violations using the
			// function facts, since they cannot exist. Instead, we
			// do a fresh analysis using the current lock state.
			fnls := ls.fork()
			for i, arg := range call.Common().Args {
				fnls.store(fn.Params[i], arg)
			}
			pc.checkFunction(call, fn, &lff, fnls, true /* force */)
		}
	case *ssa.MakeClosure:
		// Note that creating and then invoking closures locally is
		// allowed, but analysis of passing closures is done when
		// checking individual instructions.
		pc.checkClosure(call, fn, ls)
	default:
		return
	}
}

// postFunctionCallUpdate updates all conditions.
func (pc *passContext) postFunctionCallUpdate(call callCommon, lff *lockFunctionFacts, ls *lockState) {
	// Release all locks not still held.
	for fieldName, fg := range lff.HeldOnEntry {
		if _, ok := lff.HeldOnExit[fieldName]; ok {
			continue
		}
		r := fg.resolveCall(call.Common().Args, call.Value())
		if s, ok := ls.unlockField(r); !ok {
			if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok {
				pc.maybeFail(call.Pos(), "attempt to release %s (%s), but not held (locks: %s)", fieldName, s, ls.String())
			}
		}
	}

	// Update all held locks if acquired.
	for fieldName, fg := range lff.HeldOnExit {
		if _, ok := lff.HeldOnEntry[fieldName]; ok {
			continue
		}
		// Acquire the lock per the annotation.
		r := fg.resolveCall(call.Common().Args, call.Value())
		if s, ok := ls.lockField(r); !ok {
			if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok {
				pc.maybeFail(call.Pos(), "attempt to acquire %s (%s), but already held (locks: %s)", fieldName, s, ls.String())
			}
		}
	}
}

// checkFunctionCall checks preconditions for function calls, and tracks the
// lock state by recording relevant calls to sync functions. Note that calls to
// atomic functions are tracked by checkFieldAccess by looking directly at the
// referrers (because ordering doesn't matter there, so we need not scan in
// instruction order).
func (pc *passContext) checkFunctionCall(call callCommon, fn *ssa.Function, lff *lockFunctionFacts, ls *lockState) {
	// Check all guards required are held.
	for fieldName, fg := range lff.HeldOnEntry {
		r := fg.resolveCall(call.Common().Args, call.Value())
		if s, ok := ls.isHeld(r); !ok {
			if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok {
				pc.maybeFail(call.Pos(), "must hold %s (%s) to call %s, but not held (locks: %s)", fieldName, s, fn.Name(), ls.String())
			} else {
				// Force the lock to be acquired.
				ls.lockField(r)
			}
		}
	}

	// Update all lock state accordingly.
	pc.postFunctionCallUpdate(call, lff, ls)

	// Check if it's a method dispatch for something in the sync package.
	// See: https://godoc.org/golang.org/x/tools/go/ssa#Function
	if fn.Package() != nil && fn.Package().Pkg.Name() == "sync" && fn.Signature.Recv() != nil {
		switch fn.Name() {
		case "Lock", "RLock":
			if s, ok := ls.lockField(resolvedValue{value: call.Common().Args[0], valid: true}); !ok {
				if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok {
					// Double locking a mutex that is already locked.
					pc.maybeFail(call.Pos(), "%s already locked (locks: %s)", s, ls.String())
				}
			}
		case "Unlock", "RUnlock":
			if s, ok := ls.unlockField(resolvedValue{value: call.Common().Args[0], valid: true}); !ok {
				if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok {
					// Unlocking something that is already unlocked.
					pc.maybeFail(call.Pos(), "%s already unlocked (locks: %s)", s, ls.String())
				}
			}
		}
	}
}

// checkClosure forks the lock state, and creates a binding for the FreeVars of
// the closure. This allows the analysis to resolve the closure.
func (pc *passContext) checkClosure(call callCommon, fn *ssa.MakeClosure, ls *lockState) {
	clls := ls.fork()
	clfn := fn.Fn.(*ssa.Function)
	for i, fv := range clfn.FreeVars {
		clls.store(fv, fn.Bindings[i])
	}

	// Note that this is *not* a call to check function call, which checks
	// against the function preconditions. Instead, this does a fresh
	// analysis of the function from source code with a different state.
	var nolff lockFunctionFacts
	pc.checkFunction(call, clfn, &nolff, clls, true /* force */)
}

// freshAlloc indicates that v has been allocated within the local scope. There
// is no lock checking done on objects that are freshly allocated.
func freshAlloc(v ssa.Value) bool {
	switch x := v.(type) {
	case *ssa.Alloc:
		return true
	case *ssa.FieldAddr:
		return freshAlloc(x.X)
	case *ssa.Field:
		return freshAlloc(x.X)
	case *ssa.IndexAddr:
		return freshAlloc(x.X)
	case *ssa.Index:
		return freshAlloc(x.X)
	case *ssa.Convert:
		return freshAlloc(x.X)
	case *ssa.ChangeType:
		return freshAlloc(x.X)
	default:
		return false
	}
}

// isWrite indicates that this value is used as the addr field in a store.
//
// Note that this may still be used for a write. The return here is optimistic
// but sufficient for basic analysis.
func isWrite(v ssa.Value) bool {
	refs := v.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		if s, ok := ref.(*ssa.Store); ok && s.Addr == v {
			return true
		}
	}
	return false
}

// callCommon is an ssa.Value that also implements Common.
type callCommon interface {
	Pos() token.Pos
	Common() *ssa.CallCommon
	Value() *ssa.Call
}

// checkInstruction checks the legality the single instruction based on the
// current lockState.
func (pc *passContext) checkInstruction(inst ssa.Instruction, ls *lockState) (*ssa.Return, *lockState) {
	switch x := inst.(type) {
	case *ssa.Store:
		// Record that this value is holding this other value. This is
		// because at the beginning of each ssa execution, there is a
		// series of assignments of parameter values to alloc objects.
		// This allows us to trace these back to the original
		// parameters as aliases above.
		//
		// Note that this may overwrite an existing value in the lock
		// state, but this is intentional.
		ls.store(x.Addr, x.Val)
	case *ssa.Field:
		if !freshAlloc(x.X) {
			pc.checkFieldAccess(x, x.X, x.Field, ls, false)
		}
	case *ssa.FieldAddr:
		if !freshAlloc(x.X) {
			pc.checkFieldAccess(x, x.X, x.Field, ls, isWrite(x))
		}
	case *ssa.Call:
		pc.checkCall(x, ls)
	case *ssa.Defer:
		ls.pushDefer(x)
	case *ssa.RunDefers:
		for d := ls.popDefer(); d != nil; d = ls.popDefer() {
			pc.checkCall(d, ls)
		}
	case *ssa.MakeClosure:
		refs := x.Referrers()
		if refs == nil {
			// This is strange, it's not used? Ignore this case,
			// since it will probably be optimized away.
			return nil, nil
		}
		hasNonCall := false
		for _, ref := range *refs {
			switch ref.(type) {
			case *ssa.Call, *ssa.Defer:
				// Analysis will be done on the call itself
				// subsequently, including the lock state at
				// the time of the call.
			default:
				// We need to analyze separately. Per below,
				// this means that we'll analyze at closure
				// construction time no zero assumptions about
				// when it will be called.
				hasNonCall = true
			}
		}
		if !hasNonCall {
			return nil, nil
		}
		// Analyze the closure without bindings. This means that we
		// assume no lock facts or have any existing lock state. Only
		// trivial closures are acceptable in this case.
		clfn := x.Fn.(*ssa.Function)
		var nolff lockFunctionFacts
		pc.checkFunction(nil, clfn, &nolff, nil, false /* force */)
	case *ssa.Return:
		return x, ls // Valid return state.
	}
	return nil, nil
}

// checkBasicBlock traverses the control flow graph starting at a set of given
// block and checks each instruction for allowed operations.
func (pc *passContext) checkBasicBlock(fn *ssa.Function, block *ssa.BasicBlock, lff *lockFunctionFacts, parent *lockState, seen map[*ssa.BasicBlock]*lockState) *lockState {
	if oldLS, ok := seen[block]; ok && oldLS.isCompatible(parent) {
		return nil
	}

	// If the lock state is not compatible, then we need to do the
	// recursive analysis to ensure that it is still sane. For example, the
	// following is guaranteed to generate incompatible locking states:
	//
	//	if foo {
	//		mu.Lock()
	//	}
	//	other stuff ...
	//	if foo {
	//		mu.Unlock()
	//	}

	var (
		rv  *ssa.Return
		rls *lockState
	)

	// Analyze this block.
	seen[block] = parent
	ls := parent.fork()
	for _, inst := range block.Instrs {
		rv, rls = pc.checkInstruction(inst, ls)
		if rls != nil {
			failed := false
			// Validate held locks.
			for fieldName, fg := range lff.HeldOnExit {
				r := fg.resolveStatic(fn, rv)
				if s, ok := rls.isHeld(r); !ok {
					if _, ok := pc.forced[pc.positionKey(rv.Pos())]; !ok {
						pc.maybeFail(rv.Pos(), "lock %s (%s) not held (locks: %s)", fieldName, s, rls.String())
						failed = true
					} else {
						// Force the lock to be acquired.
						rls.lockField(r)
					}
				}
			}
			// Check for other locks, but only if the above didn't trip.
			if !failed && rls.count() != len(lff.HeldOnExit) {
				pc.maybeFail(rv.Pos(), "return with unexpected locks held (locks: %s)", rls.String())
			}
		}
	}

	// Analyze all successors.
	for _, succ := range block.Succs {
		// Collect possible return values, and make sure that the lock
		// state aligns with any return value that we may have found
		// above. Note that checkBasicBlock will recursively analyze
		// the lock state to ensure that Releases and Acquires are
		// respected.
		if pls := pc.checkBasicBlock(fn, succ, lff, ls, seen); pls != nil {
			if rls != nil && !rls.isCompatible(pls) {
				if _, ok := pc.forced[pc.positionKey(fn.Pos())]; !ok {
					pc.maybeFail(fn.Pos(), "incompatible return states (first: %s, second: %v)", rls.String(), pls.String())
				}
			}
			rls = pls
		}
	}
	return rls
}

// checkFunction checks a function invocation, typically starting with nil lockState.
func (pc *passContext) checkFunction(call callCommon, fn *ssa.Function, lff *lockFunctionFacts, parent *lockState, force bool) {
	defer func() {
		// Mark this function as checked. This is used by the top-level
		// loop to ensure that all anonymous functions are scanned, if
		// they are not explicitly invoked here. Note that this can
		// happen if the anonymous functions are e.g. passed only as
		// parameters or used to initialize some structure.
		pc.functions[fn] = struct{}{}
	}()
	if _, ok := pc.functions[fn]; !force && ok {
		// This function has already been analyzed at least once.
		// That's all we permit for each function, although this may
		// cause some anonymous functions to be analyzed in only one
		// context.
		return
	}

	// If no return value is provided, then synthesize one. This is used
	// below only to check against the locks preconditions, which may
	// include return values.
	if call == nil {
		call = &ssa.Call{Call: ssa.CallCommon{Value: fn}}
	}

	// Initialize ls with any preconditions that require locks to be held
	// for the method to be invoked. Note that in the overwhleming majority
	// of cases, parent will be nil. However, in the case of closures and
	// anonymous functions, we may start with a non-nil lock state.
	ls := parent.fork()
	for fieldName, fg := range lff.HeldOnEntry {
		// The first is the method object itself so we skip that when looking
		// for receiver/function parameters.
		r := fg.resolveStatic(fn, call.Value())
		if s, ok := ls.lockField(r); !ok {
			// This can only happen if the same value is declared
			// multiple times, and should be caught by the earlier
			// fact scanning. Keep it here as a sanity check.
			pc.maybeFail(fn.Pos(), "lock %s (%s) acquired multiple times (locks: %s)", fieldName, s, ls.String())
		}
	}

	// Scan the blocks.
	seen := make(map[*ssa.BasicBlock]*lockState)
	if len(fn.Blocks) > 0 {
		pc.checkBasicBlock(fn, fn.Blocks[0], lff, ls, seen)
	}

	// Scan the recover block.
	if fn.Recover != nil {
		pc.checkBasicBlock(fn, fn.Recover, lff, ls, seen)
	}

	// Update all lock state accordingly. This will be called only if we
	// are doing inline analysis for e.g. an anonymous function.
	if call != nil && parent != nil {
		pc.postFunctionCallUpdate(call, lff, parent)
	}
}
