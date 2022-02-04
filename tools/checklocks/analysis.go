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

// atomicRules specify read constraints.
type atomicRules int

const (
	nonAtomic atomicRules = iota
	readWriteAtomic
	readOnlyAtomic
	mixedAtomic
)

// checkAtomicCall checks for an atomic access.
//
// inst is the instruction analyzed, obj is used only for maybeFail.
func (pc *passContext) checkAtomicCall(inst ssa.Instruction, obj types.Object, ar atomicRules) {
	switch x := inst.(type) {
	case *ssa.Call:
		if x.Common().IsInvoke() {
			if ar != nonAtomic {
				// This is an illegal interface dispatch.
				pc.maybeFail(inst.Pos(), "dynamic dispatch with atomic-only field")
			}
			return
		}
		fn, ok := x.Common().Value.(*ssa.Function)
		if !ok {
			if ar != nonAtomic {
				// This is an illegal call to a non-static function.
				pc.maybeFail(inst.Pos(), "dispatch to non-static function with atomic-only field")
			}
			return
		}
		pkg := fn.Package()
		if pkg == nil {
			if ar != nonAtomic {
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
			if ar != nonAtomic {
				// This is an illegal call to a non-atomic package function.
				pc.maybeFail(inst.Pos(), "dispatch to non-atomic function with atomic-only field")
			}
			return
		}
		if ar == nonAtomic {
			// We are *not* expecting an atomic dispatch.
			if _, ok := pc.forced[pc.positionKey(inst.Pos())]; !ok {
				pc.maybeFail(inst.Pos(), "unexpected call to atomic function")
			}
		}
		if !strings.HasPrefix(fn.Name(), "Load") && ar == readOnlyAtomic {
			// We are not allowing any reads in this context.
			if _, ok := pc.forced[pc.positionKey(inst.Pos())]; !ok {
				pc.maybeFail(inst.Pos(), "unexpected call to atomic write function, is a lock missing?")
			}
			return
		}
		return // Don't hit common case.
	case *ssa.ChangeType:
		// Allow casts for atomic values, but nothing else.
		if refs := x.Referrers(); refs != nil && len(*refs) == 1 {
			pc.checkAtomicCall((*refs)[0], obj, ar)
			return
		}
	case *ssa.UnOp:
		if x.Op == token.MUL && ar == mixedAtomic {
			// This is allowed; this is a strict reading.
			return
		}
	}
	if ar != nonAtomic {
		// This is something else entirely.
		if _, ok := pc.forced[pc.positionKey(inst.Pos())]; !ok {
			pc.maybeFail(inst.Pos(), "illegal use of atomic-only field by %T instruction", inst)
		}
		return
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
	if !ok || field >= structType.NumFields() {
		return nil, false
	}
	return structType.Field(field), true
}

// almostInst is a generalization over ssa.Field, ssa.FieldAddr, ssa.Global.
type almostInst interface {
	Pos() token.Pos
	Referrers() *[]ssa.Instruction
}

// checkGuards checks the guards held.
//
// This also enforces atomicity constraints for fields that must be accessed
// atomically. The parameter isWrite indicates whether this field is used
// downstream for a write operation.
//
// Note that this function is not called if lff.Ignore is true, since it cannot
// discover any local anonymous functions or closures.
func (pc *passContext) checkGuards(inst almostInst, from ssa.Value, accessObj types.Object, ls *lockState, isWrite bool) {
	var (
		lgf         lockGuardFacts
		guardsFound int
		guardsHeld  = make(map[string]struct{}) // Keyed by resolved string.
	)

	// Load the facts for the object accessed.
	pc.pass.ImportObjectFact(accessObj, &lgf)

	// Check guards held.
	for guardName, fgr := range lgf.GuardedBy {
		guardsFound++
		r := fgr.resolveField(pc, ls, from)
		if !r.valid() {
			// See above; this cannot be forced.
			pc.maybeFail(inst.Pos(), "field %s cannot be resolved", guardName)
			continue
		}
		s, ok := ls.isHeld(r, isWrite)
		if ok {
			guardsHeld[s] = struct{}{}
			continue
		}
		if _, ok := pc.forced[pc.positionKey(inst.Pos())]; ok {
			// Mark this as locked, since it has been forced. All
			// forces are treated as an exclusive lock.
			s, _ := ls.lockField(r, true /* exclusive */)
			guardsHeld[s] = struct{}{}
			continue
		}
		// Note that we may allow this if the disposition is atomic,
		// and we are allowing atomic reads only. This will fall into
		// the atomic disposition check below, which asserts that the
		// access is atomic. Further, len(guardsHeld) < guardsFound
		// will be true for this case, so we require it to be
		// read-only.
		if lgf.AtomicDisposition != atomicRequired {
			// There is no force key, no atomic access and no lock held.
			pc.maybeFail(inst.Pos(), "invalid field access, %s (%s) must be locked when accessing %s (locks: %s)", guardName, s, accessObj.Name(), ls.String())
		}
	}

	// Check the atomic access for this field.
	switch lgf.AtomicDisposition {
	case atomicRequired:
		// Check that this is used safely as an input.
		ar := readWriteAtomic
		if guardsFound > 0 {
			if len(guardsHeld) < guardsFound {
				ar = readOnlyAtomic
			} else {
				ar = mixedAtomic
			}
		}
		if refs := inst.Referrers(); refs != nil {
			for _, otherInst := range *refs {
				pc.checkAtomicCall(otherInst, accessObj, ar)
			}
		}
		// Check that this is not otherwise written non-atomically,
		// even if we do hold all the locks.
		if isWrite {
			pc.maybeFail(inst.Pos(), "non-atomic write of field %s, writes must still be atomic with locks held (locks: %s)", accessObj.Name(), ls.String())
		}
	case atomicDisallow:
		// Check that this is *not* used atomically.
		if refs := inst.Referrers(); refs != nil {
			for _, otherInst := range *refs {
				pc.checkAtomicCall(otherInst, accessObj, nonAtomic)
			}
		}
	}

	// Check inferred locks.
	if accessObj.Pkg() == pc.pass.Pkg {
		oo := pc.observationsFor(accessObj)
		oo.total++
		for s, info := range ls.lockedMutexes {
			// Is this an object for which we have facts? If there
			// is no ability to name this object, then we don't
			// bother with any inferrence. We also ignore any self
			// references (e.g. accessing a mutex while you are
			// holding that exact mutex).
			if info.object == nil || accessObj == info.object {
				continue
			}
			// Has this already been held?
			if _, ok := guardsHeld[s]; ok {
				oo.counts[info.object]++
				continue
			}
			// Is this a global? Record directly.
			if _, ok := from.(*ssa.Global); ok {
				oo.counts[info.object]++
				continue
			}
			// Is the object a sibling to the accessObj? We need to
			// check all fields and see if they match. We accept
			// only siblings and globals for this recommendation.
			structType, ok := resolveStruct(from.Type())
			if !ok {
				continue
			}
			for i := 0; i < structType.NumFields(); i++ {
				if fieldObj := structType.Field(i); fieldObj == info.object {
					// Add to the maybe list.
					oo.counts[info.object]++
				}
			}
		}
	}
}

// checkFieldAccess checks the validity of a field access.
func (pc *passContext) checkFieldAccess(inst almostInst, structObj ssa.Value, field int, ls *lockState, isWrite bool) {
	fieldObj, _ := findField(structObj.Type(), field)
	pc.checkGuards(inst, structObj, fieldObj, ls, isWrite)
}

// checkGlobalAccess checks the validity of a global access.
func (pc *passContext) checkGlobalAccess(g *ssa.Global, ls *lockState, isWrite bool) {
	pc.checkGuards(g, g, g.Object(), ls, isWrite)
}

func (pc *passContext) checkCall(call callCommon, lff *lockFunctionFacts, ls *lockState) {
	// See: https://godoc.org/golang.org/x/tools/go/ssa#CallCommon
	//
	// "invoke" mode: Method is non-nil, and Value is the underlying value.
	if fn := call.Common().Method; fn != nil {
		var nlff lockFunctionFacts
		pc.pass.ImportObjectFact(fn, &nlff)
		nlff.Ignore = nlff.Ignore || lff.Ignore // Inherit ignore.
		pc.checkFunctionCall(call, fn, &nlff, ls)
		return
	}

	// "call" mode: when Method is nil (!IsInvoke), a CallCommon represents an ordinary
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
		nlff := lockFunctionFacts{
			Ignore: lff.Ignore, // Inherit ignore.
		}
		if obj := fn.Object(); obj != nil {
			pc.pass.ImportObjectFact(obj, &nlff)
			nlff.Ignore = nlff.Ignore || lff.Ignore // See above.
			pc.checkFunctionCall(call, obj.(*types.Func), &nlff, ls)
		} else {
			// Anonymous functions have no facts, and cannot be
			// annotated.  We don't check for violations using the
			// function facts, since they cannot exist. Instead, we
			// do a fresh analysis using the current lock state.
			fnls := ls.fork()
			for i, arg := range call.Common().Args {
				fnls.store(fn.Params[i], arg)
			}
			pc.checkFunction(call, fn, &nlff, fnls, true /* force */)
		}
	case *ssa.MakeClosure:
		// Note that creating and then invoking closures locally is
		// allowed, but analysis of passing closures is done when
		// checking individual instructions.
		pc.checkClosure(call, fn, lff, ls)
	default:
		return
	}
}

// postFunctionCallUpdate updates all conditions.
func (pc *passContext) postFunctionCallUpdate(call callCommon, lff *lockFunctionFacts, ls *lockState, aliases bool) {
	// Release all locks not still held.
	for fieldName, fg := range lff.HeldOnEntry {
		if _, ok := lff.HeldOnExit[fieldName]; ok {
			continue
		}
		if fg.IsAlias && !aliases {
			continue
		}
		r := fg.Resolver.resolveCall(pc, ls, call.Common().Args, call.Value())
		if !r.valid() {
			// See above: this cannot be forced.
			pc.maybeFail(call.Pos(), "field %s cannot be resolved", fieldName)
			continue
		}
		if s, ok := ls.unlockField(r, fg.Exclusive); !ok && !lff.Ignore {
			if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok && !lff.Ignore {
				pc.maybeFail(call.Pos(), "attempt to release %s (%s), but not held (locks: %s)", fieldName, s, ls.String())
			}
		}
	}

	// Update all held locks if acquired.
	for fieldName, fg := range lff.HeldOnExit {
		if _, ok := lff.HeldOnEntry[fieldName]; ok {
			continue
		}
		if fg.IsAlias && !aliases {
			continue
		}
		// Acquire the lock per the annotation.
		r := fg.Resolver.resolveCall(pc, ls, call.Common().Args, call.Value())
		if s, ok := ls.lockField(r, fg.Exclusive); !ok && !lff.Ignore {
			if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok && !lff.Ignore {
				pc.maybeFail(call.Pos(), "attempt to acquire %s (%s), but already held (locks: %s)", fieldName, s, ls.String())
			}
		}
	}
}

// exclusiveStr returns a string describing exclusive requirements.
func exclusiveStr(exclusive bool) string {
	if exclusive {
		return "exclusively"
	}
	return "non-exclusively"
}

// checkFunctionCall checks preconditions for function calls, and tracks the
// lock state by recording relevant calls to sync functions. Note that calls to
// atomic functions are tracked by checkFieldAccess by looking directly at the
// referrers (because ordering doesn't matter there, so we need not scan in
// instruction order).
func (pc *passContext) checkFunctionCall(call callCommon, fn *types.Func, lff *lockFunctionFacts, ls *lockState) {
	// Extract the "receiver" properly.
	var args []ssa.Value
	if call.Common().Method != nil {
		// This is an interface dispatch for sync.Locker.
		args = append([]ssa.Value{call.Common().Value}, call.Common().Args...)
	} else {
		// This matches the signature for the relevant
		// sync.Lock/sync.Unlock functions below.
		args = call.Common().Args
	}

	// Check all guards required are held. Note that this explicitly does
	// not include aliases, hence false being passed below.
	for fieldName, fg := range lff.HeldOnEntry {
		if fg.IsAlias {
			continue
		}
		r := fg.Resolver.resolveCall(pc, ls, args, call.Value())
		if s, ok := ls.isHeld(r, fg.Exclusive); !ok {
			if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok && !lff.Ignore {
				pc.maybeFail(call.Pos(), "must hold %s %s (%s) to call %s, but not held (locks: %s)", fieldName, exclusiveStr(fg.Exclusive), s, fn.Name(), ls.String())
			} else {
				// Force the lock to be acquired.
				ls.lockField(r, fg.Exclusive)
			}
		}
	}

	// Update all lock state accordingly.
	pc.postFunctionCallUpdate(call, lff, ls, false /* aliases */)

	// Check if it's a method dispatch for something in the sync package.
	// See: https://godoc.org/golang.org/x/tools/go/ssa#Function
	if fn.Pkg() != nil && fn.Pkg().Name() == "sync" && len(args) > 0 {
		rv := makeResolvedValue(args[0], nil)
		isExclusive := false
		switch fn.Name() {
		case "Lock":
			isExclusive = true
			fallthrough
		case "RLock":
			if s, ok := ls.lockField(rv, isExclusive); !ok && !lff.Ignore {
				if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok {
					// Double locking a mutex that is already locked.
					pc.maybeFail(call.Pos(), "%s already locked (locks: %s)", s, ls.String())
				}
			}
		case "Unlock":
			isExclusive = true
			fallthrough
		case "RUnlock":
			if s, ok := ls.unlockField(rv, isExclusive); !ok && !lff.Ignore {
				if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok {
					// Unlocking something that is already unlocked.
					pc.maybeFail(call.Pos(), "%s already unlocked or locked differently (locks: %s)", s, ls.String())
				}
			}
		case "DowngradeLock":
			if s, ok := ls.downgradeField(rv); !ok {
				if _, ok := pc.forced[pc.positionKey(call.Pos())]; !ok && !lff.Ignore {
					// Downgrading something that may not be downgraded.
					pc.maybeFail(call.Pos(), "%s already unlocked or not exclusive (locks: %s)", s, ls.String())
				}
			}
		}
	}
}

// checkClosure forks the lock state, and creates a binding for the FreeVars of
// the closure. This allows the analysis to resolve the closure.
func (pc *passContext) checkClosure(call callCommon, fn *ssa.MakeClosure, lff *lockFunctionFacts, ls *lockState) {
	clls := ls.fork()
	clfn := fn.Fn.(*ssa.Function)
	for i, fv := range clfn.FreeVars {
		clls.store(fv, fn.Bindings[i])
	}

	// Note that this is *not* a call to check function call, which checks
	// against the function preconditions. Instead, this does a fresh
	// analysis of the function from source code with a different state.
	nlff := lockFunctionFacts{
		Ignore: lff.Ignore, // Inherit ignore.
	}
	pc.checkFunction(call, clfn, &nlff, clls, true /* force */)
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
func (pc *passContext) checkInstruction(inst ssa.Instruction, lff *lockFunctionFacts, ls *lockState) (*ssa.Return, *lockState) {
	// Record any observed globals, and check for violations. The global
	// value is not itself an instruction, but we check all referrers to
	// see where they are consumed.
	var stackLocal [16]*ssa.Value
	ops := inst.Operands(stackLocal[:])
	for _, v := range ops {
		if v == nil {
			continue
		}
		g, ok := (*v).(*ssa.Global)
		if !ok {
			continue
		}
		_, isWrite := inst.(*ssa.Store)
		pc.checkGlobalAccess(g, ls, isWrite)
	}

	// Process the instruction.
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
		if !freshAlloc(x.X) && !lff.Ignore {
			pc.checkFieldAccess(x, x.X, x.Field, ls, false)
		}
	case *ssa.FieldAddr:
		if !freshAlloc(x.X) && !lff.Ignore {
			pc.checkFieldAccess(x, x.X, x.Field, ls, isWrite(x))
		}
	case *ssa.Call:
		pc.checkCall(x, lff, ls)
	case *ssa.Defer:
		ls.pushDefer(x)
	case *ssa.RunDefers:
		for d := ls.popDefer(); d != nil; d = ls.popDefer() {
			pc.checkCall(d, lff, ls)
		}
	case *ssa.MakeClosure:
		if refs := x.Referrers(); refs != nil {
			var (
				calls    int
				nonCalls int
			)
			for _, ref := range *refs {
				switch ref.(type) {
				case *ssa.Call, *ssa.Defer:
					// Analysis will be done on the call
					// itself subsequently, including the
					// lock state at the time of the call.
					calls++
				default:
					// We need to analyze separately. Per
					// below, this means that we'll analyze
					// at closure construction time no zero
					// assumptions about when it will be
					// called.
					nonCalls++
				}
			}
			if calls > 0 && nonCalls == 0 {
				return nil, nil
			}
		}
		// Analyze the closure without bindings. This means that we
		// assume no lock facts or have any existing lock state. Only
		// trivial closures are acceptable in this case.
		clfn := x.Fn.(*ssa.Function)
		nlff := lockFunctionFacts{
			Ignore: lff.Ignore, // Inherit ignore.
		}
		pc.checkFunction(nil, clfn, &nlff, nil, false /* force */)
	case *ssa.Return:
		return x, ls // Valid return state.
	}
	return nil, nil
}

// checkBasicBlock traverses the control flow graph starting at a set of given
// block and checks each instruction for allowed operations.
func (pc *passContext) checkBasicBlock(fn *ssa.Function, block *ssa.BasicBlock, lff *lockFunctionFacts, parent *lockState, seen map[*ssa.BasicBlock]*lockState, rg map[*ssa.BasicBlock]struct{}) *lockState {
	// Check for cached results from entering this block from a *different*
	// execution path. Note that this is not the same path, which is
	// checked with the recursion guard below.
	if oldLS, ok := seen[block]; ok && oldLS.isCompatible(parent) {
		return nil
	}

	// Prevent recursion. If the lock state is constantly changing and we
	// are a recursive path, then there will never be a return block.
	if rg == nil {
		rg = make(map[*ssa.BasicBlock]struct{})
	}
	if _, ok := rg[block]; ok {
		return nil
	}
	rg[block] = struct{}{}
	defer func() { delete(rg, block) }()

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
		rv, rls = pc.checkInstruction(inst, lff, ls)
		if rls != nil {
			failed := false
			// Validate held locks.
			for fieldName, fg := range lff.HeldOnExit {
				r := fg.Resolver.resolveStatic(pc, ls, fn, rv)
				if !r.valid() {
					// This cannot be forced, since we have no reference.
					pc.maybeFail(rv.Pos(), "lock %s cannot be resolved", fieldName)
					continue
				}
				if s, ok := rls.isHeld(r, fg.Exclusive); !ok {
					if _, ok := pc.forced[pc.positionKey(rv.Pos())]; !ok && !lff.Ignore {
						pc.maybeFail(rv.Pos(), "lock %s (%s) not held %s (locks: %s)", fieldName, s, exclusiveStr(fg.Exclusive), rls.String())
						failed = true
					} else {
						// Force the lock to be acquired.
						rls.lockField(r, fg.Exclusive)
					}
				}
			}
			// Check for other locks, but only if the above didn't trip.
			if !failed && rls.count() != len(lff.HeldOnExit) && !lff.Ignore {
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
		if pls := pc.checkBasicBlock(fn, succ, lff, ls, seen, rg); pls != nil {
			if rls != nil && !rls.isCompatible(pls) {
				if _, ok := pc.forced[pc.positionKey(fn.Pos())]; !ok && !lff.Ignore {
					pc.maybeFail(fn.Pos(), "incompatible return states (first: %s, second: %s)", rls.String(), pls.String())
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
	//
	// Note that this will include all aliases, which are also released
	// appropriately below.
	ls := parent.fork()
	for fieldName, fg := range lff.HeldOnEntry {
		// The first is the method object itself so we skip that when looking
		// for receiver/function parameters.
		r := fg.Resolver.resolveStatic(pc, ls, fn, call.Value())
		if !r.valid() {
			// See above: this cannot be forced.
			pc.maybeFail(fn.Pos(), "lock %s cannot be resolved", fieldName)
			continue
		}
		if s, ok := ls.lockField(r, fg.Exclusive); !ok && !lff.Ignore {
			// This can only happen if the same value is declared
			// multiple times, and should be caught by the earlier
			// fact scanning. Keep it here as a sanity check.
			pc.maybeFail(fn.Pos(), "lock %s (%s) acquired multiple times or differently (locks: %s)", fieldName, s, ls.String())
		}
	}

	// Scan the blocks.
	seen := make(map[*ssa.BasicBlock]*lockState)
	if len(fn.Blocks) > 0 {
		pc.checkBasicBlock(fn, fn.Blocks[0], lff, ls, seen, nil)
	}

	// Scan the recover block.
	if fn.Recover != nil {
		pc.checkBasicBlock(fn, fn.Recover, lff, ls, seen, nil)
	}

	// Update all lock state accordingly. This will be called only if we
	// are doing inline analysis for e.g. an anonymous function.
	if call != nil && parent != nil {
		pc.postFunctionCallUpdate(call, lff, parent, true /* aliases */)
	}
}

// checkInferred checks for any inferred lock annotations.
func (pc *passContext) checkInferred() {
	for obj, oo := range pc.observations {
		var lgf lockGuardFacts
		pc.pass.ImportObjectFact(obj, &lgf)
		for other, count := range oo.counts {
			// Is this already a guard?
			if _, ok := lgf.GuardedBy[other.Name()]; ok {
				continue
			}
			// Check to see if this field is used with a given lock
			// held above the threshold. If yes, provide a helpful
			// hint that this may something you wish to annotate.
			const threshold = 0.9
			if usage := float64(count) / float64(oo.total); usage >= threshold {
				pc.maybeFail(obj.Pos(), "may require checklocks annotation for %s, used with lock held %2.0f%% of the time", other.Name(), usage*100)
			}
		}
	}
}
